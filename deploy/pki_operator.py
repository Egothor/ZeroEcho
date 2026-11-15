#!/usr/bin/env python3
# Copyright (C) 2026, Leo Galambos
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. All advertising materials mentioning features or use of this software must
#    display the following acknowledgement:
#    This product includes software developed by the Egothor project.
#
# 4. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without
#    specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Reusable host-only PKI requests and artifacts; no scenario or deployment dependency.

Only a terminal durable SUCCEEDED record with a result means mutation completion.
Attempted requests are never reposted, including after an uncertain acknowledgement.
Local checkpoints may contain sensitive operation input; keep them private.
"""
import argparse
import base64
import binascii
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

from pki_http import (Api, ExerciseFailure, _atomic_json, _fields, _identity,
                      _json_bytes, _private_file, _result, _receipt_wire)

_TERMINAL = {"SUCCEEDED", "FAILED", "REJECTED", "EXPIRED", "CANCELLED", "RECONCILIATION_REQUIRED"}


def _identifier(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 1024 or any(ord(c) < 32 for c in value):
        raise ExerciseFailure("Invalid identity")
    return quote(value, safe="")


def _same_intent(left, right):
    try:
        return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ExerciseFailure("Intent is not finite structured JSON") from error


def _private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ExerciseFailure("Expected an owned private directory")
    return path


def _publish(path, data):
    path = Path(path)
    with tempfile.TemporaryDirectory(prefix=".pki-output-", dir=path.parent) as directory:
        source = Path(directory) / "output"
        descriptor = os.open(source, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.link(source, path, follow_symlinks=False)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _der(raw, kind, representation):
    if representation == "original":
        if not raw or raw[0] != 0x30:
            raise ExerciseFailure("Expected X.509 DER sequence")
        return raw
    label = b"CERTIFICATE" if kind == "certificate" else b"X509 CRL"
    pattern = rb"\s*-----BEGIN " + label + rb"-----\s*([A-Za-z0-9+/=\s]+)-----END " + label + rb"-----\s*"
    matched = re.fullmatch(pattern, raw)
    if not matched:
        raise ExerciseFailure("Expected exactly one PEM object")
    try:
        return _der(base64.b64decode(re.sub(rb"\s", b"", matched[1]), validate=True), kind, "original")
    except (ValueError, binascii.Error) as error:
        raise ExerciseFailure("Invalid PEM encoding") from error


def _parse_x509(der, kind):
    try:
        parsed = subprocess.run(["openssl", "x509" if kind == "certificate" else "crl",
            "-inform", "DER", "-outform", "DER"], input=der,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExerciseFailure("Local X.509 parser unavailable") from error
    if parsed.returncode or parsed.stdout != der:
        raise ExerciseFailure("Invalid or noncanonical X.509 object")


class Operator:
    """Host request session with private, origin/realm/client-bound durable checkpoints.

    Args:
        api: Authenticated shared HTTPS transport.
        realm_id: Explicit expected realm, checked before every request.
        checkpoint_directory: Owner-only directory for retained intents and receipts.
        crypto_classpath: Optional client-local Java helper classpath; defaults to the installed app distribution.
    Raises:
        ExerciseFailure: Identity, directory or concurrent-session validation fails.
        OSError: Checkpoint storage cannot be opened.
    """

    def __init__(self, api, realm_id, checkpoint_directory, crypto_classpath=None):
        if not api.client_authenticated:
            raise ExerciseFailure("Operator requires explicit mTLS identity")
        _identifier(realm_id)
        self.api, self.realm_id = api, realm_id
        self.crypto_classpath = crypto_classpath or str(Path(__file__).resolve().parent.parent / "app/build/install/app/lib/*")
        self.directory = _private_directory(checkpoint_directory)
        self._lock = None
        descriptor = os.open(self.directory / "session.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self._lock = descriptor
        try:
            _private_file(self.directory / "session.lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            binding = {"origin": api.origin, "realmId": realm_id,
                       "clientIdentitySha256": api.client_identity_sha256}
            path = self.directory / "session.json"
            if path.exists() or path.is_symlink():
                if _json_bytes(_private_file(path).read_bytes()) != binding:
                    raise ExerciseFailure("Checkpoint belongs to a different target or client identity")
            else:
                _atomic_json(path, binding)
        except BaseException:
            self.close()
            raise

    def close(self):
        """Release the session lock; repeated close is harmless and returns None."""
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None

    def __enter__(self):
        """Return this locked session for a with statement."""
        return self

    def __exit__(self, *_):
        """Release the session lock without suppressing errors."""
        self.close()

    def _guard(self):
        if self._lock is None:
            raise ExerciseFailure("Operator session is closed")
        _, wire = self.api.json("GET", "/admin/v1/realm")
        if _fields(_result(wire, "realm.inspect")).get("realmId") != self.realm_id:
            raise ExerciseFailure("Authenticated realm differs from the selected realm")

    def discover(self):
        """Return operation descriptors and schema from the selected authenticated realm.

        Raises ExerciseFailure on malformed discovery or transport/realm rejection.
        """
        self._guard()
        _, wire = self.api.json("GET", "/admin/v1/operations")
        operations = _result(wire, "operation.list").get("operations")
        _, schema = self.api.json("GET", "/admin/v1/schema")
        if not isinstance(operations, list) or not isinstance(schema, list):
            raise ExerciseFailure("Invalid operation discovery")
        return {"operations": operations, "schema": schema}

    def read(self, operation, arguments, authority=None):
        """Execute a discovered nonmutating operation and return terminal result fields.

        Args:
            operation: Exact canonical operation ID.
            arguments: Structured argument object; server validates semantics.
            authority: Optional explicit authority context.
        Raises:
            ExerciseFailure: Operation mutates, is unavailable, pending or rejected.
        """
        discovery = self.discover()
        descriptor = next((item for item in discovery["operations"] if item.get("operation") == operation), None)
        schema = next((item for item in discovery["schema"] if item.get("operationId") == operation), None)
        if descriptor is None or schema is None or schema.get("mutating") is not False:
            raise ExerciseFailure("Use durable submit for mutations; read requires a discovered read operation")
        if not isinstance(arguments, dict):
            raise ExerciseFailure("Arguments must be an object")
        payload = {"version": 1, "arguments": arguments}
        if authority is not None:
            payload["authorityId"] = authority
        self._guard()
        _, wire = self.api.json("POST", "/admin/v1/operations/" + _identifier(operation), payload)
        result = _result(wire, operation)
        if wire["status"] != "SUCCEEDED":
            raise ExerciseFailure("Read operation did not complete")
        return _fields(result)

    def _path(self, request_id):
        _identifier(request_id)
        return self.directory / (hashlib.sha256(request_id.encode()).hexdigest() + ".json")

    def _load(self, request_id):
        checkpoint = _json_bytes(_private_file(self._path(request_id)).read_bytes())
        if "refusal" in checkpoint:
            raise ExerciseFailure(checkpoint["refusal"]["code"], checkpoint["refusal"]["status"])
        return checkpoint

    def _refusal(self, path, checkpoint, error):
        if error.status in (400, 401, 403, 404, 405, 409, 413, 415, 422, 429):
            checkpoint["refusal"] = {"code": str(error), "status": error.status}
            _atomic_json(path, checkpoint)
            raise error

    def _record(self, checkpoint, wire, operation):
        record = _result(wire, operation)
        intent = checkpoint["intent"]
        if record.get("requestId") != intent["requestId"] or record.get("operation") != intent["operation"]:
            raise ExerciseFailure("Durable receipt identity differs from retained intent")
        previous = checkpoint.get("receipt", {})
        for identity in ("approvalId", "signingOperationId"):
            if previous.get(identity) is not None and record.get(identity) != previous[identity]:
                raise ExerciseFailure("Linked durable receipt identity changed")
        if record.get("state") == "SUCCEEDED" and not isinstance(record.get("result"), dict):
            raise ExerciseFailure("Completed request omitted its result")
        checkpoint["receipt"] = record
        _atomic_json(self._path(intent["requestId"]), checkpoint)
        return record

    def submit(self, intent):
        """Submit an exact durable intent at most once, returning its durable record.

        Args:
            intent: Version 1 object with requestId, operation, arguments and optional authorityId.
        Returns:
            Raw durable record; WAITING_APPROVAL/APPROVED/RUNNING never imply success.
        Raises:
            ExerciseFailure: Unsupported operation, changed intent or uncertain acknowledgement.
            OSError: Private intent cannot be retained before submission.
        """
        if not isinstance(intent, dict) or set(intent) - {"version", "requestId", "operation", "arguments", "authorityId"} or type(intent.get("version")) is not int or intent["version"] != 1 or not isinstance(intent.get("arguments"), dict):
            raise ExerciseFailure("Invalid structured durable intent")
        _identifier(intent.get("requestId"))
        _identifier(intent.get("operation"))
        path = self._path(intent["requestId"])
        if path.exists() or path.is_symlink():
            checkpoint = self._load(intent["requestId"])
            if not _same_intent(checkpoint["intent"], intent) or checkpoint.get("mode") == "dedicated":
                raise ExerciseFailure("Retained request target changed; refusing replay")
            return self.observe(intent["requestId"])
        _same_intent(intent, intent)
        discovery = self.discover()
        descriptor = next((item for item in discovery["operations"] if item.get("operation") == intent["operation"]), {})
        if descriptor.get("durableRequest") is not True:
            raise ExerciseFailure("Operation does not support durable submit")
        checkpoint = {"intent": intent, "attempted": True}
        self._guard()
        _atomic_json(path, checkpoint)
        try:
            status, wire = self.api.json("POST", "/admin/v1/requests", intent)
            if status != 202:
                raise ExerciseFailure("Expected durable HTTP 202 acknowledgement")
            return self._record(checkpoint, wire, "administrative.request.submit")
        except ExerciseFailure as error:
            self._refusal(path, checkpoint, error)
            return self.observe(intent["requestId"])

    def action(self, intent):
        """Execute one non-durable dedicated action once, retaining its exact target.

        Args:
            intent: Version/requestId/operation/arguments and optional authorityId;
                requestId is a local once-only identity, not server idempotency.
        Returns:
            Original envelope on first response; a redacted envelope on reuse.
            Pending is never completion and unknown acknowledgement is never retried.
        Raises:
            ExerciseFailure: Invalid target, durable operation or unknown result.
        """
        if not isinstance(intent, dict) or set(intent) - {"version", "requestId", "operation", "arguments", "authorityId"} or type(intent.get("version")) is not int or intent["version"] != 1 or not isinstance(intent.get("arguments"), dict):
            raise ExerciseFailure("Invalid structured dedicated intent")
        _identifier(intent.get("operation"))
        path = self._path(intent.get("requestId"))
        if path.exists() or path.is_symlink():
            checkpoint = self._load(intent["requestId"])
            if not _same_intent(checkpoint.get("intent"), intent) or checkpoint.get("mode") != "dedicated":
                raise ExerciseFailure("Retained request target changed; refusing replay")
            if "envelope" not in checkpoint:
                raise UnknownAcceptance("Dedicated acknowledgement unknown; never repeat the action")
            return checkpoint["envelope"]
        _same_intent(intent, intent)
        discovery = self.discover()
        descriptor = next((item for item in discovery["operations"] if item.get("operation") == intent["operation"]), {})
        if descriptor.get("durableRequest") is not False:
            raise ExerciseFailure("Use durable submit for this operation")
        checkpoint = {"intent": intent, "mode": "dedicated", "attempted": True}
        payload = {key: value for key, value in intent.items() if key not in ("requestId", "operation")}
        self._guard()
        _atomic_json(path, checkpoint)
        try:
            _, wire = self.api.json("POST", "/admin/v1/operations/" + _identifier(intent["operation"]), payload)
            _result(wire, intent["operation"])
            checkpoint["envelope"] = _receipt_wire(intent["operation"], wire)
            _atomic_json(path, checkpoint)
            return wire
        except ExerciseFailure as error:
            self._refusal(path, checkpoint, error)
            raise UnknownAcceptance("Dedicated action lacks a validated receipt; never replay it") from error

    def observe(self, request_id):
        """GET one retained request, returning its exact record without any mutation.

        Args:
            request_id: Identity already retained in this client checkpoint.
        Raises:
            ExerciseFailure: Receipt identity differs or acceptance remains unknown.
            OSError: Retained intent cannot be read.
        """
        checkpoint = self._load(request_id)
        if checkpoint.get("mode") == "dedicated":
            raise ExerciseFailure("Dedicated actions have no durable observation route")
        self._guard()
        try:
            _, wire = self.api.json("GET", "/admin/v1/requests/" + _identifier(request_id))
        except ExerciseFailure as error:
            if error.status == 404 or not error.status:
                raise UnknownAcceptance("Acceptance unknown; retain checkpoint and observe; never resubmit") from error
            raise
        return self._record(checkpoint, wire, "administrative.request.inspect")

    def download(self, kind, identity, representation, target):
        """Download one certificate/CRL through authenticated binary routes without overwrite.

        Args:
            kind: certificate or crl (status is an alias).
            identity: Exact credential/status identity.
            representation: Advertised original DER or pem.
            target: New output path; existing files/symlinks fail unchanged.
        Returns:
            Source identity, byte hashes and exact PEM/DER equivalence evidence.
            This is transport/object evidence, not a signature or trust assertion.
        Raises:
            ExerciseFailure: Metadata, route, representation, bytes or permission differs.
            OSError: Destination exists or cannot be published safely.
        """
        self._guard()
        if kind not in ("certificate", "crl", "status") or representation not in ("original", "pem"):
            raise ExerciseFailure("Unsupported artifact kind or representation")
        certificate = kind == "certificate"
        segment, operation, field = ("certificate-artifacts", "certificate.artifact.inspect", "credentialId") if certificate else ("status-artifacts", "status.artifact.inspect", "statusObjectId")
        path = "/admin/v1/" + segment + "/" + _identifier(identity)
        _, wire = self.api.json("GET", path)
        metadata = _fields(_result(wire, operation))
        if metadata.get(field) != identity or metadata.get("formatId") != "x509":
            raise ExerciseFailure("Artifact metadata identity or format differs")
        advertised = metadata.get("representations", [])
        if not isinstance(advertised, list):
            raise ExerciseFailure("Malformed artifact representations")
        representations = {item["id"]: item for item in advertised}
        if len(representations) != len(advertised) or representation not in representations or "original" not in representations:
            raise ExerciseFailure("Required representation is not advertised or permitted")
        downloaded = {}
        with tempfile.TemporaryDirectory(prefix=".pki-artifact-", dir=Path(target).parent) as directory:
            for selected in dict.fromkeys(("original", representation)):
                expected = path + "/content?representation=" + selected
                if representations[selected].get("href") != expected:
                    raise ExerciseFailure("Artifact link differs from canonical same-origin binary route")
                destination = Path(directory) / selected
                self.api.download(expected, destination, overwrite=False)
                downloaded[selected] = destination.read_bytes()
            der = _der(downloaded["original"], kind, "original")
            _parse_x509(der, kind)
            if _der(downloaded[representation], kind, representation) != der:
                raise ExerciseFailure("PEM and DER representations differ")
            _publish(target, downloaded[representation])
        return {"state": "DOWNLOADED", field: identity, "representation": representation,
                "sha256": hashlib.sha256(downloaded[representation]).hexdigest(),
                "derSha256": hashlib.sha256(der).hexdigest(), "pemDerEquivalent": representation == "pem",
                "signatureVerified": False}

    def ca(self, authority_id, representation, target):
        """Download the selected CA generation certificate with exact generation digest check.

        Args:
            authority_id: Explicit CA identity.
            representation: original or pem.
            target: New destination file.
        Returns:
            Download evidence after the immutable generation digest matches.
        Raises:
            ExerciseFailure: Discovery, authorization or digest fails.
            OSError: Destination cannot be published without overwrite.
        """
        ca = self.read("ca.inspect", {"caId": authority_id}, authority_id)
        if ca.get("caId") != authority_id:
            raise ExerciseFailure("CA inspection identity differs")
        generation = self.read("issuer.generation.inspect", {"issuerId": ca["currentIssuanceIssuerId"]})
        if generation.get("issuerId") != ca["currentIssuanceIssuerId"] or generation.get("authorityId") != authority_id:
            raise ExerciseFailure("CA generation coordinates differ from selected authority")
        with tempfile.TemporaryDirectory(prefix=".pki-ca-", dir=Path(target).parent) as directory:
            temporary = Path(directory) / "certificate"
            result = self.download("certificate", generation["credentialId"], representation, temporary)
            if result["derSha256"] != generation["cryptographicBinding"]["certificateSha256"]:
                raise ExerciseFailure("CA artifact differs from selected immutable generation")
            _publish(target, temporary.read_bytes())
        return result | {"issuerId": generation["issuerId"]}

    def chain(self, path_id, target, representation="pem"):
        """Download an authenticated ordered issuer path into a new PEM bundle.

        Args:
            path_id: Exact issuer path identity.
            target: New destination bundle, never overwritten.
            representation: pem; DER has no concatenated bundle representation here.
        Returns:
            Ordered credential, equivalence and primary/alternative signature evidence;
            the last downloaded certificate is the selected anchor, without external trust assertion.
        Raises:
            ExerciseFailure: Path/order/permission/representation fails.
            OSError: Output cannot be published safely.
        """
        if representation != "pem":
            raise ExerciseFailure("Chain bundle requires PEM; use certificate downloads for DER")
        path = self.read("issuer.path.inspect", {"pathId": path_id})
        identities = path.get("orderedCredentialIds")
        if path.get("pathId") != path_id or not isinstance(identities, list) or not identities or len(identities) > 32 or len(set(identities)) != len(identities):
            raise ExerciseFailure("Invalid ordered issuer path")
        artifacts, bundle = [], b""
        with tempfile.TemporaryDirectory(prefix=".pki-chain-", dir=Path(target).parent) as directory:
            for index, identity in enumerate(identities):
                destination = Path(directory) / str(index)
                artifacts.append(self.download("certificate", identity, "pem", destination))
                bundle += destination.read_bytes().strip() + b"\n"
            candidate = Path(directory) / "bundle.pem"
            _publish(candidate, bundle)
            try:
                checked = subprocess.run(["java", "-cp", self.crypto_classpath,
                    "zeroecho.pki.cli.CertificateScenarioCrypto", "verify-chain", str(candidate)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ExerciseFailure("Local chain verifier unavailable; no bundle accepted") from error
            if checked.returncode or not checked.stdout.startswith(b"VERIFIED issuer-chain "):
                raise ExerciseFailure("Issuer chain cryptographic verification failed; no bundle accepted")
            _publish(target, bundle)
        return {"state": "DOWNLOADED", "pathId": path_id, "orderedCredentialIds": identities,
                "artifacts": artifacts, "sha256": hashlib.sha256(bundle).hexdigest(), "signatureVerified": True,
                "trust": "explicitly-selected-downloaded-anchor"}


class UnknownAcceptance(ExerciseFailure):
    """A mutation may have been accepted; only GET observation is safe."""


def result_exit(record):
    """Return 0 only for completed success, 2 terminal failure, 3 pending/approval.

    Args:
        record: Durable request record with state and optional result.
    Raises:
        ExerciseFailure: Record lacks a valid state/result.
    """
    state = record.get("state")
    if state == "SUCCEEDED":
        if not isinstance(record.get("result"), dict):
            raise ExerciseFailure("Success lacks result")
        return 0
    if state in _TERMINAL:
        return 2
    if state in {"READY", "DISPATCHING", "ACCEPTED", "WAITING_APPROVAL", "APPROVED", "RUNNING", "EXECUTING", "QUEUED"}:
        return 3
    raise ExerciseFailure("Unrecognized durable state")


def action_exit(envelope):
    """Return completion semantics for a dedicated response without implying target execution.

    Args:
        envelope: Validated dedicated operation response.
    Returns:
        Three for pending or approval-only, zero for another completed action.
    Raises:
        ExerciseFailure: Envelope is not a recognized successful/pending response.
    """
    if envelope.get("status") not in ("SUCCEEDED", "PENDING"):
        raise ExerciseFailure("Dedicated action lacks a validated result")
    if envelope["status"] == "PENDING" or envelope.get("operation") in ("security.approval.approve", "security.approval.reject"):
        return 3
    return 0


def main(arguments=None):
    """Run the host CLI; return 0 completed, 2 error, 3 pending, 4 unknown acceptance.

    Args:
        arguments: Optional argument list; defaults to process arguments.
    Passwords come only from TTY or a caller-owned inherited FD. No password values
    are accepted in arguments or environment; extracted local keys are temporary.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--p12", type=Path, required=True)
    parser.add_argument("--password-fd", type=int)
    parser.add_argument("--crypto-classpath")
    parser.add_argument("--checkpoint", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("discover")
    for name in ("submit", "read", "action"):
        sub.add_parser(name).add_argument("input", type=Path)
    observe = sub.add_parser("observe")
    observe.add_argument("request_id")
    observe.add_argument("--wait", type=float, default=0)
    for name in ("certificate", "crl", "ca", "chain"):
        command = sub.add_parser(name)
        command.add_argument("identity")
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--representation", choices=("original", "pem"), default="pem" if name == "chain" else "original")
    options = parser.parse_args(arguments)
    try:
        if options.command == "observe" and not 0 <= options.wait <= 3600:
            raise ExerciseFailure("Wait must be between zero and 3600 seconds")
        _private_file(options.p12)
        if options.password_fd is None:
            if not sys.stdin.isatty():
                raise ExerciseFailure("Noninteractive use requires --password-fd")
            password = getpass.getpass("Administrator PKCS#12 password: ")
        else:
            if options.password_fd < 0:
                raise ExerciseFailure("Invalid password descriptor")
            with os.fdopen(os.dup(options.password_fd), "rb") as source:
                secret = source.readline(4097)
            if len(secret) > 4096:
                raise ExerciseFailure("Password exceeds its byte bound")
            password = secret.decode("utf-8").removesuffix("\n")
        with tempfile.TemporaryDirectory(prefix="zeroecho-operator-") as directory:
            certificate, key = _identity(Path(directory), options.p12, password)
            del password
            api = Api(options.url, options.trust, certificate, key)
            with Operator(api, options.realm, options.checkpoint, options.crypto_classpath) as operator:
                if options.command == "discover":
                    result = operator.discover()
                elif options.command in ("submit", "read", "action"):
                    document = _json_bytes(_private_file(options.input).read_bytes())
                    if options.command == "submit":
                        result = operator.submit(document)
                    elif options.command == "action":
                        result = operator.action(document)
                    else:
                        result = operator.read(document["operation"], document["arguments"], document.get("authorityId"))
                elif options.command == "observe":
                    deadline = time.monotonic() + options.wait
                    while True:
                        result = operator.observe(options.request_id)
                        if result_exit(result) != 3 or time.monotonic() >= deadline:
                            break
                        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
                elif options.command == "ca":
                    result = operator.ca(options.identity, options.representation, options.output)
                elif options.command == "chain":
                    result = operator.chain(options.identity, options.output, options.representation)
                else:
                    result = operator.download(options.command, options.identity, options.representation, options.output)
                code = result_exit(result) if options.command in ("submit", "observe") else action_exit(result) if options.command == "action" else 0
                # Request results may carry one-time secrets; stdout is an explicit private consumer.
                print(json.dumps({"exit": code, "result": result}, sort_keys=True))
                return code
    except UnknownAcceptance as error:
        print(json.dumps({"exit": 4, "error": str(error)}))
        return 4
    except (ExerciseFailure, OSError, ValueError, KeyError, TypeError, EOFError, subprocess.SubprocessError) as error:
        diagnostic = str(error) if isinstance(error, ExerciseFailure) else "Invalid input or local client I/O failure"
        print(json.dumps({"exit": 2, "error": diagnostic}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
