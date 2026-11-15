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

"""Qualify newly created demo PKI objects through the real authenticated HTTP API.

The operator runs this program; importing it has no host or network effects.
Passwords are passed to OpenSSL through stdin, never command arguments or environment.
Durable mutation intents are checkpointed before their single POST attempt.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, urlsplit
import uuid

if __name__ == "__main__":
    sys.modules.setdefault("exercise_pki", sys.modules[__name__])

CATALOG_IDS = tuple("""acme.account.deactivate
acme.account.inspect
acme.account.list
acme.directory.activate
acme.directory.deactivate
acme.directory.inspect
acme.directory.list
acme.directory.register
algorithm.binding.inspect
algorithm.binding.list
algorithm.binding.validate
backup.export
backup.restore
backup.stream.acknowledge
backup.stream.download
backup.stream.export
backup.stream.reserve
backup.stream.restore
backup.stream.status
backup.stream.upload
backup.stream.verify
backup.verify
ca.create
ca.inspect
ca.intermediate.create
ca.intermediate.issue
ca.list
ca.rollover
ca.rotate
ca.transition
certificate.publication.enroll
cmp.endpoint.deregister
cmp.endpoint.inspect
cmp.endpoint.list
cmp.endpoint.register
configuration.choices
configuration.validate
credential.confirmation.challenge.issue
credential.confirmation.pending.list
credential.confirmation.pending.revoke
credential.confirmation.proof.complete
credential.hold
credential.inspect
credential.issue
credential.list
credential.reissue
credential.renew
credential.replace
credential.revoke
credential.search
credential.unhold
dashboard.authority
dashboard.certificate
dashboard.publication
dashboard.revocation
dashboard.server
enrollment.profile.activate
enrollment.profile.inspect
enrollment.profile.list
enrollment.profile.register
enrollment.profile.suspend
enrollment.profile.update
enrollment.request.approve
enrollment.request.inspect
enrollment.request.list
enrollment.request.reject
est.endpoint.deregister
est.endpoint.inspect
est.endpoint.list
est.endpoint.register
inventory.status
issuer.generation.inspect
issuer.generation.list
issuer.path.inspect
issuer.path.list
issuer.path.register
issuer.path.select
ocsp.responder.activate
ocsp.responder.deactivate
ocsp.responder.inspect
ocsp.responder.list
ocsp.responder.register
profile.activate
profile.inspect
profile.list
profile.list-all
profile.register
profile.validate
publication.inspect
publication.list
publication.process
publication.reconcile
publication.register
publication.retry
repository.alias.inspect
repository.alias.list
repository.alias.remove
repository.alias.set
request.import
request.inspect
request.list
request.verify
revocation.history
revocation.inspect
revocation.snapshot
scep.endpoint.deregister
scep.endpoint.inspect
scep.endpoint.list
scep.endpoint.register
security.approval.approve
security.approval.cancel
security.approval.inspect
security.approval.list
security.approval.reject
security.approval.request
security.audit-view.inspect-full
security.audit-view.inspect-pii
security.audit-view.inspect-redacted
security.audit.search
security.audit.verify-integrity
security.authorization.evaluate
security.break-glass.activate
security.break-glass.create
security.break-glass.inspect
security.break-glass.list
security.break-glass.revoke
security.disclosure.capability.issue
security.disclosure.capability.list
security.disclosure.capability.revoke
security.disclosure.inspect
security.disclosure.set
security.grant.create
security.grant.inspect
security.grant.list
security.grant.revoke
security.principal.disable
security.principal.enable
security.principal.inspect
security.principal.list
security.principal.register
security.role-assignment.create
security.role-assignment.inspect
security.role-assignment.list
security.role-assignment.revoke
security.role-template.inspect
security.role-template.list
status.generate
status.inspect
status.schedule.inspect
status.schedule.list
status.schedule.set""".split())
CATALOG_UNAVAILABLE = frozenset(('backup.restore',))
CATALOG_SHA256 = 'af9b341bede1b18aef243d07d2b10d7aa57cab3a2cbb231e179b0dc7262ecdbb'
TERMINAL = frozenset({"SUCCEEDED", "FAILED", "REJECTED", "EXPIRED", "CANCELLED", "RECONCILIATION_REQUIRED"})
LIMIT = 8 * 1024 * 1024


from pki_http import (
    Api, ExerciseFailure, _atomic_json, _fields, _identity, _json_bytes, _openssl,
    _private_file, _receipt_fields, _receipt_wire, _result,
)


class ExternalRestartRequired(ExerciseFailure):
    """A retained restore is staged; only the separate deployment script may restart its server."""
    waiting_external_restart=True


class Exercise:
    """Checkpointed demo-only scenario executor with explicit receipt-based operation coverage."""

    def __init__(self, api, directory, *, clock=time.monotonic, sleep=time.sleep, timeout=180):
        """Acquire exclusive ownership of a private checkpoint directory.

        Args:
            api: Same-origin HTTPS client.
            directory: Owned private output directory, empty or resumable.
            clock: Monotonic time source in seconds.
            sleep: Bounded observation pause callback.
            timeout: Maximum observation duration in seconds.
        Returns:
            None; the output lock remains held until close.
        Raises:
            ExerciseFailure: Directory ownership, concurrent use or retained origin is unsafe.
            OSError: Private files cannot be created or loaded.
        """
        self.api, self.directory = api, Path(directory)
        self.clock, self.sleep, self.timeout = clock, sleep, timeout
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self.directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ExerciseFailure("Output must be a private directory owned by this user")
        lock_path = self.directory / ".exercise.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self._lock = os.fdopen(descriptor, "r+b")
        _private_file(lock_path)
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self._lock.close()
            raise ExerciseFailure("Another exercise owns this output directory") from error
        self.path = self.directory / "checkpoint.json"
        if self.path.exists():
            _private_file(self.path)
            self.state = _json_bytes(self.path.read_bytes())
            if self.state.get("version") != 1 or self.state.get("origin") != api.origin:
                raise ExerciseFailure("Checkpoint belongs to another API origin or version")
        else:
            if any(path.name != ".exercise.lock" for path in self.directory.iterdir()):
                raise ExerciseFailure("Use an empty output directory or resume its existing checkpoint")
            self.state = {"version": 1, "origin": api.origin, "runId": uuid.uuid4().hex, "jobs": {}, "coverage": {operation:{"state":"NOT_APPLICABLE" if operation in CATALOG_UNAVAILABLE else "BLOCKED","reason":"Reviewed catalog marks globally unavailable" if operation in CATALOG_UNAVAILABLE else "Not yet discovered or qualified"} for operation in CATALOG_IDS}, "artifacts": {}}
            self.save()
        self.schema = {}
        self.descriptors = {}
        self.target_guard = None

    def close(self):
        """Release exclusive output ownership; retained artifacts and checkpoints remain private.
        
        Returns:
            None; retained files remain available for resumption.
        
        Raises:
            OSError: Output lock cannot be closed.
        """
        self._lock.close()

    def save(self):
        """Persist the exact run state atomically before external mutations; never store login passwords.
        
        Returns:
            None after an atomic private checkpoint replacement.
        
        Raises:
            OSError: The checkpoint cannot be safely written or synchronized.
        """
        _atomic_json(self.path, self.state)

    def discover(self):
        """Read actual operation descriptors and typed schema; keep every reviewed catalog ID in coverage.
        
        Returns:
            None; typed schema, runtime descriptors and coverage are updated.
        
        Raises:
            ExerciseFailure: Discovery transport or response shape is invalid.
            OSError: Discovery evidence cannot be persisted.
        """
        _, schema = self.api.json("GET", "/admin/v1/schema")
        _, wire = self.api.json("GET", "/admin/v1/operations")
        operations = _result(wire, "operation.list").get("operations")
        if not isinstance(schema, list) or not isinstance(operations, list):
            raise ExerciseFailure("Operation discovery is malformed")
        self.schema = {item["operationId"]: item for item in schema}
        self.descriptors = {item["operation"]: item for item in operations}
        for operation in sorted(set(CATALOG_IDS) | set(self.schema)):
            self.state["coverage"].setdefault(operation, {"state": "NOT_APPLICABLE" if operation in CATALOG_UNAVAILABLE else "BLOCKED", "reason": "Reviewed catalog declares globally unavailable; catalog SHA256 " + CATALOG_SHA256 if operation in CATALOG_UNAVAILABLE else "No verified scenario receipt; excluded from live-demo mutation scope" if operation in self.descriptors else "Not offered to this identity/deployment"})
        _atomic_json(self.directory / "schema.json", schema)
        self.save()

    def _payload(self, operation, arguments, authority=None):
        spec = self.schema.get(operation)
        if spec is None or operation not in self.descriptors:
            raise ExerciseFailure("Operation is not offered: " + operation, 403)
        fields = {field["name"]: field for field in spec["fields"]}
        if set(arguments) - set(fields) or any(field["required"] and name not in arguments for name, field in fields.items()):
            raise ExerciseFailure("Arguments do not match the discovered schema: " + operation)
        for name, value in arguments.items():
            kind = fields[name]["type"]
            if kind == "integer" and type(value) is not int or kind == "boolean" and type(value) is not bool or kind in ("text", "enum", "base64") and not isinstance(value, str) or kind == "object" and not isinstance(value, dict):
                raise ExerciseFailure("Argument type does not match the schema: " + name)
            if kind in ("text-set", "enum-set") and (not isinstance(value, list) or any(not isinstance(item, str) for item in value) or len(set(value)) != len(value)):
                raise ExerciseFailure("Expected a unique string set: " + name)
            choices = fields[name].get("choices", [])
            values = value if kind == "enum-set" else [value]
            if choices and any(item not in choices for item in values):
                raise ExerciseFailure("Argument is outside the discovered choices: " + name)
            if kind == "base64":
                try:
                    base64.b64decode(value, validate=True)
                except ValueError as error:
                    raise ExerciseFailure("Expected canonical Base64: " + name) from error
        payload = {"version": 1, "arguments": arguments}
        if authority is not None:
            payload["authorityId"] = authority
        if spec.get("scope") == "authority" and authority is None and not spec.get("authorityFrom"):
            raise ExerciseFailure("Authority context is required: " + operation)
        return payload

    def operation(self, operation, arguments, authority=None, *, approval_id=None):
        """Execute a declared read/dedicated action once and retain only its validated success receipt.
        
        Args:
            operation: Discovered canonical operation ID.
            arguments: Schema-validated argument object.
            authority: Optional canonical authority context.
            approval_id: Optional retained approval for a dedicated legacy action.
        
        Returns:
            Validated operation result fields; one-time secrets exist only in this immediate return.
        
        Raises:
            ExerciseFailure: Schema, authorization, execution or receipt validation fails.
            OSError: The non-secret receipt cannot be persisted.
        """
        if callable(self.target_guard) and self.schema.get(operation,{}).get("mutating") is True:self.target_guard(self.api.origin,self.state["runId"])
        payload = self._payload(operation, arguments, authority)
        if approval_id is not None:
            payload["approvalId"] = approval_id
        try:
            _, wire = self.api.json("POST", "/admin/v1/operations/" + operation, payload)
        except ExerciseFailure as error:
            self._failed(operation, error)
            raise ExerciseFailure(operation + ": " + str(error), error.status) from error
        result = _result(wire, operation)
        if wire["status"] != "SUCCEEDED":
            _atomic_json(self.directory / (operation + ".pending.json"), _receipt_wire(operation, wire))
            raise ExerciseFailure("Dedicated operation is not terminal; retained receipt requires observation: " + operation)
        self.state["coverage"][operation] = {"state": "EXECUTED", "reason": "Validated successful HTTP operation receipt"}
        _atomic_json(self.directory / (operation + ".json"), _receipt_wire(operation, wire))
        self.save()
        return _fields(result)

    def job(self, name, operation, arguments, authority=None):
        """Submit one durable intent once, explicitly decide its approval and observe through GET only.
        
        Parameters identify a stable scenario step and exact target. A lost acknowledgement
        is reconciled by its retained request ID, never by an automatic second POST.
        Returns verified terminal operation fields; raises ExerciseFailure for rejection,
        expiry, missing grants, unknown acceptance or a bounded observation timeout.
        
        Args:
            name: Stable checkpoint-local intent name.
            operation: Discovered durable operation ID.
            arguments: Exact target arguments retained before submission.
            authority: Optional canonical authority context.
        
        Returns:
            Terminal successful result fields after GET-only observation.
        
        Raises:
            ExerciseFailure: Changed intent, rejected or expired request, missing approval capability, unknown acknowledgement or observation deadline.
            OSError: The durable intent cannot be retained.
        """
        if callable(self.target_guard):self.target_guard(self.api.origin,self.state["runId"])
        self._payload(operation, arguments, authority)
        if self.descriptors[operation].get("durableRequest") is not True:
            raise ExerciseFailure("Operation has no durable request support: " + operation)
        intent = {"version": 1, "requestId": "exercise-" + self.state["runId"] + "-" + name,
                  "operation": operation, "arguments": arguments}
        if authority is not None:
            intent["authorityId"] = authority
        step = self.state["jobs"].setdefault(name, {"intent": intent, "attempted": False, "decisionAttempted": False})
        if step["intent"] != intent:
            raise ExerciseFailure("A retained scenario target changed; refusing replay")
        self.save()
        record = None
        if not step["attempted"]:
            step["attempted"] = True
            self.save()
            try:
                status, wire = self.api.json("POST", "/admin/v1/requests", intent)
                if status != 202:
                    raise ExerciseFailure("Expected durable HTTP 202 acknowledgement")
                record = _result(wire, "administrative.request.submit")
            except ExerciseFailure as error:
                step["submissionDiagnostic"] = str(error)
                self.save()
                if error.status in (400, 401, 403, 409, 422):
                    self._failed(operation, error)
                    raise
        deadline = self.clock() + self.timeout
        while self.clock() < deadline:
            if record is None:
                _, wire = self.api.json("GET", "/admin/v1/requests/" + quote(intent["requestId"], safe=""))
                record = _result(wire, "administrative.request.inspect")
            if record.get("requestId") != intent["requestId"] or record.get("operation") != operation:
                raise ExerciseFailure("Durable receipt does not match the retained target")
            step["receipt"] = record
            self.save()
            state = record.get("state")
            if state == "SUCCEEDED":
                result = record.get("result")
                if not isinstance(result, dict):
                    raise ExerciseFailure("Completed request has no typed result")
                self.state["coverage"][operation] = {"state": "EXECUTED", "requestId": intent["requestId"], "reason": "Verified durable terminal receipt"}
                self.save()
                return _fields(result)
            if state in TERMINAL:
                failure_code = record.get("failureCode", "UNSPECIFIED")
                if not isinstance(failure_code, str) or not re.fullmatch(r"[A-Z0-9_]{1,128}", failure_code):
                    failure_code = "UNSPECIFIED"
                error = ExerciseFailure(operation + " ended " + str(state) + ": " + failure_code)
                self._failed(operation, error)
                raise error
            if state == "WAITING_APPROVAL" and not step["decisionAttempted"]:
                approval = record.get("approvalId")
                if not isinstance(approval, str) or not approval:
                    raise ExerciseFailure("Waiting request has no approval identity")
                step["decisionAttempted"] = True
                self.save()
                try:
                    self.operation("security.approval.approve", {"approvalId": approval,
                        "justification": "Operator-requested isolated demo objects; run " + self.state["runId"]}, authority)
                except ExerciseFailure as error:
                    if error.status:
                        self._failed(operation, error)
                        raise ExerciseFailure("Approval was not permitted; decide the retained approval externally, then resume", error.status) from error
            record = None
            self.sleep(0.5)
        raise ExerciseFailure("Observation timed out; retain checkpoint and resume without resubmitting")

    def dedicated(self, name, operation, arguments, authority=None, *, approval_id=None):
        """Execute one dedicated mutation once; secret-bearing results are returned only immediately, never persisted.
        
        Repeated calls return the retained redacted receipt, without reissuing a lost token.
        
        Args:
            name: Stable checkpoint-local dedicated action name.
            operation: Discovered canonical operation ID.
            arguments: Exact schema-validated target arguments.
            authority: Optional canonical authority context.
            approval_id: Optional explicit approval ID for the dedicated action.
        
        Returns:
            Immediate result fields, or the retained redacted result on resume.
        
        Raises:
            ExerciseFailure: Changed intent, unknown acknowledgement or failed execution.
            OSError: The once-only checkpoint cannot be persisted.
        """
        if callable(self.target_guard):self.target_guard(self.api.origin,self.state["runId"])
        payload = self._payload(operation, arguments, authority)
        if approval_id is not None:
            payload["approvalId"] = approval_id
        actions = self.state.setdefault("dedicated", {})
        retained = actions.setdefault(name, {"operation": operation, "payload": payload, "attempted": False})
        if retained["operation"] != operation or retained["payload"] != payload:
            raise ExerciseFailure("Retained dedicated action changed")
        if "result" in retained:
            return retained["result"]
        if retained["attempted"]:
            raise ExerciseFailure("Dedicated action acknowledgement is unknown; reconcile its retained identity before continuing")
        retained["attempted"] = True
        self.save()
        result = self.operation(operation, arguments, authority, approval_id=approval_id)
        retained["result"] = _receipt_fields(operation, result)
        self.save()
        return result

    def _failed(self, operation, error):
        self.state["coverage"][operation] = {"state": "BLOCKED" if error.status in (401, 403, 404) else "FAILED", "reason": str(error)}
        self.save()

    def report(self, *, strict=False):
        """Write all catalog rows and return zero only when requested qualification coverage is complete.
        
        Args:
            strict: Require the entire reviewed catalogue rather than discovered deployment coverage.
        
        Returns:
            Process result code: zero when qualified, otherwise three.
        
        Raises:
            OSError: The private qualification report cannot be written.
        """
        rows = self.state["coverage"]
        proofs = self.state.get("demoVerified") is True and "failure" not in self.state
        if self.state.get("mode") in ("full", "isolated-full"):
            proofs = proofs and self.state.get("publicArtifacts", {}).get("state") == "EXECUTED"
        deployment_qualified = bool(self.descriptors) and proofs and all(rows.get(operation, {}).get("state") == "EXECUTED" for operation in self.descriptors)
        catalogue_qualified = bool(rows) and proofs and all(row["state"] in ("EXECUTED", "NOT_APPLICABLE") for row in rows.values())
        protocol_rows = self.state.get("protocolWireProofs", {})
        protocol_qualified = all(protocol_rows.get(protocol, {}).get("state") == "VERIFIED" and
            all(protocol_rows[protocol].get(proof) is True for proof in ("issuanceVerified", "keyMatchVerified", "chainVerified"))
            for protocol in ("acme", "est", "scep", "cmp"))
        qualified = catalogue_qualified if strict else deployment_qualified
        if self.state.get("mode") in ("full", "isolated-full"):
            qualified = qualified and protocol_qualified
        result = {"version": 1, "runId": self.state["runId"], "origin": self.state["origin"],
                  "qualified": qualified, "protocolQualified": protocol_qualified, "protocolWireProofs": protocol_rows,
                  "transportKind": self.state.get("transportKind",self.state.get("isolated", {}).get("kind", "live")), "executionState": self.state.get("executionState"),
                  "deploymentQualified": deployment_qualified, "catalogueQualified": catalogue_qualified,
                  "catalogueCount": len(rows), "discoveredCount": len(self.descriptors),
                  "executedCount": sum(row["state"] == "EXECUTED" for row in rows.values()),
                  "notConfiguredCount": sum(row["state"] == "NOT_CONFIGURED" for row in rows.values()),
                  "demoVerified": self.state.get("demoVerified", False), "publicArtifacts": self.state.get("publicArtifacts"),
                  "mode": self.state.get("mode", "live-demo"), "catalogSha256": CATALOG_SHA256, "coverage": rows, "artifacts": self.state["artifacts"]}
        _atomic_json(self.directory / "report.json", result)
        return 3 if strict and not qualified else 0


def _generate_client(directory, run_id):
    key, csr, der = (directory / name for name in ("client.key", "client.csr", "client.csr.der"))
    checkpoint = directory / "checkpoint.json"
    retained_identity = checkpoint.exists() and bool(_json_bytes(_private_file(checkpoint).read_bytes()).get("clientKeySha256"))
    if not key.exists() and (retained_identity or csr.exists() or der.exists() or (directory / "client.pem").exists()):
        raise ExerciseFailure("Client private key is missing for an existing identity; retain the old output and start a fresh output directory")
    if not csr.exists() and retained_identity:
        raise ExerciseFailure("Retained client CSR is missing; refusing to silently rebind an issued identity")
    if not key.exists():
        _openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key])
        key.chmod(0o600)
    _private_file(key)
    if not csr.exists():
        _openssl(["req", "-new", "-sha256", "-key", key, "-subj", "/CN=ZeroEcho demo client " + run_id,
                  "-addext", "subjectAltName=URI:spiffe://zeroecho.invalid/demo/" + run_id, "-out", csr])
    _openssl(["req", "-in", csr, "-verify", "-noout"])
    _openssl(["req", "-in", csr, "-outform", "DER", "-out", der])
    return key, csr, der


def _verify_certificates(directory):
    ca, client = directory / "ca.pem", directory / "client.pem"
    for prefix in ("ca", "client"):
        from_der = _openssl(["x509", "-inform", "DER", "-in", directory / (prefix + ".der"), "-outform", "DER"])
        from_pem = _openssl(["x509", "-in", directory / (prefix + ".pem"), "-outform", "DER"])
        if from_der != from_pem:
            raise ExerciseFailure("PEM and DER identify different certificates")
    key = _openssl(["pkey", "-in", directory / "client.key", "-pubout", "-outform", "DER"])
    public_pem = _openssl(["x509", "-in", client, "-pubkey", "-noout"])
    public_der = _openssl(["pkey", "-pubin", "-outform", "DER"], data=public_pem)
    if key != public_der:
        raise ExerciseFailure("Issued client certificate does not match its retained private key")
    _openssl(["verify", "-CAfile", ca, "-purpose", "sslclient", client])
    return _openssl(["x509", "-in", client, "-serial", "-noout"]).decode().strip().split("=", 1)[1].lstrip("0").upper() or "0"


def _verify_crls(directory, serial):
    full = directory / "full.pem"
    delta = directory / "delta.pem"
    for path in (full, delta):
        original = path.with_suffix(".der")
        if _openssl(["crl", "-inform", "DER", "-in", original, "-outform", "DER"]) != _openssl(["crl", "-in", path, "-outform", "DER"]):
            raise ExerciseFailure("PEM and DER identify different CRLs")
        _openssl(["crl", "-in", path, "-verify", "-CAfile", directory / "ca.pem", "-noout"])
    full_text = _openssl(["crl", "-in", full, "-text", "-noout"]).decode("ascii")
    delta_text = _openssl(["crl", "-in", delta, "-text", "-noout"]).decode("ascii")
    full_serials = {value.replace(":", "").lstrip("0").upper() or "0" for value in re.findall(r"Serial Number:\s*([0-9A-Fa-f:]+)", full_text)}
    delta_serials = {value.replace(":", "").lstrip("0").upper() or "0" for value in re.findall(r"Serial Number:\s*([0-9A-Fa-f:]+)", delta_text)}
    if serial in full_serials or serial not in delta_serials:
        raise ExerciseFailure("CRL transition does not prove the newly revoked client serial")
    after = directory / "full-after.pem"
    _openssl(["crl", "-in", after, "-verify", "-CAfile", directory / "ca.pem", "-noout"])
    if _openssl(["crl", "-inform", "DER", "-in", after.with_suffix(".der"), "-outform", "DER"]) != _openssl(["crl", "-in", after, "-outform", "DER"]):
        raise ExerciseFailure("Post-revocation full CRL representations differ")
    after_text = _openssl(["crl", "-in", after, "-text", "-noout"]).decode("ascii")
    after_serials = {value.replace(":", "").lstrip("0").upper() or "0" for value in re.findall(r"Serial Number:\s*([0-9A-Fa-f:]+)", after_text)}
    if serial not in after_serials or "Key Compromise" not in after_text:
        raise ExerciseFailure("Post-revocation full CRL omits the expected serial or reason")
    verification = subprocess.run(["openssl", "verify", "-CAfile", str(directory / "ca.pem"), "-CRLfile", str(after), "-crl_check", str(directory / "client.pem")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
    failures = re.findall(rb"error ([0-9]+) at [0-9]+ depth lookup: ([^\r\n]+)", verification.stderr)
    if verification.returncode == 0 or failures != [(b"23", b"certificate revoked")]:
        raise ExerciseFailure("Certificate verification did not fail specifically because of revocation")
    number = _openssl(["crl", "-in", full, "-crlnumber", "-noout"]).decode().strip().split("=", 1)[1]
    base = re.search(r"Delta CRL Indicator:[^\n]*\n\s*(0x[0-9A-Fa-f]+|[0-9]+)", delta_text)
    if not base or int(base[1], 0 if base[1].startswith("0x") else 10) != int(number, 0):
        raise ExerciseFailure("Delta CRL base does not match the verified full CRL")


def _artifact(exercise, kind, identity, prefix, maximum):
    segment, operation, id_field = ("certificate-artifacts", "certificate.artifact.inspect", "credentialId") if kind == "certificate" else ("status-artifacts", "status.artifact.inspect", "statusObjectId")
    path = "/admin/v1/" + segment + "/" + quote(identity, safe="")
    _, wire = exercise.api.json("GET", path)
    metadata = _fields(_result(wire, operation))
    if metadata.get(id_field) != identity or metadata.get("formatId") != "x509":
        raise ExerciseFailure("Artifact identity or selected X.509 format does not match")
    representations = {value["id"]: value for value in metadata.get("representations", [])}
    if not {"original", "pem"} <= set(representations):
        flag = "--certificate-access" if kind == "certificate" else "--status-access"
        raise ExerciseFailure("Required artifact access unavailable; operator may run deploy/rootless-pki.sh update " + flag, 403)
    for representation, extension in (("original", "der"), ("pem", "pem")):
        item = representations[representation]
        expected = path + "/content?representation=" + representation
        if item.get("href") != expected:
            raise ExerciseFailure("Artifact link is not the canonical same-origin route")
        target = exercise.directory / (prefix + "." + extension)
        if target.exists():
            _private_file(target)
        exercise.api.download(expected, target, maximum=maximum)
        exercise.state["artifacts"][target.name] = {"sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "sourceId": identity, "verified": False}
    exercise.save()
    return metadata


def _confirm(exercise, credential, authority):
    challenge = exercise.dedicated("client-challenge", "credential.confirmation.challenge.issue", {"credentialId": credential}, authority)
    if challenge.get("proofSuiteId") != "zeroecho.signature-pop.v1":
        raise ExerciseFailure("Client proof provider is not the reviewed signature suite")
    response = exercise.state.get("clientProofResponse")
    if response is None:
        presentation = challenge["presentation"]
        payload = base64.urlsafe_b64decode(presentation + "=" * (-len(presentation) % 4))
        signature = _openssl(["dgst", "-sha256", "-sign", exercise.directory / "client.key"], data=payload)
        response = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        exercise.state["clientProofResponse"] = response
        exercise.save()
    arguments = {name: challenge[name] for name in ("credentialId", "expectedLifecycleRevision", "expectedLifecycleRecordCommitment", "expectedChallengeRecordCommitment")}
    arguments["response"] = response
    confirmed = exercise.dedicated("client-proof", "credential.confirmation.proof.complete", arguments, authority)
    if confirmed.get("confirmationResult") != "CONFIRMED":
        raise ExerciseFailure("Client holder proof was not confirmed")


def _preflight_access(exercise, principal):
    if not principal:
        raise ExerciseFailure("A known current principal is required for permission preflight; supply --principal-id with custom login settings")
    for action, resource, view, flag, relationship in (("CERTIFICATE_READ_CONTENT", "CERTIFICATE", "CONTENT_FULL", "--certificate-access", "ANY"),
            ("CERTIFICATE_DOWNLOAD", "CERTIFICATE", "CONTENT_FULL", "--certificate-access", "ANY"),
            ("CRL_DOWNLOAD", "STATUS_OBJECT", "CONTENT_FULL", "--status-access", "ANY")):
        decision = exercise.operation("security.authorization.evaluate", {"principalId": principal, "action": action,
            "resourceType": resource, "relationship": relationship, "dataView": view})
        if decision.get("allowed") is not True:
            raise ExerciseFailure("Required demo access is missing (" + action + "); the operator may explicitly run deploy/rootless-pki.sh update " + flag + " before resuming", 403)

    offset = 0
    while True:
        page = exercise.operation("security.grant.list", {"offset": offset, "limit": 100})
        if any(row.get("principalId") == principal and row.get("enabled") is True and row.get("effect") == "ALLOW" and row.get("action") == "APPROVAL_DECIDE_OWN" for row in page.get("items", [])):
            break
        if page.get("hasMore") is not True:
            raise ExerciseFailure("No explicit own-approval capability is configured for this principal; operator may run deploy/rootless-pki.sh update --root-admin", 403)
        following = page.get("nextOffset")
        if type(following) is not int or following <= offset:
            raise ExerciseFailure("Permission preflight pagination did not advance")
        offset = following


def _live(exercise, options):
    exercise.discover()
    _preflight_access(exercise, options.principal_id)
    choices = exercise.operation("configuration.choices", {"limit": 100})
    available_keys = {value["keyRef"] for value in choices.get("keys", {}).get("items", [])}
    if options.ca_key_ref not in available_keys:
        raise ExerciseFailure("Requested server-protected CA key is unavailable; select --ca-key-ref from configuration choices")
    key, _, csr_der = _generate_client(exercise.directory, exercise.state["runId"])
    digest = hashlib.sha256(key.read_bytes()).hexdigest()
    previous = exercise.state.setdefault("clientKeySha256", digest)
    if previous != digest:
        raise ExerciseFailure("Retained client private key changed; refusing to reuse issuance intents")
    exercise.save()
    created = exercise.job("ca", "ca.create", {"formatId": "x509", "subjectRef": "CN=ZeroEcho DEMO " + exercise.state["runId"],
        "profileId": options.ca_profile, "keyRef": options.ca_key_ref})
    ca_metadata = _artifact(exercise, "certificate", created["credentialId"], "ca", options.maximum_download_bytes)
    authority = ca_metadata["authorityId"]
    inspected = exercise.operation("ca.inspect", {"caId": authority}, authority)
    objects = exercise.state.setdefault("objects", {})
    objects.update(authorityId=authority, caId=authority, caCredentialId=created["credentialId"], issuerId=inspected["currentIssuanceIssuerId"])
    exercise.save()
    imported = exercise.job("csr", "request.import", {"formatId": "x509", "encoded": base64.b64encode(csr_der.read_bytes()).decode("ascii")})
    exercise.operation("request.verify", {"requestId": imported["requestId"]})
    issued = exercise.job("client", "credential.issue", {"issuerCaId": authority, "requestId": imported["requestId"], "profileId": options.client_profile}, authority)
    credential = issued["credentialId"]
    objects.update(clientCredentialId=credential, credentialId=credential, requestId=imported["requestId"])
    exercise.save()
    _artifact(exercise, "certificate", credential, "client", options.maximum_download_bytes)
    owner = exercise.state["jobs"]["client"]["receipt"]["requesterPrincipalId"]
    enrolled = exercise.job("client-enrollment", "certificate.publication.enroll", {"credentialId": credential, "ownerPrincipalId": owner})
    objects["clientDisclosurePolicy"] = enrolled.get("policy")
    exercise.save()
    _confirm(exercise, credential, authority)
    serial = _verify_certificates(exercise.directory)
    full = exercise.job("full", "status.generate", {"issuerCaId": authority, "type": "CRL", "formatId": "x509"}, authority)
    _artifact(exercise, "status", full["statusObjectId"], "full", options.maximum_download_bytes)
    exercise.job("revoke", "credential.revoke", {"credentialId": credential, "reason": "KEY_COMPROMISE", "justification": "Demo key withdrawal; isolated new credential only"}, authority)
    delta = exercise.job("delta", "status.generate", {"issuerCaId": authority, "type": "DELTA_CRL", "formatId": "x509"}, authority)
    _artifact(exercise, "status", delta["statusObjectId"], "delta", options.maximum_download_bytes)
    after = exercise.job("full-after", "status.generate", {"issuerCaId": authority, "type": "CRL", "formatId": "x509"}, authority)
    _artifact(exercise, "status", after["statusObjectId"], "full-after", options.maximum_download_bytes)
    objects.update(fullStatusId=full["statusObjectId"], deltaStatusId=delta["statusObjectId"], fullAfterStatusId=after["statusObjectId"])
    exercise.save()
    _verify_crls(exercise.directory, serial)
    inspected_ca = exercise.operation("ca.inspect", {"caId": authority}, authority)
    objects["issuerId"] = inspected_ca.get("currentIssuanceIssuerId") or objects.get("issuerId")
    if not objects["issuerId"]:
        generations = exercise.operation("issuer.generation.list", {"limit": 100}, authority).get("generations", [])
        objects["issuerId"] = next((row["issuerId"] for row in generations if row.get("credentialId") == objects["caCredentialId"]), None)
    exercise.operation("credential.list", {"limit": 100}, authority)
    exercise.operation("credential.inspect", {"credentialId": credential}, authority)
    exercise.operation("revocation.inspect", {"credentialId": credential}, authority)
    _, wire = exercise.api.json("GET", "/admin/v1/realm")
    public = _result(wire, "realm.inspect").get("publicRepository", {})
    exercise.state["publicArtifacts"] = {"state": "BLOCKED", "reason": "No public binding/disclosure was enabled by this exercise"}
    if public.get("available") is True and public.get("basePath") == "/public/v1":
        exercise.state["publicArtifacts"]["reason"] = "Published listener exists; explicit disclosure and aliases must be qualified separately"
    for value in exercise.state["artifacts"].values():
        value["verified"] = True
    exercise.state["demoVerified"] = True
    exercise.state.pop("failure", None)
    exercise.save()
    if options.require_public and not getattr(options, "defer_public_verification", False):
        raise ExerciseFailure("Anonymous public artifact qualification is BLOCKED; private mTLS downloads are not public proof")


def _public_verification(exercise, public_api, *, publish=False, assert_disposable=None):
    if public_api.client_authenticated:
        raise ExerciseFailure("Public qualification requires a separate client without any client certificate")
    objects = exercise.state["objects"]
    authority, issuer = objects["authorityId"], objects["issuerId"]
    if not issuer:
        raise ExerciseFailure("Authoritative current issuer identity is unavailable")
    if publish:
        if assert_disposable is None:
            raise ExerciseFailure("Demo publication changes require a live disposable ownership proof")
        for alias, name in (("CURRENT_CRL", "fullStatusId"), ("CURRENT_DELTA_CRL", "deltaStatusId")):
            assert_disposable(exercise.api.origin, exercise.state["runId"])
            exercise.job("alias-" + alias.lower(), "repository.alias.set", {"authorityId": authority, "type": alias,
                "targetObjectId": objects[name], "issuerId": issuer}, authority)
    paths = {"ca.der": "/public/v1/authorities/" + quote(authority, safe="") + "/issuers/" + quote(issuer, safe="") + "/certificate",
        "full.der": "/public/v1/status/" + quote(objects["fullStatusId"], safe=""),
        "delta.der": "/public/v1/status/" + quote(objects["deltaStatusId"], safe=""),
        "full-after.der": "/public/v1/status/" + quote(objects["fullAfterStatusId"], safe="")}
    if publish:
        paths.update({"full-alias": "/public/v1/authorities/" + quote(authority, safe="") + "/crl",
                      "delta-alias": "/public/v1/authorities/" + quote(authority, safe="") + "/delta-crl"})
    observed = {}
    for name, path in paths.items():
        _, _, raw = public_api.request("GET", path)
        expected = exercise.directory / ({"full-alias": "full.der", "delta-alias": "delta.der"}.get(name, name))
        if raw != expected.read_bytes():
            raise ExerciseFailure("Anonymous public artifact differs from verified authenticated content: " + name)
        observed[name] = {"path": path, "sha256": hashlib.sha256(raw).hexdigest()}
    client_path = "/public/v1/certificates/" + quote(objects["clientCredentialId"], safe="")
    policy = objects.get("clientDisclosurePolicy")
    if policy == "PUBLIC":
        _, _, content = public_api.request("GET", client_path)
        if content != (exercise.directory / "client.der").read_bytes():
            raise ExerciseFailure("Public client certificate differs from authenticated content")
        observed["client"] = {"expectedAudience": "PUBLIC", "sha256": hashlib.sha256(content).hexdigest()}
    elif policy in ("OWNER_ONLY", "RESTRICTED"):
        try:
            public_api.request("GET", client_path)
        except ExerciseFailure as refusal:
            if refusal.status != 404:
                raise ExerciseFailure("Private certificate denial did not use the public non-disclosure boundary") from refusal
        else:
            raise ExerciseFailure("A private client certificate was anonymously disclosed")
        observed["client"] = {"expectedAudience": policy, "anonymousStatus": 404, "authenticatedDownloadVerified": True}
    else:
        raise ExerciseFailure("Client disclosure policy is unknown; no anonymous-public conclusion is valid")
    exercise.state["publicArtifacts"] = {"state": "EXECUTED", "reason": "Verified anonymous TLS GETs without client certificate, cookie, bearer token or admin transport", "origin": public_api.origin, "artifacts": observed}
    exercise.save()


def _wait_backup(exercise, handle, wanted):
    deadline = exercise.clock()+exercise.timeout
    while exercise.clock()<deadline:
        current=exercise.operation("backup.stream.status",{"artifactHandle":handle})
        if current.get("state") in wanted: return current
        if current.get("state") in ("FAILED","REJECTED","UNCERTAIN","CONSUMED"):
            raise ExerciseFailure("Backup artifact ended "+str(current.get("state")))
        exercise.sleep(0.5)
    raise ExerciseFailure("Backup observation timed out; retain its exact handle and do not replay")


def _backup_transfer(exercise, operation, values, context):
    context["assert_disposable"](exercise.api.origin,exercise.state["runId"])
    def once(name, action, arguments, *, approval_id=None):
        context["assert_disposable"](exercise.api.origin,exercise.state["runId"])
        return exercise.dedicated(name,action,arguments,approval_id=approval_id)
    state=exercise.state.setdefault("backupScenario",{"receipts":{}})
    receipts=state["receipts"]
    if operation in receipts and (operation!="backup.stream.restore" or "backup.stream.acknowledge" in receipts): return receipts[operation]
    if operation in ("backup.export","backup.verify"):
        exported=once("catalog-backup-legacy-export","backup.export",{"label":"exercise-"+exercise.state["runId"]})
        receipts["backup.export"]=exported
        if operation=="backup.verify":
            prepared=exported
            if context.get("clientDirectory") is not None:
                reference=context.get("legacyBackup")
                if not isinstance(reference,dict):raise ExerciseFailure("Prepared bounded legacy backup is missing from the client connection",403)
                root=Path(context["clientDirectory"]).resolve()
                relative=Path(reference.get("path",""))
                if relative.is_absolute() or not relative.parts or ".." in relative.parts:raise ExerciseFailure("Prepared legacy backup must be a client-owned relative path")
                path=root/relative
                if not path.resolve().is_relative_to(root):raise ExerciseFailure("Prepared backup escapes the client directory")
                path=_private_file(path)
                if path.stat().st_size>LIMIT:raise ExerciseFailure("Prepared legacy backup exceeds its client byte bound")
                raw=path.read_bytes()
                if hashlib.sha256(raw).hexdigest()!=reference.get("sha256"):raise ExerciseFailure("Prepared legacy backup identity changed")
                prepared=_fields(_json_bytes(raw))
                if prepared.get("backupId")!=reference.get("backupId") or not isinstance(prepared.get("payload"),str):raise ExerciseFailure("Prepared legacy backup receipt is malformed")
            verified=exercise.operation("backup.verify",{"backupId":prepared["backupId"],"payload":prepared["payload"]})
            if verified.get("valid") is not True: raise ExerciseFailure("Legacy backup verification rejected the actual exported archive")
            receipts[operation]=verified
        exercise.save()
        return receipts[operation]
    if "export" not in state:
        state["export"]=once("catalog-backup-stream-export","backup.stream.export",{"label":"exercise-"+exercise.state["runId"]})
        exercise.save()
    exported=_wait_backup(exercise,state["export"]["artifactHandle"],{"READY"}) if "download" not in state else state["exportReady"]
    state["exportReady"]=exported
    receipts["backup.stream.export"]=exported
    archive=exercise.directory/"disposable-backup.zip"
    if "download" not in state:
        if state.get("downloadAttempted"): raise ExerciseFailure("Backup download acknowledgement is unknown; its consumed handle is never automatically replayed")
        state["downloadAttempted"]=True;exercise.save()
        context["assert_disposable"](exercise.api.origin,exercise.state["runId"])
        downloaded=exercise.api.backup_transfer("download",exported["artifactHandle"],target=archive)
        if downloaded["length"]!=exported["length"] or downloaded["sha256"]!=exported["sha256"]:
            raise ExerciseFailure("Downloaded backup does not match the server's exact length and SHA-256")
        state["download"]=downloaded
        receipts["backup.stream.download"]=downloaded
        exercise.state["coverage"]["backup.stream.download"]={"state":"EXECUTED","reason":"Authenticated one-shot ZIP bytes matched declared length and SHA-256"}
        exercise.save()
    if "upload" not in state:
        state["upload"]=once("catalog-backup-reserve","backup.stream.reserve",{"backupId":exported["backupId"],"length":state["download"]["length"],"sha256":state["download"]["sha256"]})
        receipts["backup.stream.reserve"]=state["upload"];exercise.save()
    handle=state["upload"]["artifactHandle"]
    if "backup.stream.upload" not in receipts:
        if state.get("uploadAttempted"):
            uploaded=_wait_backup(exercise,handle,{"READY","VERIFIED"})
        else:
            state["uploadAttempted"]=True;exercise.save()
            context["assert_disposable"](exercise.api.origin,exercise.state["runId"])
            uploaded=exercise.api.backup_transfer("upload",handle,source=archive)
        if uploaded.get("sha256")!=state["download"]["sha256"] or uploaded.get("length")!=state["download"]["length"]:
            raise ExerciseFailure("Uploaded archive identity changed")
        receipts["backup.stream.upload"]=uploaded
        exercise.state["coverage"]["backup.stream.upload"]={"state":"EXECUTED","reason":"Authenticated binary ZIP upload retained the verified archive identity"}
        exercise.save()
    if "backup.stream.verify" not in receipts:
        once("catalog-backup-verify","backup.stream.verify",{"artifactHandle":handle})
        verified=_wait_backup(exercise,handle,{"VERIFIED"})
        receipts["backup.stream.verify"]=verified;exercise.save()
    if operation=="backup.stream.status":
        receipts[operation]=exercise.operation(operation,{"artifactHandle":handle});exercise.save()
    if operation=="backup.stream.restore":
        approval_id="exercise-"+exercise.state["runId"]+"-restore-approval"
        once("catalog-restore-approval-request","security.approval.request",{"approvalId":approval_id,"targetOperation":operation,"targetArguments":{"artifactHandle":handle}})
        once("catalog-restore-approval-decision","security.approval.approve",{"approvalId":approval_id,"justification":"Explicit restoration of this disposable qualification instance only"})
        once("catalog-backup-restore",operation,{"artifactHandle":handle},approval_id=approval_id)
        staged=_wait_backup(exercise,handle,{"STAGED","ACTIVATED"})
        retained=state.setdefault("stagedRestoreId",staged.get("restoreId"))
        if not retained or staged.get("restoreId")!=retained:raise ExerciseFailure("Restore workflow identity changed")
        if staged["state"]=="STAGED":
            exercise.state["waitingExternalRestart"]={"artifactHandle":handle,"restoreId":retained}
            exercise.state["coverage"][operation]={"state":"BLOCKED","reason":"WAITING_EXTERNAL_RESTART"}
            exercise.save()
            raise ExternalRestartRequired("WAITING_EXTERNAL_RESTART: the deployment script must restart the qualification server")
        activated=staged
        if activated.get("restoreId")!=staged.get("restoreId"): raise ExerciseFailure("Activated restore does not match its retained workflow identity")
        receipts[operation]=activated
        exercise.state.pop("waitingExternalRestart",None)
        exercise.state["coverage"][operation]={"state":"EXECUTED","reason":"Authoritative HTTP restore workflow ACTIVATED after external restart"}
        exercise.save()
    if operation in ("backup.stream.restore","backup.stream.acknowledge") and receipts.get("backup.stream.restore",{}).get("state")=="ACTIVATED" and "backup.stream.acknowledge" not in receipts:
        acknowledged=once("catalog-restore-ack","backup.stream.acknowledge",{"artifactHandle":handle})
        if acknowledged.get("value")!="ACKNOWLEDGED": raise ExerciseFailure("Restore outcome was not acknowledged")
        receipts["backup.stream.acknowledge"]=acknowledged
        exercise.save()
    if operation not in receipts: raise ExerciseFailure("Backup scenario did not produce the requested actual receipt")
    exercise.save()
    return receipts[operation]


def _connection(path):
    """Read a private, client-only qualification connection descriptor.

    Args:
        path: Owner-only regular JSON file exported by the deployment script.
    Returns:
        Validated public connection metadata with absolute client paths.
    Raises:
        ExerciseFailure: Ownership, schema, target identity or client paths are invalid.
        OSError: The private descriptor cannot be read.
    """
    path=_private_file(Path(path).expanduser())
    if path.stat().st_size>256*1024:raise ExerciseFailure("Client connection file exceeds its byte bound")
    value=_json_bytes(path.read_bytes())
    required={"version","purpose","environmentId","realmId","adminUrl","adminPrincipalId","adminP12","trustFile","clientDirectory"}
    optional={"publicUrl","protocolUrls","protocolAuthorityId","protocolEnrollmentProfileId","protocolPublicKeyAlgorithms","protocolX509BindingPolicies","challengeProviderIds","preparedPublications","legacyBackup","clientJavaClasspath","requesterCertificate","requesterKey","acmeDirectoryOrigin","acmeDnsChallengeFile","acmeDnsNamespace","signatureAlgorithm","rootKeyRef","intermediateKeyRef","rotationKeyRef","publicationTargetId"}
    if not isinstance(value,dict) or required-set(value) or set(value)-required-optional or type(value["version"]) is not int or value["version"]!=1 or value["purpose"]!="qualification":
        raise ExerciseFailure("Use a version-1 qualification CLIENT connection file; server configuration is not accepted")
    if not isinstance(value["environmentId"],str) or not re.fullmatch(r"[0-9a-f]{32}",value["environmentId"]):raise ExerciseFailure("Invalid qualification environment identity")
    if value["realmId"]!="zeroecho-exercise-"+value["environmentId"]:raise ExerciseFailure("Qualification realm does not bind the exported environment identity")
    for field in ("realmId","adminPrincipalId"):
        if not isinstance(value[field],str) or not 1<=len(value[field])<=256 or any(not character.isprintable() for character in value[field]):raise ExerciseFailure("Invalid client target identity")
    def origin(candidate):
        if not isinstance(candidate,str):raise ExerciseFailure("Qualification endpoints must be HTTPS origins")
        parsed=urlsplit(candidate)
        if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("","/"):raise ExerciseFailure("Qualification endpoints must be HTTPS origins")
        return candidate.rstrip("/")
    value["adminUrl"]=origin(value["adminUrl"])
    if value.get("publicUrl"):value["publicUrl"]=origin(value["publicUrl"])
    protocols=value.get("protocolUrls",{})
    if not isinstance(protocols,dict) or set(protocols)-{"acme","est","scep","cmp"}:raise ExerciseFailure("Invalid protocol endpoint metadata")
    value["protocolUrls"]={name:origin(endpoint) for name,endpoint in protocols.items()}
    for field in ("adminP12","trustFile","clientDirectory"):
        if not isinstance(value[field],str) or not value[field]:raise ExerciseFailure("Invalid client artifact path")
        candidate=Path(value[field]).expanduser()
        if not candidate.is_absolute():candidate=path.parent/candidate
        value[field]=candidate
    directory=value["clientDirectory"]
    metadata=directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.geteuid() or metadata.st_mode&0o077:raise ExerciseFailure("Client artifact directory must be private and owned by this user")
    for field in ("adminP12","trustFile"):
        if not value[field].resolve().is_relative_to(directory.resolve()):raise ExerciseFailure("Qualification login and trust material must belong to the client directory")
        _private_file(value[field])
    if "clientJavaClasspath" in value and (not isinstance(value["clientJavaClasspath"],list) or any(not isinstance(item,str) or any(character in item for character in "\r\n\0") for item in value["clientJavaClasspath"])):raise ExerciseFailure("Invalid host client classpath metadata")
    return value


def _target_guard(exercise, connection):
    """Bind every risky request to a prepared qualification realm through verified HTTPS.

    Args:
        exercise: Checkpointed HTTP client.
        connection: Validated client-only deployment descriptor.
    Returns:
        Callable checking the exact origin, run and authoritative realm identity.
    Raises:
        ExerciseFailure: A retained environment identity or live realm differs.
    """
    identity={key:connection[key] for key in ("environmentId","realmId","adminPrincipalId")}
    if exercise.state.setdefault("connectionIdentity",identity)!=identity:raise ExerciseFailure("Retained qualification target changed")
    def guard(origin,run_id):
        if origin!=connection["adminUrl"] or run_id!=exercise.state["runId"]:raise ExerciseFailure("Qualification target changed")
        _,wire=exercise.api.json("GET","/admin/v1/realm")
        if _result(wire,"realm.inspect").get("realmId")!=connection["realmId"]:raise ExerciseFailure("HTTPS realm differs from the prepared qualification target")
    guard(exercise.api.origin,exercise.state["runId"])
    return guard


def _full_client(exercise, options, connection):
    exercise.state.update(mode="full",transportKind="host-https-client",executionState="RUNNING")
    try:
        return _full_client_run(exercise,options,connection)
    except Exception as failure:
        reason=str(failure) if isinstance(failure,ExerciseFailure) else "Full HTTP client failed: "+type(failure).__name__
        exercise.state.update(failure=reason,executionState="FAILED")
        exercise.save();exercise.report(strict=True)
        print(reason,file=sys.stderr)
        return 2
    finally:
        print("Client artifacts and qualification report: "+str(exercise.directory))


def _full_client_run(exercise, options, connection):
    import exercise_catalog
    from exercise_protocols import prepare_client_context
    guard=_target_guard(exercise,connection)
    exercise.target_guard=guard
    exercise.state.update(mode="full",transportKind="host-https-client",executionState="RUNNING")
    context={key:connection[key] for key in ("protocolAuthorityId","protocolEnrollmentProfileId","protocolPublicKeyAlgorithms","protocolX509BindingPolicies","challengeProviderIds","signatureAlgorithm","rootKeyRef","intermediateKeyRef","rotationKeyRef","publicationTargetId","acmeDnsNamespace","preparedPublications","legacyBackup","clientDirectory") if key in connection}
    context.update(assert_disposable=guard,adminPrincipalId=connection["adminPrincipalId"],objects=exercise.state.setdefault("objects",{}),scenarios={"backup_transfer":_backup_transfer})
    try:
        exercise.discover()
        exercise.state.pop("failure",None)
        if not exercise.state.get("demoVerified"):_live(exercise,options)
        if connection.get("publicUrl"):
            public=Api(connection["publicUrl"],connection["trustFile"])
            context["publicApi"]=public
            _public_verification(exercise,public,publish=True,assert_disposable=guard)
        else:
            exercise.state["publicArtifacts"]={"state":"BLOCKED","reason":"The deployment script did not provide a public HTTPS endpoint"}
        connection["assert_disposable"]=guard
        try:
            prepared=prepare_client_context(exercise,connection)
            context["scenarios"].update(prepared.pop("scenarios",{}));context.update(prepared)
        except (ExerciseFailure,ValueError) as missing:
            exercise.state["protocolWireProofs"]={protocol:{"state":"BLOCKED","reason":"Prepared protocol metadata unavailable"} for protocol in ("acme","est","scep","cmp")}
            exercise.state["protocolPrerequisiteFailure"]=type(missing).__name__
            exercise.save()
        exercise_catalog.run(exercise,context)
        exercise.state["executionState"]="COMPLETE"
    except ExternalRestartRequired:
        exercise.state["executionState"]="WAITING_EXTERNAL_RESTART"
        exercise.save();exercise.report(strict=True)
        print("WAITING_EXTERNAL_RESTART: enter restart in the deployment script console, then repeat this client command with --output "+str(exercise.directory))
        return 4
    finally:
        exercise.save()
    return exercise.report(strict=True)


def _default_output(prefix):
    candidate = Path(os.environ.get("XDG_STATE_HOME", str(Path.home()/".local/state"))).expanduser()
    if not candidate.is_absolute():
        candidate = Path.home()/".local/state"
    return candidate/"zeroecho-pki/exercises"/(prefix+"-"+uuid.uuid4().hex)


def main(arguments=None):
    """Run a host-only demo, approved algorithm scenario, full qualification or plan.

    Args:
        arguments: Optional CLI argument list; None reads the process arguments.
    Returns:
        Zero for the requested verified scenario, two for invalid/blocked execution,
        three for incomplete full/strict qualification, four for an external restart.
        Existing PKI objects are never deleted.
    Raises:
        ExerciseFailure: Inputs, permission preflight or safe fixture setup are invalid.
        OSError: Private inputs or output state cannot be accessed.
        subprocess.SubprocessError: A required cryptographic helper fails or times out.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("live-demo", "full", "plan", "algorithms"), default="live-demo")
    parser.add_argument("--variant", choices=("p384", "rsa4096", "mldsa87", "hybrid"))
    parser.add_argument("--realm-id", help="Exact selected HTTPS realm for algorithm scenarios")
    parser.add_argument("--crypto-classpath", help="Locally built app distribution lib/* for scenario crypto")
    parser.add_argument("--sdk-authentication", choices=("direct-mtls-v1", "trusted-proxy-mtls-v1"))
    parser.add_argument("--sdk-transport-principal", help="Actual configured administrative proxy principal")
    parser.add_argument("--approved-sdk-target", help="SHA-512 of the exact operator-reviewed SDK target proposal")
    parser.add_argument("--directory", type=Path, default=Path.home() / ".local/share/zeroecho-pki")
    parser.add_argument("--url")
    parser.add_argument("--connection-file", type=Path, help="Private client connection file exported by the deployment script for full qualification")
    parser.add_argument("--admin-p12", type=Path)
    parser.add_argument("--trust", type=Path)
    parser.add_argument("--public-url", help="Separate genuinely anonymous public HTTPS origin")
    parser.add_argument("--public-trust", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--principal-id", help="Current principal identity for permission preflight; defaults to installation manifest administrator")
    parser.add_argument("--ca-key-ref", default="zeroecho-lib:root.prv")
    parser.add_argument("--ca-profile", default="root-ca")
    parser.add_argument("--client-profile", default="vpn-client")
    parser.add_argument("--maximum-download-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--strict-coverage", action="store_true")
    parser.add_argument("--require-public", action="store_true", help="Fail unless anonymous public artifacts are independently verified")
    raw_arguments=list(sys.argv[1:] if arguments is None else arguments)
    if "isolated-full" in raw_arguments or "--mode=isolated-full" in raw_arguments:
        parser.error("isolated-full no longer deploys containers; use the deployment script first, then --mode full --connection-file FILE")
    options = parser.parse_args(raw_arguments)
    if options.mode != "algorithms" and any(value is not None for value in (options.variant, options.realm_id,
            options.crypto_classpath, options.sdk_authentication, options.sdk_transport_principal, options.approved_sdk_target)):
        parser.error("Algorithm scenario arguments require --mode algorithms")
    if options.mode == "algorithms" and (options.public_url or options.public_trust or options.require_public or options.strict_coverage):
        parser.error("Algorithm scenarios do not qualify public artifacts or full catalogue coverage")
    os.umask(0o077)
    if options.mode == "plan":
        print(json.dumps({"mode": "plan", "catalogCount": len(CATALOG_IDS), "operations": list(CATALOG_IDS),
            "liveScope": "Only newly created demo CA, request, client credential and status objects",
            "fullScope": "Only HTTPS against a separately prepared qualification server; lifecycle belongs to the deployment script"}, indent=2))
        return 0
    if not 1024 <= options.maximum_download_bytes <= 1024 * 1024 * 1024:
        raise ExerciseFailure("Download byte bound must be between 1 KiB and 1 GiB")
    connection=None
    if options.mode=="full":
        if options.connection_file is None:parser.error("--mode full requires --connection-file from the deployment script")
        if options.url or options.admin_p12 or options.trust or options.public_url or options.public_trust:parser.error("Full qualification uses only its bound connection file, not endpoint overrides")
        connection=_connection(options.connection_file)
        options.url=connection["adminUrl"];options.admin_p12=connection["adminP12"];options.trust=connection["trustFile"];options.principal_id=connection["adminPrincipalId"]
    elif options.connection_file is not None:parser.error("--connection-file is only valid with --mode full")
    manifest_path = options.directory / "installation.json"
    manifest = _json_bytes(manifest_path.read_bytes()) if connection is None and manifest_path.is_file() else {}
    options.principal_id = options.principal_id or manifest.get("admin")
    url = options.url or "https://" + str(manifest["hostname"]) + ":" + str(manifest["port"])
    p12 = options.admin_p12 or options.directory / "logins/administrator.p12"
    trust = options.trust or options.directory / "logins/web-ca.pem"
    output = (options.output or _default_output("qualification-client" if connection is not None else "demo")).expanduser().absolute()
    password = getpass.getpass("Administrator PKCS#12 password: ")
    with tempfile.TemporaryDirectory(prefix="zeroecho-exercise-auth-") as temporary:
        authentication = Path(temporary)
        authentication.chmod(0o700)
        certificate, key = _identity(authentication, p12, password)
        if connection is not None:connection["clientPassword"]=lambda:password
        else:del password
        api = Api(url, trust, certificate, key)
        exercise = Exercise(api, output)
        if connection is not None:
            try:
                options.defer_public_verification=True
                result=_full_client(exercise,options,connection)
                return result
            finally:exercise.close()
        if options.mode == "algorithms":
            from exercise_algorithms import run
            try:
                exercise.state["mode"] = "algorithms"
                run(exercise, options, certificate)
                print("Verified algorithm scenario artifacts: " + str(output))
                return 0
            except (ExerciseFailure, KeyError, ValueError) as error:
                reason = str(error) if isinstance(error, ExerciseFailure) else "Incomplete algorithm scenario response"
                exercise.state["failure"] = reason
                exercise.save()
                _atomic_json(output / "algorithm-report.json", {"version": 1, "variant": options.variant,
                    "verified": False, "podmanQualified": False, "environment": "external-https-client", "reason": reason})
                print(reason, file=sys.stderr)
                print("Retained algorithm scenario artifacts: " + str(output))
                return 2
            finally:
                exercise.close()
        exercise.state["mode"] = "live-demo"
        exercise.save()
        code = 0
        try:
            options.defer_public_verification = bool(options.public_url)
            _live(exercise, options)
            if options.public_url:
                _public_verification(exercise, Api(options.public_url, options.public_trust or trust))
        except (ExerciseFailure, KeyError, ValueError) as error:
            exercise.state["failure"] = str(error) if isinstance(error, ExerciseFailure) else "The API returned an incomplete scenario result"
            exercise.save()
            code = 2
        report = exercise.report(strict=options.strict_coverage)
        print("Private artifacts and qualification report: " + str(output))
        if code:
            print(exercise.state["failure"], file=sys.stderr)
        exercise.close()
        return code or report


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ExerciseFailure, OSError, subprocess.SubprocessError) as failure:
        print("Exercise failed: " + (str(failure) if isinstance(failure, ExerciseFailure) else type(failure).__name__), file=sys.stderr)
        sys.exit(2)
