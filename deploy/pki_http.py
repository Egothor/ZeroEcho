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

"""Reusable bounded host HTTPS transport and private client-file primitives.

Importing this module has no host or network effects. It does not depend on the
qualification runner and never performs deployment or server lifecycle actions.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import time
from urllib.parse import quote, urlsplit
import uuid

LIMIT = 8 * 1024 * 1024


class ExerciseFailure(Exception):
    """A safe diagnostic with HTTP status; arguments and secret-bearing bodies are omitted."""

    def __init__(self, message, status=0):
        """Initialize a nonsecret diagnostic and optional HTTP status (zero means unknown)."""
        super().__init__(message)
        self.status = status


def _openssl(arguments, *, secret=None, data=None):
    if secret is not None:
        if any(character in secret for character in "\r\n\0"):
            raise ExerciseFailure("The PKCS#12 password cannot contain line separators")
        if data is not None:
            raise ExerciseFailure("Conflicting OpenSSL stdin inputs")
        data = secret.encode("utf-8") + b"\n"
    completed = subprocess.run(["openssl", *map(str, arguments)], input=data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False, timeout=60)
    if completed.returncode:
        raise ExerciseFailure("OpenSSL verification or key operation failed: " + str(arguments[0]))
    return completed.stdout


def _private_file(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ExerciseFailure("Expected an owned private regular file: " + str(path))
    return path


def _atomic_json(path, value):
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _json_bytes(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ExerciseFailure("Duplicate JSON property")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeError) as error:
        raise ExerciseFailure("Invalid JSON response") from error


class Api:
    """Same-origin HTTPS/mTLS client with bounded bodies and no redirect following.

    ``client_identity_sha256`` identifies the supplied client certificate PEM bytes
    for local checkpoint binding; it is None for an anonymous connection. It is
    not a substitute for the server's authenticated principal identity.
    """

    def __init__(self, base_url, ca_file, identity=None, key=None):
        """Bind trust and optional client identity without opening a connection.

        Args:
            base_url: HTTPS origin without credentials, query or path.
            ca_file: PEM trust-anchor file.
            identity: Optional PEM client certificate; requires key.
            key: Optional private PEM client key; requires identity.
        Returns:
            None; the origin and TLS context are retained.
        Raises:
            ExerciseFailure: The origin or paired identity is invalid.
            OSError: Trust or identity material cannot be loaded.
        """
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ExerciseFailure("Use an HTTPS origin without credentials, path, query or fragment")
        self.origin = base_url.rstrip("/")
        self.host, self.port = parsed.hostname, parsed.port or 443
        self.client_authenticated = identity is not None
        self.client_identity_sha256 = hashlib.sha256(Path(identity).read_bytes()).hexdigest() if identity is not None else None
        self.context = ssl.create_default_context(cafile=str(ca_file))
        if (identity is None) != (key is None):
            raise ExerciseFailure("Client certificate and private key must be supplied together")
        if identity is not None:
            self.context.load_cert_chain(str(identity), str(key))

    def request(self, method, path, document=None):
        """Return status, headers and bytes for one bounded same-origin request; never retry a POST.
        
        Args:
            method: HTTP verb.
            path: Same-origin absolute path.
            document: Optional JSON request body.
        
        Returns:
            Tuple of HTTP status, headers and unchanged response bytes.
        
        Raises:
            ExerciseFailure: Invalid path, transport failure, excessive response or non-success status.
        """
        if not path.startswith("/") or path.startswith("//") or "\r" in path or "\n" in path:
            raise ExerciseFailure("Invalid API path")
        body = None if document is None else json.dumps(document, separators=(",", ":")).encode()
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=30)
        try:
            headers = {"Accept": "application/json" if document is not None else "*/*"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ExerciseFailure("API response exceeds its byte bound", response.status)
            if not 200 <= response.status < 300:
                code = "HTTP_" + str(response.status)
                try:
                    candidate = _json_bytes(raw).get("failure", {}).get("code")
                    if isinstance(candidate, str) and re.fullmatch(r"[A-Z0-9_]{1,128}", candidate):
                        code = candidate
                except (ExerciseFailure, AttributeError, TypeError):
                    pass
                raise ExerciseFailure(code, response.status)
            return response.status, dict(response.getheaders()), raw
        except (OSError, http.client.HTTPException) as error:
            raise ExerciseFailure("HTTPS request failed; acknowledgement may be unknown") from error
        finally:
            connection.close()

    def backup_transfer(self, action, handle, *, target=None, source=None, maximum=64*1024*1024):
        """Perform one authenticated binary backup POST without retries, redirects, token URLs or JSON conversion.
        
        Args:
            action: Upload or download.
            handle: Ephemeral opaque transfer handle; never logged.
            target: Private destination for a download.
            source: Private archive for an upload.
            maximum: Maximum permitted archive size in bytes.
        
        Returns:
            Verified download identity or upload receipt fields.
        
        Raises:
            ExerciseFailure: Invalid transfer, unknown acknowledgement, byte/time bound or integrity failure.
        """
        if action not in ("upload", "download") or not isinstance(handle, str) or not 1<=len(handle)<=1024 or any(character in handle for character in "\r\n\0") or type(maximum) is not int or not 1<=maximum<=1024*1024*1024:
            raise ExerciseFailure("Invalid binary backup transfer")
        headers = {"X-ZeroEcho-Transfer": "1"}
        stream = None
        if action == "upload":
            source = _private_file(Path(source))
            if source.stat().st_size > maximum:
                raise ExerciseFailure("Backup archive exceeds the transfer byte bound")
            stream = source.open("rb")
            body = stream
            headers.update({"Content-Type": "application/zip", "Content-Length": str(source.stat().st_size), "X-ZeroEcho-Artifact": handle})
        else:
            body = ("artifactHandle=" + quote(handle, safe="")).encode()
            headers.update({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))})
        connection = http.client.HTTPSConnection(self.host,self.port,context=self.context,timeout=30)
        temporary = None
        deadline = time.monotonic()+180
        try:
            if stream is None:
                connection.request("POST","/admin/v1/backup/" + action,body=body,headers=headers)
            else:
                connection.putrequest("POST","/admin/v1/backup/" + action)
                for name,value in headers.items(): connection.putheader(name,value)
                connection.endheaders()
                while True:
                    if time.monotonic()>=deadline: raise ExerciseFailure("Backup upload exceeded its total deadline")
                    block=stream.read(65536)
                    if not block: break
                    connection.send(block)
            response = connection.getresponse()
            if response.status != 200:
                raise ExerciseFailure("Binary backup transfer refused",response.status)
            if action == "upload":
                chunks=[]
                length=0
                while True:
                    if time.monotonic()>=deadline: raise ExerciseFailure("Backup receipt exceeded its total deadline")
                    block=response.read1(65536)
                    if not block: break
                    length+=len(block)
                    if length>LIMIT: raise ExerciseFailure("Backup transfer receipt exceeds its bound")
                    chunks.append(block)
                raw=b"".join(chunks)
                if len(raw)>LIMIT: raise ExerciseFailure("Backup transfer receipt exceeds its bound")
                return _fields(_result(_json_bytes(raw),"backup.stream.upload"))
            if target is None or not response.getheader("Content-Length","").isdigit():
                raise ExerciseFailure("Backup download has no exact declared length")
            declared = int(response.getheader("Content-Length"))
            if declared>maximum: raise ExerciseFailure("Backup archive exceeds the transfer byte bound")
            target = Path(target)
            temporary = target.with_name("."+target.name+"."+uuid.uuid4().hex+".download")
            descriptor = os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            digest,total = hashlib.sha256(),0
            with os.fdopen(descriptor,"wb") as output:
                while True:
                    if time.monotonic()>=deadline: raise ExerciseFailure("Backup download exceeded its total deadline")
                    block=response.read1(65536)
                    if not block: break
                    total+=len(block)
                    if total>maximum: raise ExerciseFailure("Backup archive exceeds the transfer byte bound")
                    digest.update(block);output.write(block)
                output.flush();os.fsync(output.fileno())
            if total!=declared: raise ExerciseFailure("Backup download was truncated")
            os.replace(temporary,target)
            return {"length":total,"sha256":digest.hexdigest()}
        except (OSError,http.client.HTTPException) as failure:
            raise ExerciseFailure("Backup transfer acknowledgement is unknown; do not repeat its POST") from failure
        finally:
            if stream is not None: stream.close()
            if temporary is not None: temporary.unlink(missing_ok=True)
            connection.close()

    def json(self, method, path, document=None):
        """Decode one bounded response as strict JSON; status and secret bodies are never logged.
        
        Args:
            method: HTTP verb.
            path: Same-origin absolute path.
            document: Optional JSON request body.
        
        Returns:
            Tuple of HTTP status and strictly decoded JSON document.
        
        Raises:
            ExerciseFailure: Transport, status or strict JSON validation fails.
        """
        status, _, raw = self.request(method, path, document)
        return status, _json_bytes(raw)


    def download(self, path, target, *, maximum=64 * 1024 * 1024, overwrite=True):
        """Stream one authenticated attachment to a private file within byte/time limits, atomically.
        
        Args:
            path: Canonical same-origin administrator artifact path.
            target: Private output file replaced only after a complete attachment.
            maximum: Maximum accepted attachment length in bytes.
            overwrite: Whether to replace an existing destination. False publishes
                with an atomic no-clobber link and rejects existing symlinks too.
        
        Returns:
            None after the complete private attachment replaces its destination.
        
        Raises:
            ExerciseFailure: Refused attachment, transport failure or byte/time bound.
            OSError: Private destination cannot be created or committed.
        """
        if not path.startswith("/admin/v1/") or any(character in path for character in "\r\n\0"):
            raise ExerciseFailure("Invalid authenticated attachment path")
        if type(maximum) is not int or maximum < 1:
            raise ExerciseFailure("Invalid attachment byte bound")
        target = Path(target)
        if not overwrite and os.path.lexists(target):
            raise ExerciseFailure("Attachment destination already exists")
        temporary = target.with_name("." + target.name + "." + uuid.uuid4().hex + ".download")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=30)
        try:
            connection.request("GET", path, headers={"Accept": "*/*"})
            # HTTP/1.0 response handling may detach connection.sock while the
            # response still owns it; retain the live TLS socket before headers.
            receive_socket = connection.sock
            response = connection.getresponse()
            if response.status != 200:
                raise ExerciseFailure("Attachment download refused", response.status)
            if "attachment" not in response.getheader("Content-Disposition", "").lower():
                raise ExerciseFailure("Server did not return an attachment")
            declared = response.getheader("Content-Length", "")
            if not declared.isdigit() or int(declared) > maximum:
                raise ExerciseFailure("Invalid attachment length or configured byte bound")
            digest = hashlib.sha256()
            expected_digest = response.getheader("Content-Digest")
            total, deadline = 0, time.monotonic() + 180
            with os.fdopen(descriptor, "wb") as output:
                descriptor = None
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ExerciseFailure("Attachment download exceeded its time bound")
                    if not response.isclosed():
                        receive_socket.settimeout(min(30, remaining))
                    block = response.read1(65536)
                    if time.monotonic() >= deadline:
                        raise ExerciseFailure("Attachment download exceeded its time bound")
                    if not block:
                        break
                    total += len(block)
                    if total > maximum:
                        raise ExerciseFailure("Attachment exceeds the configured byte bound")
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            if total != int(declared):
                raise ExerciseFailure("Attachment download was truncated")
            if expected_digest is not None and expected_digest != "sha-256=:" + base64.b64encode(digest.digest()).decode("ascii") + ":":
                raise ExerciseFailure("Attachment content digest does not match")
            if overwrite:
                os.replace(temporary, target)
            else:
                os.link(temporary, target, follow_symlinks=False)
        except (OSError, http.client.HTTPException) as error:
            raise ExerciseFailure("Attachment transport failed; no partial file accepted") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
            connection.close()


def _result(envelope, operation):
    if not isinstance(envelope, dict) or type(envelope.get("version")) is not int or envelope["version"] != 1 or envelope.get("operation") != operation or envelope.get("status") not in ("SUCCEEDED", "PENDING") or envelope.get("failure") is not None or not isinstance(envelope.get("result"), dict):
        raise ExerciseFailure("Invalid success envelope for " + operation)
    return envelope["result"]


def _fields(result):
    return result["value"] if isinstance(result.get("value"), dict) else result


def _receipt_fields(operation, value):
    if operation != "security.disclosure.capability.issue":
        return value
    fields = _fields(value)
    identity = fields.get("capabilityId")
    if not isinstance(identity, str) or not identity:
        raise ExerciseFailure("One-time capability response omitted its safe identity")
    return {"capabilityId": identity, "oneTimeSecretRedacted": True}


def _receipt_wire(operation, wire):
    if operation != "security.disclosure.capability.issue":
        return wire
    return {key: value for key, value in wire.items() if key != "result"} | {"result": _receipt_fields(operation, wire["result"])}


def _identity(directory, p12, password):
    identity, key = directory / "administrator.pem", directory / "administrator.key"
    _openssl(["pkcs12", "-in", p12, "-clcerts", "-nokeys", "-out", identity, "-passin", "stdin"], secret=password)
    _openssl(["pkcs12", "-in", p12, "-nocerts", "-nodes", "-out", key, "-passin", "stdin"], secret=password)
    identity.chmod(0o600)
    key.chmod(0o600)
    return identity, key


