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

"""Host session contracts; real HTTPS/crypto coverage lives in CertificateScenarioHttpTest."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pki_http import ExerciseFailure
from pki_operator import Operator, UnknownAcceptance, action_exit, main, result_exit


def envelope(operation, result, status="SUCCEEDED"):
    return {"version": 1, "operation": operation, "status": status, "result": result}


class HostApi:
    origin = "https://host.test:443"
    client_authenticated = True
    client_identity_sha256 = "a" * 64

    def __init__(self):
        self.calls = []
        self.realm = "realm"
        self.state = "WAITING_APPROVAL"
        self.lost = False
        self.missing = False
        self.record_operation = "ca.create"
        self.signing_id = None
        self.approval_id = "approval"
        self.pem = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(self.certificate_der) + b"-----END CERTIFICATE-----\n"
        self.der = self.certificate_der
        self.bad_href = False
        self.denied = None
        self.path_ids = ["leaf", "root"]

    def json(self, method, path, document=None):
        self.calls.append((method, path, document))
        if path == "/admin/v1/realm":
            return 200, envelope("realm.inspect", {"realmId": self.realm})
        if path == "/admin/v1/operations":
            return 200, envelope("operation.list", {"operations": [
                {"operation": "ca.create", "durableRequest": True},
                {"operation": "security.approval.approve", "durableRequest": False},
                {"operation": "issuer.path.inspect", "durableRequest": False},
                {"operation": "ca.inspect", "durableRequest": False},
                {"operation": "issuer.generation.inspect", "durableRequest": False}]})
        if path == "/admin/v1/schema":
            return 200, [{"operationId": operation, "mutating": operation in ("ca.create", "security.approval.approve")}
                         for operation in ("ca.create", "security.approval.approve", "issuer.path.inspect", "ca.inspect", "issuer.generation.inspect")]
        if path.startswith("/admin/v1/requests"):
            if method == "POST" and self.lost:
                raise ExerciseFailure("unknown")
            if method == "GET" and self.missing:
                raise ExerciseFailure("absent", 404)
            record = {"requestId": "request", "operation": self.record_operation, "state": self.state, "approvalId": self.approval_id}
            if self.signing_id is not None:
                record["signingOperationId"] = self.signing_id
            if self.state == "SUCCEEDED":
                record["result"] = {"credentialId": "leaf"}
            return (202 if method == "POST" else 200), envelope("administrative.request.submit" if method == "POST" else "administrative.request.inspect", record)
        if path.endswith("security.approval.approve"):
            if self.lost:
                raise ExerciseFailure("unknown")
            return 200, envelope("security.approval.approve", {"approvalId": "approval"}, "PENDING")
        if path.endswith("issuer.path.inspect"):
            return 200, envelope("issuer.path.inspect", {"value": {"pathId": "path", "orderedCredentialIds": self.path_ids}})
        if path.endswith("ca.inspect"):
            return 200, envelope("ca.inspect", {"caId": "ca", "currentIssuanceIssuerId": "issuer"})
        if path.endswith("issuer.generation.inspect"):
            import hashlib
            return 200, envelope("issuer.generation.inspect", {"issuerId": "issuer", "authorityId": "ca", "credentialId": "leaf", "cryptographicBinding": {"certificateSha256": hashlib.sha256(self.der).hexdigest()}})
        if "-artifacts/" in path:
            identity = path.rsplit("/", 1)[1]
            if identity == self.denied:
                raise ExerciseFailure("denied", 404)
            certificate = "certificate-artifacts" in path
            return 200, envelope("certificate.artifact.inspect" if certificate else "status.artifact.inspect", {
                "credentialId" if certificate else "statusObjectId": identity, "formatId": "x509",
                "representations": [{"id": representation, "href": "https://evil.invalid/" if self.bad_href else path + "/content?representation=" + representation} for representation in ("original", "pem")]})
        raise AssertionError(path)

    def download(self, path, target, *, overwrite):
        self.calls.append(("BINARY", path, None))
        with open(target, "xb") as output:
            output.write(self.pem if path.endswith("pem") else self.der)


class OperatorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pki_http import _openssl
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            HostApi.certificate_der = _openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384", "-nodes", "-days", "1", "-subj", "/CN=Host operator fixture", "-keyout", root / "key", "-outform", "DER"])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.api = HostApi()
        self.operator = Operator(self.api, "realm", self.root / "checkpoint")
        self.intent = {"version": 1, "requestId": "request", "operation": "ca.create", "arguments": {"nested": [1, {"a": True}]}}

    def tearDown(self):
        self.operator.close()
        self.temp.cleanup()

    def test_submit_once_pending_approval_and_terminal_observation(self):
        self.assertEqual(3, result_exit(self.operator.submit(self.intent)))
        self.api.state = "APPROVED"
        self.assertEqual(3, result_exit(self.operator.observe("request")))
        self.api.state = "SUCCEEDED"
        self.assertEqual(0, result_exit(self.operator.submit(self.intent)))
        self.assertEqual(1, sum(method == "POST" and path == "/admin/v1/requests" for method, path, _ in self.api.calls))
        with self.assertRaisesRegex(ExerciseFailure, "changed"):
            self.operator.submit(self.intent | {"arguments": {}})
        self.assertEqual(0o600, self.operator._path("request").stat().st_mode & 0o777)

    def test_lost_ack_get_only_across_session_reopen(self):
        self.api.lost = self.api.missing = True
        with self.assertRaises(UnknownAcceptance):
            self.operator.submit(self.intent)
        self.operator.close()
        self.operator = Operator(self.api, "realm", self.root / "checkpoint")
        self.api.missing = False
        self.api.state = "SUCCEEDED"
        self.assertEqual(0, result_exit(self.operator.submit(self.intent)))
        self.assertEqual(1, sum(method == "POST" for method, _, _ in self.api.calls))

    def test_wrong_receipt_and_realm_fail_closed(self):
        self.api.record_operation = "key.generate"
        with self.assertRaisesRegex(ExerciseFailure, "identity"):
            self.operator.submit(self.intent)
        self.api.realm = "other"
        with self.assertRaisesRegex(ExerciseFailure, "realm"):
            self.operator.observe("request")

    def test_checkpoint_binding_and_concurrent_lock(self):
        with self.assertRaises(BlockingIOError):
            Operator(self.api, "realm", self.root / "checkpoint")
        self.operator.close()
        self.api.client_identity_sha256 = "b" * 64
        with self.assertRaisesRegex(ExerciseFailure, "different"):
            Operator(self.api, "realm", self.root / "checkpoint")

    def test_read_mutation_rejection_and_dedicated_no_replay(self):
        with self.assertRaisesRegex(ExerciseFailure, "mutations"):
            self.operator.read("ca.create", {})
        self.assertEqual("path", self.operator.read("issuer.path.inspect", {"pathId": "path"})["pathId"])
        intent = self.intent | {"operation": "security.approval.approve", "arguments": {"approvalId": "approval"}}
        first = self.operator.action(intent)
        self.assertEqual("PENDING", first["status"])
        self.assertEqual(first, self.operator.action(intent))
        self.assertEqual(1, sum(method == "POST" and path.endswith("security.approval.approve") for method, path, _ in self.api.calls))
        with self.assertRaisesRegex(ExerciseFailure, "durable"):
            self.operator.observe("request")

    def test_dedicated_unknown_is_never_replayed(self):
        self.api.lost = True
        intent = self.intent | {"operation": "security.approval.approve"}
        for _ in range(2):
            with self.assertRaises(UnknownAcceptance):
                self.operator.action(intent)
        self.assertEqual(1, sum(method == "POST" for method, _, _ in self.api.calls))

    def test_download_binary_routes_equivalence_and_no_overwrite(self):
        target = self.root / "cert.pem"
        result = self.operator.download("certificate", "leaf", "pem", target)
        self.assertTrue(result["pemDerEquivalent"])
        self.assertFalse(result["signatureVerified"])
        self.assertEqual(self.api.pem, target.read_bytes())
        with self.assertRaises(FileExistsError):
            self.operator.download("certificate", "leaf", "pem", target)
        self.api.pem = b"-----BEGIN CERTIFICATE-----\nMAI=\n-----END CERTIFICATE-----"
        with self.assertRaisesRegex(ExerciseFailure, "differ"):
            self.operator.download("certificate", "leaf", "pem", self.root / "mismatch")
        self.assertFalse((self.root / "mismatch").exists())
        self.api.bad_href = True
        with self.assertRaisesRegex(ExerciseFailure, "route"):
            self.operator.download("certificate", "leaf", "original", self.root / "bad")

    def test_chain_order_permission_and_ca_digest(self):
        target = self.root / "chain.pem"
        import subprocess
        from types import SimpleNamespace
        execute = subprocess.run
        def verifier(command, **kwargs):
            if command[0] == "java":
                return SimpleNamespace(returncode=0, stdout=b"VERIFIED issuer-chain certificates=2")
            return execute(command, **kwargs)
        with patch("pki_operator.subprocess.run", side_effect=verifier):
            result = self.operator.chain("path", target)
        self.assertEqual(["leaf", "root"], result["orderedCredentialIds"])
        self.assertEqual(self.api.pem * 2, target.read_bytes())
        self.operator.ca("ca", "original", self.root / "ca.der")
        self.api.denied = "root"
        with self.assertRaises(ExerciseFailure):
            self.operator.chain("path", self.root / "denied")
        self.assertFalse((self.root / "denied").exists())
        self.api.path_ids = []
        with self.assertRaisesRegex(ExerciseFailure, "path"):
            self.operator.chain("path", self.root / "empty")

    def test_nested_typed_target_changes_are_rejected(self):
        self.operator.submit(self.intent)
        for replacement in (True, 1.0):
            changed = self.intent | {"arguments": {"nested": [replacement, {"a": True}]}}
            with self.assertRaisesRegex(ExerciseFailure, "changed"):
                self.operator.submit(changed)
        action = self.intent | {"requestId": "dedicated", "operation": "security.approval.approve"}
        self.operator.action(action)
        with self.assertRaisesRegex(ExerciseFailure, "changed"):
            self.operator.action(action | {"arguments": {"nested": [True, {"a": True}]}})

    def test_ca_rejects_wrong_generation_coordinates(self):
        original = self.api.json
        for fields in ({"issuerId": "wrong"}, {"authorityId": "wrong"}):
            def wrong(method, path, document=None):
                status, wire = original(method, path, document)
                if path.endswith("issuer.generation.inspect"):
                    wire["result"].update(fields)
                return status, wire
            with patch.object(self.api, "json", side_effect=wrong):
                with self.assertRaisesRegex(ExerciseFailure, "generation"):
                    self.operator.ca("ca", "original", self.root / "wrong-ca")
            (self.root / "wrong-ca").unlink(missing_ok=True)

    def test_definitive_refusal_is_failed_not_unknown_and_not_retried(self):
        original = self.api.json
        for operation, status in (("ca.create", 422), ("security.approval.approve", 403)):
            calls = []
            def refused(method, path, document=None):
                if method == "POST":
                    calls.append(path)
                    raise ExerciseFailure("FORBIDDEN", status)
                return original(method, path, document)
            intent = self.intent | {"requestId": "refused-" + str(status), "operation": operation}
            with patch.object(self.api, "json", side_effect=refused):
                for _ in range(2):
                    with self.assertRaises(ExerciseFailure) as caught:
                        (self.operator.submit if operation == "ca.create" else self.operator.action)(intent)
                    self.assertNotIsInstance(caught.exception, UnknownAcceptance)
                    self.assertEqual(status, caught.exception.status)
            self.assertEqual(1, len(calls))

    def test_malformed_x509_der_is_not_published(self):
        self.api.der = b"\x30\x01"
        with self.assertRaisesRegex(ExerciseFailure, "X.509"):
            self.operator.download("certificate", "leaf", "original", self.root / "malformed")
        self.assertFalse((self.root / "malformed").exists())

    def test_discover_validates_offered_schema_and_realm(self):
        self.assertEqual("ca.create", self.operator.discover()["operations"][0]["operation"])
        original = self.api.json
        def malformed(method, path, document=None):
            if path == "/admin/v1/schema":
                return 200, {}
            return original(method, path, document)
        with patch.object(self.api, "json", side_effect=malformed):
            with self.assertRaisesRegex(ExerciseFailure, "discovery"):
                self.operator.discover()
        self.api.realm = "other"
        with self.assertRaisesRegex(ExerciseFailure, "realm"):
            self.operator.discover()

    def test_observation_preserves_linked_approval_and_signing_identities(self):
        self.api.signing_id = "signing-original"
        self.operator.submit(self.intent)
        self.api.signing_id = "signing-other"
        with self.assertRaisesRegex(ExerciseFailure, "identity"):
            self.operator.observe("request")
        self.api.signing_id = "signing-original"
        self.api.approval_id = "approval-other"
        with self.assertRaisesRegex(ExerciseFailure, "identity"):
            self.operator.observe("request")

    def test_exit_semantics(self):
        self.assertEqual(3, action_exit(envelope("security.approval.approve", {}, "SUCCEEDED")))
        self.assertEqual(3, action_exit(envelope("other", {}, "PENDING")))
        self.assertEqual(0, action_exit(envelope("other", {}, "SUCCEEDED")))
        with self.assertRaises(ExerciseFailure):
            action_exit({"status": "FAILED"})
        for state in ("FAILED", "REJECTED", "EXPIRED", "CANCELLED", "RECONCILIATION_REQUIRED"):
            self.assertEqual(2, result_exit({"state": state}))
        for state in ("WAITING_APPROVAL", "APPROVED", "RUNNING", "ACCEPTED", "READY", "DISPATCHING"):
            self.assertEqual(3, result_exit({"state": state}))
        for record in ({"state": "SUCCEEDED"}, {"state": "MYSTERY"}):
            with self.assertRaises(ExerciseFailure):
                result_exit(record)

    def test_cli_private_input_and_safe_error(self):
        p12 = self.root / "client.p12"
        p12.write_bytes(b"not a real identity")
        p12.chmod(0o600)
        output = io.StringIO()
        with patch("pki_operator.sys.stdin.isatty", return_value=True), patch("pki_operator.getpass.getpass", return_value="secret"), contextlib.redirect_stdout(output):
            code = main(["--url", self.api.origin, "--realm", "realm", "--trust", str(p12), "--p12", str(p12), "--checkpoint", str(self.root / "cli"), "discover"])
        self.assertEqual(2, code)
        self.assertNotIn("secret", output.getvalue())
        self.assertEqual(2, json.loads(output.getvalue())["exit"])


if __name__ == "__main__":
    unittest.main()
