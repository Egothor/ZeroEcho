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

"""Offline host-script checks; no server, network or container engine required."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import smoke_test as smoke


class SmokeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.calls = self.directory / "calls.jsonl"
        self.cli = self.directory / "app"
        self.settings = {
            "SMOKE_CLI": str(self.cli), "SMOKE_BASE_URL": "https://example.test:8443",
            "SMOKE_ADMIN_CERT": "tls/admin.pem", "SMOKE_ADMIN_KEY": "tls/admin-key.pem",
            "SMOKE_CA_BUNDLE": "tls/ca.pem", "SMOKE_CA_ID": "ca:quoted/α;$(false)",
            "SMOKE_PROFILE_ID": "team/α profile", "SMOKE_REQUEST_ID": "request-existing",
        }

    def fake_cli(self, outcome, code=0):
        # Test-only executable receives argv directly, returns the real remote JSON shape.
        source = '''#!/usr/bin/env python3
import json, pathlib, sys
with pathlib.Path(CALLS).open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
operation = sys.argv[2]
if operation == "request.import":
    print(json.dumps({"version": 1, "mode": "remote", "operation": operation,
        "status": "SUCCEEDED", "requestId": "wrong-top-level-id", "result": {"requestId": "request-imported"}}))
    sys.exit(0)
print(json.dumps({"version": 1, "mode": "remote", "operation": operation,
    "status": OUTCOME, "operationId": "signing-receipt", "result": {"credentialId": "credential-completed"}}))
sys.exit(CODE)
'''.replace("CALLS", repr(str(self.calls))).replace("OUTCOME", repr(outcome)).replace("CODE", str(code))
        self.cli.write_text(source)
        self.cli.chmod(0o700)

    def invocations(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_success_submits_exactly_once_with_authority_arguments(self):
        self.fake_cli("SUCCEEDED")
        smoke.issuance_flow(self.settings, self.directory)
        calls = self.invocations()
        self.assertEqual(1, len(calls))
        self.assertEqual(["pki", "credential.issue"], calls[0][:2])
        self.assertIn("issuerCaId=" + self.settings["SMOKE_CA_ID"], calls[0])
        self.assertIn("profileId=" + self.settings["SMOKE_PROFILE_ID"], calls[0])
        self.assertEqual("120", calls[0][calls[0].index("--pending-wait") + 1])
        self.assertEqual(self.settings["SMOKE_CA_ID"], calls[0][calls[0].index("--authority-id") + 1])

    def test_pending_error_and_interruption_preserve_receipt_without_resubmission(self):
        for status, code in [("PENDING", 7), ("FAILED", 8), ("PENDING", 130)]:
            with self.subTest(status=status, code=code):
                if self.calls.exists():
                    self.calls.unlink()
                self.fake_cli(status, code)
                with self.assertRaises(smoke.SmokeFailure) as failure:
                    smoke.issuance_flow(self.settings, self.directory)
                self.assertEqual(code, failure.exception.code)
                self.assertEqual(1, len(self.invocations()))
                receipt = json.loads((self.directory / "credential-issue.json").read_text())
                self.assertEqual("signing-receipt", receipt["operationId"])

    def test_import_forwards_exact_fields_and_reads_nested_result(self):
        self.fake_cli("SUCCEEDED")
        envelope = self.directory / "request.json"
        envelope.write_text(json.dumps({"version": 1, "arguments": {"formatId": "x509", "encoded": "QUJD"},
                                        "approvalId": "approval/α", "deadline": "PT30S"}))
        arguments = smoke.import_arguments(envelope)
        self.assertEqual(["--arg", "formatId=x509", "--arg", "encoded=QUJD",
                          "--approval-id", "approval/α", "--deadline", "PT30S"], arguments)
        smoke.issuance_flow(self.settings, self.directory, arguments)
        calls = self.invocations()
        self.assertEqual(["request.import", "credential.issue"], [row[1] for row in calls])
        self.assertNotIn("--authority-id", calls[0])
        self.assertIn("requestId=request-imported", calls[1])
        self.assertNotIn("requestId=wrong-top-level-id", calls[1])

    def test_invalid_import_fails_before_any_issuance(self):
        document = self.directory / "request.json"
        settings = dict(self.settings, SMOKE_IMPORT_ARGS_FILE=str(document))
        settings.pop("SMOKE_REQUEST_ID")
        valid = {"version": 1, "arguments": {"formatId": "x509", "encoded": "QUJD"}}
        invalid = [
            '{"version":1,"version":1,"arguments":{"formatId":"x509","encoded":"QUJD"}}',
            json.dumps(dict(valid, authorityId="ca:forbidden")),
            json.dumps(dict(valid, unknown="rejected")),
            json.dumps(dict(valid, version=True)),
            json.dumps(dict(valid, approvalId=None)),
            json.dumps({"version": 1, "arguments": {"formatId": "x509", "encoded": "QUJD", "extra": 1}}),
            " " * (smoke.IMPORT_LIMIT + 1),
        ]
        for value in invalid:
            with self.subTest(size=len(value)):
                document.write_text(value)
                with mock.patch.dict(os.environ, settings, clear=True), mock.patch.object(smoke, "run_cli") as execute, \
                        mock.patch.object(smoke.tempfile, "mkdtemp", return_value=str(self.directory)), \
                        mock.patch.object(smoke, "configuration", return_value=settings), contextlib.redirect_stderr(io.StringIO()):
                    self.assertNotEqual(0, smoke.main(["--no-up", "--no-down"]))
                    execute.assert_not_called()

    def test_success_requires_receipt_and_credential_in_remote_envelope(self):
        self.fake_cli("SUCCEEDED")
        receipt = self.directory / "receipt.json"
        for value in [{"version": 1, "mode": "local", "status": "SUCCEEDED", "result": {}},
                      {"version": 1, "mode": "remote", "operation": "credential.issue", "status": "SUCCEEDED", "result": {}}]:
            receipt.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                smoke.successful_result(receipt, "credential.issue", signing=True)

    def test_environment_file_is_literal_and_environment_has_precedence(self):
        env_file = self.directory / ".env"
        env_file.write_text('SMOKE_PROFILE_ID="team profile"\nSMOKE_CA_ID=$(not-executed)\nOTHER_SECRET=hidden\n')
        settings = smoke.configuration({"SMOKE_PROFILE_ID": "override"}, env_file)
        self.assertEqual("override", settings["SMOKE_PROFILE_ID"])
        self.assertEqual("$(not-executed)", settings["SMOKE_CA_ID"])
        self.assertNotIn("OTHER_SECRET", settings)


if __name__ == "__main__":
    unittest.main()
