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

"""Focused C04 target binding, fail-closed retention and deployment-selection checks."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import exercise_algorithms as scenarios
from exercise_pki import Exercise, ExerciseFailure
import rootless_pki as installer


class ScenarioTest(unittest.TestCase):
    def context(self):
        spki, alternative = b"issuer-public", b"issuer-alternative"
        def role(key, value):
            return dict(keyRef=key, publicKeyAlgorithmId="public-algorithm", signatureAlgorithmId="signature-algorithm",
                signatureAlgorithmIdentifierDer=scenarios._b64(b"der"), subjectSpkiSha256=hashlib.sha256(value).hexdigest())
        binding = {"primary": role("primary", spki), "alternative": role("alternative", alternative),
                   "certificateSha256": hashlib.sha256(b"certificate").hexdigest()}
        return dict(arguments={"issuerCaId": "ca", "requestId": "csr", "profileId": "leaf"}, principal="admin", ca="ca",
            generation={"issuerId": "generation", "cryptographicBinding": binding}, path={"pathId": "path"},
            profile={"profileId": "leaf", "profileVersion": 1, "canonicalSha256": "a" * 64}, issuer_der=b"certificate",
            issuer_spki=spki, issuer_alternative=alternative, effective={"subjectRef": "CN=client"},
            disclosure={"visibility": "private"}, approval_commitment="b" * 64)

    def target(self, c):
        return scenarios._frame(7, {1: b"credential.issue", 2: scenarios._value(c["arguments"]), 3: b"admin", 4: b"ca",
            5: b"generation", 6: b"path", 7: ("sha512:" + hashlib.sha512(b"certificate").hexdigest()).encode(),
            8: scenarios._role_frame(8, c["generation"]["cryptographicBinding"]["primary"], c["issuer_spki"]),
            9: scenarios._role_frame(9, c["generation"]["cryptographicBinding"]["alternative"], c["issuer_alternative"]),
            10: b"leaf", 11: struct.pack(">Q", 1), 12: b"sha256:" + b"a" * 64, 13: b"sha512:" + b"c" * 128,
            14: b"sha256:" + b"b" * 64, 15: scenarios._value(c["effective"]), 16: scenarios._value(c["disclosure"]),
            17: scenarios._value({})})

    def test_target_matches_exact_selected_coordinates_and_rejects_substitutions(self):
        context = self.context()
        target = self.target(context)
        self.assertEqual(hashlib.sha512(target).hexdigest(), scenarios._validate_target(target, **context))
        fields = scenarios._fields(target, 7, range(1, 18))
        for tag, replacement in ((2, scenarios._value({})), (5, b"other-generation"), (6, b"other-path"),
                (8, fields[9]), (10, b"other-profile"), (12, b"sha256:" + b"0" * 64), (15, scenarios._value({})),
                (16, scenarios._value({})), (17, scenarios._value({"unexpected": True}))):
            with self.subTest(tag=tag), self.assertRaises(ExerciseFailure):
                scenarios._validate_target(scenarios._frame(7, dict(fields, **{}) | {tag: replacement}), **context)
        context["issuer_spki"] = b"wrong-key"
        with self.assertRaises(ExerciseFailure):
            scenarios._validate_target(target, **context)

    def test_malformed_frames_and_values_fail_closed(self):
        for value in (b"", b"\x03\x02", b"\x01\x00\x00\x00\x02a", b"\x06\xff\xff\xff\xff"):
            with self.subTest(value=value), self.assertRaises(ExerciseFailure):
                scenarios._read_value(value)
        target = self.target(self.context())
        for encoded in (target[:-1], target + b"trailing", scenarios._frame(2, {1: b"wrong"})):
            with self.assertRaises(ExerciseFailure):
                scenarios._fields(encoded, 7, range(1, 18))
        with self.assertRaises(ExerciseFailure):
            scenarios._decode("AA==")

    def test_profiles_select_only_approved_family_and_distinct_managed_keys(self):
        for variant, (_, family) in scenarios.VARIANTS.items():
            profiles = scenarios._profiles(variant, "run", {"root": {"keyRef": "root-alt"}, "intermediate": {"keyRef": "child-alt"}}, "ml87")
            self.assertEqual([family], profiles["client"]["leafCertificate"]["allowedKeyAlgorithms"])
            self.assertEqual([family], profiles["root"]["caCertificate"]["allowedSubjectKeyAlgorithms"])
            if variant == "hybrid":
                self.assertEqual("root-alt", profiles["root"]["hybridMode"]["altKeyRef"])
                self.assertEqual("child-alt", profiles["intermediate"]["hybridMode"]["altKeyRef"])
                self.assertEqual("REQUEST", profiles["client"]["hybridMode"]["subjectKeySource"])
            else:
                self.assertNotIn("hybridMode", profiles["client"])

    def test_unknown_challenge_is_not_reposted(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            api = SimpleNamespace(origin="https://localhost:8443")
            exercise = Exercise(api, directory)
            try:
                keys = directory / "client-keys"
                keys.mkdir()
                (keys / "client.csr.der").write_bytes(b"csr")
                options = SimpleNamespace()
                with patch.object(scenarios, "_sdk_json", side_effect=ExerciseFailure("lost")) as post:
                    for _ in range(2):
                        with self.assertRaises(ExerciseFailure):
                            scenarios._sdk_issue(exercise, options, {}, "ca", {}, directory / "login.pem")
                    self.assertEqual(1, post.call_count)
            finally:
                exercise.close()

    def test_lost_acceptance_is_observed_and_never_reposted_on_resume(self):
        from test_exercise_pki import FakeApi
        with tempfile.TemporaryDirectory() as temporary:
            api = FakeApi()
            exercise = Exercise(api, Path(temporary) / "output", sleep=lambda seconds: None)
            try:
                exercise.discover()
                arguments = {"issuerCaId": "ca", "requestId": "csr", "profileId": "leaf"}
                exercise.schema["credential.issue"] = {"scope": "authority", "authorityFrom": "issuerCaId",
                    "fields": [{"name": name, "required": True, "type": "text"} for name in arguments]}
                exercise.descriptors["credential.issue"] = {"durableRequest": True}
                keys = exercise.directory / "client-keys"
                keys.mkdir(mode=0o700)
                for name, content in (("client.csr.der", b"csr"), ("primary.proof", b"proof"), ("alternative.proof", b"alternative")):
                    (keys / name).write_bytes(content)
                    (keys / name).chmod(0o600)
                context = self.context()
                context["effective"] = {"subjectRef": "CN=ZeroEcho scenario client", "rdns": [{"type": "COMMON_NAME", "value": "ZeroEcho scenario client"}],
                    "sans": [{"type": "URI", "value": "spiffe://zeroecho.invalid/scenario/client"}]}
                target = self.target(context)
                digest = hashlib.sha512(target).hexdigest()
                options = SimpleNamespace(approved_sdk_target=digest)
                first = scenarios._frame(1, {tag: b"i" * 32 if tag == 3 else b"value" for tag in range(1, 18)})
                base = {"version": 1, "profile": scenarios.PROFILE, "operationId": "credential.issue", "arguments": arguments,
                        "requestDer": scenarios._b64(b"csr")}
                exercise.state["algorithmSdk"] = dict(base=base, nonce="00" * 32, challengeAttempted=True, acceptAttempted=False, proofsReady=True,
                    challenge={"intentId": (b"i" * 32).hex(), "primaryFrame": scenarios._b64(first), "alternativeFrame": scenarios._b64(b"f2"),
                               "targetFrame": scenarios._b64(target), "expiresAt": "2026-11-15T22:00:00Z"})
                def lost(api_argument, path, body):
                    self.assertIs(api, api_argument)
                    self.assertTrue(path.endswith("/accept"))
                    api.records[body["sdkRequestId"]] = {"requestId": body["sdkRequestId"], "operation": "credential.issue",
                        "state": "WAITING_APPROVAL", "approvalId": "approval-one"}
                    raise ExerciseFailure("Acceptance acknowledgement lost")
                validation = {key: value for key, value in context.items() if key not in ("arguments", "effective", "disclosure", "approval_commitment")}
                with patch.object(scenarios, "_sdk_json", side_effect=lost) as accept:
                    for _ in range(2):
                        result = scenarios._sdk_issue(exercise, options, arguments, "ca", dict(validation, arguments=arguments), keys / "login.pem")
                        self.assertEqual("cert:new", result["credentialId"])
                    self.assertEqual(1, accept.call_count)
                self.assertFalse(any(method == "POST" and path == "/admin/v1/requests" for method, path, _ in api.calls))
                request_id = "exercise-" + exercise.state["runId"] + "-client"
                self.assertTrue(all(path.endswith(request_id) for method, path, _ in api.calls if method == "GET" and "/requests/" in path))
            finally:
                exercise.close()

    def test_algorithm_flags_cannot_silently_run_legacy_demo(self):
        import contextlib
        import io
        from exercise_pki import main
        for arguments in (["--variant", "p384"], ["--mode", "algorithms", "--require-public"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                main(arguments)
            self.assertEqual(2, failure.exception.code)

    def test_fresh_install_sdk_selection_is_explicit_and_does_not_change_business_default(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("config", "profiles"):
                (root / name).mkdir()
            values = {name: default for name, _, default, _ in installer.FIELDS}
            values.update(hostname="pki.example.test", port="8443")
            fingerprints = {name: "a" * 64 for name in ("proxy", "administrator", "approver")}
            for enabled in (False, True):
                values["hybrid_sdk"] = enabled
                candidate = root / str(enabled)
                (candidate / "config").mkdir(parents=True)
                (candidate / "profiles").mkdir()
                installer._configuration(candidate, values, fingerprints)
                config = json.loads((candidate / "config/server.json").read_text())
                self.assertEqual(enabled, "hybridSdk" in config["listener"])
                self.assertEqual(installer.ALGORITHM, config["realm"]["pkiSession"]["signing"]["signatureAlgorithm"])
                if enabled:
                    self.assertEqual({"canonicalOrigin": "https://pki.example.test:8443"}, config["listener"]["hybridSdk"])


if __name__ == "__main__":
    unittest.main()
