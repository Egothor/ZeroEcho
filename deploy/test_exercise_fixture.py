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

"""Validation, real TLS generation and systemd contracts for rootless installation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

import exercise_fixture as fixture
from exercise_pki import ExerciseFailure


class FakeApi:
    def __init__(self, origin, trust, identity=None, key=None):
        self.origin = origin
        self.client_authenticated = identity is not None

    def json(self, method, path, document=None):
        return 200, {"status": "SUCCEEDED"}


class FakePodman:
    def __init__(self):
        self.calls, self.containers, self.networks, self.inputs = [], {}, {}, []

    def __call__(self, arguments, check=True, redactions=(), input_data=None):
        values = list(map(str, arguments))
        self.calls.append(values)
        self.inputs.append(input_data)
        raw, code = b"", 0
        if values[0] == "info": raw = b"true"
        elif values[:2] == ["network", "create"]:
            name = values[-1]
            label = values[values.index("--label") + 1].split("=", 1)
            self.networks[name] = {"name": name, "labels": {label[0]: label[1]}, "subnets": [{"subnet": "10.99.0.0/24", "gateway": "10.99.0.1"}]}
        elif values[:2] == ["network", "inspect"]: raw = json.dumps([self.networks[values[-1]]]).encode()
        elif values[:2] == ["network", "exists"]: code = 0 if values[-1] in self.networks else 1
        elif values[:2] == ["network", "rm"]: self.networks.pop(values[-1])
        elif values[0] == "run" and "--name" in values:
            name = values[values.index("--name") + 1]
            label = values[values.index("--label") + 1].split("=", 1)
            identity = ("c" if name.endswith("server") else "d") * 64
            self.containers[name] = {"Id": identity, "Image": next(value for value in values if len(value)==64 and all(character in "0123456789abcdef" for character in value)), "Config": {"Labels": {label[0]: label[1]}}, "State": {"Running": True}}
            raw = identity.encode()
        elif values[0] == "run":
            if "zeroecho-pki-certificate-access" in str(values): raw = b"CERTIFICATE_ACCESS_READY\n"
            if "zeroecho-pki-profile-bootstrap" in str(values): raw = b"Profile bootstrap completed: registered=5 skipped=0\n"
            if "zeroecho-pki-status-access" in str(values): raw = b"STATUS_ACCESS_READY\n"
            if "zeroecho.pki.server.ExerciseCatalogStateSeed" in values: raw = b"PUBLICATION_STATE_READY\n"
            if "zeroecho.pki.server.ExerciseProtocolSeed" in values: raw = b"PROTOCOL_FIXTURE_READY\n" if "--cmp-wire" not in values else b"CMP_GENERAL_MESSAGE_VERIFIED\n"
        elif values[:2] == ["container", "exists"]: code = 0 if values[-1] in self.containers else 1
        elif values[0] in ("stop", "start", "restart"):
            self.containers[values[-1]]["State"]["Running"] = values[0] != "stop"
        elif values[0] == "logs": raw = b"PROTOCOL_DNS_READY\n"
        elif values[0] == "inspect": raw = json.dumps([self.containers[values[-1]]]).encode()
        elif values[0] == "rm": self.containers.pop(values[-1])
        elif values[0] == "port": raw = ("127.0.0.1:"+str(35000+int(values[-1].split("/")[0]))).encode()
        return subprocess.CompletedProcess(values, code, raw, b"")


class PodmanDiagnosticTest(unittest.TestCase):
    def test_failure_identifies_static_phase_exit_and_stderr_without_argv_or_stdout(self):
        args=["run","--entrypoint","/opt/zeroecho/server/bin/zeroecho-pki-server","image","--validate-config","--config","PRIVATE-CONFIG-ARG"]
        with patch.object(fixture.subprocess,"run",return_value=subprocess.CompletedProcess(args,125,b"PRIVATE-STDOUT",b"permission denied on bind mount")):
            with self.assertRaises(ExerciseFailure) as failure:fixture._command(args)
        message=str(failure.exception)
        self.assertIn("validate-config",message)
        self.assertIn("exit 125",message)
        self.assertIn("permission denied on bind mount",message)
        self.assertNotIn("PRIVATE-CONFIG-ARG",message)
        self.assertNotIn("PRIVATE-STDOUT",message)

    def test_secret_pem_controls_and_excessive_stderr_are_redacted(self):
        secret="fresh-super-secret"
        raw=("\x1b[31mpermission denied\x1b[0m\0 "+secret+" -----BEGIN PRIVATE KEY-----\nPRIVATE-KEY-BODY\n-----END PRIVATE KEY----- "+"x"*5000).encode()
        with patch.object(fixture.subprocess,"run",return_value=subprocess.CompletedProcess([],126,b"STDOUT",raw)):
            with self.assertRaises(ExerciseFailure) as failure:fixture._command(["run"],redactions=(secret,))
        message=str(failure.exception)
        self.assertIn("permission denied",message)
        self.assertNotIn(secret,message)
        self.assertNotIn("PRIVATE-KEY-BODY",message)
        self.assertNotIn("\x1b",message)
        self.assertNotIn("\0",message)
        self.assertLess(len(message),1800)
        with patch.object(fixture.subprocess,"run",return_value=subprocess.CompletedProcess([],1,b"",b"")):
            self.assertEqual(1,fixture._command(["container","exists","private-name"],check=False).returncode)


class DisposableFixtureTest(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        self.podman = FakePodman()
        self.images = {"server": "a" * 64, "web": "b" * 64}

    def tearDown(self):
        os.umask(self.mask)

    def test_fixture_redacts_all_three_generated_secrets_on_real_command_failure(self):
        command=fixture._command
        with patch.object(fixture,"_command",side_effect=self.podman),patch.object(fixture,"Api",FakeApi):
            with fixture.DisposableFixture(self.images) as isolated:
                self.assertEqual(3,len(isolated._diagnostic_secrets))
                raw=("failure "+" ".join(isolated._diagnostic_secrets)).encode()
                with patch.object(fixture,"_command",command),patch.object(fixture.subprocess,"run",return_value=subprocess.CompletedProcess([],125,b"",raw)):
                    with self.assertRaises(ExerciseFailure) as failure:isolated._run(["run"])
                for value in isolated._diagnostic_secrets:self.assertNotIn(value,str(failure.exception))
                self.assertIn("[secret redacted]",str(failure.exception))

    def test_fresh_crypto_configuration_isolated_ports_and_owned_cleanup(self):
        with patch.object(fixture, "_command", side_effect=self.podman), patch.object(fixture, "Api", FakeApi):
            with fixture.DisposableFixture(self.images) as isolated:
                root = isolated.directory
                isolated.bind("run-one")
                isolated.assert_disposable(isolated.admin_url, "run-one")
                self.assertNotEqual(isolated.admin_url, isolated.public_url)
                self.assertTrue(isolated.api.client_authenticated)
                self.assertFalse(isolated.public_api.client_authenticated)
                self.assertTrue(isolated.configuration["publicListener"]["enabled"])
                self.assertEqual("DIRECT_MTLS", isolated.configuration["publicListener"]["authentication"]["mode"])
                self.assertEqual(0o600, (root / "provisioning/administrator.key").stat().st_mode & 0o777)
                self.assertNotIn(isolated.login_password, repr(self.podman.calls))
                self.assertFalse(any("systemctl" in str(call) for call in self.podman.calls))
                published = [call[index+1] for call in self.podman.calls for index,value in enumerate(call) if value=="--publish"]
                self.assertEqual(["127.0.0.1::8444", "127.0.0.1::8445", "127.0.0.1::8446", "127.0.0.1::8447", "127.0.0.1::8448", "127.0.0.1::8443"], published)
                self.assertEqual(4,len(set(isolated.protocol_urls.values())))
            self.assertFalse(root.exists())
        self.assertFalse(self.podman.containers)
        self.assertFalse(self.podman.networks)

    def test_dns_sidecar_is_owned_keyless_and_reused(self):
        with patch.object(fixture, "_command", side_effect=self.podman), patch.object(fixture, "Api", FakeApi), patch.object(fixture.DisposableFixture, "_helper_classes", return_value=Path("/tmp/qualification-classes")):
            with fixture.DisposableFixture(self.images) as isolated:
                isolated.bind("run-one")
                first = isolated.start_protocol_dns()
                self.assertEqual(first, isolated.start_protocol_dns())
                isolated.restart()
                self.assertIn(isolated.prefix+"-dns", isolated.ids)
                launches = [call for call in self.podman.calls if "--name" in call and call[call.index("--name")+1].endswith("-dns")]
                self.assertEqual(2, len(launches))
                self.assertIn("--network=container:"+isolated.server, launches[0])
                self.assertNotIn("keyring", repr(launches[0]))
                self.assertNotIn("secrets.conf", repr(launches[0]))
                self.assertNotIn("--publish", launches[0])
            self.assertFalse(self.podman.containers)

    def test_offline_seed_requires_owned_stop_exact_scope_and_receipt(self):
        with patch.object(fixture, "_command", side_effect=self.podman), patch.object(fixture, "Api", FakeApi), patch.object(fixture.DisposableFixture, "_helper_classes", return_value=Path("/tmp/qualification-classes")):
            with fixture.DisposableFixture(self.images) as isolated:
                isolated.bind("run-one")
                proof = isolated.seed_publication("exercise-run-one-publication", "f"*64, "OUTCOME_UNKNOWN")
                self.assertTrue(proof["fixtureSeededCrashState"])
                marker = json.loads((isolated.directory/".exercise-seed-authorization.json").read_text())
                self.assertTrue(marker["backendStopped"])
                self.assertEqual(isolated.ids[isolated.server], marker["serverId"])
                calls = self.podman.calls
                stop = next(index for index, call in enumerate(calls) if call[0]=="stop")
                seed = next(index for index, call in enumerate(calls) if "zeroecho.pki.server.ExerciseCatalogStateSeed" in call)
                self.assertLess(stop, seed)
                self.assertIn("--network=none", calls[seed])
                before=len(calls)
                with self.assertRaisesRegex(ExerciseFailure, "outside"):
                    isolated.seed_publication("foreign", "f"*64, "OUTCOME_UNKNOWN")
                with self.assertRaisesRegex(ExerciseFailure, "Unknown"):
                    isolated.offline_seed("ArbitraryHelper", [], authorization={})
                with self.assertRaisesRegex(ExerciseFailure, "authorization"):
                    isolated.offline_seed("ExerciseProtocolSeed", [], authorization={"unexpected":"value"})
                with self.assertRaisesRegex(ExerciseFailure,"client unlock"):
                    isolated.offline_seed("ExerciseProtocolSeed",["authority","credential"],authorization={"authorityId":"authority","credentialId":"credential"},client_password="bad\ninput")
                self.assertFalse(any(call[0]=="stop" for call in calls[before:]))

    def test_all_actual_nginx_template_tls_references_are_generated(self):
        import re
        template=(fixture.installer.REPOSITORY/"deploy/nginx/conf.d/default.conf.template").read_text()
        references=set(re.findall(r"(?:ssl_(?:certificate|certificate_key|client_certificate)|proxy_ssl_(?:certificate|certificate_key|trusted_certificate))\s+(/etc/nginx/tls/[^;\s]+);",template))
        self.assertEqual(6,len(references))
        with patch.object(fixture,"_command",side_effect=self.podman),patch.object(fixture,"Api",FakeApi):
            with fixture.DisposableFixture(self.images) as isolated:
                missing=sorted(path for path in references if not (isolated.directory/"tls"/path.removeprefix("/etc/nginx/tls/")).is_file())
                self.assertEqual([],missing)

    def test_web_preflight_uses_default_entrypoint_and_same_network_env_tls_mounts(self):
        with patch.object(fixture,"_command",side_effect=self.podman),patch.object(fixture,"Api",FakeApi):
            with fixture.DisposableFixture(self.images) as isolated:
                validation=next(call for call in self.podman.calls if call[-2:]==["nginx","-t"])
                detached=next(call for call in self.podman.calls if "--name" in call and call[call.index("--name")+1]==isolated.web)
                self.assertLess(self.podman.calls.index(validation),self.podman.calls.index(detached))
                for flag in ("--network","--label","--env","--volume"):
                    selected=lambda command:[command[index+1] for index,value in enumerate(command) if value==flag]
                    self.assertEqual(selected(validation),selected(detached))
                self.assertEqual(self.images["web"],validation[-3])
                self.assertIn("--rm",validation)
                for forbidden in ("--entrypoint","--detach","--publish"):self.assertNotIn(forbidden,validation)

    def test_web_preflight_timeout_cleans_only_tracked_nonce_owned_resources(self):
        def timeout(arguments,**kwargs):
            result=self.podman(arguments,**kwargs)
            if list(arguments[-2:])==["nginx","-t"]:
                raise subprocess.TimeoutExpired("podman",600)
            return result
        fingerprints={"administrator":"1"*64,"approver":"2"*64,"proxy":"3"*64}
        with patch.object(fixture,"_command",side_effect=timeout),patch.object(fixture,"Api",FakeApi),patch.object(fixture,"_tls",return_value=fingerprints):
            with self.assertRaises(subprocess.TimeoutExpired):
                with fixture.DisposableFixture(self.images):pass
        validation=next(call for call in self.podman.calls if call[-2:]==["nginx","-t"])
        name=validation[validation.index("--name")+1]
        self.assertTrue(name.endswith("-webcheck"))
        self.assertIn(["rm","--force",name],self.podman.calls)
        self.assertFalse(self.podman.containers)
        self.assertFalse(self.podman.networks)

    def test_empty_binding_reports_owned_state_and_redacts_logs_without_relaxing_guard(self):
        with patch.object(fixture,"_command",side_effect=self.podman),patch.object(fixture,"Api",FakeApi):
            with fixture.DisposableFixture(self.images) as isolated:
                self.podman.containers[isolated.web]["State"]={"Status":"exited","Running":False,"ExitCode":1}
                def inspect_failure(arguments,**kwargs):
                    if arguments[0]=="port":return subprocess.CompletedProcess(arguments,0,b"",b"")
                    if arguments[0]=="logs":return subprocess.CompletedProcess(arguments,0,("missing TLS path "+isolated.login_password+" -----BEGIN PRIVATE KEY-----\nprivate-body\n-----END PRIVATE KEY-----").encode(),b"")
                    return self.podman(arguments,**kwargs)
                with patch.object(fixture,"_command",side_effect=inspect_failure):
                    with self.assertRaises(ExerciseFailure) as failure:isolated._binding(isolated.web,"8443/tcp")
                message=str(failure.exception)
                self.assertIn("port metadata",message);self.assertIn("exited",message);self.assertIn("exit=1",message)
                self.assertIn("missing TLS path",message);self.assertNotIn(isolated.login_password,message);self.assertNotIn("private-body",message)
                with patch.object(fixture,"_command",return_value=subprocess.CompletedProcess([],0,b"0.0.0.0:49152",b"")):
                    with self.assertRaises(ExerciseFailure):isolated._binding(isolated.web,"8443/tcp")

    def test_validator_receives_both_companions_and_backup_spool_mount(self):
        import exercise_environment
        fingerprints={"administrator":"1"*64,"approver":"2"*64,"proxy":"3"*64}
        with patch.object(fixture,"_command",side_effect=self.podman),patch.object(fixture,"Api",FakeApi),patch.object(fixture,"_tls",return_value=fingerprints):
            with fixture.DisposableFixture(self.images,prepare=exercise_environment.prepare) as isolated:
                command=next(call for call in self.podman.calls if "--validate-config" in call)
                self.assertEqual("/deployment/config/enrollment-runtime.json",command[command.index("--enrollment-config")+1])
                self.assertEqual("/deployment/config/backup-transfer.json",command[command.index("--backup-transfer-config")+1])
                self.assertIn(str(isolated.directory/"backup-spool")+":/deployment/backup-spool:rw,z",command)
                self.assertIn("--network=none",command)
                self.assertEqual("/opt/zeroecho/server/bin/zeroecho-pki-server",command[command.index("--entrypoint")+1])

    def test_six_character_client_password_round_trips_real_pkcs12(self):
        with patch.object(fixture,"_command",side_effect=self.podman),patch.object(fixture,"Api",FakeApi):
            with fixture.DisposableFixture(self.images,login_password="sixsix") as isolated:
                public=fixture._openssl(["pkcs12","-in",isolated.directory/"logins/administrator.p12","-nokeys","-passin","stdin"],secret="sixsix")
                self.assertIn(b"-----BEGIN CERTIFICATE-----",public)
                self.assertEqual("sixsix",isolated.login_password)
                self.assertNotIn("sixsix",str(self.podman.calls))

    def test_separate_client_ring_secret_reaches_only_stopped_helper_stdin(self):
        with patch.object(fixture,"_command",side_effect=self.podman),patch.object(fixture,"Api",FakeApi),patch.object(fixture.DisposableFixture,"_helper_classes",return_value=Path("/tmp/qualification-classes")):
            with fixture.DisposableFixture(self.images,login_password="client-unlock-only") as isolated:
                isolated.bind("a"*32)
                self.assertNotEqual(isolated._keyring_password,isolated.login_password)
                isolated.offline_seed("ExerciseProtocolSeed",["authority","credential"],authorization={"authorityId":"authority","credentialId":"credential"},client_password=isolated.login_password)
                index=next(i for i,call in enumerate(self.podman.calls) if "--client-password-stdin" in call)
                self.assertIn("--interactive",self.podman.calls[index])
                self.assertEqual(b"client-unlock-only\n",self.podman.inputs[index])
                self.assertNotIn("client-unlock-only",str(self.podman.calls))
                self.assertNotIn("client-unlock-only",(isolated.directory/"secrets.conf").read_text())

    def test_legacy_client_unlock_is_stdin_only_and_invalid_phase_has_no_helper_effect(self):
        with patch.object(fixture, "_command", side_effect=self.podman), patch.object(fixture, "Api", FakeApi), patch.object(fixture.DisposableFixture, "_helper_classes", return_value=Path("/tmp/qualification-classes")):
            with fixture.DisposableFixture(self.images) as isolated:
                isolated.bind("run-one")
                with patch.object(fixture.subprocess,"run",return_value=subprocess.CompletedProcess([],0,b"LEGACY_CLIENT_READY\n",b"")) as helper:
                    self.assertEqual("VERIFIED",isolated.legacy_wire("cmp","verify")["state"])
                    args,kwargs=helper.call_args
                    self.assertNotIn(isolated._keyring_password,repr(args))
                    self.assertEqual((isolated._keyring_password+"\n").encode(),kwargs["input"])
                    self.assertNotIn("env",kwargs)
                    self.assertIn("--network=none",args[0])
                    with self.assertRaisesRegex(ExerciseFailure,"Invalid legacy"):
                        isolated.legacy_wire("cmp","arbitrary")
                    helper.assert_called_once()
                with patch.object(fixture.subprocess,"run",return_value=subprocess.CompletedProcess([],0,b"BAD",b"")):
                    with self.assertRaisesRegex(ExerciseFailure,"did not verify"):
                        isolated.legacy_wire("scep","initial")

    def test_cmp_wire_verifies_owned_endpoint_and_exact_receipt(self):
        with patch.object(fixture, "_command", side_effect=self.podman), patch.object(fixture, "Api", FakeApi), patch.object(fixture.DisposableFixture, "_helper_classes", return_value=Path("/tmp/qualification-classes")):
            with fixture.DisposableFixture(self.images) as isolated:
                isolated.bind("run-one")
                self.assertTrue(isolated.cmp_wire("exercise-run-one-cmp")["protectedExchangeVerified"])
                exchange=next(call for call in self.podman.calls if "--cmp-wire" in call)
                self.assertIn("--network=container:"+isolated.server, exchange)
                with self.assertRaisesRegex(ExerciseFailure, "outside"):
                    isolated.cmp_wire("foreign")
                original=self.podman
                def missing_receipt(arguments, check=True, redactions=()):
                    response=original(arguments,check)
                    if "--cmp-wire" in arguments: return subprocess.CompletedProcess(arguments,0,b"UNVERIFIED",b"")
                    return response
                with patch.object(fixture,"_command",side_effect=missing_receipt):
                    with self.assertRaisesRegex(ExerciseFailure,"not cryptographically"):
                        isolated.cmp_wire("exercise-run-one-cmp")

    def test_profiles_are_staged_only_after_an_owned_stop(self):
        with patch.object(fixture,"_command",side_effect=self.podman),patch.object(fixture,"Api",FakeApi):
            with fixture.DisposableFixture(self.images) as isolated:
                isolated.bind("run-one")
                self.assertEqual("off",isolated.environment["ZEROECHO_PROFILE_RECONCILE"])
                expected={path.name for path in (fixture.installer.REPOSITORY/"pki/src/main/resources/zeroecho/pki/profiles/v1").glob("*.json") if path.name!="catalog.json"}
                self.assertEqual(expected,{path.name for path in (isolated.directory/"profiles").glob("*.json")})
                self.assertFalse(any("zeroecho-pki-profile-bootstrap" in str(call) for call in self.podman.calls))
                isolated.load_profiles()
                bootstrap=next(index for index,call in enumerate(self.podman.calls) if "zeroecho-pki-profile-bootstrap" in str(call))
                stop=next(index for index,call in enumerate(self.podman.calls) if call[0]=="stop")
                self.assertLess(stop,bootstrap)
                self.assertIn("--network=none",self.podman.calls[bootstrap])
                self.assertTrue(self.podman.containers[isolated.server]["State"]["Running"])
                original=self.podman
                def no_receipt(arguments,check=True,redactions=()):
                    result=original(arguments,check)
                    return subprocess.CompletedProcess(arguments,0,b"",b"") if "zeroecho-pki-profile-bootstrap" in str(arguments) else result
                with patch.object(fixture,"_command",side_effect=no_receipt):
                    with self.assertRaisesRegex(ExerciseFailure,"completion receipt"):isolated.load_profiles()
                self.assertTrue(self.podman.containers[isolated.server]["State"]["Running"])
                self.podman.containers[isolated.server]["Config"]["Labels"][fixture.LABEL]="foreign"
                with self.assertRaisesRegex(ExerciseFailure,"ownership"):isolated.load_profiles()
                self.podman.containers[isolated.server]["Config"]["Labels"][fixture.LABEL]=isolated.nonce

    def test_foreign_ownership_prevents_mutation_proof_and_cleanup(self):
        with patch.object(fixture, "_command", side_effect=self.podman), patch.object(fixture, "Api", FakeApi):
            isolated = fixture.DisposableFixture(self.images).__enter__()
            isolated.bind("run-one")
            root = isolated.directory
            self.podman.containers[isolated.web]["Config"]["Labels"][fixture.LABEL] = "foreign"
            with self.assertRaisesRegex(ExerciseFailure, "ownership"):
                isolated.assert_disposable(isolated.admin_url, "run-one")
            with self.assertRaisesRegex(ExerciseFailure, "Foreign"):
                isolated.__exit__(None, None, None)
            self.assertIn(isolated.web, self.podman.containers)
            self.assertTrue(root.exists())
            shutil.rmtree(root)

    def test_immutable_images_and_exact_runtime_origin_are_required(self):
        with self.assertRaisesRegex(ExerciseFailure, "immutable"):
            fixture.DisposableFixture({"server": "latest", "web": "latest"})
        isolated = fixture.DisposableFixture(self.images)
        isolated.admin_url = "https://127.0.0.1:43443"
        isolated.bind("run-one")
        with self.assertRaisesRegex(ExerciseFailure, "exact active"):
            isolated.assert_disposable("https://production.invalid", "run-one")
        with self.assertRaisesRegex(ExerciseFailure, "exact active"):
            isolated.assert_disposable(isolated.admin_url, "another-run")


if __name__ == "__main__":
    unittest.main()
