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

"""Deployment-only ownership, client export and foreground lifecycle boundaries."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import exercise_environment as environment
from exercise_pki import ExerciseFailure


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def test_existing_or_nested_paths_are_rejected_before_password_or_build(self):
        prompt = Mock()
        for root, client in ((self.base, self.base/"client"), (self.base/"state", self.base/"state/client")):
            with self.assertRaises(ExerciseFailure):
                environment.start(root,client_directory=client,password_prompt=prompt)
        prompt.assert_not_called()

    def test_ready_console_controls_only_its_owned_deployment(self):
        import subprocess
        fixture=Mock();fixture.assert_disposable=Mock();fixture.admin_url="https://localhost:10000";fixture.run_id="a"*32
        manager=Mock();manager.__enter__=Mock(return_value=fixture);manager.__exit__=Mock(return_value=False)
        connection={"version":1,"purpose":"qualification","environmentId":"a"*32}
        commands=iter(("status","restart","stop"))
        def command(_prompt):
            # Connection file exists before the user can start the independent client.
            self.assertEqual(connection,json.loads((self.base/"state-client/client-config.json").read_text()))
            return next(commands)
        with patch("exercise_fixture.DisposableFixture",return_value=manager),patch("rootless_pki._image",side_effect=("a"*64,"b"*64)),patch("shutil.which",return_value="tool"),patch("subprocess.run",return_value=subprocess.CompletedProcess([],0,b"-jdktrust",b"")),patch("os.geteuid",return_value=1000),patch.object(environment,"_provision",return_value=connection) as prepare,patch("builtins.print"):
            environment.start(self.base/"state",read_command=command,password_prompt=lambda _:"sixsix")
        prepare.assert_called_once_with(fixture,self.base/"state-client","sixsix")
        fixture.restart.assert_called_once()
        fixture.assert_disposable.assert_called_once_with(fixture.admin_url,fixture.run_id)
        manager.__exit__.assert_called_once()

    def test_provider_preparation_binds_exact_fresh_realm(self):
        (self.base/".exercise-owner.json").write_text(json.dumps({"nonce":"a"*32}))
        configuration={"realm":{"realmId":"zeroecho-exercise-"+"a"*32,"pkiSession":{"store":{"properties":{}},"signing":{"signatureAlgorithm":"algorithm"}}}}
        self.assertEqual({},environment.prepare_fixture(self.base,configuration))
        self.assertEqual("h2",configuration["realm"]["pkiSession"]["store"]["properties"]["credentialSearch"])
        self.assertTrue((self.base/"artifacts/publication").is_dir())
        self.assertEqual(0o600,(self.base/"config/catalog-context.json").stat().st_mode & 0o777)
        configuration["realm"]["realmId"]="foreign"
        with self.assertRaises(ExerciseFailure): environment.prepare_fixture(self.base,configuration)
        alias=self.base/"alias";alias.symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(ExerciseFailure): environment.prepare_fixture(alias,configuration)

    def test_early_failure_removes_only_new_empty_client_directory_for_retry(self):
        import subprocess
        manager=Mock();manager.__enter__=Mock(side_effect=ExerciseFailure("rootless engine unavailable"));manager.__exit__=Mock(return_value=False)
        with patch("exercise_fixture.DisposableFixture",return_value=manager),patch("rootless_pki._image",return_value="a"*64),patch("shutil.which",return_value="tool"),patch("subprocess.run",return_value=subprocess.CompletedProcess([],0,b"-jdktrust",b"")),patch("os.geteuid",return_value=self.base.stat().st_uid):
            for _ in range(2):
                with self.assertRaisesRegex(ExerciseFailure,"engine unavailable"):
                    environment.start(self.base/"state",password_prompt=lambda _:"client-secret")
                self.assertFalse((self.base/"state-client").exists())

    def test_failed_export_cleanup_refuses_replaced_directory_and_symlink(self):
        client=self.base/"client";client.mkdir()
        metadata=client.stat();identity=(metadata.st_dev,metadata.st_ino)
        client.rename(self.base/"original-client")
        client.mkdir()
        with patch("builtins.print"):
            environment._failed_client_export(client,identity)
        self.assertTrue(client.is_dir())
        client.rmdir();client.symlink_to(self.base/"original-client",target_is_directory=True)
        with patch("builtins.print"):
            environment._failed_client_export(client,identity)
        self.assertTrue(client.is_symlink())
        self.assertTrue((self.base/"original-client").is_dir())

    def test_failed_preparation_preserves_nonempty_client_evidence(self):
        import subprocess
        fixture=Mock();manager=Mock();manager.__enter__=Mock(return_value=fixture);manager.__exit__=Mock(return_value=False)
        def fail(_fixture,client,_password):
            (client/"partial-public-certificate.der").write_bytes(b"public-evidence")
            raise ExerciseFailure("preparation interrupted")
        with patch("exercise_fixture.DisposableFixture",return_value=manager),patch("rootless_pki._image",return_value="a"*64),patch("shutil.which",return_value="tool"),patch("subprocess.run",return_value=subprocess.CompletedProcess([],0,b"-jdktrust",b"")),patch("os.geteuid",return_value=self.base.stat().st_uid),patch.object(environment,"_provision",side_effect=fail),patch("builtins.print") as output:
            with self.assertRaisesRegex(ExerciseFailure,"interrupted"):
                environment.start(self.base/"state",password_prompt=lambda _:"client-secret")
        self.assertEqual(b"public-evidence",(self.base/"state-client/partial-public-certificate.der").read_bytes())
        self.assertTrue(any("retained" in str(call) for call in output.call_args_list))

    def test_cli_routes_test_start_before_production_manifest_loading(self):
        import rootless_pki
        root=self.base/"fresh-environment"
        with patch("sys.argv",["rootless-pki.sh","test-start","--directory",str(root)]),patch.object(environment,"start") as start:
            rootless_pki._main()
        start.assert_called_once_with(root)

    def test_password_mismatch_refuses_before_image_build(self):
        with patch("rootless_pki._image") as build:
            passwords=iter(("first","second"))
            with self.assertRaises(ExerciseFailure): environment.start(self.base/"new",password_prompt=lambda _:next(passwords))
        build.assert_not_called()

    def test_public_copy_refuses_symlinks(self):
        source = self.base/"source"
        source.write_text("public")
        alias = self.base/"alias"
        alias.symlink_to(source)
        with self.assertRaises(ExerciseFailure): environment._copy_private(alias,self.base/"target")
        self.assertFalse((self.base/"target").exists())
        environment._copy_private(source,self.base/"target")
        self.assertEqual(0o600,(self.base/"target").stat().st_mode & 0o777)

    def test_preparation_exports_only_client_inputs_and_does_not_verify_backup(self):
        root, client = self.base/"deployment", self.base/"client"
        root.mkdir(); client.mkdir()
        for name in ("config", "keyring/protocol-custody", "protocol-client", "provisioning", "logins", "deployment-preparation"):
            (root/name).mkdir(parents=True,exist_ok=True)
        for name in ("authority", "est-ra", "scep-ra", "cmp-ra", "cmp-client"):
            (root/("keyring/protocol-custody/"+name+".der")).write_bytes(b"public")
        for name in ("protocol-client/client.zek", "protocol-client/client.zek.nonce", "logins/administrator.p12", "logins/web-ca.pem", "provisioning/approver.crt", "provisioning/approver.key"):
            (root/name).write_bytes(b"client-only")
        (root/"config/protocol-context.json").write_text(json.dumps({"protocolEnrollmentProfileId":"protocol-policy"}))
        prep=Mock();prep.directory=root/"deployment-preparation";prep.state={}
        prep.dedicated.return_value={"backupId":"minimal-backup","payload":"archive"}
        prep.job.side_effect=[{"credentialId":"root-cert"},{"statusObjectId":"crl"}, {}, {}]
        prep.operation.return_value={"publicKeyAlgorithms":["RSA"],"x509BindingPolicies":["binding"]}
        fixture=Mock();fixture.directory=root;fixture.nonce="a"*32;fixture.prefix="zeroecho-exercise-"+fixture.nonce
        fixture.admin_url="https://localhost:10000";fixture.public_url="https://localhost:10001";fixture.protocol_urls={name:"https://localhost:"+str(11000+i) for i,name in enumerate(("acme","est","scep","cmp"))}
        fixture.configuration={"acmeListener":{"externalBaseUri":"https://localhost:8445"},"realm":{"pkiSession":{"signing":{"signatureAlgorithm":"safe-algorithm"}}}}
        fixture._helper_classes.return_value=Path("/public/helper/classes")
        def artifact(adapter,kind,identity,prefix,limit):
            (adapter.directory/(prefix+".der")).write_bytes(b"source")
            return {"authorityId":"seed-ca"}
        with patch("exercise_pki.Exercise",return_value=prep),patch("exercise_pki._artifact",side_effect=artifact):
            result=environment._provision(fixture,client,"CLIENT-PASSWORD")
        self.assertEqual(fixture.protocol_urls["acme"],result["acmeDirectoryOrigin"])
        self.assertEqual(fixture.protocol_urls["acme"],json.loads((root/"config/server.json").read_text())["acmeListener"]["externalBaseUri"])
        fixture.restart.assert_called_once()
        self.assertEqual(b"client-only",(client/"protocol-client/client.zek.nonce").read_bytes())
        self.assertEqual(0o600,(client/"protocol-client/client.zek.nonce").stat().st_mode & 0o777)
        self.assertEqual("qualification",result["purpose"])
        self.assertEqual("dns/protocol-dns.json",result["acmeDnsChallengeFile"])
        self.assertEqual(client/"dns",fixture.dns_records_directory)
        self.assertEqual("crl",result["preparedPublications"]["retry"]["sourceId"])
        self.assertEqual(hashlib.sha256((client/"legacy-backup.json").read_bytes()).hexdigest(),result["legacyBackup"]["sha256"])
        first=fixture.offline_seed.call_args_list[0]
        self.assertEqual("CLIENT-PASSWORD",first.kwargs["client_password"])
        self.assertNotIn("CLIENT-PASSWORD",json.dumps(result))
        self.assertNotIn(str(root),json.dumps(result))
        self.assertFalse(any("backup.verify" in str(call) for call in prep.mock_calls))
        self.assertEqual("backup.export",prep.dedicated.call_args.args[1])
        prep.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
