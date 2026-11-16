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
import fcntl
import os
from pathlib import Path
import subprocess
import tempfile
import socket
import unittest
from unittest.mock import patch

import rootless_pki as installer


def _values(directory):
    values = {name: default for name, _, default, _ in installer.FIELDS}
    values.update(directory=str(directory), hostname="pki.example.test", key_password="signing-password-12345",
                  admin_password="admin-password-123456", approver_password="approver-password-123456")
    return values


class ValidationTest(unittest.TestCase):
    def test_valid_form_and_port_boundaries(self):
        with tempfile.TemporaryDirectory() as parent:
            values = _values(Path(parent) / "new")
            for port in ("1024", "65535"):
                values["port"] = port
                installer._validate(values)

    def test_rejects_invalid_fields_before_effects(self):
        with tempfile.TemporaryDirectory() as parent:
            baseline = _values(Path(parent) / "new")
            for key, value in (("hostname", "x;touch /tmp/pwn"), ("hostname", "bad..host"),
                               ("bind", "localhost"), ("port", "1023"), ("port", "65536"),
                               ("realm", "../escape"), ("admin", "trusted-proxy"),
                               ("admin", baseline["approver"]), ("key_password", "short"),
                               ("key_password", "a" * 20 + "\nINJECT=yes"),
                               ("admin_password", baseline["approver_password"]),
                               ("edge_cert", "missing.pem"), ("directory", str(installer.REPOSITORY / "data")),
                               ("directory", str(parent))):
                with self.subTest(key=key, value=value):
                    values = dict(baseline, **{key: value})
                    with self.assertRaises(ValueError):
                        installer._validate(values)
            self.assertFalse((Path(parent) / "new").exists())

    def test_quote_systemd_metacharacters(self):
        self.assertEqual('"a %% $$ \\"b\\" \\\\ c"', installer._systemd_quote('a % $ "b" \\ c'))

    def test_service_keeps_secrets_out_of_command_and_limits_publication(self):
        with tempfile.TemporaryDirectory(prefix="pki spaces %$") as directory:
            root = Path(directory)
            (root / "units").mkdir()
            values = _values(root)
            installer._units(root, values, {"server": "sha256:abc", "web": "sha256:def"}, "zeroecho-test", ["10.88.0.2", "10.88.0.3"])
            server = (root / "units/zeroecho-test-server.service").read_text()
            web = (root / "units/zeroecho-test-web.service").read_text()
            self.assertIn("keep-id:uid=10001,gid=10001", server)
            self.assertIn('"--replace"', server)
            self.assertIn('"--replace"', web)
            self.assertNotIn("--publish", server)
            self.assertIn("127.0.0.1:8443:8443", web)
            self.assertIn("ExecStartPost=", server)
            self.assertIn('"--ip" "10.88.0.2"', server)
            self.assertIn('"--ip" "10.88.0.3"', web)
            self.assertIn("Wants=zeroecho-test-server.service", web)
            self.assertIn("secrets.conf", server)
            self.assertNotIn(values["key_password"], server)

    def test_backend_defines_runtime_healthcheck_for_oci_images(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "units").mkdir()
            installer._units(root, _values(root), {"server": "sha256:abc", "web": "sha256:def"},
                             "zeroecho-test", ["10.88.0.2", "10.88.0.3"])
            server = (root / "units/zeroecho-test-server.service").read_text()
            self.assertIn('"--health-cmd"', server)
            self.assertIn('/deployment/tls/health/health-client.pem', server)
            self.assertIn('/deployment/tls/health/health-client-key.pem', server)
            self.assertIn('/deployment/tls/health/health-ca.pem', server)
            self.assertIn('https://127.0.0.1:8443/health/ready', server)
            self.assertIn('"--health-timeout" "5s"', server)
            self.assertIn('"--health-retries" "5"', server)

    def test_missing_healthcheck_fails_immediately_with_safe_diagnostic(self):
        result = subprocess.CompletedProcess([], 125, b"", b"Error: container arbitrary has no defined healthcheck")
        with patch.object(installer.subprocess, "run", return_value=result), \
             patch.object(installer.time, "sleep") as wait:
            with self.assertRaisesRegex(RuntimeError, "no defined healthcheck"):
                installer._ready(Path("/tmp/unused"), {"prefix": "zeroecho-test"})
        wait.assert_not_called()

    def test_healthcheck_timeout_does_not_print_untrusted_diagnostics(self):
        result = subprocess.CompletedProcess([], 1, b"", b"untrusted diagnostic password=should-not-appear")
        with patch.object(installer.subprocess, "run", return_value=result), \
             patch.object(installer.time, "monotonic", side_effect=[0, 0, 121]), \
             patch.object(installer.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "health probe exited 1") as caught:
                installer._ready(Path("/tmp/unused"), {"prefix": "zeroecho-test"})
        self.assertNotIn("password", str(caught.exception))

    def test_stable_addresses_exclude_gateway_and_reject_small_network(self):
        network = [{"subnets": [{"subnet": "10.90.0.0/24", "gateway": "10.90.0.1"}]}]
        self.assertEqual(["10.90.0.2", "10.90.0.3"], installer._network_addresses(network))
        network[0]["subnets"][0]["subnet"] = "10.90.0.0/30"
        with self.assertRaises(ValueError):
            installer._network_addresses(network)

    def test_form_cancel_has_no_installation_effect(self):
        class Screen:
            def keypad(self, value): pass
            def erase(self): pass
            def getmaxyx(self): return 24, 100
            def addnstr(self, *args): pass
            def move(self, *args): pass
            def get_wch(self): return "\x1b"
        with patch.object(installer.curses, "curs_set"):
            with self.assertRaises(KeyboardInterrupt):
                installer._form(Screen())

    def test_edge_startup_observes_until_https_ready_without_mutation(self):
        manifest = {"hostname": "localhost", "port": 8443, "bind": "127.0.0.1"}
        with patch.object(installer, "_run", side_effect=[RuntimeError("not listening"), b"{}"] ) as run, \
             patch.object(installer.time, "monotonic", side_effect=[0, 0, 1]), \
             patch.object(installer.time, "sleep"):
            installer._verify_edge(Path("/tmp/fixture"), manifest)
        self.assertEqual(2, run.call_count)
        for call in run.call_args_list:
            self.assertEqual("curl", call.args[0][0])
            self.assertTrue(call.args[0][-1].endswith("/admin/v1/realm"))
            self.assertNotIn("--insecure", call.args[0])

    def test_edge_startup_has_a_bounded_failure(self):
        manifest = {"hostname": "localhost", "port": 8443, "bind": "127.0.0.1"}
        with patch.object(installer, "_run", side_effect=RuntimeError("not listening")), \
             patch.object(installer.time, "monotonic", side_effect=[0, 0, 121]), \
             patch.object(installer.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "120 seconds"):
                installer._verify_edge(Path("/tmp/fixture"), manifest)

    def test_runner_does_not_echo_secret_tool_diagnostics(self):
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"password=value")):
            with self.assertRaisesRegex(RuntimeError, r"openssl failed \(exit 1\)") as caught:
                installer._run(["openssl", "secret"])
            self.assertNotIn("password", str(caught.exception))


class SourceUpdateTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pki-source-update-")
        self.root = Path(self.temporary.name) / "installation"
        self.root.mkdir(mode=0o700)
        for directory in ("config", "profiles", "tls/server", "tls/health", "tls/edge", "tls/upstream", "tls/admin-trust", "store-container", "store-container/store", "keyring", "audit", "artifacts", "units"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.unit_directory = Path(self.temporary.name) / "user-units"
        self.unit_directory.mkdir()
        self.prefix = "zeroecho-" + installer.hashlib.sha256(str(self.root).encode()).hexdigest()[:12]
        self.manifest = {"version": 1, "prefix": self.prefix, "hostname": "pki.example.test", "port": 8443,
                         "bind": "127.0.0.1", "images": {"server": "a" * 64, "web": "b" * 64},
                         "addresses": ["10.90.0.2", "10.90.0.3"], "admin": "bootstrap-admin", "approver": "bootstrap-approver"}
        for suffix in ("server", "web"):
            path = self.root / "units" / f"{self.prefix}-{suffix}.service"
            path.write_text("existing unit")
            (self.unit_directory / path.name).symlink_to(path)
        (self.root / "manage.py").write_text("existing manager")
        (self.root / "installation.json").write_text(json.dumps(self.manifest))
        self.original = {}
        for name in ("config/server.json", "secrets.conf", "keyring/ca-keyring.zek", "store-container/server-control/server-control.log", "store-container/store/VERSION"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"unchanged-artifact")
            self.original[name] = path.read_bytes()
        self.commands = []

    def tearDown(self):
        self.temporary.cleanup()

    def command(self, arguments, **kwargs):
        self.commands.append([str(argument) for argument in arguments])
        if "network" in arguments and "inspect" in arguments:
            return json.dumps([{"name": self.prefix, "internal": True,
                                "subnets": [{"subnet": "10.90.0.0/24", "gateway": "10.90.0.1"}]}]).encode()
        if "zeroecho-pki-root-admin" in str(arguments):
            current = json.loads((self.root / "installation.json").read_text())
            self.assertEqual({"server": "c" * 64, "web": "d" * 64}, current["images"])
            self.assertIn("c" * 64, (self.root / "units" / f"{self.prefix}-server.service").read_text())
            return b"ROOT_ADMIN_READY\n"
        if "zeroecho-pki-certificate-access" in str(arguments):
            return b"CERTIFICATE_ACCESS_READY\n"
        if "zeroecho-pki-status-access" in str(arguments):
            return b"STATUS_ACCESS_READY\n"
        return b""

    def test_explicit_certificate_access_is_independent_and_runs_after_new_image_pins(self):
        def command(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            if "zeroecho-pki-certificate-access" in str(arguments):
                self.assertEqual({"server": "c" * 64, "web": "d" * 64}, json.loads((self.root / "installation.json").read_text())["images"])
                return b"CERTIFICATE_ACCESS_READY\n"
            return result
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=command), patch.object(installer, "_verify_edge"):
            installer._update(self.root, self.manifest, certificate_access=True, unit_directory=self.unit_directory)
        helper = next(i for i, value in enumerate(self.commands) if "zeroecho-pki-certificate-access" in str(value))
        stop = next(i for i, value in enumerate(self.commands) if "stop" in value)
        reload = next(i for i, value in enumerate(self.commands) if "daemon-reload" in value)
        start = next(i for i, value in enumerate(self.commands) if "start" in value)
        self.assertLess(stop, reload)
        self.assertLess(reload, helper)
        self.assertLess(helper, start)
        self.assertFalse(any("zeroecho-pki-root-admin" in str(value) for value in self.commands))
        self.assertIn("--network=none", self.commands[helper])
        self.assertEqual(["--config", "/deployment/config/server.json", "--admin-id", "bootstrap-admin", "--approver-id", "bootstrap-approver", "--proxy-id", "trusted-proxy"], self.commands[helper][-8:])
        for name, content in self.original.items():
            self.assertEqual(content, (self.root / name).read_bytes(), name)

    def test_certificate_failure_retains_exact_intent_and_resumes_without_rebuilding(self):
        def fail(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            if "zeroecho-pki-certificate-access" in str(arguments):
                raise RuntimeError("migration unconfirmed")
            return result
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=fail), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                installer._update(self.root, self.manifest, certificate_access=True, unit_directory=self.unit_directory)
        pending = json.loads((self.root / "updates/pending.json").read_text())
        self.assertEqual(3, pending["version"])
        self.assertTrue(pending["certificateAccess"])
        self.assertEqual("new-images-pinned", pending["phase"])
        self.assertFalse(any("start" in value for value in self.commands))
        current = json.loads((self.root / "installation.json").read_text())
        self.commands.clear()
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(ValueError, "same explicit certificate-access intent"):
                installer._update(self.root, current, unit_directory=self.unit_directory)
            self.assertFalse(any("stop" in value for value in self.commands))
            installer._update(self.root, current, certificate_access=True, unit_directory=self.unit_directory)
            build.assert_not_called()
        self.assertFalse((self.root / "updates/pending.json").exists())
        self.assertEqual(1, sum("zeroecho-pki-certificate-access" in str(value) for value in self.commands))

    def test_certificate_access_and_root_administrator_intents_are_independent(self):
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            installer._update(self.root, self.manifest, root_admin=True, certificate_access=True, unit_directory=self.unit_directory)
        self.assertEqual(1, sum("zeroecho-pki-root-admin" in str(value) for value in self.commands))
        self.assertEqual(1, sum("zeroecho-pki-certificate-access" in str(value) for value in self.commands))

    def test_legacy_pending_update_can_resume_only_without_new_certificate_intent(self):
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge", side_effect=RuntimeError("not ready")):
            with self.assertRaisesRegex(RuntimeError, "not ready"):
                installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        path = self.root / "updates/pending.json"
        legacy = json.loads(path.read_text())
        legacy["version"] = 1
        legacy.pop("certificateAccess")
        legacy.pop("statusAccess")
        path.write_text(json.dumps(legacy))
        current = json.loads((self.root / "installation.json").read_text())
        self.commands.clear()
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(ValueError, "same explicit certificate-access intent"):
                installer._update(self.root, current, certificate_access=True, unit_directory=self.unit_directory)
            self.assertFalse(any("stop" in value for value in self.commands))
            installer._update(self.root, current, unit_directory=self.unit_directory)
            build.assert_not_called()
        self.assertFalse(any("zeroecho-pki-certificate-access" in str(value) for value in self.commands))

    def test_certificate_migration_requires_exact_receipt_and_strict_journal_boolean(self):
        def invalid(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            return b"OTHER_RECEIPT" if "zeroecho-pki-certificate-access" in str(arguments) else result
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=invalid), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(RuntimeError, "migration is unconfirmed"):
                installer._update(self.root, self.manifest, certificate_access=True, unit_directory=self.unit_directory)
        path = self.root / "updates/pending.json"
        original = json.loads(path.read_text())
        current = json.loads((self.root / "installation.json").read_text())
        for change in ({"certificateAccess": "true"}, {"unexpected": False}, {"version": 1}):
            path.write_text(json.dumps(dict(original, **change)))
            self.commands.clear()
            with patch.object(installer, "_preflight"), patch.object(installer, "_run", side_effect=self.command):
                with self.assertRaisesRegex(ValueError, "Invalid retained update journal"):
                    installer._update(self.root, current, certificate_access=True, unit_directory=self.unit_directory)
            self.assertFalse(any("stop" in value for value in self.commands))

    def test_certificate_flag_is_rejected_for_other_commands_before_reading_installation(self):
        for command in ("install", "start", "stop", "status", "_ready"):
            with patch("sys.argv", ["rootless-pki.py", command, "--certificate-access"]), patch("sys.stderr"):
                with self.assertRaises(SystemExit) as failure:
                    installer._main()
            self.assertEqual(2, failure.exception.code)

    def test_certificate_flag_is_forwarded_only_to_the_explicit_update(self):
        with patch("sys.argv", ["rootless-pki.py", "update", "--directory", str(self.root), "--certificate-access"]), \
             patch.object(installer, "_update") as update:
            installer._main()
        update.assert_called_once_with(self.root, self.manifest, root_admin=False, certificate_access=True, status_access=False)

    def test_explicit_status_access_is_independent_and_runs_after_new_image_pins(self):
        def command(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            if "zeroecho-pki-status-access" in str(arguments):
                self.assertEqual({"server": "c" * 64, "web": "d" * 64}, json.loads((self.root / "installation.json").read_text())["images"])
                return b"STATUS_ACCESS_READY\n"
            return result
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=command), patch.object(installer, "_verify_edge"):
            installer._update(self.root, self.manifest, status_access=True, unit_directory=self.unit_directory)
        helper = next(i for i, value in enumerate(self.commands) if "zeroecho-pki-status-access" in str(value))
        stop = next(i for i, value in enumerate(self.commands) if "stop" in value)
        reload = next(i for i, value in enumerate(self.commands) if "daemon-reload" in value)
        start = next(i for i, value in enumerate(self.commands) if "start" in value)
        self.assertLess(stop, reload)
        self.assertLess(reload, helper)
        self.assertLess(helper, start)
        self.assertFalse(any("zeroecho-pki-root-admin" in str(value) for value in self.commands))
        self.assertIn("--network=none", self.commands[helper])
        self.assertEqual(["--config", "/deployment/config/server.json", "--admin-id", "bootstrap-admin", "--approver-id", "bootstrap-approver", "--proxy-id", "trusted-proxy"], self.commands[helper][-8:])
        for name, content in self.original.items():
            self.assertEqual(content, (self.root / name).read_bytes(), name)

    def test_status_failure_retains_exact_intent_and_resumes_without_rebuilding(self):
        def fail(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            if "zeroecho-pki-status-access" in str(arguments):
                raise RuntimeError("migration unconfirmed")
            return result
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=fail), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                installer._update(self.root, self.manifest, status_access=True, unit_directory=self.unit_directory)
        pending = json.loads((self.root / "updates/pending.json").read_text())
        self.assertEqual(3, pending["version"])
        self.assertTrue(pending["statusAccess"])
        self.assertEqual("new-images-pinned", pending["phase"])
        self.assertFalse(any("start" in value for value in self.commands))
        current = json.loads((self.root / "installation.json").read_text())
        self.commands.clear()
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(ValueError, "same explicit status-access intent"):
                installer._update(self.root, current, unit_directory=self.unit_directory)
            self.assertFalse(any("stop" in value for value in self.commands))
            installer._update(self.root, current, status_access=True, unit_directory=self.unit_directory)
            build.assert_not_called()
        self.assertFalse((self.root / "updates/pending.json").exists())
        self.assertEqual(1, sum("zeroecho-pki-status-access" in str(value) for value in self.commands))

    def test_status_access_and_root_administrator_intents_are_independent(self):
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            installer._update(self.root, self.manifest, root_admin=True, status_access=True, unit_directory=self.unit_directory)
        self.assertEqual(1, sum("zeroecho-pki-root-admin" in str(value) for value in self.commands))
        self.assertEqual(1, sum("zeroecho-pki-status-access" in str(value) for value in self.commands))

    def test_legacy_pending_update_can_resume_only_without_new_status_intent(self):
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge", side_effect=RuntimeError("not ready")):
            with self.assertRaisesRegex(RuntimeError, "not ready"):
                installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        path = self.root / "updates/pending.json"
        legacy = json.loads(path.read_text())
        legacy["version"] = 1
        legacy.pop("certificateAccess")
        legacy.pop("statusAccess")
        path.write_text(json.dumps(legacy))
        current = json.loads((self.root / "installation.json").read_text())
        self.commands.clear()
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(ValueError, "same explicit status-access intent"):
                installer._update(self.root, current, status_access=True, unit_directory=self.unit_directory)
            self.assertFalse(any("stop" in value for value in self.commands))
            installer._update(self.root, current, unit_directory=self.unit_directory)
            build.assert_not_called()
        self.assertFalse(any("zeroecho-pki-status-access" in str(value) for value in self.commands))

    def test_v2_certificate_journal_cannot_silently_gain_status_access(self):
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge", side_effect=RuntimeError("not ready")):
            with self.assertRaisesRegex(RuntimeError, "not ready"):
                installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        path = self.root / "updates/pending.json"
        legacy = json.loads(path.read_text())
        legacy["version"] = 2
        legacy.pop("statusAccess")
        path.write_text(json.dumps(legacy))
        current = json.loads((self.root / "installation.json").read_text())
        self.commands.clear()
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(ValueError, "same explicit status-access intent"):
                installer._update(self.root, current, status_access=True, unit_directory=self.unit_directory)
            self.assertFalse(any("stop" in value for value in self.commands))
            installer._update(self.root, current, unit_directory=self.unit_directory)
            build.assert_not_called()
        self.assertFalse(any("zeroecho-pki-status-access" in str(value) for value in self.commands))

    def test_status_migration_requires_exact_receipt_and_strict_journal_boolean(self):
        def invalid(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            return b"OTHER_RECEIPT" if "zeroecho-pki-status-access" in str(arguments) else result
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=invalid), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(RuntimeError, "migration is unconfirmed"):
                installer._update(self.root, self.manifest, status_access=True, unit_directory=self.unit_directory)
        path = self.root / "updates/pending.json"
        original = json.loads(path.read_text())
        current = json.loads((self.root / "installation.json").read_text())
        for change in ({"statusAccess": "true"}, {"unexpected": False}, {"version": 1}):
            path.write_text(json.dumps(dict(original, **change)))
            self.commands.clear()
            with patch.object(installer, "_preflight"), patch.object(installer, "_run", side_effect=self.command):
                with self.assertRaisesRegex(ValueError, "Invalid retained update journal"):
                    installer._update(self.root, current, status_access=True, unit_directory=self.unit_directory)
            self.assertFalse(any("stop" in value for value in self.commands))

    def test_status_flag_is_rejected_for_other_commands_before_reading_installation(self):
        for command in ("install", "start", "stop", "status", "_ready"):
            with patch("sys.argv", ["rootless-pki.py", command, "--status-access"]), patch("sys.stderr"):
                with self.assertRaises(SystemExit) as failure:
                    installer._main()
            self.assertEqual(2, failure.exception.code)

    def test_status_flag_is_forwarded_only_to_the_explicit_update(self):
        with patch("sys.argv", ["rootless-pki.py", "update", "--directory", str(self.root), "--status-access"]), \
             patch.object(installer, "_update") as update:
            installer._main()
        update.assert_called_once_with(self.root, self.manifest, root_admin=False, certificate_access=False, status_access=True)

    def test_update_pins_both_images_before_explicit_root_grant_and_preserves_state(self):
        with patch.object(installer, "_preflight"), \
             patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]) as build, \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            installer._update(self.root, self.manifest, root_admin=True, unit_directory=self.unit_directory)
        self.assertEqual(2, build.call_count)
        validation = next(i for i, command in enumerate(self.commands) if "--validate-config" in command)
        stop = next(i for i, command in enumerate(self.commands) if "stop" in command)
        grant = next(i for i, command in enumerate(self.commands) if "zeroecho-pki-root-admin" in str(command))
        start = next(i for i, command in enumerate(self.commands) if "start" in command)
        self.assertLess(validation, stop)
        self.assertLess(stop, grant)
        self.assertLess(grant, start)
        for name, content in self.original.items():
            self.assertEqual(content, (self.root / name).read_bytes(), name)
        self.assertFalse((self.root / "updates/pending.json").exists())
        self.assertTrue(list((self.root / "updates").glob("*/completed.json")))

    def test_plain_update_never_designates_a_root_administrator(self):
        with patch.object(installer, "_preflight"), \
             patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        self.assertFalse(any("zeroecho-pki-root-admin" in str(command) for command in self.commands))

    def test_root_tool_failure_retains_new_pins_and_exact_resumable_update(self):
        def fail(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            if "zeroecho-pki-root-admin" in str(arguments):
                raise RuntimeError("root designation unconfirmed")
            return result
        with patch.object(installer, "_preflight"), \
             patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=fail), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                installer._update(self.root, self.manifest, root_admin=True, unit_directory=self.unit_directory)
        self.assertTrue((self.root / "updates/pending.json").is_file())
        self.assertFalse(any("start" in command for command in self.commands))
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            installer._update(self.root, json.loads((self.root / "installation.json").read_text()), root_admin=True, unit_directory=self.unit_directory)
        build.assert_not_called()
        self.assertFalse((self.root / "updates/pending.json").exists())

    def test_invalid_config_is_rejected_before_stopping_services(self):
        def fail(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            if "--validate-config" in arguments:
                raise RuntimeError("configuration rejected")
            return result
        with patch.object(installer, "_preflight"), \
             patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "configuration rejected"):
                installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        self.assertFalse(any("stop" in command for command in self.commands))
        self.assertEqual(self.manifest, json.loads((self.root / "installation.json").read_text()))

    def prepare_failed_root_update(self):
        def fail(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            if "zeroecho-pki-root-admin" in str(arguments):
                raise RuntimeError("root designation unconfirmed")
            return result
        with patch.object(installer, "_preflight"), \
             patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=fail), patch.object(installer, "_verify_edge"):
            with self.assertRaises(RuntimeError):
                installer._update(self.root, self.manifest, root_admin=True, unit_directory=self.unit_directory)
        self.commands.clear()
        return self.root / "updates/pending.json"

    def test_journal_invalid_authority_flag_and_phase_refuse_before_stop(self):
        pending = self.prepare_failed_root_update()
        baseline = json.loads(pending.read_text())
        for field, value in (("rootAdmin", "false"), ("phase", "unexpected")):
            with self.subTest(field=field):
                journal = dict(baseline, **{field: value})
                pending.write_text(json.dumps(journal))
                with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
                     patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
                    with self.assertRaisesRegex(ValueError, "journal"):
                        installer._update(self.root, json.loads((self.root / "installation.json").read_text()),
                                          root_admin=True, unit_directory=self.unit_directory)
                build.assert_not_called()
                self.assertFalse(any("stop" in command for command in self.commands))
                self.commands.clear()

    def test_configuration_drift_during_build_refuses_before_stop(self):
        def build(name, dockerfile):
            (self.root / "config/server.json").write_bytes(b"external change")
            return "c" * 64 if "server" in name else "d" * 64
        with patch.object(installer, "_preflight"), patch.object(installer, "_image", side_effect=build), \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            with self.assertRaisesRegex(ValueError, "Configuration changed"):
                installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        self.assertFalse(any("stop" in command for command in self.commands))
        self.assertEqual(b"external change", (self.root / "config/server.json").read_bytes())
        self.assertFalse((self.root / "updates/pending.json").exists())

    def test_network_drift_refuses_before_build_or_stop(self):
        def wrong_network(arguments, **kwargs):
            if "network" in arguments:
                return b'[{"name":"foreign","internal":true,"subnets":[{"subnet":"10.90.0.0/24","gateway":"10.90.0.1"}]}]'
            return self.command(arguments, **kwargs)
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=wrong_network):
            with self.assertRaisesRegex(ValueError, "network"):
                installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        build.assert_not_called()
        self.assertFalse(any("stop" in command for command in self.commands))

    def test_snapshots_have_owner_only_directories_without_relying_on_umask(self):
        pending = self.prepare_failed_root_update()
        stage = self.root / "updates" / json.loads(pending.read_text())["id"]
        for directory in (stage, stage / "old", stage / "new", stage / "old/config", stage / "old/units", stage / "new/units"):
            self.assertEqual(0, directory.stat().st_mode & 0o077, str(directory))

    def test_retained_content_tamper_refuses_without_service_changes(self):
        pending = self.prepare_failed_root_update()
        stage = self.root / "updates" / json.loads(pending.read_text())["id"]
        (stage / "new/manage.py").write_text("modified outside updater")
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command):
            with self.assertRaisesRegex(ValueError, "content changed"):
                installer._update(self.root, json.loads((self.root / "installation.json").read_text()),
                                  root_admin=True, unit_directory=self.unit_directory)
        build.assert_not_called()
        self.assertFalse(any("stop" in command for command in self.commands))

    def test_partial_metadata_pin_resumes_without_rebuild_or_old_image_rollback(self):
        atomic = installer._atomic_bytes
        interrupted = False
        def fail_pin(path, content):
            nonlocal interrupted
            if path == self.root / "installation.json" and not interrupted:
                interrupted = True
                raise OSError("injected interruption")
            atomic(path, content)
        with patch.object(installer, "_preflight"), \
             patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=self.command), \
             patch.object(installer, "_atomic_bytes", side_effect=fail_pin):
            with self.assertRaisesRegex(RuntimeError, "injected interruption"):
                installer._update(self.root, self.manifest, root_admin=True, unit_directory=self.unit_directory)
        self.assertFalse(any("zeroecho-pki-root-admin" in str(command) for command in self.commands))
        self.assertEqual(self.manifest, json.loads((self.root / "installation.json").read_text()))
        self.commands.clear()
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command), patch.object(installer, "_verify_edge"):
            installer._update(self.root, self.manifest, root_admin=True, unit_directory=self.unit_directory)
        build.assert_not_called()
        self.assertEqual({"server": "c" * 64, "web": "d" * 64}, json.loads((self.root / "installation.json").read_text())["images"])

    def test_plain_update_cannot_resume_explicit_root_designation(self):
        self.prepare_failed_root_update()
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command):
            with self.assertRaisesRegex(ValueError, "root-administrator intent"):
                installer._update(self.root, json.loads((self.root / "installation.json").read_text()),
                                  unit_directory=self.unit_directory)
        build.assert_not_called()
        self.assertFalse(any("stop" in command for command in self.commands))

    def test_root_flag_cannot_expand_retained_plain_update(self):
        def stop_failure(arguments, **kwargs):
            result = self.command(arguments, **kwargs)
            if "stop" in arguments:
                raise RuntimeError("stop interrupted")
            return result
        with patch.object(installer, "_preflight"), \
             patch.object(installer, "_image", side_effect=["c" * 64, "d" * 64]), \
             patch.object(installer, "_run", side_effect=stop_failure):
            with self.assertRaisesRegex(RuntimeError, "stop interrupted"):
                installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        self.commands.clear()
        with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build, \
             patch.object(installer, "_run", side_effect=self.command):
            with self.assertRaisesRegex(ValueError, "retained plain update"):
                installer._update(self.root, self.manifest, root_admin=True, unit_directory=self.unit_directory)
        build.assert_not_called()
        self.assertFalse(any("stop" in command for command in self.commands))

    def test_missing_main_store_marker_refuses_before_building(self):
        (self.root / "store-container/store/VERSION").unlink()
        with patch.object(installer, "_image") as build:
            with self.assertRaises(OSError):
                installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
        build.assert_not_called()

    def test_concurrent_update_is_rejected_before_building(self):
        with (self.root / ".update.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(installer, "_preflight"), patch.object(installer, "_image") as build:
                with self.assertRaisesRegex(ValueError, "already running"):
                    installer._update(self.root, self.manifest, unit_directory=self.unit_directory)
            build.assert_not_called()


class HybridSdkCliTest(unittest.TestCase):
    def test_test_start_explicit_sdk_opt_in_is_forwarded_before_manifest_loading(self):
        with tempfile.TemporaryDirectory() as parent:
            root=Path(parent)/"fresh"
            with patch("sys.argv",["rootless-pki.sh","test-start","--hybrid-sdk","--directory",str(root)]), \
                 patch("exercise_environment.start") as start:
                installer._main()
            start.assert_called_once_with(root,hybrid_sdk=True)

    def test_install_sdk_opt_in_keeps_existing_install_route(self):
        with tempfile.TemporaryDirectory() as parent:
            root=Path(parent)/"fresh";values=_values(root)
            with patch("sys.argv",["rootless-pki.sh","install","--hybrid-sdk","--directory",str(root)]), \
                 patch.object(installer.curses,"wrapper",return_value=values),patch.object(installer,"_install") as install:
                installer._main()
            self.assertTrue(install.call_args.args[0]["hybrid_sdk"])
            self.assertEqual(root,Path(install.call_args.args[0]["directory"]))

    def test_sdk_flag_rejected_for_unrelated_lifecycle_before_any_action(self):
        for command in ("update","start","stop","status","_ready"):
            with self.subTest(command=command),patch("sys.argv",["rootless-pki.sh",command,"--hybrid-sdk"]), \
                 patch("sys.stderr"),patch.object(installer,"_preflight") as preflight:
                with self.assertRaises(SystemExit) as error:installer._main()
                self.assertEqual(2,error.exception.code);preflight.assert_not_called()


class TLSIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="pki-installer-test-")
        cls.root = Path(cls.temporary.name)
        for path in ("provisioning", "logins", "tls/server", "tls/health", "tls/edge", "tls/upstream", "tls/admin-trust", "config", "profiles"):
            (cls.root / path).mkdir(parents=True, exist_ok=True)
        cls.values = _values(cls.root)
        cls.password = "test-transport-password-12345"
        cls.fingerprints = installer._tls(cls.root, cls.values, cls.password)
        installer._configuration(cls.root, cls.values, cls.fingerprints)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_client_pkcs12_and_private_file_modes(self):
        for name, field in (("administrator", "admin_password"), ("approver", "approver_password")):
            installer._openssl(self.root, ["pkcs12", "-in", self.root / f"logins/{name}.p12", "-info", "-noout",
                                           "-passin", "env:ZEROECHO_OPENSSL_PASSWORD"], self.values[field])
            self.assertEqual(0, (self.root / f"logins/{name}.p12").stat().st_mode & 0o077)
        self.assertNotEqual(self.fingerprints["administrator"], self.fingerprints["approver"])

    def test_jsse_can_decode_generated_configuration_and_trust_store(self):
        libraries = installer.REPOSITORY / "pki-server/build/install/zeroecho-pki-server/lib"
        if not libraries.is_dir():
            self.skipTest("Build :pki-server:installDist before running Java configuration integration")
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "ConfigurationCheck.java"
            source.write_text('''import java.nio.file.*;
import java.security.*;
import zeroecho.pki.server.*;
class ConfigurationCheck {
 public static void main(String[] args) throws Exception {
  var separate = PkiServerConfigurationCodec.read(Path.of(args[0]));
  if(!separate.realm().approvalPolicies().values().stream().allMatch(p -> p.requesterSeparation())) throw new AssertionError("separate default");
  KeyStore trust = KeyStore.getInstance("PKCS12");
  try(var stream=Files.newInputStream(Path.of(args[1]))) { trust.load(stream,args[2].toCharArray()); }
  if(trust.size()!=1 || !trust.isCertificateEntry(trust.aliases().nextElement())) throw new AssertionError("JSSE trust");
 }
}
''')
            result = subprocess.run(["java", "--class-path", str(libraries / "*"), str(source),
                                     str(self.root / "config/server.json"), str(self.root / "tls/server/trust.p12"), self.password],
                                    capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_profile_bootstrap_configuration_has_explicit_collections(self):
        document = json.loads((self.root / "config/profile-bootstrap.json").read_text())
        self.assertEqual([], document["publishers"])
        self.assertEqual([], document["bindingProviders"])

    def test_existing_codec_rejects_small_sdk_public_body_and_accepts_exact_minimum(self):
        libraries=installer.REPOSITORY/"pki-server/build/install/zeroecho-pki-server/lib"
        self.assertTrue(libraries.is_dir(),"Existing server distribution is required for SDK configuration integration")
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            document=json.loads((self.root/"config/server.json").read_text())
            public=json.loads((installer.REPOSITORY/"documentation/examples/configuration/pki-server-loopback-example.json").read_text())["publicListener"]
            public["tlsProvider"]=document["listener"]["tlsProvider"]
            document["publicListener"]=public
            path=root/"configuration.json"
            source=root/"SdkBudgetCodecCheck.java"
            source.write_text('''import java.nio.file.Path;
import zeroecho.pki.server.PkiServerConfigurationCodec;
class SdkBudgetCodecCheck {
 public static void main(String[] args) throws Exception {
  PkiServerConfigurationCodec.read(Path.of(args[0]));
 }
}
''')
            def validate():
                path.write_text(json.dumps(document))
                return subprocess.run(["java","--class-path",str(libraries/"*"),
                    str(source),str(path)],capture_output=True,text=True)
            public["maximumBodyBytes"]=1024
            baseline=validate();self.assertEqual(0,baseline.returncode,baseline.stderr)
            public["hybridSdk"]={"canonicalOrigin":"https://localhost:19444"}
            too_small=validate();self.assertNotEqual(0,too_small.returncode)
            self.assertIn("SDK_BODY_BUDGET_TOO_SMALL",too_small.stderr)
            public["maximumBodyBytes"]=16384
            accepted=validate();self.assertEqual(0,accepted.returncode,accepted.stderr)

    def test_regular_install_sdk_configuration_is_admin_only_and_preserves_public_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            baseline=root/"baseline";opted_in=root/"sdk"
            for directory in (baseline,opted_in):
                (directory/"config").mkdir(parents=True);(directory/"profiles").mkdir()
            values=dict(self.values,hybrid_sdk=False)
            installer._configuration(baseline,values,self.fingerprints)
            baseline_public=json.loads((baseline/"config/server.json").read_text())["publicListener"]
            values["hybrid_sdk"]=True
            installer._configuration(opted_in,values,self.fingerprints)
            document=json.loads((opted_in/"config/server.json").read_text())
            self.assertEqual({"canonicalOrigin":"https://pki.example.test:8443"},document["listener"]["hybridSdk"])
            self.assertNotIn("hybridSdk",document["publicListener"])
            self.assertEqual(baseline_public,document["publicListener"])

    def test_tls_rejects_wrong_export_password(self):
        with self.assertRaises(RuntimeError):
            installer._openssl(self.root, ["pkcs12", "-in", self.root / "logins/administrator.p12", "-noout",
                                           "-passin", "env:ZEROECHO_OPENSSL_PASSWORD"], "wrong-password")


@unittest.skipUnless(os.environ.get("ZEROECHO_RUN_INSTALLER_INTEGRATION") == "1",
                     "Opt-in: builds images and creates private user services with real Podman")
class RootlessDeploymentIntegrationTest(unittest.TestCase):
    def test_install_restart_authentication_and_stop_preserve_state(self):
        installer._preflight()
        with tempfile.TemporaryDirectory(prefix="zeroecho-install-gate-") as temporary:
            root = Path(temporary) / "installation"
            values = _values(root)
            values["hostname"] = "localhost"
            with socket.socket() as port:
                port.bind(("127.0.0.1", 0))
                values["port"] = str(port.getsockname()[1])
            prefix = "zeroecho-" + installer.hashlib.sha256(str(root).encode()).hexdigest()[:12]
            names = [prefix + "-web.service", prefix + "-server.service"]
            try:
                installer._install(values)
                manifest = json.loads((root / "installation.json").read_text())
                keyring = (root / "keyring/ca-keyring.zek").read_bytes()
                configuration = (root / "config/server.json").read_bytes()
                administrator = (root / "logins/administrator.p12").read_bytes()
                installer._update(root, manifest, root_admin=True)
                manifest = json.loads((root / "installation.json").read_text())
                self.assertEqual(configuration, (root / "config/server.json").read_bytes())
                self.assertEqual(administrator, (root / "logins/administrator.p12").read_bytes())
                # Recreating backend must preserve keys and nginx connectivity at the stable IP.
                installer._run(["systemctl", "--user", "restart", names[1]])
                installer._run(["systemctl", "--user", "is-active", names[0]])
                installer._verify_edge(root, manifest)
                self.assertEqual(keyring, (root / "keyring/ca-keyring.zek").read_bytes())
                result = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--max-time", "5",
                                         "--noproxy", "*", "--cacert", str(root / "logins/web-ca.pem"),
                                         f"https://localhost:{values['port']}/admin/v1/realm"], capture_output=True)
                self.assertNotEqual(0, result.returncode, "Anonymous administrative access must fail")
                with self.assertRaises(ValueError):
                    installer._install(values)
                installer._run(["systemctl", "--user", "stop", *names])
                self.assertTrue((root / "store-container/server-control/server-control.log").is_file())
                installer._run(["systemctl", "--user", "start", *names])
                installer._verify_edge(root, manifest)
            finally:
                # Names are derived from the exclusively owned temporary path; never prune globally.
                subprocess.run(["systemctl", "--user", "disable", "--now", *names], capture_output=True)
                for name in names:
                    link = Path.home() / ".config/systemd/user" / name
                    if link.is_symlink() and link.resolve().parent == root / "units":
                        link.unlink()
                subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
                subprocess.run([*installer.PODMAN, "network", "rm", prefix], capture_output=True)


if __name__ == "__main__":
    unittest.main()
