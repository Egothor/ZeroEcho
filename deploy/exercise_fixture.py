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

"""Disposable rootless Podman qualification fixture; never creates host user services.

Only newly generated TLS identities, protected signing keys and realm state are used.
The separately published public TLS endpoint is deliberately tested without client auth.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid

import rootless_pki as installer
from exercise_pki import Api, ExerciseFailure, _atomic_json, _openssl, _private_file

LABEL = "io.zeroecho.exercise"


def _phase(arguments):
    values=list(map(str,arguments))
    if not values or values[0]!="run":
        return "podman-"+values[0] if values and values[0] in {"info","image","network","inspect","stop","start","restart","rm","port","logs","container"} else "podman-action"
    if values[-2:] == ["nginx", "-t"]:
        return "validate-web"
    if "--entrypoint" in values:
        position=values.index("--entrypoint")+1
        entry=values[position] if position<len(values) else ""
        phases={"/opt/zeroecho/app/bin/app":"generate-signing-key",
            "/opt/zeroecho/server/bin/zeroecho-pki-admin-bootstrap":"bootstrap-administrators",
            "/opt/zeroecho/server/bin/zeroecho-pki-certificate-access":"certificate-access",
            "/opt/zeroecho/server/bin/zeroecho-pki-status-access":"status-access",
            "/opt/zeroecho/app/bin/zeroecho-pki-profile-bootstrap":"load-profiles"}
        if entry=="/opt/zeroecho/server/bin/zeroecho-pki-server":return "validate-config" if "--validate-config" in values else "server-command"
        if entry in phases:return phases[entry]
        for helper,phase in {"ExerciseCatalogStateSeed":"seed-publication","ExerciseProtocolSeed":"protocol-helper","ExerciseProtocolDns":"start-dns","ExerciseLegacyEnrollmentClient":"protocol-client"}.items():
            if "zeroecho.pki.server."+helper in values:return phase
    if "--name" in values:
        position=values.index("--name")+1
        name=values[position] if position<len(values) else ""
        for role in ("server","web","dns"):
            if re.fullmatch(r"zeroecho-exercise-[0-9a-f]{32}-"+role,name):return "start-"+role
    return "run-container"


def _diagnostic(stderr, redactions):
    text=stderr.decode("utf-8",errors="replace") if isinstance(stderr,bytes) else str(stderr or "")
    text=re.sub(r"-----BEGIN [^\r\n-]{1,80}-----.*?(?:-----END [^\r\n-]{1,80}-----|\Z)","[PEM redacted]",text,flags=re.S)
    text=re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]","",text)
    text="".join(character for character in text if character.isprintable() or character in "\n\t")
    for value in sorted((value for value in redactions if value),key=len,reverse=True):text=text.replace(value,"[secret redacted]")
    return " ".join(text.split())[:1600] or "no stderr"


def _command(arguments, *, check=True, redactions=(), input_data=None):
    completed = subprocess.run(["podman", "--remote=false", *map(str, arguments)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, input=input_data, check=False, timeout=600)
    if check and completed.returncode:
        raise ExerciseFailure("Disposable Podman phase "+_phase(arguments)+" failed (exit "+str(completed.returncode)+"): "+_diagnostic(completed.stderr,redactions))
    return completed


def _tls(root, tls_password, login_password):
    provisioning = root / "provisioning"
    ca_key, ca = provisioning / "ca.key", provisioning / "ca.crt"
    _openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=ZeroEcho disposable qualification transport", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", ca_key, "-out", ca])
    pairs = {}
    for index, name in enumerate(("server", "proxy", "health", "administrator", "approver", "edge"), 1):
        key, csr, cert, extension = (provisioning / (name + suffix) for suffix in (".key", ".csr", ".crt", ".ext"))
        server = name in ("server", "edge")
        extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + ("serverAuth" if server else "clientAuth") + ("\nsubjectAltName=DNS:pki-server,DNS:localhost,IP:127.0.0.1" if server else "") + "\n")
        _openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name, "-keyout", key, "-out", csr])
        _openssl(["x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-set_serial", str(int.from_bytes(os.urandom(16), "big") or index), "-days", "2", "-sha256", "-extfile", extension, "-out", cert])
        pairs[name] = key, cert
    for name, target, password in (("server", root / "tls/server/server-identity.p12", tls_password),
                                    ("administrator", root / "logins/administrator.p12", login_password),
                                    ("approver", root / "logins/approver.p12", secrets.token_urlsafe(36))):
        key, cert = pairs[name]
        _openssl(["pkcs12", "-export", "-inkey", key, "-in", cert, "-certfile", ca, "-out", target, "-passout", "stdin"], secret=password)
        target.chmod(0o600)
    _openssl(["pkcs12", "-export", "-nokeys", "-in", ca, "-jdktrust", "anyExtendedKeyUsage", "-out", root / "tls/server/trust.p12", "-passout", "stdin"], secret=tls_password)
    copies = {"tls/health/health-client.pem": pairs["health"][1], "tls/health/health-client-key.pem": pairs["health"][0],
              "tls/health/health-ca.pem": ca, "tls/upstream/proxy-client.crt": pairs["proxy"][1],
              "tls/upstream/proxy-client.key": pairs["proxy"][0], "tls/upstream/pki-server-ca.pem": ca,
              "tls/admin-trust/admin-ca-bundle.pem": ca, "logins/web-ca.pem": ca,
              "tls/edge/edge.crt": pairs["edge"][1], "tls/edge/edge.key": pairs["edge"][0]}
    for target, source in copies.items():
        shutil.copyfile(source, root / target)
        (root / target).chmod(0o600)
    return {name: hashlib.sha256(_openssl(["x509", "-in", cert, "-outform", "DER"])).hexdigest() for name, (_, cert) in pairs.items()}


class DisposableFixture:
    """An owned fresh realm, private network and two disposable containers with explicit cleanup."""

    def __init__(self, images, *, prepare=None, directory=None, login_password=None):
        """Prepare an ownership identity without contacting Podman.

        Args:
            images: Exact server and web immutable SHA-256 image identities.
            prepare: Optional hook receiving fresh root and configuration; returns environment additions.
            directory: Optional new exact deployment directory, never an existing deployment.
            login_password: Optional independent client P12 password, never a server signing secret.
        Returns:
            None; resources are created only on context entry.
        Raises:
            ExerciseFailure: Images are missing, mutable or malformed.
        """
        if set(images) != {"server", "web"} or any(not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value) for value in images.values()):
            raise ExerciseFailure("Isolated qualification requires immutable server and web image IDs")
        self.images, self.prepare = images, prepare
        self.requested_directory = Path(directory) if directory is not None else None
        self.requested_login_password = login_password
        self._diagnostic_secrets=()
        self.nonce = uuid.uuid4().hex
        self.prefix = "zeroecho-exercise-" + self.nonce
        self.server, self.web = self.prefix + "-server", self.prefix + "-web"
        self.ids = {}
        self.network_created = False
        self.directory = None
        self.run_id = None
        self.configuration = None
        self.environment = {}
        self.intended_names = [self.server,self.web]

    def _run(self, arguments, *, check=True, input_data=None):
        if input_data is None:
            return _command(arguments,check=check,redactions=self._diagnostic_secrets)
        return _command(arguments,check=check,redactions=self._diagnostic_secrets,input_data=input_data)

    def __enter__(self):
        """Create and start only fresh owned resources; any failure cleans up those same resources."""
        if os.geteuid() == 0 or self._run(["info", "--format", "{{.Host.Security.Rootless}}"] ).stdout.strip() != b"true":
            raise ExerciseFailure("Run isolated qualification with a local rootless Podman engine")
        for image in self.images.values():
            self._run(["image", "exists", image])
        if self.requested_directory is None:
            self.directory = Path(tempfile.mkdtemp(prefix="zeroecho-isolated-pki-"))
        else:
            self.requested_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
            self.directory = self.requested_directory
        self.directory.chmod(0o700)
        _atomic_json(self.directory / ".exercise-owner.json", {"nonce": self.nonce})
        try:
            self._prepare()
            self._start()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _prepare(self):
        root = self.directory
        for directory in ("provisioning", "logins", "config", "profiles", "tls/server", "tls/health", "tls/edge", "tls/upstream", "tls/admin-trust", "store-container", "keyring", "audit", "artifacts", "backup-spool"):
            (root / directory).mkdir(parents=True, mode=0o700, exist_ok=True)
        tls_password = secrets.token_urlsafe(48)
        self.login_password = self.requested_login_password or secrets.token_urlsafe(48)
        keyring_password = secrets.token_urlsafe(48)
        self._keyring_password = keyring_password
        self._diagnostic_secrets=(tls_password,keyring_password,self.login_password)
        fingerprints = _tls(root, tls_password, self.login_password)
        (root / "secrets.conf").write_text("ZEROECHO_TLS_PASSWORD=" + tls_password + "\nZEROECHO_KEYRING_PASSWORD=" + keyring_password + "\n")
        (root / "secrets.conf").chmod(0o600)
        values = {"realm": self.prefix, "admin": "exercise-admin", "approver": "exercise-approver", "key_password": keyring_password}
        installer._configuration(root, values, fingerprints)
        for profile in (installer.REPOSITORY/"pki/src/main/resources/zeroecho/pki/profiles/v1").glob("*.json"):
            if profile.name != "catalog.json":
                shutil.copyfile(profile,root/"profiles"/profile.name)
                (root/"profiles"/profile.name).chmod(0o600)
        self.configuration = json.loads((root / "config/server.json").read_text())
        public = json.loads((installer.REPOSITORY / "documentation/examples/configuration/pki-server-loopback-example.json").read_text())["publicListener"]
        public.update(address="0.0.0.0", port=8444)
        public["tlsProvider"] = self.configuration["listener"]["tlsProvider"]
        public["authentication"] = {"mode": "DIRECT_MTLS", "directClientMappings": [{"mappingId": "fixture-admin", "principalId": "exercise-admin", "certificateSha256": fingerprints["administrator"]}]}
        self.configuration["publicListener"] = public
        _atomic_json(root / "config/backup-transfer.json", {"version": 1, "directory": "/deployment/backup-spool", "maximumArchiveBytes": 16777216,
            "maximumRetainedBytes": 33554432, "maximumArtifacts": 4, "maximumConcurrentJobs": 1, "maximumWorkspaceBytes": 8606711808,
            "lifetimeSeconds": 3600, "transferTimeoutSeconds": 30, "browserOrigin": "https://localhost"})
        self.environment = {"ZEROECHO_PROFILE_RECONCILE": "off", "ZEROECHO_BACKUP_TRANSFER_CONFIG": "/deployment/config/backup-transfer.json"}
        if self.prepare:
            extra = self.prepare(root, self.configuration)
            if extra:
                self.environment.update(extra)
        _atomic_json(root / "config/server.json", self.configuration)
        options = ["run", "--pull=never", "--rm", "--network=none", *installer._server_options(root)]
        # This direct entrypoint bypasses the image shell's environment-to-CLI companion conversion.
        companions = []
        for key, flag in (("ZEROECHO_ENROLLMENT_CONFIG", "--enrollment-config"),
                          ("ZEROECHO_BACKUP_TRANSFER_CONFIG", "--backup-transfer-config")):
            if key in self.environment:
                companions += [flag, self.environment[key]]
        self._run([*options, "--volume", f"{root / 'backup-spool'}:/deployment/backup-spool:rw,z",
            "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-server", self.images["server"],
            "--validate-config", "--config", "/deployment/config/server.json", *companions])
        for alias in ("root", "intermediate", "rotation", "grandchild"):
            self._run([*options, "--entrypoint", "/opt/zeroecho/app/bin/app", self.images["server"], "-K", "--generate", "--alg", "RSA", "--alias", alias,
                      "--keystore", "/deployment/keyring/ca-keyring.zek", "--keystore-password-env", "ZEROECHO_KEYRING_PASSWORD"])
        self._run([*options, "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-admin-bootstrap", self.images["server"], "--config", "/deployment/config/server.json",
                  "--admin-id", "exercise-admin", "--approver-id", "exercise-approver", "--proxy-id", "trusted-proxy"])

        for helper, receipt in (("certificate-access", b"CERTIFICATE_ACCESS_READY"), ("status-access", b"STATUS_ACCESS_READY")):
            confirmed = self._run([*options, "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-" + helper, self.images["server"],
                "--config", "/deployment/config/server.json", "--admin-id", "exercise-admin", "--approver-id", "exercise-approver", "--proxy-id", "trusted-proxy"]).stdout.strip()
            if confirmed != receipt:
                raise ExerciseFailure("Fresh disposable content-access provisioning was not confirmed")

    def _start(self):
        root = self.directory
        self.network_created = True
        self._run(["network", "create", "--internal", "--label", LABEL + "=" + self.nonce, self.prefix])
        network = json.loads(self._run(["network", "inspect", self.prefix]).stdout)
        addresses = installer._network_addresses(network)
        options = ["run", "--detach", "--pull=never", "--name", self.server, "--label", LABEL + "=" + self.nonce, "--network", self.prefix,
                   "--ip", addresses[0], "--network-alias", "pki-server", "--publish", "127.0.0.1::8444", *installer._server_options(root),
                   "--volume", f"{root / 'backup-spool'}:/deployment/backup-spool:rw,z"]
        for port in (8445, 8446, 8447, 8448):
            options += ["--publish", f"127.0.0.1::{port}"]
        for key, value in self.environment.items():
            options += ["--env", key + "=" + value]
        self.ids[self.server] = self._run([*options, self.images["server"]]).stdout.decode().strip()
        web_options = ["--pull=never", "--label", LABEL + "=" + self.nonce, "--network", self.prefix,
                       "--image-volume=ignore", "--env", "NGINX_SERVER_NAME=localhost",
                       "--env", "PKI_UPSTREAM=pki-server:8443", "--env", "PKI_PROXY_SSL_NAME=pki-server"]
        for name in ("edge", "upstream", "admin-trust"):
            web_options += ["--volume", f"{root / 'tls' / name}:/etc/nginx/tls/{name}:ro,z"]
        # Keep the image entrypoint: it renders the same templates before checking or starting nginx.
        validator = self.prefix + "-webcheck"
        self.intended_names.append(validator)
        self._run(["run", "--rm", "--name", validator, *web_options, self.images["web"], "nginx", "-t"])
        self.ids[self.web] = self._run(["run", "--detach", "--name", self.web, "--ip", addresses[1],
            "--publish", "127.0.0.1::8443", *web_options, self.images["web"]]).stdout.decode().strip()
        self.admin_url = self._binding(self.web, "8443/tcp")
        self.public_url = self._binding(self.server, "8444/tcp")
        self.protocol_urls = {name: self._binding(self.server, str(port) + "/tcp") for name, port in (("acme",8445),("est",8446),("scep",8447),("cmp",8448))}
        self.api = Api(self.admin_url, root / "logins/web-ca.pem", root / "provisioning/administrator.crt", root / "provisioning/administrator.key")
        self.public_api = Api(self.public_url, root / "logins/web-ca.pem")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                self.api.json("GET", "/admin/v1/realm")
                return
            except ExerciseFailure:
                time.sleep(0.5)
        raise ExerciseFailure("Disposable administrator endpoint did not become ready")

    def _binding(self, name, port):
        result = self._run(["port", name, port], check=False)
        value = result.stdout.decode("utf-8", errors="replace").strip()
        if result.returncode or not re.fullmatch(r"127\.0\.0\.1:[0-9]+", value):
            metadata = _diagnostic(value, self._diagnostic_secrets) if value else "empty"
            raise ExerciseFailure("Expected one IPv4-loopback published port; port metadata=" + metadata
                + "; query exit=" + str(result.returncode) + "; " + self._owned_container_diagnostic(name))
        return "https://" + value

    def _owned_container_diagnostic(self, name):
        """Return bounded redacted state and logs only after immutable ownership is confirmed."""
        if name not in self.ids:
            return "unknown container; logs withheld"
        try:
            inspected = self._run(["inspect", name], check=False)
            if inspected.returncode:
                return "container state unavailable; logs withheld"
            document = json.loads(inspected.stdout)[0]
            expected = self.images["web" if name == self.web else "server"].removeprefix("sha256:")
            if document.get("Id") != self.ids[name] or str(document.get("Image", "")).removeprefix("sha256:") != expected or ((document.get("Config") or {}).get("Labels") or {}).get(LABEL) != self.nonce:
                return "container ownership changed; logs withheld"
            state = document.get("State") or {}
            status = state.get("Status", "unknown")
            status = status if isinstance(status,str) and re.fullmatch(r"[a-z-]{1,32}",status) else "unknown"
            code = state.get("ExitCode")
            code = str(code) if type(code) is int and -255 <= code <= 255 else "unknown"
            logs = self._run(["logs", "--tail", "20", name], check=False)
            raw = logs.stdout + logs.stderr
            # A tail may start inside a PEM block; never print that orphaned body.
            diagnostic = "[PEM log omitted]" if b"-----END " in raw and b"-----BEGIN " not in raw else _diagnostic(raw, self._diagnostic_secrets)
            return "container state=" + status + " exit=" + code + "; logs=" + diagnostic
        except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError, ExerciseFailure):
            return "container diagnostic unavailable; logs withheld"

    def bind(self, run_id):
        """Bind the fresh instance to one exercise run; later recipe calls must prove the same identity.
        
        Args:
            run_id: Stable exercise checkpoint identity.
        
        Returns:
            None after the fixture is bound to that run.
        
        Raises:
            ExerciseFailure: The fixture was already bound to a different run.
        """
        if self.run_id is not None and self.run_id != run_id:
            raise ExerciseFailure("Disposable instance is already bound to another exercise")
        self.run_id = run_id

    def assert_disposable(self, origin, run_id):
        """Recheck immutable container IDs, ownership labels, loopback origin and run identity before dangerous recipes.
        
        Args:
            origin: Exact active administrator origin.
            run_id: Bound exercise identity.
        
        Returns:
            None after actual container IDs, image pins, labels and running states agree.
        
        Raises:
            ExerciseFailure: Origin, run, ownership, immutable image or running identity differs.
        """
        if origin != self.admin_url or run_id != self.run_id or self.run_id is None:
            raise ExerciseFailure("Dangerous recipes require the exact active disposable fixture")
        for name, identity in self.ids.items():
            document = json.loads(self._run(["inspect", name]).stdout)[0]
            expected_image = self.images["web" if name == self.web else "server"].removeprefix("sha256:")
            actual_image = str(document.get("Image", "")).removeprefix("sha256:")
            if document.get("Id") != identity or actual_image != expected_image or (document.get("Config", {}).get("Labels") or {}).get(LABEL) != self.nonce or document.get("State", {}).get("Running") is not True:
                raise ExerciseFailure("Disposable container ownership or running identity changed")

    def load_profiles(self):
        """Load fixture profiles after bounded legacy backup qualification, with exclusive store access.

        Returns:
            None after the owned backend is restarted and ready.
        Raises:
            ExerciseFailure: Ownership, stopped state or profile bootstrap receipt is invalid.
        """
        self.assert_disposable(self.admin_url,self.run_id)
        dns_active=self._retire_protocol_dns()
        self._run(["stop","--time","40",self.server])
        stopped=json.loads(self._run(["inspect",self.server]).stdout)[0]
        if stopped.get("Id")!=self.ids[self.server] or stopped.get("Image", "").removeprefix("sha256:")!=self.images["server"].removeprefix("sha256:") or (stopped.get("Config",{}).get("Labels") or {}).get(LABEL)!=self.nonce or stopped.get("State",{}).get("Running") is not False:
            raise ExerciseFailure("Profile staging requires the confirmed stopped owned backend")
        try:
            result=self._run(["run","--pull=never","--rm","--network=none",*installer._server_options(self.directory),
                "--entrypoint","/opt/zeroecho/app/bin/zeroecho-pki-profile-bootstrap",self.images["server"],
                "--config","/deployment/config/profile-bootstrap.json","--profiles-dir","/deployment/profiles","--store-dir","/deployment/store-container/store"])
            if not re.search(rb"Profile bootstrap completed: registered=[0-9]+ skipped=[0-9]+",result.stdout+result.stderr):
                raise ExerciseFailure("Owned profile staging did not return its completion receipt")
        finally:
            self._run(["start",self.server]);self._wait_ready()
            if dns_active:self.start_protocol_dns()
        self.assert_disposable(self.admin_url,self.run_id)

    def restart(self):
        """Restart only the verified disposable backend and retain the same published endpoint identities.
        
        Returns:
            None after the same owned backend is ready again.
        
        Raises:
            ExerciseFailure: Ownership changed, restart failed or readiness expired.
        """
        self.assert_disposable(self.admin_url, self.run_id)
        dns_active = self._retire_protocol_dns()
        self._run(["restart", self.server])
        self._wait_ready()
        if dns_active:
            self.start_protocol_dns()
        self.assert_disposable(self.admin_url, self.run_id)

    def _wait_ready(self):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                self.api.json("GET", "/admin/v1/realm")
                return
            except ExerciseFailure:
                time.sleep(0.5)
        raise ExerciseFailure("Disposable backend did not recover after restart")

    def seed_publication(self, publication_id, content_sha256, state):
        """Seed one owned pending publication through the exact test-only failure-state helper.
        
        Args:
            publication_id: Existing pending publication owned by this run.
            content_sha256: Expected source artifact SHA-256.
            state: Reviewed retryable-failure or uncertain-outcome fixture state.
        
        Returns:
            Evidence explicitly identifying a fixture-seeded state, not an observed crash.
        
        Raises:
            ExerciseFailure: Scope, helper authorization, ownership or restart validation fails.
        """
        if not isinstance(publication_id, str) or not publication_id.startswith("exercise-" + str(self.run_id) + "-") or not re.fullmatch(r"[0-9a-f]{64}", content_sha256) or state not in ("RETRYABLE_FAILURE", "OUTCOME_UNKNOWN"):
            raise ExerciseFailure("Publication fixture seed is outside this disposable run")
        self.offline_seed("ExerciseCatalogStateSeed", [publication_id, content_sha256, state],
            authorization={"publicationId": publication_id, "sourceSha256": content_sha256, "state": state})
        return {"fixtureSeededCrashState": True, "publicationId": publication_id, "state": state}

    def offline_seed(self, helper_class, arguments, *, authorization, client_password=None):
        """Stop the nonce-owned backend, authorize one reviewed fixture helper, then restart and recheck ownership.
        
        The helper is restricted to the two test-only classes, receives no secret arguments,
        and consumes its one-use authorization only after the backend stop was inspected.
        
        Args:
            helper_class: One of the two reviewed test-only helper class names.
            arguments: Non-secret helper arguments.
            authorization: Exact helper-specific one-use ownership assertions.
            client_password: Optional separate client-ring password sent only through helper stdin.
        
        Returns:
            None after the helper receipt and recovered owned backend are verified.
        
        Raises:
            ExerciseFailure: Helper, ownership, authorization, receipt or readiness validation fails.
            OSError: Private helper authorization cannot be retained.
        """
        self.assert_disposable(self.admin_url, self.run_id)
        contracts = {"ExerciseCatalogStateSeed": (".exercise-seed-authorization.json", "PUBLICATION_STATE_READY", {"publicationId", "sourceSha256", "state"}),
                     "ExerciseProtocolSeed": (".exercise-protocol-authorization.json", "PROTOCOL_FIXTURE_READY", {"authorityId", "credentialId"})}
        if helper_class not in contracts:
            raise ExerciseFailure("Unknown disposable fixture helper")
        marker, receipt, keys = contracts[helper_class]
        if not isinstance(authorization, dict) or set(authorization) != keys or any(not isinstance(value, str) or len(value) > 4096 or any(character in value for character in "\r\n\0") for value in [*arguments, *authorization.values()]):
            raise ExerciseFailure("Invalid disposable helper authorization")
        if client_password is not None and (helper_class != "ExerciseProtocolSeed" or not client_password or any(c in client_password for c in "\r\n\0")):
            raise ExerciseFailure("Invalid independent client unlock input")
        classes = self._helper_classes(helper_class)
        dns_active = self._retire_protocol_dns()
        self._run(["stop", "--time", "40", self.server])
        stopped = json.loads(self._run(["inspect", self.server]).stdout)[0]
        if stopped.get("Id") != self.ids[self.server] or (stopped.get("Config", {}).get("Labels") or {}).get(LABEL) != self.nonce or stopped.get("State", {}).get("Running") is not False:
            raise ExerciseFailure("Disposable backend stop was not confirmed; no seed tool was invoked")
        ticket = dict(authorization, nonce=self.nonce, runId=self.run_id, backendStopped=True,
                      serverId=self.ids[self.server], ticket=uuid.uuid4().hex)
        _atomic_json(self.directory / marker, ticket)
        try:
            result = self._run(["run", *(["--interactive"] if client_password is not None else []), "--pull=never", "--rm", "--network=none", *installer._server_options(self.directory),
                "--volume", str(classes) + ":/qualification/classes:ro,z", "--volume", str(self.directory) + ":/qualification/root:rw,z",
                "--entrypoint", "java", self.images["server"], "-cp", "/qualification/classes:/opt/zeroecho/server/lib/*",
                "zeroecho.pki.server." + helper_class, *(["--client-password-stdin"] if client_password is not None else []), "/qualification/root", self.nonce, self.run_id, *arguments],
                input_data=(client_password+"\n").encode() if client_password is not None else None)
            if result.stdout.decode().strip() != receipt:
                raise ExerciseFailure("Disposable fixture helper did not return its exact receipt")
        finally:
            self._run(["start", self.server])
            self._wait_ready()
            if dns_active:
                self.start_protocol_dns()
        self.assert_disposable(self.admin_url, self.run_id)
        return {"state": "FIXTURE_SEEDED", "helper": helper_class, "simulatedCrashState": authorization.get("state")}

    def _helper_classes(self, helper_class):
        classes = installer.REPOSITORY / "pki-server/build/classes/java/test"
        helper = classes / ("zeroecho/pki/server/" + helper_class + ".class")
        source = installer.REPOSITORY / ("pki-server/src/test/java/zeroecho/pki/server/" + helper_class + ".java")
        libraries = installer.REPOSITORY / "pki-server/build/install/zeroecho-pki-server/lib"
        if not helper.is_file() or not libraries.is_dir() or source.stat().st_mtime_ns > helper.stat().st_mtime_ns:
            with (self.directory / "qualification-build.log").open("wb") as log:
                result = subprocess.run([str(installer.REPOSITORY / "gradlew"), ":pki-server:installDist", ":pki-server:testClasses", "--console=plain"], stdout=log, stderr=subprocess.STDOUT, check=False, timeout=600)
            if result.returncode or not helper.is_file():
                raise ExerciseFailure("Test-only fixture helper did not compile; inspect private qualification-build.log")
        return classes

    def legacy_wire(self, protocol, phase):
        """Prepare or verify one real SCEP/CMP client message using stdin-only fresh unlock material.

        Args:
            protocol: SCEP or CMP in lowercase.
            phase: Initial, poll, verify or confirm client phase.
        Returns:
            Actual cryptographic client-helper readiness evidence.
        Raises:
            ExerciseFailure: Owned scope, helper execution or its exact receipt is invalid.
        """
        self.assert_disposable(self.admin_url,self.run_id)
        if protocol not in ("scep","cmp") or phase not in ("initial","poll","verify","confirm"):
            raise ExerciseFailure("Invalid legacy protocol client phase")
        classes=self._helper_classes("ExerciseLegacyEnrollmentClient")
        arguments=["podman","--remote=false","run","--pull=never","--rm","--network=none",
            "--userns=keep-id:uid=10001,gid=10001","--image-volume=ignore",
            "--volume",str(classes)+":/qualification/classes:ro,z","--volume",str(self.directory)+":/qualification/root:rw,z",
            "--entrypoint","java",self.images["server"],"-cp","/qualification/classes:/opt/zeroecho/server/lib/*",
            "zeroecho.pki.server.ExerciseLegacyEnrollmentClient","/qualification/root",self.nonce,self.run_id,protocol,phase]
        result=subprocess.run(arguments,input=(self._keyring_password+"\n").encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=120)
        if result.returncode or result.stdout.strip()!=b"LEGACY_CLIENT_READY":
            raise ExerciseFailure("Legacy protocol client cryptographic phase did not verify")
        self.assert_disposable(self.admin_url,self.run_id)
        return {"state":"VERIFIED","protocol":protocol,"phase":phase}

    def cmp_wire(self, label):
        """Run the real protected CMP client inside the owned network namespace without exporting its private key.
        
        Args:
            label: CMP endpoint label owned by the bound exercise run.
        
        Returns:
            Evidence of an actual cryptographically verified protected CMP exchange.
        
        Raises:
            ExerciseFailure: Endpoint ownership, client helper receipt or container identity is invalid.
        """
        self.assert_disposable(self.admin_url,self.run_id)
        if not isinstance(label,str) or not label.startswith("exercise-"+str(self.run_id)+"-") or any(character in label for character in "\r\n\0"):
            raise ExerciseFailure("CMP endpoint label is outside this disposable run")
        classes=self._helper_classes("ExerciseProtocolSeed")
        result=self._run(["run","--pull=never","--rm","--network=container:"+self.server,*installer._server_options(self.directory),
            "--volume",str(classes)+":/qualification/classes:ro,z","--volume",str(self.directory)+":/qualification/root:rw,z",
            "--entrypoint","java",self.images["server"],"-cp","/qualification/classes:/opt/zeroecho/server/lib/*",
            "zeroecho.pki.server.ExerciseProtocolSeed","--cmp-wire","/qualification/root",self.nonce,self.run_id,"https://localhost:8448",label])
        if result.stdout.strip()!=b"CMP_GENERAL_MESSAGE_VERIFIED":
            raise ExerciseFailure("Protected CMP exchange was not cryptographically verified")
        self.assert_disposable(self.admin_url,self.run_id)
        return {"protectedExchangeVerified":True,"endpointLabel":label}

    def _retire_protocol_dns(self):
        name = self.prefix + "-dns"
        if name not in self.ids:
            return False
        self.assert_disposable(self.admin_url, self.run_id)
        self._run(["rm", "--force", name])
        del self.ids[name]
        self.intended_names.remove(name)
        return True

    def start_protocol_dns(self):
        """Start one nonce-owned loopback-only DNS fixture in the backend network namespace, without signing-key mounts.
        
        Returns:
            Owned running DNS sidecar identity, reusing the same sidecar on subsequent calls.
        
        Raises:
            ExerciseFailure: Ownership, helper launch or bounded readiness verification fails.
            OSError: The private keyless DNS mount cannot be prepared.
        """
        self.assert_disposable(self.admin_url,self.run_id)
        name=self.prefix+"-dns"
        if name in self.ids:
            return {"running":True,"containerId":self.ids[name]}
        classes=self._helper_classes("ExerciseProtocolDns")
        dns_root=self.directory/"dns-sidecar"
        dns_root.mkdir(mode=0o700,exist_ok=True)
        shutil.copyfile(self.directory/".exercise-owner.json",dns_root/".exercise-owner.json")
        (dns_root/".exercise-owner.json").chmod(0o600)
        self.intended_names.append(name)
        self.ids[name]=self._run(["run","--detach","--pull=never","--name",name,"--label",LABEL+"="+self.nonce,
            "--userns=keep-id:uid=10001,gid=10001","--image-volume=ignore","--network=container:"+self.server,
            "--volume",str(classes)+":/qualification/classes:ro,z","--volume",str(dns_root)+":/qualification/root:ro,z",
            "--volume",str(getattr(self,"dns_records_directory",self.directory/"config"))+":/qualification/root/config:ro,z","--entrypoint","java",self.images["server"],
            "-cp","/qualification/classes:/opt/zeroecho/server/lib/*","zeroecho.pki.server.ExerciseProtocolDns","/qualification/root",self.nonce,self.run_id]).stdout.decode().strip()
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            self.assert_disposable(self.admin_url,self.run_id)
            if b"PROTOCOL_DNS_READY" in self._run(["logs",name]).stdout.splitlines():
                return {"running":True,"containerId":self.ids[name]}
            time.sleep(0.1)
        raise ExerciseFailure("Owned DNS fixture did not become ready")

    def __exit__(self, exception_type, exception, traceback):
        """Remove only nonce-labelled owned resources; never touch deployment services or foreign containers."""
        refused = False
        for name in [value for value in reversed(self.intended_names) if value not in (self.server,self.web)]+[self.web,self.server]:
            identity = self.ids.get(name)
            exists = self._run(["container", "exists", name], check=False)
            if exists.returncode == 1:
                continue
            if exists.returncode:
                raise ExerciseFailure("Container ownership cannot be inspected; cleanup refused")
            document = json.loads(self._run(["inspect", name]).stdout)[0]
            if (identity is not None and document.get("Id") != identity) or (document.get("Config", {}).get("Labels") or {}).get(LABEL) != self.nonce:
                refused = True
                continue
            self._run(["rm", "--force", name])
        if self.network_created and not refused:
            exists = self._run(["network", "exists", self.prefix], check=False)
            if exists.returncode not in (0, 1):
                raise ExerciseFailure("Network ownership cannot be inspected; cleanup refused")
            if exists.returncode == 0:
                network = json.loads(self._run(["network", "inspect", self.prefix]).stdout)[0]
                if (network.get("labels") or {}).get(LABEL) == self.nonce:
                    self._run(["network", "rm", self.prefix])
                else:
                    refused = True
        if refused:
            raise ExerciseFailure("Foreign resource ownership detected; cleanup refused and private fixture state retained")
        if self.directory is not None:
            marker = _private_file(self.directory / ".exercise-owner.json")
            if json.loads(marker.read_text()) != {"nonce": self.nonce}:
                raise ExerciseFailure("Disposable directory ownership changed; removal refused")
            shutil.rmtree(self.directory)
