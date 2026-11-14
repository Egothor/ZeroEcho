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

"""Install a fresh PKI realm through one curses form and manage its user services.

Run with ``python3 deploy/rootless_pki.py install`` on Linux as the service owner.
Configuration and secrets stay in a private directory outside the checkout.
Commands update, start, stop and status operate only the selected installation.
Use ``update --certificate-access`` to explicitly migrate certificate-download
access for the initial administrator pair; ``--root-admin`` is independent.
Update retains exact image pins for forward recovery. Failures retain state for diagnosis; existing installations are never bootstrapped again.
"""
from __future__ import annotations

import argparse
import fcntl
import curses
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid

REPOSITORY = Path(__file__).resolve().parents[1]
FIELDS = [
    ("directory", "Data directory", str(Path.home() / ".local/share/zeroecho-pki"), False),
    ("hostname", "Web DNS name", socket.getfqdn(), False),
    ("bind", "Published IP", "127.0.0.1", False),
    ("port", "HTTPS port (1024-65535)", "8443", False),
    ("realm", "Realm ID", "production", False),
    ("admin", "Administrator ID", "bootstrap-admin", False),
    ("approver", "Independent approver ID", "bootstrap-approver", False),
    ("key_password", "Signing keyring password", "", True),
    ("admin_password", "Admin PKCS12 password", "", True),
    ("approver_password", "Approver PKCS12 password", "", True),
    ("edge_cert", "Existing web PEM chain*", "", False),
    ("edge_key", "Existing web PEM key*", "", False),
    ("edge_ca", "Web CA PEM bundle*", "", False),
]
ALGORITHM = "zealg:2:9:signature8:zeroecho14:rsa-pkcs1-v1_516:zeroecho.builtin39:ZGlnZXN0PXplcm9lY2hvLnNoYTItMjU2Lm5vbmU"
PODMAN = ["podman", "--remote=false"]


def _run(arguments, *, env=None, capture=False):
    # Diagnostics can contain key material or tool arguments; surface only the executable.
    result = subprocess.run([str(arg) for arg in arguments], env=env,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError(f"{arguments[0]} failed (exit {result.returncode}); state retained")
    return result.stdout if capture else b""


def _write(path, content, mode=0o600):
    with path.open("x", encoding="utf-8") as output:
        output.write(content)
    path.chmod(mode)


def _json(path, value):
    _write(path, json.dumps(value, indent=2) + "\n")


def _form(screen, initial_directory=None):
    curses.curs_set(1)
    screen.keypad(True)
    values = {name: default for name, _, default, _ in FIELDS}
    if initial_directory is not None:
        values["directory"] = str(initial_directory.expanduser())
    selected = 0
    error = ""
    while True:
        screen.erase()
        height, width = screen.getmaxyx()
        if height < 22 or width < 78:
            raise ValueError("Terminal must be at least 78 columns by 22 rows")
        def put(row, text, attr=0):
            screen.addnstr(row, 1, text, width - 2, attr)
        put(0, "ZeroEcho PKI - rootless production installation", curses.A_BOLD)
        put(1, "Tab/arrows: field   Enter: next   F2: prepare and start   Esc: cancel")
        put(2, "* All three blank: create private web CA; otherwise supply all three.")
        put(3, "Passwords: 16+ characters. Initial admin is root; ordinary admins need other eyes.")
        for index, (name, label, _, masked) in enumerate(FIELDS):
            displayed = "*" * len(values[name]) if masked else values[name]
            attr = curses.A_REVERSE if index == selected else 0
            put(index + 5, f"{label:28} {displayed}", attr)
        put(height - 3, error or "Creates persistent data, two login certificates and systemd --user services.")
        put(height - 2, "Existing data is refused. No OS trust store or firewall changes.")
        name, _, _, _ = FIELDS[selected]
        screen.move(selected + 5, min(width - 2, 30 + len(values[name])))
        key = screen.get_wch()
        if key == "\x1b":
            raise KeyboardInterrupt
        if key == curses.KEY_F2:
            try:
                _validate(values)
                return values
            except ValueError as failure:
                error = str(failure)
        elif key in ("\t", "\n", "\r", curses.KEY_DOWN):
            selected = (selected + 1) % len(FIELDS)
        elif key in (curses.KEY_BTAB, curses.KEY_UP):
            selected = (selected - 1) % len(FIELDS)
        elif key in (curses.KEY_BACKSPACE, "\x7f", "\b"):
            values[name] = values[name][:-1]
        elif key == "\x15":
            values[name] = ""
        elif isinstance(key, str) and key.isprintable():
            values[name] += key


def _validate(values):
    hostname = values["hostname"]
    if len(hostname) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", hostname):
        raise ValueError("Web DNS name must contain only DNS letters, digits, dots and hyphens")
    if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-") for part in hostname.split(".")):
        raise ValueError("Invalid DNS label")
    try:
        ipaddress.IPv4Address(values["bind"])
    except ValueError as failure:
        raise ValueError("Published IP must be a numeric IPv4 address") from failure
    if not values["port"].isdigit() or not 1024 <= int(values["port"]) <= 65535:
        raise ValueError("HTTPS port must be 1024-65535")
    for name in ("realm", "admin", "approver"):
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", values[name]):
            raise ValueError(f"{name}: use 1-64 letters, digits, underscore or hyphen")
    if values["admin"] == values["approver"] or "trusted-proxy" in (values["admin"], values["approver"]):
        raise ValueError("Administrator, approver and trusted-proxy must be distinct")
    for name in ("key_password", "admin_password", "approver_password"):
        if len(values[name]) < 16 or any(char in values[name] for char in "\n\r\x00"):
            raise ValueError("Each password needs at least 16 characters and no line breaks")
    if values["admin_password"] == values["approver_password"]:
        raise ValueError("Administrator and approver need different export passwords")
    if not re.fullmatch(r"[A-Za-z0-9!@#$%^&*()_+=.,:;/?<>\[\]{}|~`-]{16,256}", values["key_password"]):
        raise ValueError("Keyring password: 16-256 ASCII letters/digits/punctuation; no quotes, spaces or backslash")
    directory = Path(values["directory"]).expanduser()
    if not directory.is_absolute() or any(char in str(directory) for char in "\n\r\x00:,"):
        raise ValueError("Data directory must be absolute, without line breaks, colon or comma")
    directory = directory.resolve()
    if directory == REPOSITORY or REPOSITORY in directory.parents:
        raise ValueError("Keep production data outside the source checkout")
    if directory.exists():
        raise ValueError("Data directory already exists; install requires a new directory")
    edge = [values[key] for key in ("edge_cert", "edge_key", "edge_ca")]
    if any(edge) and not all(edge):
        raise ValueError("Provide web certificate, key and CA bundle together, or leave all blank")
    for path in filter(None, edge):
        if not Path(path).is_file():
            raise ValueError("A supplied TLS file does not exist")


def _preflight():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("Run on Linux as an ordinary user, without sudo")
    for executable in ("podman", "openssl", "systemctl", "curl"):
        if not shutil.which(executable):
            raise ValueError(f"Required executable missing: {executable}")
    if _run([*PODMAN, "info", "--format", "{{.Host.Security.Rootless}}"], capture=True).strip() != b"true":
        raise ValueError("Podman must use a rootless local engine")
    _run(["systemctl", "--user", "show-environment"], capture=True)
    help_result = subprocess.run(["openssl", "pkcs12", "-help"], capture_output=True, check=False)
    if b"-jdktrust" not in help_result.stdout + help_result.stderr:
        raise ValueError("OpenSSL with pkcs12 -jdktrust support is required (3.4 or later)")


def _openssl(root, args, password=None):
    env = os.environ.copy()
    if password is not None:
        env["ZEROECHO_OPENSSL_PASSWORD"] = password
    return _run(["openssl", *args], env=env, capture=True)


def _identity(root, name, cn, *, server=False, san=None, password):
    private = root / "provisioning" / f"{name}.key"
    request = root / "provisioning" / f"{name}.csr"
    cert = root / "provisioning" / f"{name}.crt"
    extension = root / "provisioning" / f"{name}.ext"
    _write(extension, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
           + ("extendedKeyUsage=serverAuth\n" if server else "extendedKeyUsage=clientAuth\n")
           + (f"subjectAltName={san}\n" if san else ""))
    _openssl(root, ["req", "-new", "-newkey", "rsa:3072", "-nodes", "-subj", f"/CN={cn}",
                    "-keyout", private, "-out", request])
    _openssl(root, ["x509", "-req", "-in", request, "-CA", root / "provisioning/ca.crt",
                    "-CAkey", root / "provisioning/ca.key", "-passin", "env:ZEROECHO_OPENSSL_PASSWORD",
                    "-set_serial", str(secrets.randbits(159) or 1), "-days", "365", "-sha256",
                    "-extfile", extension, "-out", cert], password)
    return private, cert


def _tls(root, values, tls_password):
    provisioning = root / "provisioning"
    _openssl(root, ["req", "-x509", "-newkey", "rsa:3072", "-sha256", "-days", "3650",
                    "-subj", "/CN=ZeroEcho deployment transport and login CA",
                    "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                    "-keyout", provisioning / "ca.key", "-out", provisioning / "ca.crt",
                    "-passout", "env:ZEROECHO_OPENSSL_PASSWORD"], tls_password)
    pairs = {}
    for name in ("server", "proxy", "health", "administrator", "approver", "edge"):
        if name == "edge" and values["edge_cert"]:
            continue
        san = "DNS:pki-server,IP:127.0.0.1" if name == "server" else f"DNS:{values['hostname']}"
        pairs[name] = _identity(root, name, name, server=name in ("server", "edge"),
                                 san=san if name in ("server", "edge") else None, password=tls_password)
    for name, export_password in (("server", tls_password), ("administrator", values["admin_password"]),
                                   ("approver", values["approver_password"])):
        target = root / ("tls/server/server-identity.p12" if name == "server" else f"logins/{name}.p12")
        private, cert = pairs[name]
        _openssl(root, ["pkcs12", "-export", "-inkey", private, "-in", cert,
                        "-certfile", provisioning / "ca.crt", "-out", target,
                        "-passout", "env:ZEROECHO_OPENSSL_PASSWORD"], export_password)
    # A cert-only PKCS12 is a JSSE trust store only when it has Java trusted-key usage.
    _openssl(root, ["pkcs12", "-export", "-nokeys", "-in", provisioning / "ca.crt",
                    "-jdktrust", "anyExtendedKeyUsage", "-out", root / "tls/server/trust.p12",
                    "-passout", "env:ZEROECHO_OPENSSL_PASSWORD"], tls_password)
    copies = {
        "tls/health/health-client.pem": pairs["health"][1],
        "tls/health/health-client-key.pem": pairs["health"][0],
        "tls/health/health-ca.pem": provisioning / "ca.crt",
        "tls/upstream/proxy-client.crt": pairs["proxy"][1],
        "tls/upstream/proxy-client.key": pairs["proxy"][0],
        "tls/upstream/pki-server-ca.pem": provisioning / "ca.crt",
        "tls/admin-trust/admin-ca-bundle.pem": provisioning / "ca.crt",
        "logins/administrators-ca.pem": provisioning / "ca.crt",
    }
    if values["edge_cert"]:
        copies.update({"tls/edge/edge.crt": Path(values["edge_cert"]),
                       "tls/edge/edge.key": Path(values["edge_key"]),
                       "logins/web-ca.pem": Path(values["edge_ca"])})
    else:
        copies.update({"tls/edge/edge.crt": pairs["edge"][1], "tls/edge/edge.key": pairs["edge"][0],
                       "logins/web-ca.pem": provisioning / "ca.crt"})
    for target, source in copies.items():
        shutil.copyfile(source, root / target)
        (root / target).chmod(0o600)
    # Reject mismatched, expired, wrong-host and untrusted supplied edge identities before deployment.
    cert_pub = _openssl(root, ["x509", "-in", root / "tls/edge/edge.crt", "-pubkey", "-noout"])
    key_pub = _openssl(root, ["pkey", "-in", root / "tls/edge/edge.key", "-pubout", "-passin", "pass:"])
    if cert_pub != key_pub:
        raise ValueError("Web certificate and private key do not match")
    _openssl(root, ["verify", "-purpose", "sslserver", "-verify_hostname", values["hostname"],
                    "-CAfile", root / "logins/web-ca.pem", "-untrusted", root / "tls/edge/edge.crt",
                    root / "tls/edge/edge.crt"])
    return {name: hashlib.sha256(_openssl(root, ["x509", "-in", cert, "-outform", "DER"])).hexdigest()
            for name, (_, cert) in pairs.items()}


def _configuration(root, values, fingerprints):
    document = json.loads((REPOSITORY / "documentation/examples/configuration/pki-server-trusted-proxy-rfc9440-example.json").read_text())
    realm = document["realm"]
    realm.update(realmId=values["realm"], displayName=values["realm"],
                 controlLog="/deployment/store-container/server-control/server-control.log",
                 controlStoreId=secrets.token_hex(16), authorizationCommitment=secrets.token_hex(32),
                 disclosureCommitment=secrets.token_hex(32))
    realm["confirmationProof"]["audience"] = "urn:uuid:" + str(uuid.uuid4())
    realm["approvalPolicy"]["eligibleApprovers"] = [values["admin"], values["approver"]]
    # Mirrors ApprovalService.Policy.commitment; the production codec verifies it again.
    approvers = ",".join(sorted((values["admin"], values["approver"])))
    realm["approvalCommitment"] = hashlib.sha256(
        f"high-risk|1|{approvers}||true|3600|true".encode()).hexdigest()
    realm["authorityExposure"]["creationPermitted"] = True
    realm["pkiSession"] = {
        "version": 6, "store": {"id": "fs", "properties": {"root": "/deployment/store-container/store"}},
        "audit": {"id": "file", "properties": {"root": "/deployment/audit"}},
        "publishers": [{"id": "filesystem", "properties": {"root": "/deployment/artifacts", "targetId": "local"}}],
        "bindingProviders": [],
        "signing": {"provider": {"id": "zeroecho-lib", "properties": {
            "keyringPath": "/deployment/keyring/ca-keyring.zek", "keyRefPrefix": "zeroecho-lib:",
            "requireComponentSuffix": "true"}}, "signatureAlgorithm": ALGORITHM,
            "signingTtlMillis": 120000, "topology": {"coordinator": {"pageSize": 1,
                "claimLeaseMillis": 30000, "providerCallTimeoutMillis": 10000,
                "idlePollIntervalMillis": 100, "closeTimeoutMillis": 5000}, "exactGroups": [],
                "catchAll": {"laneCount": 1, "prefetchSize": 1}}}}
    document["listener"]["address"] = "0.0.0.0"
    document["listener"]["tlsProvider"]["properties"] = {
        "keyStore": "/deployment/tls/server/server-identity.p12",
        "keyStorePasswordEnvironment": "ZEROECHO_TLS_PASSWORD",
        "trustStore": "/deployment/tls/server/trust.p12", "trustStorePasswordEnvironment": "ZEROECHO_TLS_PASSWORD"}
    auth = document["authentication"]
    auth["proxyTransportMappings"] = [{"mappingId": "proxy", "principalId": "trusted-proxy",
                                        "certificateSha256": fingerprints["proxy"]}]
    auth["forwardedClientMappings"] = [
        {"mappingId": name, "principalId": values[field], "certificateSha256": fingerprints[name]}
        for name, field in (("administrator", "admin"), ("approver", "approver"))]
    auth["administrativeClientTrust"]["properties"] = {
        "trustStore": "/deployment/tls/server/trust.p12", "trustStorePasswordEnvironment": "ZEROECHO_TLS_PASSWORD"}
    document["publicListener"] = {"enabled": False}
    document["runtime"] = {"keyUnlockEnvironmentVariable": "ZEROECHO_KEYRING_PASSWORD"}
    _json(root / "config/server.json", document)
    _json(root / "config/profile-bootstrap.json", {"version": 1, "mode": "local", "operatorId": "deployment-profile-bootstrap",
        "store": {"provider": "fs", "properties": {"root": "/deployment/store-container/store"}},
        "audit": {"provider": "file", "properties": {"root": "/deployment/audit"}},
        "publishers": [], "bindingProviders": []})
    for profile in (REPOSITORY / "deploy/pki-server/profiles").glob("*.json"):
        shutil.copyfile(profile, root / "profiles" / profile.name)


def _image(name, dockerfile):
    print(f"Building {name} from this checkout (may take several minutes)", flush=True)
    _run([*PODMAN, "build", "--tag", name, "--file", REPOSITORY / dockerfile, REPOSITORY])
    return _run([*PODMAN, "image", "inspect", "--format", "{{.Id}}", name], capture=True).decode().strip()


def _server_options(root):
    options = ["--userns=keep-id:uid=10001,gid=10001", "--image-volume=ignore",
               "--env-file", str(root / "secrets.conf")]
    for directory in ("config", "profiles", "tls/server", "tls/health", "store-container", "keyring", "audit", "artifacts"):
        readonly = directory in ("config", "profiles", "tls/server", "tls/health")
        options += ["--volume", f"{root / directory}:/deployment/{directory}:{'ro' if readonly else 'rw'},z"]
    options += ["--env", "ZEROECHO_SERVER_CONFIG=/deployment/config/server.json",
                "--env", "ZEROECHO_STORE_DIR=/deployment/store-container/store",
                "--env", "ZEROECHO_PROFILE_BOOTSTRAP_CONFIG=/deployment/config/profile-bootstrap.json",
                "--env", "ZEROECHO_PROFILES_DIR=/deployment/profiles",
                "--env", "ZEROECHO_HEALTH_CLIENT_CERT=/deployment/tls/health/health-client.pem",
                "--env", "ZEROECHO_HEALTH_CLIENT_KEY=/deployment/tls/health/health-client-key.pem",
                "--env", "ZEROECHO_HEALTH_CA=/deployment/tls/health/health-ca.pem"]
    return options


def _systemd_quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def _service(root, name, arguments, *, requires=None, ready=False, output_directory=None):
    podman = shutil.which("podman")
    # Keep the edge running while systemd recovers the backend after a failure.
    dependency = f"Wants={requires}.service\nAfter={requires}.service\n" if requires else ""
    unit = ("[Unit]\nDescription=ZeroEcho PKI " + name + "\n" + dependency
            + "\n[Service]\nType=exec\nRestart=on-failure\nRestartSec=5\nTimeoutStartSec=180\nTimeoutStopSec=60\n"
            + "ExecStart=" + " ".join(map(_systemd_quote, [podman, "--remote=false", "run", "--pull=never", "--replace", "--rm", "--name", name, *arguments])) + "\n"
            + "ExecStop=" + " ".join(map(_systemd_quote, [podman, "--remote=false", "stop", "--time", "40", name])) + "\n")
    if ready:
        # systemd holds dependent startup until the backend's real mTLS health probe succeeds.
        unit += "ExecStartPost=" + " ".join(map(_systemd_quote, [sys.executable, root / "manage.py", "_ready", "--directory", root])) + "\n"
    unit += "\n[Install]\nWantedBy=default.target\n"
    _write((output_directory or root / "units") / f"{name}.service", unit)


def _network_addresses(document):
    for subnet in document[0]["subnets"]:
        network = ipaddress.ip_network(subnet["subnet"])
        if network.version == 4:
            gateway = subnet.get("gateway")
            addresses = []
            for address in network.hosts():
                if str(address) != gateway:
                    addresses.append(str(address))
                if len(addresses) == 2:
                    return addresses
    raise ValueError("Private Podman network needs at least two usable IPv4 addresses")


def _units(root, values, images, prefix, addresses, *, output_directory=None):
    # nginx resolves its upstream once: fixed addresses survive container replacement.
    # OCI builds omit Dockerfile HEALTHCHECK metadata; this runtime contract is explicit.
    health = ["--health-cmd", "curl -fsS --max-time 4 "
              "--cert /deployment/tls/health/health-client.pem "
              "--key /deployment/tls/health/health-client-key.pem "
              "--cacert /deployment/tls/health/health-ca.pem https://127.0.0.1:8443/health/ready",
              "--health-interval", "15s", "--health-timeout", "5s",
              "--health-start-period", "40s", "--health-retries", "5"]
    _service(root, prefix + "-server", ["--network", prefix, "--ip", addresses[0], "--network-alias", "pki-server",
                                       *health, *_server_options(root), images["server"]], ready=True, output_directory=output_directory)
    edge = ["--network", prefix, "--ip", addresses[1], "--image-volume=ignore", "--publish", f"{values['bind']}:{values['port']}:8443",
            "--env", f"NGINX_SERVER_NAME={values['hostname']}", "--env", "PKI_UPSTREAM=pki-server:8443",
            "--env", "PKI_PROXY_SSL_NAME=pki-server"]
    for directory in ("edge", "upstream", "admin-trust"):
        edge += ["--volume", f"{root / 'tls' / directory}:/etc/nginx/tls/{directory}:ro,z"]
    _service(root, prefix + "-web", [*edge, images["web"]], requires=prefix + "-server", output_directory=output_directory)


def _ready(root, manifest):
    deadline = time.monotonic() + 120
    last_failure = "no successful health probe"
    while time.monotonic() < deadline:
        result = subprocess.run([*PODMAN, "healthcheck", "run", manifest["prefix"] + "-server"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode == 0:
            return
        if b"no defined healthcheck" in result.stderr:
            raise RuntimeError("Backend container has no defined healthcheck; update its service configuration with an explicit health command")
        last_failure = f"health probe exited {result.returncode}"
        time.sleep(1)
    raise RuntimeError(f"Backend did not become ready in 120 seconds ({last_failure}); inspect journalctl --user")



def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_bytes(path, content):
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValueError("Refusing to replace an unowned or nonregular update file")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.pending")
    try:
        with temporary.open("xb") as output:
            temporary.chmod(0o600)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _update_json(path, document):
    _atomic_bytes(path, (json.dumps(document, indent=2) + "\n").encode())


def _file_hash(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise ValueError("Update files must be regular files owned by the current user")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _owned_directory(path, *, private=False):
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or (private and metadata.st_mode & 0o077):
        raise ValueError("Update directories must be owned, unlinked and private where required")


def _validate_update_manifest(manifest, prefix):
    fields = {"version", "prefix", "hostname", "port", "bind", "images", "addresses", "admin", "approver"}
    if not isinstance(manifest, dict) or set(manifest) != fields or type(manifest["version"]) is not int \
            or manifest["version"] != 1 or manifest["prefix"] != prefix:
        raise ValueError("Installation manifest does not match this directory")
    if not isinstance(manifest["hostname"], str) or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", manifest["hostname"]):
        raise ValueError("Invalid update hostname")
    if type(manifest["port"]) is not int or not 1024 <= manifest["port"] <= 65535:
        raise ValueError("Invalid update port")
    ipaddress.IPv4Address(manifest["bind"])
    if not isinstance(manifest["addresses"], list) or len(manifest["addresses"]) != 2:
        raise ValueError("Invalid update network addresses")
    for address in manifest["addresses"]:
        ipaddress.IPv4Address(address)
    if len(set(manifest["addresses"])) != 2:
        raise ValueError("Update network addresses must differ")
    for identity in (manifest["admin"], manifest["approver"]):
        if not isinstance(identity, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", identity):
            raise ValueError("Invalid initial administrator identity")
    if len({manifest["admin"], manifest["approver"], "trusted-proxy"}) != 3:
        raise ValueError("Initial administrator identities must differ")
    _validate_update_image_ids(manifest["images"])


def _update(root, manifest, *, root_admin=False, certificate_access=False, status_access=False, unit_directory=None):
    unit_directory = unit_directory or Path.home() / ".config/systemd/user"
    metadata = root.lstat()
    prefix = "zeroecho-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError("Update requires a private installation owned by the current user")
    _validate_update_manifest(manifest, prefix)
    if type(status_access) is not bool:
        raise ValueError("Status-access intent must be boolean")
    if type(certificate_access) is not bool:
        raise ValueError("Certificate-access migration must be explicit")
    if type(root_admin) is not bool:
        raise ValueError("Root-administrator designation must be explicit")
    for directory in ("units", "config", "profiles", "tls", "tls/server", "tls/health", "tls/edge",
                      "tls/upstream", "tls/admin-trust", "store-container", "store-container/store", "keyring", "audit", "artifacts"):
        _owned_directory(root / directory)
    for name in ("secrets.conf", "store-container/store/VERSION", "store-container/server-control/server-control.log"):
        metadata = (root / name).lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValueError("Update requires existing owned regular installation files")
    files = ("manage.py", "installation.json", f"units/{prefix}-server.service", f"units/{prefix}-web.service")
    for name in files:
        _file_hash(root / name)
    for name in files[2:]:
        link = unit_directory / Path(name).name
        if not link.is_symlink() or link.resolve() != root / name:
            raise ValueError("Update refuses an unrelated service link")
    lock_descriptor = os.open(root / ".update.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_descriptor, "r+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode) or os.fstat(lock.fileno()).st_uid != os.geteuid():
            raise ValueError("Invalid update lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("An installation update is already running") from error
        if json.loads((root / "installation.json").read_text()) != manifest:
            raise ValueError("Installation manifest changed before the update lock was acquired")
        _update_locked(root, manifest, prefix, files, root_admin, certificate_access, status_access)


def _update_locked(root, manifest, prefix, files, root_admin, certificate_access, status_access):
    _preflight()
    network = json.loads(_run([*PODMAN, "network", "inspect", prefix], capture=True))
    if not isinstance(network, list) or len(network) != 1 or network[0].get("name") != prefix \
            or network[0].get("internal") is not True or _network_addresses(network) != manifest["addresses"]:
        raise ValueError("Retained private network does not match this installation")
    updates = root / "updates"
    if updates.is_symlink() or (updates.exists() and (not updates.is_dir() or updates.stat().st_uid != os.geteuid())):
        raise ValueError("Invalid private update directory")
    updates.mkdir(mode=0o700, exist_ok=True)
    _owned_directory(updates, private=True)
    _sync_directory(root)
    pending = updates / "pending.json"
    config_hash = _file_hash(root / "config/server.json")
    if os.path.lexists(pending):
        _file_hash(pending)
        journal = json.loads(pending.read_text())
        if not isinstance(journal, dict) or set(journal) != {"version", "id", "prefix", "rootAdmin", "phase", "oldImages", "newImages", "configHash", "files"} | ({"certificateAccess"} if journal.get("version") in (2, 3) else set()) | ({"statusAccess"} if journal.get("version") == 3 else set()) \
                or type(journal.get("version")) is not int or journal["version"] not in (1, 2, 3) or journal.get("prefix") != prefix \
                or not isinstance(journal.get("id"), str) or not re.fullmatch(r"[0-9a-f]{32}", journal["id"]) \
                or type(journal["rootAdmin"]) is not bool \
                or (journal["version"] in (2, 3) and type(journal.get("certificateAccess")) is not bool) \
                or (journal["version"] == 3 and type(journal.get("statusAccess")) is not bool) \
                or journal["phase"] not in ("prepared", "new-images-pinned", "ready-to-start", "completed") \
                or not isinstance(journal["configHash"], str) or not re.fullmatch(r"[0-9a-f]{64}", journal["configHash"]):
            raise ValueError("Invalid retained update journal")
        if journal.get("certificateAccess", False) != certificate_access:
            raise ValueError("Repeat the retained update with the same explicit certificate-access intent (--certificate-access)")
        if journal.get("statusAccess", False) != status_access:
            raise ValueError("Repeat update with the same explicit status-access intent")
        journal = dict(journal, version=3, certificateAccess=certificate_access, statusAccess=status_access)
        if root_admin and not journal.get("rootAdmin"):
            raise ValueError("Finish the retained plain update before explicitly designating a root administrator")
        if journal["rootAdmin"] != root_admin:
            raise ValueError("Repeat the retained update with the same explicit root-administrator intent (--root-admin)")
        print("Resuming the exact retained update; no images are rebuilt", flush=True)
        stage = updates / journal["id"]
        images = journal["newImages"]
    else:
        if not all((REPOSITORY / path).is_file() for path in ("deploy/pki-server/Dockerfile", "deploy/nginx/Dockerfile")):
            raise ValueError("Run update from the reviewed source checkout")
        images = {"server": _image("localhost/zeroecho-pki-server:installer", "deploy/pki-server/Dockerfile"),
                  "web": _image("localhost/zeroecho-pki-nginx:installer", "deploy/nginx/Dockerfile")}
        _validate_update_image_ids(images)
        _run([*PODMAN, "run", "--pull=never", "--rm", "--network=none", *_server_options(root),
              "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-server", images["server"],
              "--validate-config", "--config", "/deployment/config/server.json"])
        if _file_hash(root / "config/server.json") != config_hash:
            raise ValueError("Configuration changed while images were built; update refused")
        stage = updates / uuid.uuid4().hex
        stage.mkdir(mode=0o700)
        for directory in ("old", "new", "old/units", "old/config", "new/units"):
            (stage / directory).mkdir(mode=0o700)
        for name in (*files, "config/server.json"):
            _atomic_bytes(stage / "old" / name, (root / name).read_bytes())
        updated = dict(manifest, images=images)
        _units(root, updated, images, prefix, updated["addresses"], output_directory=stage / "new/units")
        _atomic_bytes(stage / "new/manage.py", Path(__file__).read_bytes())
        _update_json(stage / "new/installation.json", updated)
        for name in files[2:]:
            with (stage / "new" / name).open("rb") as content:
                os.fsync(content.fileno())
        _sync_directory(stage / "new/units")
        for directory in ("old/units", "old/config", "old", "new", ""):
            _sync_directory(stage / directory)
        _sync_directory(updates)
        journal = {"version": 3, "id": stage.name, "prefix": prefix, "rootAdmin": bool(root_admin), "certificateAccess": certificate_access, "statusAccess": status_access,
                   "phase": "prepared", "oldImages": manifest["images"], "newImages": images,
                   "configHash": config_hash, "files": {name: {"old": _file_hash(stage / "old" / name),
                   "new": _file_hash(stage / "new" / name)} for name in files}}
        _update_json(pending, journal)
    _validate_update_image_ids(images)
    _validate_update_image_ids(journal["oldImages"])
    for directory in ("", "old", "new", "old/units", "old/config", "new/units"):
        _owned_directory(stage / directory, private=True)
    if not isinstance(journal["files"], dict) or set(journal["files"]) != set(files):
        raise ValueError("Retained update files do not match the installation")
    if config_hash != journal["configHash"] or _file_hash(stage / "old/config/server.json") != config_hash:
        raise ValueError("Configuration changed since this update was prepared; update refused")
    for name in files:
        expected = journal["files"][name]
        if not isinstance(expected, dict) or set(expected) != {"old", "new"} or any(
                not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in expected.values()):
            raise ValueError("Invalid retained update file hashes")
        if _file_hash(stage / "old" / name) != expected["old"] or _file_hash(stage / "new" / name) != expected["new"]:
            raise ValueError("Retained update content changed; update refused")
        if _file_hash(root / name) not in (expected["old"], expected["new"]):
            raise ValueError("Installation metadata changed outside the retained update")
    for image in images.values():
        _run([*PODMAN, "image", "exists", image])
    updated = json.loads((stage / "new/installation.json").read_text())
    original = json.loads((stage / "old/installation.json").read_text())
    _validate_update_manifest(updated, prefix)
    _validate_update_manifest(original, prefix)
    if updated != dict(original, images=images) or original["images"] != journal["oldImages"]:
        raise ValueError("Retained update must change only installed image identities")
    if _file_hash(root / "config/server.json") != journal["configHash"]:
        raise ValueError("Configuration changed before service activation; update refused")
    print(f"Update snapshot: {stage}; configuration, keys and PKI state remain in place", flush=True)
    names = [prefix + "-web.service", prefix + "-server.service"]
    try:
        _run(["systemctl", "--user", "stop", *names])
        for name in files:
            _atomic_bytes(root / name, (stage / "new" / name).read_bytes())
        _run(["systemctl", "--user", "daemon-reload"])
        journal["phase"] = "new-images-pinned"
        _update_json(pending, journal)
        if journal["rootAdmin"]:
            receipt = _run([*PODMAN, "run", "--pull=never", "--rm", "--network=none", *_server_options(root),
                "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-root-admin", images["server"],
                "--config", "/deployment/config/server.json", "--admin-id", updated["admin"],
                "--approver-id", updated["approver"], "--proxy-id", "trusted-proxy"], capture=True)
            if receipt.strip() != b"ROOT_ADMIN_READY":
                raise RuntimeError("Root-administrator designation is unconfirmed")
        if journal["certificateAccess"]:
            receipt = _run([*PODMAN, "run", "--pull=never", "--rm", "--network=none", *_server_options(root),
                "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-certificate-access", images["server"],
                "--config", "/deployment/config/server.json", "--admin-id", updated["admin"],
                "--approver-id", updated["approver"], "--proxy-id", "trusted-proxy"], capture=True)
            if receipt.strip() != b"CERTIFICATE_ACCESS_READY":
                raise RuntimeError("Certificate-access migration is unconfirmed")
        if journal["statusAccess"]:
            receipt = _run([*PODMAN, "run", "--pull=never", "--rm", "--network=none", *_server_options(root),
                "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-status-access", images["server"],
                "--config", "/deployment/config/server.json", "--admin-id", updated["admin"],
                "--approver-id", updated["approver"], "--proxy-id", "trusted-proxy"], capture=True)
            if receipt.strip() != b"STATUS_ACCESS_READY":
                raise RuntimeError("Status-access migration is unconfirmed")
        journal["phase"] = "ready-to-start"
        _update_json(pending, journal)
        _run(["systemctl", "--user", "start", *names])
        _verify_edge(root, updated)
    except (OSError, ValueError, RuntimeError) as error:
        raise RuntimeError(f"{error}; update retained at {stage}. New image pins may already be active; repeat update to resume, without rolling back state") from error
    journal["phase"] = "completed"
    _update_json(pending, journal)
    os.replace(pending, stage / "completed.json")
    _sync_directory(updates)
    _sync_directory(stage)
    if journal["rootAdmin"]:
        print(f"Root administrator: {updated['admin']}; own approval decisions still require an explicit recorded justification", flush=True)
    if journal["certificateAccess"]:
        print("Certificate access confirmed for the initial administrator pair", flush=True)
    if journal["statusAccess"]:
        print("Status content access confirmed for the initial administrator pair", flush=True)
    print(f"Update complete: https://{updated['hostname']}:{updated['port']}/", flush=True)


def _validate_update_image_ids(images):
    if not isinstance(images, dict) or set(images) != {"server", "web"} or any(
            not isinstance(value, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value) for value in images.values()):
        raise ValueError("Update requires immutable local server and web image IDs")


def _install(values):
    _validate(values)
    _preflight()
    root = Path(values["directory"]).expanduser().resolve()
    prefix = "zeroecho-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    # Reserve both service names before any key, store or network mutation.
    unit_directory = Path.home() / ".config/systemd/user"
    for name in (prefix + "-server", prefix + "-web"):
        if os.path.lexists(unit_directory / f"{name}.service"):
            raise ValueError("A service for this directory already exists")
    images = {"server": _image("localhost/zeroecho-pki-server:installer", "deploy/pki-server/Dockerfile"),
              "web": _image("localhost/zeroecho-pki-nginx:installer", "deploy/nginx/Dockerfile")}
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    print(f"Installation state: {root}; retained if any later step fails", flush=True)
    for directory in ("provisioning", "logins", "config", "profiles", "tls/server", "tls/health", "tls/edge",
                      "tls/upstream", "tls/admin-trust", "store-container", "keyring", "audit", "artifacts", "units"):
        (root / directory).mkdir(mode=0o700, parents=True, exist_ok=True)
    tls_password = secrets.token_urlsafe(48)
    _write(root / "secrets.conf", f"ZEROECHO_TLS_PASSWORD={tls_password}\nZEROECHO_KEYRING_PASSWORD={values['key_password']}\n")
    print("Generating TLS and browser identities", flush=True)
    fingerprints = _tls(root, values, tls_password)
    _configuration(root, values, fingerprints)
    options = [*PODMAN, "run", "--pull=never", "--rm", "--network=none", *_server_options(root)]
    print("Validating server configuration and preparing signing keys", flush=True)
    _run([*options, "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-server", images["server"],
          "--validate-config", "--config", "/deployment/config/server.json"])
    # Keys are created by the existing keyring tool; no raw CA signing key is exported.
    for alias in ("root", "intermediate"):
        _run([*options, "--entrypoint", "/opt/zeroecho/app/bin/app", images["server"], "-K", "--generate",
              "--alg", "RSA", "--alias", alias, "--keystore", "/deployment/keyring/ca-keyring.zek",
              "--keystore-password-env", "ZEROECHO_KEYRING_PASSWORD"])
    print("Creating the initial independent administrator pair", flush=True)
    _run([*options, "--entrypoint", "/opt/zeroecho/server/bin/zeroecho-pki-admin-bootstrap", images["server"],
          "--config", "/deployment/config/server.json", "--admin-id", values["admin"],
          "--approver-id", values["approver"], "--proxy-id", "trusted-proxy"])
    _run([*PODMAN, "network", "create", "--internal", prefix])
    network = json.loads(_run([*PODMAN, "network", "inspect", prefix], capture=True))
    addresses = _network_addresses(network)
    _units(root, values, images, prefix, addresses)
    manifest = {"version": 1, "prefix": prefix, "hostname": values["hostname"], "port": int(values["port"]),
                "bind": values["bind"], "images": images, "addresses": addresses,
                "admin": values["admin"], "approver": values["approver"]}
    _json(root / "installation.json", manifest)
    shutil.copyfile(Path(__file__), root / "manage.py")
    _write(root / "NEXT-STEPS.txt", f"""Web: https://{values['hostname']}:{values['port']}/
Published on: {values['bind']}
Import logins/administrator.p12 into the administrator browser; use its form password.
The initial administrator is root and may approve their own requests with a recorded reason.
Give logins/approver.p12 to an ordinary second administrator if you need a separate approver.
Import logins/web-ca.pem into browser trust if the edge CA is not already trusted.
Never give provisioning/ca.key or secrets.conf to either browser.
Signing keys: zeroecho-lib:root.prv and zeroecho-lib:intermediate.prv.
Create the root CA with the root-ca profile, then an intermediate with intermediate-ca.
Create the approval request explicitly, approve it, then use its approval ID to execute.
Only root has the own-decision permission; ordinary administrators still require another approver.
This installer enables only the admin API and console, not ACME/EST/OCSP/public listeners.
Protect and back up this entire directory consistently while the service is stopped.
Generated transport and login certificates expire after 365 days; arrange renewal before then.
Stop: python3 {root / 'manage.py'} stop --directory {root}
Status: python3 {root / 'manage.py'} status --directory {root}
To start at boot without login, the host administrator must enable user lingering.
Failure recovery: inspect journalctl --user -u {prefix}-server -u {prefix}-web.
Do not rerun install or remove state to recover signing operations.
""")
    unit_directory.mkdir(parents=True, exist_ok=True)
    for unit in (root / "units").glob("*.service"):
        (unit_directory / unit.name).symlink_to(unit)
    _run(["systemctl", "--user", "daemon-reload"])
    print("Starting user services and checking published administrator access", flush=True)
    _run(["systemctl", "--user", "enable", "--now", prefix + "-web.service"])
    _verify_edge(root, manifest)
    print((root / "NEXT-STEPS.txt").read_text())


def _verify_edge(root, manifest):
    # Validate the published edge and the mapped administrator, not merely container liveness.
    hostname, port = manifest["hostname"], manifest["port"]
    address = "127.0.0.1" if manifest["bind"] == "0.0.0.0" else manifest["bind"]
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            # Type=exec precedes nginx listening; retry only this read, never provisioning.
            _run(["curl", "--fail", "--silent", "--show-error", "--connect-timeout", "2",
                  "--max-time", "4", "--noproxy", "*", "--resolve", f"{hostname}:{port}:{address}",
                  "--cacert", root / "logins/web-ca.pem", "--cert", root / "provisioning/administrator.crt",
                  "--key", root / "provisioning/administrator.key",
                  f"https://{hostname}:{port}/admin/v1/realm"], capture=True)
            return
        except RuntimeError:
            time.sleep(1)
    raise RuntimeError("Published HTTPS administrator path not ready in 120 seconds; inspect both user service journals")


def _main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "update", "start", "stop", "status", "test-start", "_ready"))
    parser.add_argument("--directory", type=Path, default=Path.home() / ".local/share/zeroecho-pki", help="Installation state; test-start requires a new separate directory")
    parser.add_argument("--root-admin", action="store_true", help="With update, explicitly designate only the initial administrator for own-request approval")
    parser.add_argument("--certificate-access", action="store_true", help="With update, explicitly add certificate content/download access for the initial administrator pair")
    parser.add_argument("--status-access", action="store_true", help="With update, explicitly add status-object content download access for the initial administrator pair")
    args = parser.parse_args()
    if args.status_access and args.command != "update":
        parser.error("--status-access is only valid with update")
    if args.certificate_access and args.command != "update":
        parser.error("--certificate-access is only valid with update")
    if args.root_admin and args.command != "update":
        parser.error("--root-admin is only valid with update")
    os.umask(0o077)
    if args.command == "install":
        _install(curses.wrapper(_form, args.directory))
        return
    if args.command == "test-start":
        from exercise_environment import start
        start(args.directory)
        return
    root = args.directory.expanduser().resolve()
    if root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077:
        raise ValueError("Installation must be private and owned by the current user")
    manifest = json.loads((root / "installation.json").read_text())
    expected = "zeroecho-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    if manifest["prefix"] != expected:
        raise ValueError("Installation path changed; restore it at its original location")
    if args.command == "_ready":
        _ready(root, manifest)
    elif args.command == "update":
        _update(root, manifest, root_admin=args.root_admin, certificate_access=args.certificate_access, status_access=args.status_access)
    else:
        _preflight()
        names = [expected + "-web.service", expected + "-server.service"]
        if args.command == "status":
            result = subprocess.run(["systemctl", "--user", "status", *names], check=False)
            sys.exit(result.returncode)
        else:
            _run(["systemctl", "--user", args.command, *names])
            if args.command == "start":
                _verify_edge(root, manifest)


if __name__ == "__main__":
    try:
        _main()
    except KeyboardInterrupt:
        print("Cancelled; no further action taken", file=sys.stderr)
        sys.exit(130)
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
