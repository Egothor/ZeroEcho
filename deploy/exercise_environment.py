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

"""Own the separate rootless qualification deployment and export client-only connection metadata."""
import copy
import hashlib
import json
import re
from pathlib import Path

from exercise_pki import ExerciseFailure, _atomic_json

DNS_PROVIDER = "zeroecho.dns-01.jndi.v1"


def prepare(root, configuration):
    """Enable all optional protocol listeners only in an already nonce-owned fresh fixture.

    Args:
        root: Fresh private disposable fixture root, never an installed production directory.
        configuration: Mutable generated configuration whose realm must match the owner nonce.
    Returns:
        Explicit enrollment companion environment for the disposable server only.
    Raises:
        ExerciseFailure: If ownership or the initial empty companion cannot be established.
    """
    root = Path(root)
    owner = json.loads((root / ".exercise-owner.json").read_text())
    nonce = owner.get("nonce", "")
    if root.is_symlink() or not re.fullmatch(r"[0-9a-f]{32}", nonce) or configuration["realm"]["realmId"] != "zeroecho-exercise-" + nonce:
        raise ExerciseFailure("Optional protocols require a nonce-owned disposable realm")
    policy = copy.deepcopy(configuration["realm"]["approvalPolicy"])
    policy["policyId"] = "isolated-protocol"
    policy.update(threshold=1, requesterSeparation=True, requiredRoleTemplateIds=[], justificationRequired=True, lifetimeMillis=3600000)
    approvers = ",".join(sorted(policy["eligibleApprovers"]))
    commitment = hashlib.sha256(("isolated-protocol|1|" + approvers + "||true|3600|true").encode()).hexdigest()
    configuration["realm"]["issuanceSingleApprovalPolicy"] = policy
    configuration["realm"]["extendedApprovalCommitment"] = hashlib.sha256(("ISSUANCE_SINGLE=" + commitment).encode()).hexdigest()
    tls = copy.deepcopy(configuration["listener"]["tlsProvider"])
    lane = copy.deepcopy(configuration["execution"])
    for protocol, port in (("est", 8446), ("scep", 8447), ("cmp", 8448)):
        configuration[protocol + "Listener"] = {"enabled": True, "listenerId": "exercise-" + protocol,
            "address": "0.0.0.0", "port": port, "tlsProvider": copy.deepcopy(tls), "execution": copy.deepcopy(lane),
            "maximumHeaderBytes": 16384, "maximumBodyBytes": 1048576}
    configuration["acmeListener"] = {"enabled": True, "listenerId": "exercise-acme", "address": "0.0.0.0", "port": 8445,
        "tlsProvider": tls, "transportMode": "DIRECT_TLS", "externalBaseUri": "https://localhost:8445",
        "maximumHeaderBytes": 16384, "maximumBodyBytes": 1048576, "execution": copy.deepcopy(lane), "validationExecution": copy.deepcopy(lane),
        "nonceLifetimeMillis": 300000, "maximumOutstandingNonces": 256, "maximumAccountsPresented": 32, "maximumOrdersPresented": 32,
        "admissionWindowMillis": 60000, "maximumNewAccountsPerWindow": 32, "maximumNewOrdersPerAccountWindow": 32,
        "maximumPendingOrdersPerAccount": 16, "maximumChallengeValidationsPerAccountWindow": 32, "maximumConcurrentFinalizations": 2,
        "challengeProviders": [{"id": DNS_PROVIDER, "properties": {"providerUrl": "dns://127.0.0.1:53535", "timeoutMillis": "1000", "maximumRecords": "8", "maximumRecordBytes": "1024", "maximumCnameDepth": "0"}}], "eabProviders": []}
    companion = root / "config/enrollment-runtime.json"
    if companion.exists():
        raise ExerciseFailure("Protocol companion already exists; refusing an implicit reset")
    _atomic_json(companion, {"version": 1, "budgets": {"maximumTransactions": 100, "maximumPending": 32,
        "maximumRetainedRequestBytes": 16777216, "maximumRequestBytes": 1048576, "maximumConcurrentDispatches": 2,
        "pendingLifetimeSeconds": 3600, "retryAfterSeconds": 1}, "keyrings": [], "credentialSets": [], "activeCredentials": []})
    return {"ZEROECHO_ENROLLMENT_CONFIG": "/deployment/config/enrollment-runtime.json"}



def prepare_fixture(root, configuration):
    """Prepare bounded optional providers before the fresh owned deployment starts.

    Args:
        root: Newly created private deployment root carrying its nonce owner marker.
        configuration: Mutable generated server configuration with the matching realm.
    Returns:
        Empty environment overrides; provider configuration is retained in the mapping.
    Raises:
        ExerciseFailure: The root is not the newly owned qualification deployment.
        OSError: Its private publication directory or public metadata cannot be written.
    """
    root=Path(root)
    if not root.is_dir() or root.is_symlink(): raise ExerciseFailure("Fresh fixture root is required")
    nonce = json.loads((root / ".exercise-owner.json").read_text()).get("nonce", "")
    if not re.fullmatch(r"[0-9a-f]{32}",nonce) or configuration["realm"]["realmId"] != "zeroecho-exercise-"+nonce:
        raise ExerciseFailure("Provider preparation requires the owned qualification realm")
    session=configuration["realm"]["pkiSession"]
    session["store"]["properties"].update({"credentialSearch":"h2","credentialSearchCacheKiB":"4096", "credentialSearchQueryTimeoutMillis":"10000", "credentialSearchMaximumCertificateBytes":"1048576"})
    target=root/"artifacts"/"publication"
    target.mkdir(mode=0o700,parents=True,exist_ok=True)
    signing=session.get("signing",{})
    metadata={"signatureAlgorithm":signing.get("signatureAlgorithm")}
    (root/"config").mkdir(mode=0o700,parents=True,exist_ok=True)
    path=root/"config/catalog-context.json"
    path.write_text(json.dumps(metadata))
    path.chmod(0o600)
    session.setdefault("publishers",[]).append({"id":"filesystem","properties":{"root":"/deployment/artifacts/publication","targetId":"exercise-files"}})
    return {}


def _copy_private(source, target):
    """Copy one deployment-selected client credential without exporting server custody.

    Args:
        source: Existing regular client credential or public certificate file.
        target: New file in the separate private client directory.
    Returns:
        None; the copy is private to its owner.
    Raises:
        ExerciseFailure: The source is a symlink or not a regular file.
        OSError: The private destination cannot be written.
    """
    import shutil
    if source.is_symlink() or not source.is_file():
        raise ExerciseFailure("Expected client credential is not a regular file")
    shutil.copyfile(source, target)
    target.chmod(0o600)



def _publication_id(environment_id, name):
    """Return the bounded identity accepted by the existing stopped-publication helper."""
    if not re.fullmatch(r"[0-9a-f]{32}", environment_id) or name not in ("retry", "reconcile"):
        raise ExerciseFailure("Invalid prepared publication identity")
    return "exercise-" + environment_id + "-prepared-" + name


def _provision(fixture, client, client_password, *, hybrid_sdk=False):
    """Perform explicit one-time environment preparation, never qualification test recipes.

    Args:
        fixture: Newly created nonce-owned Podman deployment.
        client: Separate empty private client credential directory.
        client_password: Startup P12 password, distinct from server keyring custody.
        hybrid_sdk: Explicit fresh qualification opt-in for administrative/public SDK origins
            and the existing public SDK minimum 16384-byte request budget; false preserves defaults.
    Returns:
        Strict client connection metadata containing no server custody or control channel.
    Raises:
        ExerciseFailure: Any preparation API, stopped helper or ownership receipt fails.
        OSError: Client credential export cannot be retained privately.
    """
    from exercise_pki import Exercise, _artifact
    import rootless_pki as installer
    fixture.bind(fixture.nonce)
    # The external directory must advertise the actual host-published origin, not its container listener port.
    fixture.configuration["acmeListener"]["externalBaseUri"] = fixture.protocol_urls["acme"]
    if hybrid_sdk:
        fixture.configuration["listener"]["hybridSdk"] = {"canonicalOrigin": fixture.admin_url}
        fixture.configuration["publicListener"]["hybridSdk"] = {"canonicalOrigin": fixture.public_url}
        fixture.configuration["publicListener"]["maximumBodyBytes"] = 16384
    _atomic_json(fixture.directory / "config/server.json", fixture.configuration)
    fixture.restart()
    preparation = Exercise(fixture.api, fixture.directory / "deployment-preparation")
    try:
        preparation.state["runId"] = fixture.nonce
        preparation.state["purpose"] = "DEPLOYMENT_PREPARATION_NOT_QUALIFICATION"
        preparation.save()
        preparation.discover()
        # Legacy verification belongs to the client. Export while the fresh realm is still small.
        archive = preparation.dedicated("prepare-legacy-archive", "backup.export", {"label": "environment-" + fixture.nonce})
        legacy_path = client / "legacy-backup.json"
        _atomic_json(legacy_path, archive)
        fixture.load_profiles()
        preparation.discover()
        created = preparation.job("prepare-protocol-root", "ca.create", {"formatId": "x509",
            "subjectRef": "CN=Qualification prerequisites " + fixture.nonce, "profileId": "root-ca", "keyRef": "zeroecho-lib:root.prv"})
        metadata = _artifact(preparation, "certificate", created["credentialId"], "protocol-root", 64 * 1024 * 1024)
        authority = metadata["authorityId"]
        fixture.offline_seed("ExerciseProtocolSeed", [authority, created["credentialId"]],
            authorization={"authorityId": authority, "credentialId": created["credentialId"]}, client_password=client_password)
        context = json.loads((fixture.directory / "config/protocol-context.json").read_text())
        profile = preparation.operation("profile.inspect", {"profileId": "server-tls", "profileVersion": 1}, authority)
        status = preparation.job("prepare-publication-source", "status.generate", {"issuerCaId": authority, "type": "CRL", "formatId": "x509"}, authority)
        _artifact(preparation, "status", status["statusObjectId"], "publication-source", 64 * 1024 * 1024)
        source_hash = hashlib.sha256((preparation.directory / "publication-source.der").read_bytes()).hexdigest()
        publications = {}
        for name, state in (("retry", "RETRYABLE_FAILURE"), ("reconcile", "OUTCOME_UNKNOWN")):
            identity = _publication_id(fixture.nonce, name)
            preparation.job("prepare-publication-" + name, "publication.register", {"publicationId": identity,
                "sourceType": "STATUS_OBJECT", "sourceId": status["statusObjectId"], "targetType": "FILESYSTEM", "targetId": "exercise-files"}, authority)
            fixture.offline_seed("ExerciseCatalogStateSeed", [identity, source_hash, state],
                authorization={"publicationId": identity, "sourceSha256": source_hash, "state": state})
            publications[name] = {"publicationId": identity, "sourceSha256": source_hash, "authorityId": authority, "sourceId": status["statusObjectId"]}
        public = client / "public"
        public.mkdir(mode=0o700)
        for name in ("authority", "est-ra", "scep-ra", "cmp-ra", "cmp-client"):
            _copy_private(fixture.directory / ("keyring/protocol-custody/" + name + ".der"), public / (name + ".der"))
        (client / "protocol-client").mkdir(mode=0o700)
        # The authenticated nonce reservation is mandatory for opening the copied ring in a cold client JVM.
        for name in ("client.zek", "client.zek.nonce"):
            _copy_private(fixture.directory / "protocol-client" / name, client / "protocol-client" / name)
        for source, target in (("logins/administrator.p12", "administrator.p12"), ("logins/web-ca.pem", "trust.pem"),
                ("provisioning/approver.crt", "requester.crt"), ("provisioning/approver.key", "requester.key")):
            _copy_private(fixture.directory / source, client / target)
        # The DNS process sees only a public TXT input directory, never PKI configuration or signing keys.
        (client / "dns").mkdir(mode=0o700)
        fixture.dns_records_directory = client / "dns"
        fixture.start_protocol_dns()
        classes = fixture._helper_classes("ExerciseLegacyEnrollmentClient")
        return {"version": 1, "purpose": "qualification", "environmentId": fixture.nonce, "realmId": fixture.prefix,
            "adminUrl": fixture.admin_url, "publicUrl": fixture.public_url, "protocolUrls": fixture.protocol_urls,
            "adminPrincipalId": "exercise-admin", "adminP12": str(client / "administrator.p12"), "trustFile": str(client / "trust.pem"),
            "clientDirectory": str(client), "protocolAuthorityId": authority,
            "protocolEnrollmentProfileId": context["protocolEnrollmentProfileId"],
            "protocolPublicKeyAlgorithms": profile["publicKeyAlgorithms"], "protocolX509BindingPolicies": profile["x509BindingPolicies"],
            "challengeProviderIds": [DNS_PROVIDER], "clientJavaClasspath": [str(classes), str(installer.REPOSITORY / "pki-server/build/install/zeroecho-pki-server/lib/*")],
            "requesterCertificate": "requester.crt", "requesterKey": "requester.key", "acmeDirectoryOrigin": fixture.protocol_urls["acme"],
            "acmeDnsChallengeFile": "dns/protocol-dns.json", "acmeDnsNamespace": "example.invalid",
            "signatureAlgorithm": fixture.configuration["realm"]["pkiSession"]["signing"]["signatureAlgorithm"],
            "rootKeyRef": "zeroecho-lib:root.prv", "intermediateKeyRef": "zeroecho-lib:intermediate.prv", "rotationKeyRef": "zeroecho-lib:rotation.prv", "publicationTargetId": "exercise-files",
            "preparedPublications": publications, "legacyBackup": {"backupId": archive["backupId"], "path": "legacy-backup.json", "sha256": hashlib.sha256(legacy_path.read_bytes()).hexdigest()}}
    finally:
        preparation.close()



def _failed_client_export(client, identity):
    """Remove only this invocation's empty client directory; retain any credentials or evidence."""
    import os
    import stat
    try:
        current = client.lstat()
        if stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid() and (current.st_dev,current.st_ino) == identity and not any(client.iterdir()):
            client.rmdir()
            return
    except OSError:
        pass
    print("Client preparation state retained: " + str(client), flush=True)


def start(directory, *, client_directory=None, read_command=input, password_prompt=None, hybrid_sdk=False):
    """Start the separate foreground Podman environment and own its lifecycle until stop.

    Args:
        directory: New deployment state directory; existing paths are refused.
        client_directory: Optional new sibling directory for client-only credentials.
        read_command: Console input seam for status, restart and stop commands.
        password_prompt: Optional hidden startup P12 password prompt seam.
        hybrid_sdk: Explicit fresh SDK qualification opt-in; false preserves native-only defaults.
    Returns:
        None after stop; the client exports remain available independently.
    Raises:
        ExerciseFailure: Existing state, unsafe paths, preparation or owned lifecycle control fails.
        OSError: Fresh private state cannot be created.
    """
    import getpass
    import os
    import rootless_pki as installer
    from exercise_fixture import DisposableFixture
    root = Path(directory).expanduser().absolute()
    client = Path(client_directory).expanduser().absolute() if client_directory else root.with_name(root.name + "-client")
    if root.exists() or root.is_symlink() or client.exists() or client.is_symlink() or root == client or root in client.parents or client in root.parents:
        raise ExerciseFailure("Use two new separate deployment and client directories")
    if not root.parent.is_dir() or not client.parent.is_dir():
        raise ExerciseFailure("Deployment and client parent directories must exist")
    prompt = password_prompt or getpass.getpass
    password = prompt("New administrator PKCS#12 password: ")
    if not password or any(c in password for c in "\r\n\0") or len(password) > 1024 or password != prompt("Repeat administrator PKCS#12 password: "):
        raise ExerciseFailure("Client passwords must match and be nonempty")
    os.umask(0o077)
    import shutil
    import subprocess
    import sys
    if sys.platform != "linux" or os.geteuid() == 0 or any(not shutil.which(name) for name in ("podman", "openssl", "java")):
        raise ExerciseFailure("Qualification deployment requires Linux, rootless Podman, OpenSSL and Java as an ordinary user")
    help_result = subprocess.run(["openssl", "pkcs12", "-help"], capture_output=True, check=False)
    if b"-jdktrust" not in help_result.stdout + help_result.stderr:
        raise ExerciseFailure("OpenSSL pkcs12 -jdktrust support is required")
    images = {"server": installer._image("localhost/zeroecho-pki-server:installer", "deploy/pki-server/Dockerfile"),
              "web": installer._image("localhost/zeroecho-pki-nginx:installer", "deploy/nginx/Dockerfile")}
    def configure(fresh_root, configuration):
        prepare_fixture(fresh_root, configuration)
        return prepare(fresh_root, configuration)
    client.mkdir(mode=0o700)
    metadata = client.lstat()
    identity = (metadata.st_dev, metadata.st_ino)
    ready = False
    try:
        with DisposableFixture(images, prepare=configure, directory=root, login_password=password) as fixture:
            if hybrid_sdk:
                connection = _provision(fixture, client, password, hybrid_sdk=True)
            else:
                connection = _provision(fixture, client, password)
            _atomic_json(client / "client-config.json", connection)
            ready = True
            print("READY " + str(client / "client-config.json"), flush=True)
            print("Environment console: status | restart | stop. Tests run separately in another terminal.", flush=True)
            while True:
                try:
                    command = read_command("pki-environment> ").strip()
                except (EOFError, KeyboardInterrupt):
                    command = "stop"
                if command == "stop":
                    return
                if command == "restart":
                    fixture.restart()
                    print("READY " + str(client / "client-config.json"), flush=True)
                elif command == "status":
                    fixture.assert_disposable(fixture.admin_url, fixture.run_id)
                    print("RUNNING " + fixture.admin_url, flush=True)
                else:
                    print("Use status, restart or stop.", flush=True)
    except BaseException:
        if not ready:
            _failed_client_export(client, identity)
        raise
