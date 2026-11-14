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

"""Host-only HTTPS protocol qualification using public connection metadata and owned client keys."""
import base64
import hashlib
import http.client
import json
import re
import ssl
import time
import subprocess
import traceback
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, urlsplit

from exercise_pki import Api, ExerciseFailure, _artifact, _atomic_json, _openssl

DNS_PROVIDER = "zeroecho.dns-01.jndi.v1"


def _raw(api, method, path, body=None, media_type=None, accepted=(200,)):
    if not path.startswith("/") or path.startswith("//") or any(value in path for value in ("\r", "\n")):
        raise ExerciseFailure("Invalid protocol path")
    connection = http.client.HTTPSConnection(api.host, api.port, context=api.context, timeout=30)
    try:
        headers = {} if media_type is None else {"Content-Type": media_type}
        if media_type == "application/pkcs10": headers["Content-Transfer-Encoding"] = "base64"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read(1048577)
        if len(content) > 1048576 or response.status not in accepted:
            raise ExerciseFailure("Protocol prerequisite failed: " + method + " " + str(response.status), response.status)
        return response.status, {key.lower(): value for key, value in response.getheaders()}, content
    finally:
        connection.close()


def _b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _ecdsa_jose(encoded):
    if len(encoded) < 8 or encoded[0] != 0x30 or encoded[1] != len(encoded) - 2: raise ExerciseFailure("Invalid P-256 signature encoding")
    offset, values = 2, []
    for _ in range(2):
        if encoded[offset] != 2: raise ExerciseFailure("Invalid P-256 signature integer")
        size = encoded[offset + 1]; value = encoded[offset + 2:offset + 2 + size]; offset += 2 + size
        if not value or value[0] & 128 or len(value.lstrip(b"\0")) > 32: raise ExerciseFailure("Invalid P-256 signature component")
        values.append(value.lstrip(b"\0").rjust(32, b"\0"))
    if offset != len(encoded): raise ExerciseFailure("Trailing P-256 signature bytes")
    return b"".join(values)


def _wire_account(exercise, client, values):
    api = Api(client.protocol_urls["acme"], client.trust_file)
    api.acme_origin=client.acme_origin
    alias = quote(values["directoryAlias"], safe="")
    prefix = "/acme/" + alias
    _, _, directory = _raw(api, "GET", prefix + "/directory")
    endpoints = json.loads(directory)
    account_url = endpoints["newAccount"]
    nonce_url = endpoints["newNonce"]
    for url in (account_url, nonce_url):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != urlsplit(client.acme_origin).netloc or not parsed.path.startswith(prefix + "/"):
            raise ExerciseFailure("ACME directory returned an unexpected origin or scope")
    _, headers, _ = _raw(api, "HEAD", urlsplit(nonce_url).path, accepted=(200, 204))
    nonce = headers.get("replay-nonce")
    if not nonce: raise ExerciseFailure("ACME nonce missing")
    key = exercise.directory / "protocol-account.key"
    if not key.exists():
        _openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key]); key.chmod(0o600)
    public = _openssl(["pkey", "-in", key, "-pubout", "-outform", "DER"])
    if len(public) < 65 or public[-65] != 4: raise ExerciseFailure("P-256 ACME public key unavailable")
    point = public[-64:]
    jwk = {"kty": "EC", "crv": "P-256", "x": _b64(point[:32]), "y": _b64(point[32:])}
    protected = _b64(json.dumps({"alg": "ES256", "nonce": nonce, "url": account_url, "jwk": jwk}, separators=(",", ":")).encode())
    payload = _b64(json.dumps({"termsOfServiceAgreed": True, "contact": []}, separators=(",", ":")).encode())
    signature = _openssl(["dgst", "-sha256", "-sign", key], data=(protected + "." + payload).encode("ascii"))
    signature = _ecdsa_jose(signature)
    body = json.dumps({"protected": protected, "payload": payload, "signature": _b64(signature)}, separators=(",", ":")).encode()
    _, headers, _ = _raw(api, "POST", urlsplit(account_url).path, body, "application/jose+json", accepted=(200, 201))
    location = headers.get("location", "")
    parsed = urlsplit(location)
    if parsed.netloc != urlsplit(client.acme_origin).netloc or not parsed.path.startswith(prefix + "/account/"):
        raise ExerciseFailure("ACME account location unavailable")
    return parsed.path.rsplit("/", 1)[1]


def _acme_post(api, prefix, url, payload, key, kid):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != urlsplit(getattr(api,"acme_origin",api.origin)).netloc or not parsed.path.startswith(prefix + "/") or parsed.query or parsed.fragment:
        raise ExerciseFailure("ACME continuation escaped its frozen directory")
    _, headers, _ = _raw(api, "HEAD", prefix + "/new-nonce", accepted=(200, 204))
    nonce = headers.get("replay-nonce")
    if not nonce: raise ExerciseFailure("ACME continuation nonce missing")
    protected = _b64(json.dumps({"alg": "ES256", "nonce": nonce, "url": url, "kid": kid}, separators=(",", ":")).encode())
    encoded = "" if payload is None else _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = _ecdsa_jose(_openssl(["dgst", "-sha256", "-sign", key], data=(protected + "." + encoded).encode()))
    request = json.dumps({"protected": protected, "payload": encoded, "signature": _b64(signature)}, separators=(",", ":")).encode()
    return _raw(api, "POST", parsed.path, request, "application/jose+json", accepted=(200, 201, 202))


def _approve_acme_owned(exercise, client, authority, csr_hash):
    page = exercise.operation("enrollment.request.list", {"offset": 0, "limit": 100})
    for row in page.get("items", []):
        if row.get("protocol") == "ACME" and row.get("authorityId") == authority and row.get("requestSha256") == csr_hash and row.get("state") == "PENDING":
            client.assert_disposable(exercise.api.origin, exercise.state["runId"])
            exercise.dedicated("protocol-acme-vote-" + row["id"], "enrollment.request.approve", {"id": row["id"], "expectedCommitment": row["commitment"],
                "justification": "Explicit disposable ACME issuance qualification " + exercise.state["runId"]})


def _dns_challenge(api, prefix, authorization, key, kid):
    # This deployment's authorization document contains challenge URLs, not inline challenge records.
    records = []
    for url in authorization.get("challenges", []):
        if not isinstance(url, str): raise ExerciseFailure("ACME challenge reference is not a URL")
        _, _, raw = _acme_post(api, prefix, url, None, key, kid)
        challenge = json.loads(raw)
        if not isinstance(challenge, dict): raise ExerciseFailure("ACME challenge response is not an object")
        if challenge.get("type") == "dns-01": records.append(challenge)
    if len(records) != 1: raise ExerciseFailure("One DNS-01 challenge is required")
    return records[0]


def _wire_acme_issue(exercise, client, values, context, account):
    api = Api(client.protocol_urls["acme"], client.trust_file)
    api.acme_origin=client.acme_origin
    prefix = "/acme/" + quote(values["directoryAlias"], safe="")
    kid = client.acme_origin + prefix + "/account/" + account
    key = exercise.directory / "protocol-account.key"
    name = "protocol-" + exercise.state["runId"] + "." + client.acme_namespace
    _, order_headers, raw = _acme_post(api, prefix, client.acme_origin + prefix + "/new-order", {"identifiers": [{"type": "dns", "value": name}]}, key, kid)
    order = json.loads(raw); order_url = order_headers.get("location")
    if not order_url or len(order.get("authorizations", [])) != 1: raise ExerciseFailure("ACME order did not retain its exact identifier")
    _, _, raw = _acme_post(api, prefix, order["authorizations"][0], None, key, kid)
    authorization = json.loads(raw)
    challenge = _dns_challenge(api, prefix, authorization, key, kid)
    public = _openssl(["pkey", "-in", key, "-pubout", "-outform", "DER"])[-64:]
    jwk = {"crv": "P-256", "kty": "EC", "x": _b64(public[:32]), "y": _b64(public[32:])}
    thumbprint = _b64(hashlib.sha256(json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()).digest())
    token = challenge["token"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", token): raise ExerciseFailure("Invalid DNS challenge token")
    txt = _b64(hashlib.sha256((token + "." + thumbprint).encode()).digest())
    _atomic_json(client.dns_challenge_file, {"nonce": client.environment_id, "runId": client.environment_id, "name": "_acme-challenge." + name, "value": txt})
    _acme_post(api, prefix, challenge["url"], {}, key, kid)
    until = exercise.clock() + 60
    while True:
        _, _, raw = _acme_post(api, prefix, order["authorizations"][0], None, key, kid)
        state = json.loads(raw).get("status")
        if state == "valid": break
        if state == "invalid" or exercise.clock() > until: raise ExerciseFailure("Actual DNS-01 validation did not succeed")
        exercise.sleep(0.2)
    client_key, csr = exercise.directory / "protocol-acme.key", exercise.directory / "protocol-acme.csr.der"
    if client_key.exists() or csr.exists(): raise ExerciseFailure("An earlier ACME issuance intent requires inspection")
    _openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name, "-addext", "subjectAltName=DNS:" + name, "-keyout", client_key, "-out", csr, "-outform", "DER"])
    client_key.chmod(0o600); csr.chmod(0o600)
    csr_bytes = csr.read_bytes()
    _acme_post(api, prefix, order["finalize"], {"csr": _b64(csr_bytes)}, key, kid)
    until = exercise.clock() + 90
    while True:
        _approve_acme_owned(exercise, client, values["protocolAuthorityId"], hashlib.sha256(csr_bytes).hexdigest())
        _, _, raw = _acme_post(api, prefix, order_url, None, key, kid); final = json.loads(raw)
        if final.get("status") == "valid": break
        if final.get("status") == "invalid" or exercise.clock() > until: raise ExerciseFailure("Actual ACME finalization did not issue a certificate")
        exercise.sleep(0.2)
    _, _, pem = _acme_post(api, prefix, final["certificate"], None, key, kid)
    certificate = exercise.directory / "protocol-acme.pem"; certificate.write_bytes(pem); certificate.chmod(0o600)
    authority = exercise.directory / "protocol-authority.pem"
    if not authority.exists():
        authority.write_bytes(_openssl(["x509", "-inform", "DER", "-outform", "PEM"], data=(client.directory / "public/authority.der").read_bytes())); authority.chmod(0o600)
    _verify_acme_chain(exercise,authority,certificate)
    if _openssl(["x509", "-in", certificate, "-pubkey", "-noout"]) != _openssl(["pkey", "-in", client_key, "-pubout"]): raise ExerciseFailure("ACME issued certificate does not match its retained private key")
    if ("DNS:" + name).encode() not in _openssl(["x509", "-in", certificate, "-noout", "-ext", "subjectAltName"]): raise ExerciseFailure("ACME certificate identifier differs")
    return {"state": "VERIFIED", "issuanceVerified": True, "keyMatchVerified": True, "chainVerified": True, "newAccountJws": "ES256", "dns01": "external preconfigured DNS-01", "issuance": "matched retained key and signed chain", "accountId": account}



def _wait_not_before(exercise, certificate):
    maximum_wait=2.0
    raw=_openssl(["x509","-in",certificate,"-noout","-startdate"]).decode("ascii").strip()
    try:
        if not raw.startswith("notBefore="):raise ValueError("Missing validity start")
        start=ssl.cert_time_to_seconds(raw[len("notBefore="):])
    except (ValueError,OverflowError) as failure:
        raise ExerciseFailure("ACME certificate validity start is malformed") from failure
    remaining=start-time.time()
    if remaining<=0:return
    if remaining>maximum_wait:raise ExerciseFailure("ACME certificate validity start exceeds the bounded wait")
    deadline=exercise.clock()+maximum_wait
    # Issuance can round notBefore into the next second; eligibility, not a retry delay, controls this wait.
    while remaining>0:
        budget=deadline-exercise.clock()
        if budget<=0:raise ExerciseFailure("ACME certificate did not become valid within the bounded wait")
        exercise.sleep(min(remaining,budget,0.05))
        remaining=start-time.time()


def _verify_acme_chain(exercise, authority, certificate):
    _wait_not_before(exercise,certificate)
    return _verified_openssl(exercise,"acme",["verify","-CAfile",authority,certificate])


def _wire_pending(exercise, client, values):
    api = Api(client.protocol_urls["est"], client.trust_file,
        client.requester_certificate, client.requester_key)
    before = exercise.operation("enrollment.request.list", {"offset": 0, "limit": 100})
    previous = {row["id"] for row in before.get("items", [])}
    for index in range(2):
        key, csr = exercise.directory / ("protocol-" + str(index) + ".key"), exercise.directory / ("protocol-" + str(index) + ".csr")
        if key.exists() or csr.exists(): raise ExerciseFailure("Uncertain protocol admission requires inspection, not automatic replay")
        _openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=protocol-" + str(index) + ".example.invalid", "-addext", "subjectAltName=DNS:protocol-" + str(index) + ".example.invalid", "-keyout", key, "-out", csr, "-outform", "DER"])
        key.chmod(0o600); csr.chmod(0o600)
        _raw(api, "POST", "/.well-known/est/" + quote(values["endpointLabel"], safe="") + "/simpleenroll", base64.b64encode(csr.read_bytes()), "application/pkcs10", accepted=(202,))
    after = exercise.operation("enrollment.request.list", {"offset": 0, "limit": 100})
    pending = [row for row in after.get("items", []) if row["id"] not in previous]
    hashes = {hashlib.sha256((exercise.directory / ("protocol-" + str(index) + ".csr")).read_bytes()).hexdigest(): index for index in range(2)}
    if len(pending) != 2 or any(row.get("protocol") != "EST" or row.get("state") != "PENDING" or row.get("requestSha256") not in hashes for row in pending):
        raise ExerciseFailure("Expected exactly two newly admitted owned EST transactions")
    pending.sort(key=lambda row: hashes[row["requestSha256"]])
    return pending


def _verified_openssl(exercise, protocol, arguments):
    if protocol not in {"est", "ocsp", "acme"} or arguments[0] not in {"verify", "ocsp"} or any(value in arguments for value in ("-passin", "-passout", "-signkey", "-key", "-secret")):
        raise ExerciseFailure("Invalid public verification diagnostic operation")
    completed = subprocess.run(["openssl", *map(str, arguments)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60)
    diagnostic = exercise.directory / ("protocol-" + protocol + "-openssl.log")
    diagnostic.touch(mode=0o600, exist_ok=True)
    with diagnostic.open("ab") as output:
        output.write(("command=" + arguments[0] + " returnCode=" + str(completed.returncode) + "\n").encode())
        output.write(completed.stderr[:16384]); output.write(b"\n")
    if completed.returncode: raise ExerciseFailure("OpenSSL verification or key operation failed: " + arguments[0])
    return completed.stdout


def _est_delivery(exercise, values, context):
    api = Api(context["protocolUrls"]["est"], context["trustFile"], context["requesterCertificate"], context["requesterKey"])
    until = exercise.clock() + 90
    csr = (exercise.directory / "protocol-0.csr").read_bytes()
    while True:
        status, _, body = _raw(api, "POST", "/.well-known/est/" + quote(values["endpointLabel"], safe="") + "/simpleenroll", base64.b64encode(csr), "application/pkcs10", accepted=(200, 202))
        if status == 200: break
        if exercise.clock() > until: raise ExerciseFailure("Approved EST transaction did not deliver a certificate")
        exercise.sleep(0.2)
    encoded = base64.b64decode(body.replace(b"\r", b"").replace(b"\n", b""), validate=True)
    pem = _openssl(["pkcs7", "-inform", "DER", "-print_certs"], data=encoded)
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    public = _openssl(["pkey", "-in", exercise.directory / "protocol-0.key", "-pubout"])
    matching = [block for block in blocks if _openssl(["x509", "-pubkey", "-noout"], data=block) == public]
    if len(matching) != 1: raise ExerciseFailure("EST response did not match the retained client private key")
    certificate = exercise.directory / "protocol-est.pem"; certificate.write_bytes(matching[0]); certificate.chmod(0o600)
    _verified_openssl(exercise, "est", ["verify", "-CAfile", exercise.directory / "protocol-authority.pem", certificate])
    if b"DNS:protocol-0.example.invalid" not in _openssl(["x509", "-in", certificate, "-noout", "-ext", "subjectAltName"]): raise ExerciseFailure("EST certificate identifier differs")
    exercise.state.setdefault("protocolWireProofs", {})["est"] = {"state": "VERIFIED", "issuanceVerified": True, "keyMatchVerified": True, "chainVerified": True, "issuance": "approved, protected retrieval, matched retained private key and signed chain"}
    exercise.save()
    return exercise.state["protocolWireProofs"]["est"]


def _approve_est(exercise, operation, values, context):
    from exercise_catalog import _call
    result = _call(exercise, context, "est-approve", operation, {"id": values["enrollmentApproveId"], "expectedCommitment": values["enrollmentApproveCommitment"], "justification": values["justification"]}, values["protocolAuthorityId"])
    _record_wire(exercise, "est", lambda: _est_delivery(exercise, values, context))
    return result


def _wire_scep(exercise, client, values):
    api = Api(client.protocol_urls["scep"], client.trust_file)
    endpoint = "/scep/" + quote(values["endpointLabel"], safe="")
    _, _, caps = _raw(api, "GET", endpoint + "?operation=GetCACaps")
    if b"POSTPKIOperation" not in caps or b"SHA-256" not in caps:
        raise ExerciseFailure("SCEP capability discovery did not return the configured protocol")
    _, _, encoded = _raw(api, "GET", endpoint + "?operation=GetCACert")
    certificates = _openssl(["pkcs7", "-inform", "DER", "-print_certs"], data=encoded)
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", certificates, re.S)
    expected = (client.directory / "public/authority.der").read_bytes()
    decoded = [_openssl(["x509", "-inform", "PEM", "-outform", "DER"], data=block) for block in blocks]
    if expected not in decoded: raise ExerciseFailure("SCEP discovery did not return the frozen CA")
    authority = exercise.directory / "protocol-authority.pem"
    authority.write_bytes(_openssl(["x509", "-inform", "DER", "-outform", "PEM"], data=expected)); authority.chmod(0o600)
    for block in blocks: _openssl(["verify", "-CAfile", authority], data=block)
    return {"state": "VERIFIED", "caSha256": hashlib.sha256(expected).hexdigest(), "certificateCount": len(blocks)}


def _ocsp_wire(exercise, operation, values, context):
    from exercise_catalog import _call
    result = _call(exercise, context, "ocsp-activate", operation, {"responderId": values["responderId"]}, values["authorityId"])
    public = context.get("publicApi")
    if public is None or public.client_authenticated: raise ExerciseFailure("Anonymous public OCSP endpoint is required")
    _artifact(exercise, "certificate", values["caCredentialId"], "ocsp-ca", 64 * 1024 * 1024)
    _artifact(exercise, "certificate", values["lifecycleCredentialId"], "ocsp-client", 64 * 1024 * 1024)
    ca, client = exercise.directory / "ocsp-ca.pem", exercise.directory / "ocsp-client.pem"
    request, response = exercise.directory / "protocol-ocsp-request.der", exercise.directory / "protocol-ocsp-response.der"
    _verified_openssl(exercise, "ocsp", ["ocsp", "-sha256", "-issuer", ca, "-cert", client, "-no_nonce", "-reqout", request])
    _, _, encoded = _raw(public, "POST", "/ocsp/" + quote(values["responderAlias"], safe=""), request.read_bytes(), "application/ocsp-request")
    response.write_bytes(encoded); response.chmod(0o600)
    verified = _verified_openssl(exercise, "ocsp", ["ocsp", "-respin", response, "-sha256", "-issuer", ca, "-cert", client, "-CAfile", ca, "-no_nonce"]).decode()
    if ": revoked" not in verified: raise ExerciseFailure("Signed OCSP response does not match the catalogue leaf's actual revoked state")
    exercise.state.setdefault("protocolWireProofs", {})["ocsp"] = {"state": "VERIFIED", "certificateStatus": "REVOKED", "credentialId": values["lifecycleCredentialId"]}
    exercise.save()
    return result


def _record_wire(exercise, protocol, action):
    try:
        proof = action()
        if not isinstance(proof, dict) or proof.get("state") != "VERIFIED": raise ExerciseFailure("Protocol verifier returned no positive proof")
    except Exception as failure:
        frames = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name} for frame in traceback.extract_tb(failure.__traceback__)[-12:]]
        diagnostic = {"failureClass": failure.__class__.__name__, "frames": frames}
        attribute = getattr(failure, "name", None)
        if isinstance(failure, AttributeError) and isinstance(attribute, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,64}", attribute): diagnostic["attribute"] = attribute
        _atomic_json(exercise.directory / ("protocol-" + protocol + "-diagnostic.json"), diagnostic)
        proof = {"state": "FAILED", "reason": str(failure) if isinstance(failure, ExerciseFailure) else failure.__class__.__name__}
    exercise.state.setdefault("protocolWireProofs", {})[protocol] = proof
    exercise.save()
    return proof



def _client_path(root, value, *, required=True, private=False):
    """Resolve only a bounded regular client-owned file beneath the declared client directory."""
    import os
    import stat
    candidate=Path(value)
    if candidate.is_absolute() or '..' in candidate.parts or not candidate.parts:
        raise ExerciseFailure("Client prerequisite path escapes the client directory")
    path=root/candidate
    if not path.resolve().is_relative_to(root.resolve()) or any((root/Path(*candidate.parts[:index])).is_symlink() for index in range(1,len(candidate.parts)+1)):
        raise ExerciseFailure("Client prerequisite path is a symlink or outside the client directory")
    if not path.exists():
        if required: raise ExerciseFailure("Client prerequisite is missing: "+str(candidate))
        return path
    metadata=path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>16*1024*1024:
        raise ExerciseFailure("Client prerequisite is not a bounded regular file")
    if private and (metadata.st_uid!=os.geteuid() or metadata.st_mode&0o077):
        raise ExerciseFailure("Client credential is not private to its owner")
    return path


def prepare_client_context(exercise, connection):
    """Prepare host protocol callbacks using only the private public/client manifest.

    Args:
        exercise: Existing HTTPS administrative client with its own private output directory.
        connection: Validated qualification manifest plus in-memory clientPassword and
            assert_disposable callables; no server configuration, container handle or secret.
    Returns:
        Protocol scope and callbacks for enrollment, ACME issuance and public OCSP verification.
    Raises:
        ExerciseFailure: Required client material, declared external DNS input, helper
            classpath, private password provider or live HTTPS realm guard is unavailable.
    """
    import os
    required={'clientDirectory','trustFile','protocolUrls','environmentId','realmId','protocolAuthorityId','protocolEnrollmentProfileId','protocolPublicKeyAlgorithms','protocolX509BindingPolicies','challengeProviderIds','acmeDnsChallengeFile'}
    if not isinstance(connection,dict) or required-set(connection):
        raise ExerciseFailure("Required client connection metadata is missing")
    declared_root=Path(connection['clientDirectory'])
    if declared_root.is_symlink(): raise ExerciseFailure("Client directory is a symlink")
    root=declared_root.resolve()
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid!=os.geteuid() or root.stat().st_mode&0o077:
        raise ExerciseFailure("Client directory must be private and owned by the invoking user")
    if connection.get('version')!=1 or connection.get('purpose')!='qualification' or not re.fullmatch(r'[0-9a-f]{32}',connection.get('environmentId','')):
        raise ExerciseFailure("A declared qualification client manifest is required")
    guard=connection.get('assert_disposable')
    password=connection.get('clientPassword')
    if not callable(guard) or not callable(password):
        raise ExerciseFailure("Live HTTPS realm guard and in-memory client password are required")
    guard(exercise.api.origin,exercise.state['runId'])
    config=_client_path(root,'client-config.json',private=True)
    declared=json.loads(config.read_text())
    for field in ('version','purpose','environmentId','realmId'):
        if declared.get(field)!=connection.get(field): raise ExerciseFailure("Client manifest identity differs from the selected connection")
    for name in ('authority','scep-ra','cmp-ra','cmp-client'):
        _client_path(root,'public/'+name+'.der')
    _client_path(root,'protocol-client/client.zek',private=True)
    requester=_client_path(root,connection.get('requesterCertificate','requester.crt'))
    requester_key=_client_path(root,connection.get('requesterKey','requester.key'),private=True)
    classpath=connection.get('clientJavaClasspath')
    if not isinstance(classpath,list) or not classpath or any(not isinstance(value,str) or not value or '\0' in value or '\n' in value or not Path(value[:-2] if value.endswith('/*') else value).exists() for value in classpath):
        raise ExerciseFailure("Prepared host Java client classpath is unavailable")
    namespace=connection.get('acmeDnsNamespace','')
    if not isinstance(namespace,str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',namespace):
        raise ExerciseFailure("An externally prepared ACME DNS namespace is required")
    dns_file=_client_path(root,connection['acmeDnsChallengeFile'],required=False)
    if not dns_file.parent.is_dir(): raise ExerciseFailure("External DNS input parent is missing")
    origin=connection.get('acmeDirectoryOrigin',connection['protocolUrls']['acme']).rstrip('/')
    parsed=urlsplit(origin)
    if parsed.scheme!='https' or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise ExerciseFailure("Invalid declared ACME directory origin")
    client=SimpleNamespace(directory=root,trust_file=Path(connection['trustFile']),protocol_urls=connection['protocolUrls'],
        requester_certificate=requester,requester_key=requester_key,acme_origin=origin,acme_namespace=namespace,
        environment_id=connection['environmentId'],dns_challenge_file=dns_file,assert_disposable=guard)
    context={key:connection[key] for key in ('protocolAuthorityId','protocolEnrollmentProfileId','protocolPublicKeyAlgorithms',
        'protocolX509BindingPolicies','challengeProviderIds','protocolUrls','clientDirectory','trustFile')}
    context.update(requesterCertificate=requester,requesterKey=requester_key,assert_disposable=guard,
        acmeDnsNamespace=namespace,acmeDirectoryOrigin=origin)

    def legacy_client(protocol, phase):
        guard(exercise.api.origin,exercise.state['runId'])
        secret=password()
        if not isinstance(secret,str) or not secret or any(value in secret for value in '\r\n\0'):
            raise ExerciseFailure("Invalid private client keyring password")
        result=subprocess.run(['java','-cp',os.pathsep.join(classpath),'zeroecho.pki.server.ExerciseLegacyEnrollmentClient',
            str(root),connection['environmentId'],exercise.state['runId'],protocol,phase],input=(secret+'\n').encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
        del secret
        if result.returncode or result.stdout.strip()!=b'LEGACY_CLIENT_READY':
            raise ExerciseFailure("Host legacy enrollment client failed during "+phase)
    context['legacy_client']=legacy_client

    def seed_enrollment(adapter, operation, values, active):
        guard(adapter.api.origin,adapter.state['runId'])
        _record_wire(adapter,'scep',lambda:_wire_scep(adapter,client,values))
        pending=_wire_pending(adapter,client,values)
        values.update(enrollmentApproveId=pending[0]['id'],enrollmentRejectId=pending[1]['id'],enrollmentRejectCommitment=pending[1]['commitment'])
        from exercise_legacy_protocols import qualify
        for protocol in ('scep','cmp'):
            _record_wire(adapter,protocol,lambda protocol=protocol:qualify(adapter,active,values,protocol))
        return adapter.operation(operation,{'id':values['enrollmentApproveId']})

    def seed_account(adapter, operation, values, active):
        guard(adapter.api.origin,adapter.state['runId'])
        values['accountId']=_wire_account(adapter,client,values)
        _record_wire(adapter,'acme',lambda:_wire_acme_issue(adapter,client,values,active,values['accountId']))
        return adapter.operation(operation,{'accountId':values['accountId']})
    context['scenarios']={'seed_enrollment':seed_enrollment,'seed_acme_account':seed_account,
        'ocsp_wire':_ocsp_wire,'approve_enrollment':_approve_est}
    return context
