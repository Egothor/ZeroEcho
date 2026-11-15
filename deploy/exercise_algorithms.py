"""External C04 certificate scenarios over existing administrative HTTPS contracts.

No container, server configuration, store or server private-key access is permitted.
The Java helper uses local applicant keys and public downloaded certificates only.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import secrets
import struct
import subprocess

from exercise_pki import ExerciseFailure, _artifact, _atomic_json, _private_file, _result, _json_bytes

VARIANTS = {"p384": ("ECDSA_P384", "ECDSA"), "rsa4096": ("RSA_4096", "RSA"),
            "mldsa87": ("ML_DSA_87", "ML-DSA"), "hybrid": ("ECDSA_P384", "ECDSA")}
MEDIA = "application/vnd.zeroecho.hybrid-sdk+json"
PROFILE = "zeroecho-hybrid-sdk-v1"


def _b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value):
    if not isinstance(value, str) or len(value) > 1400000:
        raise ExerciseFailure("Invalid bounded SDK encoding")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise ExerciseFailure("Invalid SDK encoding") from error
    if _b64(decoded) != value:
        raise ExerciseFailure("Noncanonical SDK encoding")
    return decoded


def _value(value):
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return b"\x01" + struct.pack(">I", len(encoded)) + encoded
    if type(value) is bool:
        return b"\x03" + bytes([value])
    if type(value) is int:
        return b"\x02" + struct.pack(">q", value)
    if isinstance(value, bytes):
        return b"\x04" + struct.pack(">I", len(value)) + value
    if isinstance(value, list):
        return b"\x05" + struct.pack(">I", len(value)) + b"".join(map(_value, value))
    if isinstance(value, dict):
        fields = []
        for key in sorted(value):
            encoded = key.encode("ascii")
            if not 1 <= len(encoded) <= 128:
                raise ExerciseFailure("Invalid SDK value key")
            fields.append(struct.pack(">H", len(encoded)) + encoded + _value(value[key]))
        return b"\x06" + struct.pack(">I", len(fields)) + b"".join(fields)
    raise ExerciseFailure("Unsupported SDK target value")


def _frame(kind, fields):
    return b"ZeroEcho-Hybrid-SDK\x00" + struct.pack(">HHH", 1, kind, len(fields)) + b"".join(
        struct.pack(">HI", tag, len(value)) + value for tag, value in sorted(fields.items()))


def _fields(encoded, kind, tags):
    prefix = b"ZeroEcho-Hybrid-SDK\x00"
    if len(encoded) > 1048576 or not encoded.startswith(prefix) or len(encoded) < len(prefix) + 6:
        raise ExerciseFailure("Invalid SDK frame")
    version, observed, count = struct.unpack_from(">HHH", encoded, len(prefix))
    if (version, observed, count) != (1, kind, len(tags)):
        raise ExerciseFailure("Unexpected SDK frame kind or fields")
    offset, result = len(prefix) + 6, {}
    try:
        for expected in tags:
            tag, size = struct.unpack_from(">HI", encoded, offset)
            offset += 6
            if tag != expected or size > 262144 or offset + size > len(encoded):
                raise ExerciseFailure("Invalid SDK frame field")
            result[tag] = encoded[offset:offset + size]
            offset += size
    except struct.error as error:
        raise ExerciseFailure("Truncated SDK frame") from error
    if offset != len(encoded):
        raise ExerciseFailure("Trailing SDK frame bytes")
    return result


def _read_value(encoded):
    def read(offset, depth):
        if depth > 8 or offset >= len(encoded):
            raise ExerciseFailure("Invalid bounded SDK value")
        kind = encoded[offset]
        offset += 1
        if kind == 2:
            return struct.unpack_from(">q", encoded, offset)[0], offset + 8
        if kind == 3:
            if encoded[offset] not in (0, 1):
                raise ExerciseFailure("Invalid SDK boolean")
            return bool(encoded[offset]), offset + 1
        count = struct.unpack_from(">I", encoded, offset)[0]
        offset += 4
        if kind in (1, 4):
            if count > 262144 or offset + count > len(encoded):
                raise ExerciseFailure("Invalid SDK scalar")
            value = encoded[offset:offset + count]
            return (value.decode("utf-8") if kind == 1 else value), offset + count
        if count > 4096 or kind not in (5, 6):
            raise ExerciseFailure("Invalid SDK collection")
        result = [] if kind == 5 else {}
        for _ in range(count):
            if kind == 6:
                size = struct.unpack_from(">H", encoded, offset)[0]
                offset += 2
                if not 1 <= size <= 128 or offset + size > len(encoded):
                    raise ExerciseFailure("Invalid SDK object key")
                key = encoded[offset:offset + size].decode("ascii")
                offset += size
            value, offset = read(offset, depth + 1)
            if kind == 5:
                result.append(value)
            else:
                if key in result:
                    raise ExerciseFailure("Duplicate SDK object key")
                result[key] = value
        return result, offset
    try:
        value, offset = read(0, 0)
        if offset != len(encoded) or _value(value) != encoded:
            raise ExerciseFailure("Noncanonical SDK value")
        return value
    except (IndexError, struct.error, UnicodeError) as error:
        raise ExerciseFailure("Malformed SDK value") from error


def _public_value(value):
    if isinstance(value, bytes):
        return {"base64url": _b64(value)}
    if isinstance(value, list):
        return [_public_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _public_value(item) for key, item in value.items()}
    return value


def _sdk_json(api, path, document):
    from exercise_protocols import _raw
    status, _, raw = _raw(api, "POST", path, json.dumps(document, separators=(",", ":")).encode(), MEDIA, accepted=(200, 202))
    return status, _json_bytes(raw)


def _crypto(options, *arguments):
    completed = subprocess.run(["java", "-cp", options.crypto_classpath,
        "zeroecho.pki.cli.CertificateScenarioCrypto", *map(str, arguments)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    if completed.returncode:
        raise ExerciseFailure("Scenario cryptographic helper failed; no cryptographic success is claimed")
    return completed.stdout.decode("ascii").strip()


def _profiles(variant, run_id, alternative, signature):
    directory = Path(__file__).parent / "pki-server/profiles"
    result = {}
    family = VARIANTS[variant][1]
    for role, template in (("root", "root-ca"), ("intermediate", "intermediate-ca"), ("client", "vpn-client")):
        profile = json.loads((directory / (template + ".json")).read_text())
        profile.update(profileId="scenario-" + run_id + "-" + role, displayName="C04 " + variant + " " + role)
        if role == "client":
            profile["leafCertificate"]["allowedKeyAlgorithms"] = [family]
        else:
            profile["caCertificate"]["allowedSubjectKeyAlgorithms"] = [family]
        if variant == "hybrid":
            profile["hybridMode"] = {"type": "ALT_SIGNATURE", "altSignatureAlgorithmId": signature}
            if role == "client":
                profile["hybridMode"]["subjectKeySource"] = "REQUEST"
            else:
                profile["hybridMode"]["altKeyRef"] = alternative[role]["keyRef"]
        result[role] = profile
    return result


def _role_frame(kind, binding, spki):
    if binding["subjectSpkiSha256"] != hashlib.sha256(spki).hexdigest():
        raise ExerciseFailure("Issuer role SPKI does not match generation metadata")
    return _frame(kind, {1: binding["keyRef"].encode(), 2: binding["publicKeyAlgorithmId"].encode(),
        3: binding["signatureAlgorithmId"].encode(), 4: _decode(binding["signatureAlgorithmIdentifierDer"]),
        5: hashlib.sha512(spki).digest()})


def _validate_target(target, *, arguments, principal, ca, generation, path, profile, issuer_der,
                     issuer_spki, issuer_alternative, effective, disclosure, approval_commitment):
    fields = _fields(target, 7, range(1, 18))
    binding = generation["cryptographicBinding"]
    expected = {1: b"credential.issue", 2: _value(arguments), 3: principal.encode(), 4: ca.encode(),
        5: generation["issuerId"].encode(), 6: path["pathId"].encode(),
        7: ("sha512:" + hashlib.sha512(issuer_der).hexdigest()).encode(),
        8: _role_frame(8, binding["primary"], issuer_spki),
        9: _role_frame(9, binding["alternative"], issuer_alternative),
        10: profile["profileId"].encode(), 11: struct.pack(">Q", profile["profileVersion"]),
        12: ("sha256:" + profile["canonicalSha256"]).encode(),
        14: ("sha256:" + approval_commitment).encode(), 15: _value(effective),
        16: _value(disclosure), 17: _value({})}
    if any(fields[tag] != value for tag, value in expected.items()):
        raise ExerciseFailure("SDK target differs from the explicit selected scenario")
    # Provider authority is frozen by the server; retain the opaque commitment, never infer it from incoming signatures.
    if not fields[13].startswith(b"sha512:") or len(fields[13]) != 135:
        raise ExerciseFailure("SDK binding-set commitment is invalid")
    if binding["certificateSha256"] != hashlib.sha256(issuer_der).hexdigest():
        raise ExerciseFailure("Issuer certificate does not match immutable binding")
    return hashlib.sha512(target).hexdigest()


def _created_generation(exercise, credential_id):
    arguments = {"limit": 100}
    matches = []
    while True:
        page = exercise.operation("ca.list", arguments)
        for authority in page.get("authorities", []):
            generation = exercise.operation("issuer.generation.inspect", {"issuerId": authority["currentIssuanceIssuerId"]})
            if generation["credentialId"] == credential_id:
                matches.append(generation)
        if not page.get("truncated"):
            break
        following = page.get("nextCursor")
        if not isinstance(following, str) or following == arguments.get("after"):
            raise ExerciseFailure("Authority inventory did not advance")
        arguments["after"] = following
    if len(matches) != 1:
        raise ExerciseFailure("Created CA credential has no unique current outgoing issuer generation")
    return matches[0]


def _sdk_issue(exercise, options, arguments, authority, context, certificate):
    retained = exercise.state.setdefault("algorithmSdk", {})
    keys = exercise.directory / "client-keys"
    request = (keys / "client.csr.der").read_bytes()
    base = {"version": 1, "profile": PROFILE, "operationId": "credential.issue",
            "arguments": arguments, "requestDer": _b64(request)}
    if not retained:
        retained.update(base=base, nonce=secrets.token_hex(32), challengeAttempted=False, acceptAttempted=False)
        exercise.save()
    if retained["base"] != base:
        raise ExerciseFailure("Retained SDK request changed")
    if "challenge" not in retained:
        if retained["challengeAttempted"]:
            raise ExerciseFailure("SDK challenge acknowledgement unknown; retain this output for operator reconciliation")
        retained["challengeAttempted"] = True
        exercise.save()
        _, challenge = _sdk_json(exercise.api, "/admin/v1/hybrid-sdk/v1/challenge",
            dict(base, clientNonce=_b64(bytes.fromhex(retained["nonce"]))))
        if set(challenge) != {"version", "profile", "intentId", "primaryFrame", "alternativeFrame", "targetFrame", "expiresAt"} or challenge["version"] != 1 or challenge["profile"] != PROFILE:
            raise ExerciseFailure("Malformed SDK challenge")
        retained["challenge"] = challenge
        exercise.save()
    challenge = retained["challenge"]
    f1, f2, f7 = (_decode(challenge[name]) for name in ("primaryFrame", "alternativeFrame", "targetFrame"))
    first = _fields(f1, 1, range(1, 18))
    if first[3].hex() != challenge["intentId"]:
        raise ExerciseFailure("SDK intent identity differs from challenge")
    fields = _fields(f7, 7, range(1, 18))
    effective, disclosure = _read_value(fields[15]), _read_value(fields[16])
    if not isinstance(effective, dict) or effective.get("subjectRef") != "CN=ZeroEcho scenario client" or effective.get("rdns") != [{"type": "COMMON_NAME", "value": "ZeroEcho scenario client"}] or effective.get("sans") != [{"type": "URI", "value": "spiffe://zeroecho.invalid/scenario/client"}]:
        raise ExerciseFailure("SDK proposed subject or SAN differs from applicant")
    commitment = fields[14].decode("ascii")
    if not commitment.startswith("sha256:") or len(commitment) != 71:
        raise ExerciseFailure("Invalid SDK approval commitment")
    target_digest = _validate_target(f7, effective=effective, disclosure=disclosure,
        approval_commitment=commitment[7:], **context)
    proposal = {"targetSha512": target_digest, "effectiveSubject": _public_value(effective), "disclosure": _public_value(disclosure),
        "approvalCommitment": commitment, "bindingSetCommitment": fields[13].decode("ascii"),
        "expiresAt": challenge["expiresAt"], "selectedArguments": arguments,
        "issuerId": context["generation"]["issuerId"], "pathId": context["path"]["pathId"]}
    _atomic_json(exercise.directory / "sdk-target-proposal.json", proposal)
    if options.approved_sdk_target != target_digest:
        raise ExerciseFailure("Review sdk-target-proposal.json (including exact validity and policies), then repeat this command within challenge expiry with --approved-sdk-target " + target_digest)

    for name, content in (("primary.frame", f1), ("alternative.frame", f2), ("target.frame", f7)):
        destination = keys / name
        if destination.exists() and _private_file(destination).read_bytes() != content:
            raise ExerciseFailure("Retained SDK frame changed")
        destination.write_bytes(content)
        destination.chmod(0o600)
    if not retained.get("proofsReady"):
        auth_hash = _crypto(options, "auth-context", certificate, options.principal_id,
            options.sdk_authentication, options.sdk_transport_principal or "")
        _crypto(options, "sign", keys, keys / "primary.frame", keys / "alternative.frame", keys / "target.frame",
                exercise.api.origin, options.realm_id, retained["nonce"], target_digest, auth_hash)
        retained["proofsReady"] = True
        exercise.save()
    request_id = "exercise-" + exercise.state["runId"] + "-client"
    intent = {"version": 1, "requestId": request_id, "operation": "credential.issue", "arguments": arguments,
              "authorityId": authority}
    step = exercise.state["jobs"].setdefault("client", {"intent": intent, "attempted": True, "decisionAttempted": False})
    if step["intent"] != intent:
        raise ExerciseFailure("SDK receipt target changed")
    exercise.save()
    if not retained["acceptAttempted"]:
        retained["acceptAttempted"] = True
        exercise.save()
        payload = dict(base, intentId=challenge["intentId"], sdkRequestId=request_id,
            primaryProof=_b64(_private_file(keys / "primary.proof").read_bytes()),
            alternativeProof=_b64(_private_file(keys / "alternative.proof").read_bytes()))
        try:
            status, _ = _sdk_json(exercise.api, "/admin/v1/hybrid-sdk/v1/accept", payload)
            if status != 202:
                raise ExerciseFailure("SDK acceptance did not acknowledge a durable request")
        except ExerciseFailure as error:
            retained["acceptDiagnostic"] = str(error)
            exercise.save()
            if error.status in (400, 401, 403, 409, 422):
                raise
    return exercise.job("client", "credential.issue", arguments, authority)


def run(exercise, options, certificate):
    """Execute one approved hierarchy, retaining local keys, HTTP receipts and crypto evidence.

    Args:
        exercise: Existing locked external HTTPS exercise and durable job machinery.
        options: Explicit variant, realm, principal, helper classpath and optional SDK auth context.
        certificate: Temporary extracted applicant login leaf for trusted F6 derivation.
    Returns:
        None after certificate verification and a scenario-only report; no Podman qualification.
    Raises:
        ExerciseFailure: Missing prerequisite, changed retained target or failed cryptographic evidence.
        OSError: Local client evidence cannot be read or retained.
        subprocess.SubprocessError: Local helper failed to start or timed out.
    """
    if options.variant not in VARIANTS or not options.realm_id or not options.principal_id or not options.crypto_classpath:
        raise ExerciseFailure("Algorithm scenarios require explicit variant, realm, principal and crypto classpath")
    if options.variant == "hybrid" and (options.sdk_authentication not in ("direct-mtls-v1", "trusted-proxy-mtls-v1") or
        (options.sdk_authentication == "trusted-proxy-mtls-v1") != bool(options.sdk_transport_principal)):
        raise ExerciseFailure("Hybrid scenario requires the actual administrative authentication and proxy identity")
    _atomic_json(exercise.directory / "algorithm-report.json", {"version": 1, "variant": options.variant,
        "verified": False, "podmanQualified": False, "environment": "external-https-client", "state": "RUNNING"})
    exercise.state["algorithmVerified"] = False
    selected = {"variant": options.variant, "realmId": options.realm_id, "principalId": options.principal_id,
                "authentication": options.sdk_authentication, "transportPrincipal": options.sdk_transport_principal}
    if exercise.state.setdefault("algorithmScenario", selected) != selected:
        raise ExerciseFailure("Retained algorithm scenario target changed")
    _, wire = exercise.api.json("GET", "/admin/v1/realm")
    realm = _result(wire, "realm.inspect")
    if realm.get("realmId") != options.realm_id:
        raise ExerciseFailure("Selected realm differs from the verified HTTPS realm")
    exercise.discover()
    if options.variant == "hybrid":
        _, capability = exercise.api.json("GET", "/admin/v1/hybrid-sdk/v1")
        if capability.get("canonicalOrigin") != exercise.api.origin or capability.get("profile") != PROFILE or "credential.issue" not in capability.get("operations", []):
            raise ExerciseFailure("SDK listener unavailable or wrong origin; deployment operator must configure it")
    signature = _crypto(options, "describe", options.variant)
    alternative_signature = _crypto(options, "describe", "mldsa87")
    keys = exercise.directory / "client-keys"
    if not exercise.state.get("algorithmKeysReady"):
        _crypto(options, "generate", options.variant, keys)
        exercise.state["algorithmKeysReady"] = True
        exercise.state["algorithmKeyHashes"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in keys.iterdir()}
        exercise.save()
    for name, digest in exercise.state["algorithmKeyHashes"].items():
        if hashlib.sha256(_private_file(keys / name).read_bytes()).hexdigest() != digest:
            raise ExerciseFailure("Retained applicant keys or CSR changed")
    primary, alternative = {}, {}
    for role in ("root", "intermediate"):
        primary[role] = exercise.job("key-" + role, "key.generate", {
            "generationId": "scenario-" + exercise.state["runId"] + "-" + role,
            "parameters": VARIANTS[options.variant][0]})
        if options.variant == "hybrid":
            alternative[role] = exercise.job("key-" + role + "-alt", "key.generate", {
                "generationId": "scenario-" + exercise.state["runId"] + "-" + role + "-alt", "parameters": "ML_DSA_87"})
    profiles = _profiles(options.variant, exercise.state["runId"], alternative, alternative_signature)
    references = {}
    for role, profile in profiles.items():
        encoded = json.dumps(profile, separators=(",", ":")).encode()
        _atomic_json(exercise.directory / (role + "-profile.json"), profile)
        references[role] = exercise.job("profile-" + role, "profile.register", {"document": base64.b64encode(encoded).decode()})
    authorities, generations, paths = {}, {}, {}
    for role in ("root", "intermediate"):
        operation = "ca.create" if role == "root" else "ca.intermediate.create"
        arguments = {"formatId": "x509", "subjectRef": "CN=ZeroEcho C04 " + role + " " + exercise.state["runId"],
            "profileId": profiles[role]["profileId"], "keyRef": primary[role]["keyRef"], "signatureAlgorithmId": signature}
        parent = authorities.get("root")
        if parent:
            arguments["issuerCaId"] = parent
        created = exercise.job(role, operation, arguments, parent)
        metadata = _artifact(exercise, "certificate", created["credentialId"], role, options.maximum_download_bytes)
        # Artifact authorityId is the incoming issuer's authority for an intermediate certificate.
        # Resolve the newly created outgoing generation by its exact credential instead.
        created_generation = _created_generation(exercise, created["credentialId"])
        authorities[role] = created_generation["authorityId"]
        inspected = exercise.operation("ca.inspect", {"caId": authorities[role]}, authorities[role])
        generations[role] = exercise.operation("issuer.generation.inspect", {"issuerId": inspected["currentIssuanceIssuerId"]})
        paths[role] = exercise.operation("issuer.path.inspect", {"pathId": inspected["selectedPathId"]})
        binding = generations[role]["cryptographicBinding"]
        if binding["certificateSha256"] != hashlib.sha256((exercise.directory / (role + ".der")).read_bytes()).hexdigest():
            raise ExerciseFailure("CA artifact differs from its immutable generation binding")
        for suffix, generated, bound in (("", primary[role], binding["primary"]),) + ((("-alternative", alternative[role], binding["alternative"]),) if options.variant == "hybrid" else ()):
            spki = base64.b64decode(generated["subjectPublicKeyInfo"], validate=True)
            if hashlib.sha256(spki).hexdigest() != bound["subjectSpkiSha256"]:
                raise ExerciseFailure("Managed key differs from generation public binding")
            destination = keys / (role + suffix + ".spki.der")
            if destination.exists() and _private_file(destination).read_bytes() != spki:
                raise ExerciseFailure("Retained CA public key changed")
            destination.write_bytes(spki)
            destination.chmod(0o600)
        if binding["primary"]["keyRef"] != primary[role]["keyRef"] or binding["primary"]["signatureAlgorithmId"] != signature:
            raise ExerciseFailure("CA outgoing key or signature algorithm differs from selection")
        if options.variant == "hybrid" and (binding["alternative"]["keyRef"] != alternative[role]["keyRef"] or binding["alternative"]["signatureAlgorithmId"] != alternative_signature):
            raise ExerciseFailure("CA alternative outgoing role differs from selection")
    if options.variant == "hybrid":
        request_id = _private_file(keys / "request-id.txt").read_text().strip()
    else:
        imported = exercise.job("csr", "request.import", {"formatId": "x509", "encoded": base64.b64encode((keys / "client.csr.der").read_bytes()).decode()})
        request_id = imported["requestId"]
        exercise.operation("request.verify", {"requestId": request_id})
    arguments = {"issuerCaId": authorities["intermediate"], "requestId": request_id, "profileId": profiles["client"]["profileId"]}
    if options.variant == "hybrid":
        issuer = primary["intermediate"]["subjectPublicKeyInfo"]
        issuer_alt = alternative["intermediate"]["subjectPublicKeyInfo"]
        # key.generate returns ordinary canonical Base64 SPKI, unlike SDK base64url frames.
        context = dict(arguments=arguments, principal=options.principal_id, ca=authorities["intermediate"],
            generation=generations["intermediate"], path=paths["intermediate"], profile=references["client"],
            issuer_der=(exercise.directory / "intermediate.der").read_bytes(),
            issuer_spki=base64.b64decode(issuer, validate=True), issuer_alternative=base64.b64decode(issuer_alt, validate=True))
        issued = _sdk_issue(exercise, options, arguments, authorities["intermediate"], context, certificate)
    else:
        issued = exercise.job("client", "credential.issue", arguments, authorities["intermediate"])
    metadata = _artifact(exercise, "certificate", issued["credentialId"], "client", options.maximum_download_bytes)
    if metadata.get("issuerId") != generations["intermediate"]["issuerId"]:
        raise ExerciseFailure("Issued certificate did not use the selected generation")
    proof = _crypto(options, "verify", options.variant, keys, exercise.directory / "root.der",
                    exercise.directory / "intermediate.der", exercise.directory / "client.der")
    for role in ("root", "intermediate", "client"):
        exercise.state["artifacts"][role + ".der"]["verified"] = True
    exercise.state["algorithmVerified"] = True
    exercise.state.pop("failure", None)
    exercise.save()
    _atomic_json(exercise.directory / "algorithm-report.json", {"version": 1, "variant": options.variant,
        "verified": True, "environment": "external-https-client", "podmanQualified": False,
        "origin": exercise.api.origin, "realmId": options.realm_id, "generations": generations,
        "paths": paths, "cryptographicVerification": proof, "artifacts": exercise.state["artifacts"]})
