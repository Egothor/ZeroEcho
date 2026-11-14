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

"""Positive SCEP/CMP issuance using owned protected clients and actual admin approval.

The Java client builds and verifies independent BC protocol messages. This adapter
owns HTTPS admission, explicit administrative decisions and bounded protected poll.
A receipt never counts as issuance until its certificate matches the protected key.
"""
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

from exercise_pki import Api, ExerciseFailure


class LegacyProtocolFailure(ExerciseFailure):
    """A safe ownership, wire, administrative-decision or certificate-proof failure."""


def _private_file(path):
    metadata = path.lstat()
    import os
    import stat
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise LegacyProtocolFailure("Legacy client output is not an owned private regular file")
    if metadata.st_size > 1024 * 1024:
        raise LegacyProtocolFailure("Legacy client output exceeds its bound")
    return path.read_bytes()


def qualify(exercise, context, values, protocol):
    """Issue and retrieve one genuine certificate through SCEP or signature-protected CMP.

    Args:
        exercise: Checkpointed HTTP/approval adapter for the expected qualification realm.
        context: Supplies assert_disposable, legacy_client(protocol,phase), protocolUrls,
            clientDirectory and trustFile; no server configuration or container access.
        values: Owned endpointLabel and protocolAuthorityId generated for this run.
        protocol: Exactly scep or cmp; each uses an independent protected subject key.
    Returns:
        A VERIFIED proof with public certificate/SPKI hashes and the actual enrollment ID.
    Raises:
        LegacyProtocolFailure: On missing ownership, uncertain acknowledgement, invalid
            approval state, rejected protected response, deadline or mismatched certificate.
    """
    if protocol not in {"scep", "cmp"}:
        raise LegacyProtocolFailure("Unsupported legacy enrollment protocol")
    guard, client = context.get("assert_disposable"), context.get("legacy_client")
    if not callable(guard) or not callable(client):
        raise LegacyProtocolFailure("Owned legacy client and live HTTPS realm verifier are required")
    guard(exercise.api.origin, exercise.state["runId"])
    root = Path(context["clientDirectory"])
    directory = root / "protocol-client"
    api = Api(context["protocolUrls"][protocol], context["trustFile"])
    if api.client_authenticated:
        raise LegacyProtocolFailure("Enrollment transport must prove its own protocol authentication")
    path = ("/scep/" if protocol == "scep" else "/pkix/") + quote(values["endpointLabel"], safe="")
    if protocol == "scep":
        path += "?operation=PKIOperation"
    media = "application/x-pki-message" if protocol == "scep" else "application/pkixcmp"
    record = exercise.state.setdefault("legacyEnrollment", {}).setdefault(protocol, {"requests": {}})
    if record.get("proof", {}).get("state") == "VERIFIED":
        return record["proof"]

    def phase(name):
        guard(exercise.api.origin, exercise.state["runId"])
        client(protocol, name)

    def post(name):
        from exercise_protocols import _raw
        guard(exercise.api.origin, exercise.state["runId"])
        encoded = _private_file(directory / (protocol + "-request.der"))
        digest = hashlib.sha256(encoded).hexdigest()
        checkpoint = record["requests"].setdefault(name, {"sha256": digest, "attempted": False})
        if checkpoint["sha256"] != digest:
            raise LegacyProtocolFailure("Retained legacy wire request changed")
        retained = directory / (protocol + "-" + name + "-response.der")
        if not checkpoint["attempted"]:
            checkpoint["attempted"] = True
            exercise.save()
            _, headers, body = _raw(api, "POST", path, encoded, media)
            content_type = next((value for key, value in headers.items() if key.lower() == "content-type"), "").split(";", 1)[0].lower()
            if content_type != media:
                raise LegacyProtocolFailure("Unexpected legacy enrollment response media type")
            import os
            descriptor = os.open(retained, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(body)
            checkpoint["responseSha256"] = hashlib.sha256(body).hexdigest()
            exercise.save()
        if "responseSha256" not in checkpoint or not retained.exists():
            raise LegacyProtocolFailure("Legacy admission acknowledgement is unknown; retained request must not be resubmitted")
        body = _private_file(retained)
        if hashlib.sha256(body).hexdigest() != checkpoint["responseSha256"]:
            raise LegacyProtocolFailure("Retained legacy response changed")
        response_path = directory / (protocol + "-response.der")
        if response_path.is_symlink():
            raise LegacyProtocolFailure("Legacy response destination is a symlink")
        response_path.write_bytes(body)
        response_path.chmod(0o600)
        phase("verify")
        return json.loads(_private_file(directory / (protocol + "-result.json")))

    if "enrollmentId" not in record:
        before = exercise.operation("enrollment.request.list", {"offset": 0, "limit": 100})
        prior = {row["id"] for row in before.get("items", [])}
        phase("initial")
        pending = post("initial")
        if pending.get("state") != "PENDING":
            raise LegacyProtocolFailure("Approval-required legacy enrollment did not return protected PENDING")
        after = exercise.operation("enrollment.request.list", {"offset": 0, "limit": 100})
        admitted = [row for row in after.get("items", []) if row["id"] not in prior]
        if len(admitted) != 1:
            raise LegacyProtocolFailure("Legacy wire admission did not create exactly one owned pending request")
        record.update(enrollmentId=admitted[0]["id"], commitment=admitted[0]["commitment"])
        exercise.save()
    from exercise_catalog import _call, assert_result
    decided = _call(exercise, context, "legacy-" + protocol + "-approve", "enrollment.request.approve",
        {"id": record["enrollmentId"], "expectedCommitment": record["commitment"],
         "justification": "Explicit isolated " + protocol.upper() + " enrollment qualification " + exercise.state["runId"]})
    assert_result(decided, {"id": record["enrollmentId"]}, "enrollment.request.approve")
    deadline = exercise.clock() + 60
    issued = None
    counter = 0
    while exercise.clock() < deadline:
        phase("poll")
        result = post("poll-" + str(counter))
        counter += 1
        if result.get("state") == "ISSUED":
            issued = result
            break
        if result.get("state") != "PENDING":
            raise LegacyProtocolFailure("Unexpected protected legacy enrollment result")
        exercise.sleep(0.5)
    if issued is None:
        raise LegacyProtocolFailure("Approved legacy certificate was not delivered before its deadline")
    encoded = _private_file(directory / (protocol + "-certificate.der"))
    if hashlib.sha256(encoded).hexdigest() != issued.get("certificateSha256"):
        raise LegacyProtocolFailure("Verified legacy certificate file changed")
    if protocol == "cmp":
        phase("confirm")
        if post("confirm").get("state") != "CONFIRMED":
            raise LegacyProtocolFailure("CMP certificate confirmation was not protected and accepted")
    proof = {"state": "VERIFIED", "enrollmentId": record["enrollmentId"],
        "certificateSha256": issued["certificateSha256"], "spkiSha256": issued["spkiSha256"],
        "protectedEnrollment": True, "explicitApproval": True, "privateKeyProof": True,
        "issuanceVerified": True, "keyMatchVerified": True, "chainVerified": True,
        "certificateConfirmation": protocol == "cmp"}
    record["proof"] = proof
    exercise.state.setdefault("protocolWireProofs", {})[protocol] = proof
    exercise.save()
    return proof
