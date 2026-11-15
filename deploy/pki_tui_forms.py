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

"""Closed typed host TUI forms for the committed operation/profile contracts.

Unknown structured provider fields fail closed. These controls preserve JSON wire
values but never ask an operator to write JSON. Server validation remains final.
"""
import base64
import copy
import json
import hashlib
import struct
import re
from pathlib import Path

from pki_http import ExerciseFailure, _private_file


def _field(name, kind="text", required=True, choices=(), children=(), item=None, help=""):
    return dict(name=name, type=kind, required=required, choices=list(choices), children=list(children), item=item, help=help)


def _object(name, children, required=True):
    return _field(name, "object", required, children=children)


def _list(name, item, required=True):
    return _field(name, "list", required, item=item)


def _enum(name, choices, required=True):
    return _field(name, "enum", required, choices=choices.split())


def _ints(*names):
    return [_field(name, "integer") for name in names]


def _bools(*names):
    return [_field(name, "boolean") for name in names]


def _texts(*names):
    return [_field(name) for name in names]


_BINDING = [_field("bindingId"), _field("semanticCommitment")]
_SUBJECT_RULE = _object("rule", [_field("oid"), _enum("source", "REQUESTER PROFILE_FIXED"),
    *_ints("minimumOccurrences", "maximumOccurrences", "maximumUtf8Bytes"), _field("fixedValue", required=False)])
_SAN_RULE = _object("rule", [_enum("type", "DNS_NAME IP_ADDRESS RFC822_NAME URI"),
    *_ints("minimumOccurrences", "maximumOccurrences"),
    *[_field(name, "boolean", False) for name in ("wildcardAllowed", "ipv4Allowed", "ipv6Allowed")],
    _field("allowedSchemes", "text-set", False)])
_PROFILE = [*_ints("schemaVersion"), _enum("certificateType", "ROOT_CA INTERMEDIATE_CA END_ENTITY"),
    _field("profileId"), *_ints("profileVersion"), _enum("formatId", "x509"), _field("displayName"),
    _field("maxValidity", help="Positive ISO-8601 duration, for example PT8760H"),
    _enum("approvalRequirement", "NONE SINGLE THRESHOLD"),
    _object("algorithmBindings", [_enum("mode", "STANDARD_ONLY EXPLICIT"),
        *[_object(name, _BINDING, False) for name in ("subjectPublicKey", "csrSignature", "certificateSignature", "crlSignature")]]),
    _object("subject", [*_bools("allowEmpty"), _list("rules", _SUBJECT_RULE)]),
    _object("subjectAlternativeNames", [*_ints("minimumTotal", "maximumTotal"),
        *_bools("serviceIdentityRequired", "emailIdentityRequired", "criticalWhenSubjectNonEmpty"), _list("rules", _SAN_RULE)], False),
    _object("leafCertificate", [*_bools("basicConstraintsCritical", "keyUsageCritical"),
        _field("keyUsage", "text-set"), *_bools("extendedKeyUsageCritical"),
        _field("extendedKeyUsage", "text-set"), _field("allowedKeyAlgorithms", "text-set")], False),
    _object("caCertificate", [*_bools("basicConstraintsCritical"), _field("pathLengthConstraint", "integer", False),
        *_bools("keyUsageCritical"), _field("keyUsages", "text-set"), _field("allowedSubjectKeyAlgorithms", "text-set")], False),
    _object("confirmationPolicy", [_enum("disclosurePolicy", "PUBLIC PUBLIC_UNLISTED AUTHENTICATED OWNER_ONLY RESTRICTED NOT_PUBLISHED"),
        *_texts("confirmationWindow", "proofSuiteId", "proofSuiteCommitment"),
        dict(_field("policyCommitment", required=False), readOnly=True)], False),
    _object("hybridMode", [_enum("type", "ALT_SIGNATURE TWIN_CERTIFICATE"),
        _field("altSignatureAlgorithmId", required=False), _field("altKeyRef", required=False),
        _enum("subjectKeySource", "MANAGED REQUEST", False)], False)]

_STRUCTURED = {
    "keygen": [*_bools("enabled"), _field("permittedAlgorithms", "text-set"),
        *_ints("maximumKeySizeBits"), *_bools("storeGeneratedKeys")],
    "expectedHead": [*_ints("version"), _field("caId"), *_ints("epoch"), *_texts("issuerId", "pathId", "bindingCommitment")],
    "subject": [_list("rdns", _object("rdn", [_enum("type", "COMMON_NAME ORGANIZATION_NAME ORGANIZATIONAL_UNIT_NAME COUNTRY_NAME STATE_OR_PROVINCE_NAME LOCALITY_NAME SERIAL_NUMBER EMAIL_ADDRESS PSEUDONYM"), _field("value")]))],
    "hybridSdk": [_enum("profile", "zeroecho-hybrid-sdk-v1"), *_texts("alternativeKeyRef", "alternativeSignatureAlgorithm"),
        _field("alternativeSignatureBindingId", required=False), _field("alternativeSignatureBindingCommitment")],
    "requesterTrustPolicy": [
        _list("trustSelectors", _object("selector", [_enum("type", "MANAGED_ISSUER_GENERATIONS CONFIGURED_TRUST_ANCHORS EXACT_REQUESTER_CERTIFICATE_COMMITMENTS"), _field("identities", "text-set")])),
        _list("principalMappings", _object("mapping", [*_texts("mappingId", "principalId"),
            _enum("type", "SHA256_CERTIFICATE_COMMITMENT SHA256_SPKI_COMMITMENT ISSUER_AND_SERIAL_COMMITMENT"), _field("commitment")])),
        _list("signatureBindings", _object("binding", _texts("bindingId", "commitment"))),
        _enum("revocationPolicy", "LOCAL_AUTHORITATIVE_REQUIRED LOCAL_AUTHORITATIVE_IF_MANAGED VALIDITY_AND_TRUST_ONLY"),
        *_ints("maximumSignerCertificates", "maximumSignerChainBytes")]
}


def _operation_fields(spec, schemas, arguments=None):
    fields = copy.deepcopy(spec.get("fields", []))
    for field in fields:
        kind, name = field["type"], field["name"]
        if kind == "object":
            if name == "targetArguments":
                target = (arguments or {}).get("targetOperation")
                if target in schemas and target != "security.approval.request":
                    field["children"] = _operation_fields(schemas[target], schemas)
                else:
                    field["children"] = None
                    field["help"] = "Select targetOperation first; recursive approval requests are unsupported"
            elif name in _STRUCTURED:
                field["children"] = copy.deepcopy(_STRUCTURED[name])
            else:
                field["children"] = None
                field["help"] = "Missing typed form capability for this provider field"
        elif kind == "base64":
            field["type"] = "profile" if name == "document" and spec["operationId"] in ("profile.register", "profile.validate") else "file"
        if name == "subjectRef":
            field["help"] = "X.509: distinguished name (for example CN=Example); other formats use their own subject syntax"
        if name == "targetOperation":
            field["choices"] = sorted(name for name in schemas if name != "security.approval.request")
            field["type"] = "enum"
    return fields


def _validate(field, value, path=""):
    name = path or field["name"]
    kind = field["type"]
    if kind not in {"text", "enum", "file", "profile", "integer", "boolean", "text-set", "enum-set", "list", "object"}:
        raise ExerciseFailure("Missing typed form capability: " + name)
    if kind in ("text", "enum", "file", "profile") and (not isinstance(value, str) or not value):
        raise ExerciseFailure("Expected nonempty text: " + name)
    if kind == "integer" and type(value) is not int or kind == "boolean" and type(value) is not bool:
        raise ExerciseFailure("Wrong scalar type: " + name)
    if kind in ("enum", "enum-set") and field.get("choices"):
        if any(item not in field["choices"] for item in (value if kind == "enum-set" else [value])):
            raise ExerciseFailure("Value outside choices: " + name)
    if kind in ("text-set", "enum-set", "list"):
        if not isinstance(value, list) or len(value) > 128:
            raise ExerciseFailure("Expected a bounded list: " + name)
        if kind != "list" and (any(not isinstance(item, str) or not item for item in value) or len(set(value)) != len(value)):
            raise ExerciseFailure("Expected unique nonempty strings: " + name)
        if kind == "list":
            for index, item in enumerate(value):
                _validate(field["item"], item, name + "." + str(index))
    if kind == "object":
        children = field.get("children")
        if children is None:
            raise ExerciseFailure("Missing typed form capability: " + name)
        if not isinstance(value, dict) or set(value) - {item["name"] for item in children}:
            raise ExerciseFailure("Unknown object field: " + name)
        for child in children:
            if child["name"] not in value:
                if child.get("required", False):
                    raise ExerciseFailure("Required field: " + name + "." + child["name"])
            else:
                _validate(child, value[child["name"]], name + "." + child["name"])
    if kind in ("file", "profile"):
        try:
            base64.b64decode(value, validate=True)
        except ValueError as error:
            raise ExerciseFailure("Invalid encoded file: " + name) from error


def _file_value(path, pem_csr=False):
    source = _private_file(Path(path))
    with source.open("rb") as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
    if not data or len(data) > 8 * 1024 * 1024:
        raise ExerciseFailure("Input file is empty or exceeds 8 MiB")
    if pem_csr:
        match = re.fullmatch(rb"\s*-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----\s*([A-Za-z0-9+/=\s]+)-----END (?:NEW )?CERTIFICATE REQUEST-----\s*", data)
        if not match:
            raise ExerciseFailure("Expected exactly one PEM certification request")
        data = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
        if not data or data[0] != 0x30:
            raise ExerciseFailure("Expected DER certification request")
    return base64.b64encode(data).decode("ascii")


def _confirmation_commitment(policy):
    codes = {name: index for index, name in enumerate(("PUBLIC", "PUBLIC_UNLISTED", "AUTHENTICATED", "OWNER_ONLY", "RESTRICTED", "NOT_PUBLISHED"), 1)}
    duration = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)(?:[.,](\d{1,9}))?S)?)?", policy["confirmationWindow"])
    if not duration or not any(duration.groups()):
        raise ExerciseFailure("Confirmation window must be a positive ISO-8601 day/time duration")
    days, hours, minutes, seconds, fraction = duration.groups()
    seconds = int(days or 0) * 86400 + int(hours or 0) * 3600 + int(minutes or 0) * 60 + int(seconds or 0)
    nanos = int((fraction or "").ljust(9, "0"))
    if seconds == 0 and nanos == 0 or seconds > 36525 * 86400 or seconds == 36525 * 86400 and nanos:
        raise ExerciseFailure("Confirmation window is outside the supported positive 100-year bound")
    suite, commitment = policy["proofSuiteId"], policy["proofSuiteCommitment"]
    if len(suite) > 128 or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*", suite) or not re.fullmatch(r"[0-9a-f]{64}", commitment):
        raise ExerciseFailure("Confirmation proof-suite reference is not canonical")
    def framed(value):
        encoded = value.encode("ascii")
        return struct.pack(">I", len(encoded)) + encoded
    # Exact CredentialConfirmationPolicy.configurationCommitment framing; suite commitments are references, not derived here.
    transcript = framed("zeroecho:credential-confirmation-policy:v1") + struct.pack(">IqI", codes[policy["disclosurePolicy"]], seconds, nanos)
    transcript += framed(suite) + framed(commitment)
    return hashlib.sha256(transcript).hexdigest()


def _profile_value(document):
    document = copy.deepcopy(document)
    if "confirmationPolicy" in document:
        document["confirmationPolicy"]["policyCommitment"] = _confirmation_commitment(document["confirmationPolicy"])
    _validate(_object("profile", _PROFILE), document)
    if document.get("formatId") != "x509" or document.get("schemaVersion") != 5:
        raise ExerciseFailure("Missing typed profile capability for this format/version")
    data = json.dumps(document, separators=(",", ":"), allow_nan=False).encode()
    if len(data) > 262144:
        raise ExerciseFailure("Profile document exceeds 256 KiB")
    return base64.b64encode(data).decode("ascii")


def _profile_template(name):
    path = Path(__file__).parent / "pki-server/profiles" / (name + ".json")
    if name not in ("root-ca", "intermediate-ca", "server-tls", "vpn-client", "vpn-server"):
        raise ExerciseFailure("Unknown profile template")
    return json.loads(path.read_text())
