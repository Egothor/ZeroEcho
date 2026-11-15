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

"""Schema-driven executable scenarios for a newly owned disposable PKI deployment.

This module never starts containers or imports the live-demo transport. The caller
supplies its checkpointed HTTP adapter and a live ownership verifier. Coverage is
credited only after a positive server receipt and the recipe's result oracle.
Absent runtime operations are evidence-bearing omissions, never successful tests.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from pathlib import Path
import struct
import os
import stat
import subprocess
import time


class CatalogFailure(RuntimeError):
    """A catalog, prerequisite, ownership or positive-result assertion failed."""


# Values beginning with @ are exact context references, resolved only at execution.
# Every available catalog ID is declared explicitly: additions cannot silently pass.
_RECIPES = {}


def _add(operation, arguments=None, *, phase=50, expected=None, captures=None, authority=False, special=None):
    if operation in _RECIPES:
        raise RuntimeError("Duplicate recipe: " + operation)
    _RECIPES[operation] = {"operation":operation, "arguments":arguments or {}, "phase":phase,
                           "expected":expected or {}, "captures":captures or {},
                           "authority":authority, "special":special}


for _operation in ("configuration.validate", "configuration.choices", "ca.list", "profile.list-all",
                   "request.list", "algorithm.binding.list", "algorithm.binding.validate", "dashboard.server",
                   "security.role-template.list", "security.principal.list", "security.grant.list",
                   "security.role-assignment.list", "security.break-glass.list", "security.approval.list",
                   "security.audit.search", "security.audit.verify-integrity", "enrollment.profile.list",
                   "enrollment.request.list", "acme.directory.list", "acme.account.list", "est.endpoint.list",
                   "scep.endpoint.list", "cmp.endpoint.list", "ocsp.responder.list", "publication.list",
                   "repository.alias.list", "status.schedule.list", "revocation.snapshot"):
    _add(_operation, phase=5)

_RECIPES["security.audit.verify-integrity"]["expected"]={"status":"INTACT"}

_add("key.generate", {"generationId":"@managedGenerationId", "parameters":"@managedParameters"}, phase=6,
     expected={"generationId":"@managedGenerationId", "parameters":"@managedParameters"},
     captures={"managedKeyRef":"keyRef", "managedGenerationId":"generationId", "managedPublicKeyInfo":"subjectPublicKeyInfo"})

_add("ca.create", {"formatId":"x509", "subjectRef":"@caSubject", "profileId":"@rootProfileId", "keyRef":"@rootKeyRef"}, phase=10, special="create_ca",
     expected={"caId":None}, captures={"authorityId":"caId", "caCredentialId":"credentialId", "issuerId":"issuerId"})
_add("ca.inspect", {"caId":"@authorityId"}, phase=11, expected={"caId":"@authorityId"}, captures={"issuerId":"currentIssuanceIssuerId"})
_add("issuer.generation.list", phase=12, authority=True)
_add("issuer.generation.inspect", {"issuerId":"@issuerId"}, phase=13, expected={"issuerId":"@issuerId"}, captures={"caCredentialId":"credentialId"}, authority=True)
_add("issuer.path.list", {"issuerId":"@issuerId"}, phase=14, authority=True, special="select_current_path")
_add("issuer.path.inspect", {"pathId":"@pathId"}, phase=15, expected={"pathId":"@pathId"}, authority=True)
_add("request.import", {"formatId":"x509", "encoded":"@csrBase64"}, phase=16, captures={"requestId":"requestId"})
_add("request.inspect", {"requestId":"@requestId"}, phase=17, expected={"requestId":"@requestId"})
_add("request.verify", {"requestId":"@requestId"}, phase=18)
_add("profile.validate", {"document":"@profileDocument"}, phase=19)
_add("profile.register", {"document":"@profileDocument"}, phase=20)
_add("profile.activate", {"profileId":"@catalogProfileId", "profileVersion":1}, phase=21, expected={"profileId":"@catalogProfileId"})
_add("profile.inspect", {"profileId":"@catalogProfileId", "profileVersion":1}, phase=22, expected={"profileId":"@catalogProfileId"}, captures={"publicKeyAlgorithms":"publicKeyAlgorithms", "x509BindingPolicies":"x509BindingPolicies"})
_add("profile.list", {"profileId":"@catalogProfileId"}, phase=23)
_add("algorithm.binding.inspect", {"bindingId":"@bindingId"}, phase=24, expected={"bindingId":"@bindingId"})
_add("credential.issue", {"issuerCaId":"@authorityId", "requestId":"@requestId", "profileId":"@catalogProfileId"}, phase=25, authority=True, captures={"credentialId":"credentialId"})
_add("credential.inspect", {"credentialId":"@credentialId"}, phase=26, expected={"credentialId":"@credentialId"}, authority=True)
_add("credential.list", phase=27, authority=True)
_add("credential.search", phase=27, authority=True)
_add("certificate.publication.enroll", {"credentialId":"@credentialId", "ownerPrincipalId":"@administrator"}, phase=26, authority=True)
_add("credential.confirmation.challenge.issue", {"credentialId":"@credentialId"}, phase=27, authority=True,
     captures={"challenge":"$result"})
_add("credential.confirmation.proof.complete", phase=28, authority=True, special="holder_proof")
_add("credential.hold", {"credentialId":"@credentialId", "justification":"@justification"}, phase=31, expected={"state":"HELD"}, authority=True)
_add("credential.unhold", {"credentialId":"@credentialId", "justification":"@justification"}, phase=32, expected={"state":"CLEAR"}, authority=True)
_add("credential.renew", {"credentialId":"@credentialId"}, phase=33, authority=True, captures={"lifecycleCredentialId":"credentialId"})
_add("credential.replace", {"existingCredentialId":"@lifecycleCredentialId", "requestId":"@requestId", "profileId":"@catalogProfileId"}, phase=34, authority=True, captures={"lifecycleCredentialId":"credentialId"})
_add("credential.reissue", {"credentialId":"@lifecycleCredentialId"}, phase=35, authority=True, captures={"lifecycleCredentialId":"credentialId"})
_add("credential.confirmation.pending.list", {"cutoffInclusive":"@future"}, phase=36, authority=True)
_add("credential.confirmation.pending.revoke", phase=37, authority=True, special="overdue_confirmation")
_add("credential.revoke", {"credentialId":"@lifecycleCredentialId", "reason":"KEY_COMPROMISE", "justification":"@justification"}, phase=38, expected={"state":"PERMANENTLY_REVOKED"}, authority=True)
_add("revocation.inspect", {"credentialId":"@lifecycleCredentialId"}, phase=39, expected={"state":"PERMANENTLY_REVOKED"}, authority=True)
_add("revocation.history", {"credentialId":"@lifecycleCredentialId"}, phase=40, authority=True)
_add("status.generate", {"issuerCaId":"@authorityId", "type":"CRL", "formatId":"x509"}, phase=41, authority=True, captures={"statusObjectId":"statusObjectId"})
_add("status.inspect", {"statusObjectId":"@statusObjectId"}, phase=42, authority=True, expected={"statusObjectId":"@statusObjectId"}, captures={"statusContentSha256":"contentSha256", "statusContentLength":"contentLength"})
_add("inventory.status", {"issuerCaId":"@authorityId"}, phase=42, authority=True)
for _operation in ("dashboard.authority", "dashboard.certificate", "dashboard.publication", "dashboard.revocation"):
    _add(_operation, {"caId":"@authorityId"}, phase=43, authority=True)
_add("status.schedule.set", {"caId":"@authorityId", "statusType":"CRL", "formatId":"x509", "interval":"PT1H", "graceSeconds":60, "enabled":False}, phase=44, authority=True)
_add("status.schedule.inspect", {"caId":"@authorityId", "statusType":"CRL"}, phase=45, authority=True, expected={"enabled":False})
_add("repository.alias.set", {"authorityId":"@authorityId", "type":"CURRENT_CRL", "targetObjectId":"@statusObjectId", "issuerId":"@issuerId"}, phase=46, authority=True, captures={"aliasCommitment":"recordCommitment"})
_add("repository.alias.inspect", {"authorityId":"@authorityId", "type":"CURRENT_CRL"}, phase=47, authority=True)
_add("repository.alias.remove", {"authorityId":"@authorityId", "type":"CURRENT_CRL", "expectedCurrentCommitment":"@aliasCommitment"}, phase=97, authority=True)
_add("publication.register", {"publicationId":"@publicationId", "sourceType":"STATUS_OBJECT", "sourceId":"@statusObjectId", "targetType":"FILESYSTEM", "targetId":"exercise-files"}, phase=48, authority=True, expected={"publicationId":"@publicationId"})
_add("publication.process", {"publicationId":"@publicationId"}, phase=49, authority=True)
_add("publication.inspect", {"publicationId":"@publicationId"}, phase=50, authority=True, expected={"publicationId":"@publicationId","status":"SUCCEEDED"})
_add("publication.retry", {"publicationId":"@publicationId"}, phase=51, authority=True, special="publication_retry")
_add("publication.reconcile", {"publicationId":"@publicationId"}, phase=52, authority=True, special="publication_reconcile")
_add("issuer.path.register", {"caId":"@intermediateCaId", "issuerId":"@intermediateIssuerId", "parentPathId":"@pathId"}, phase=88, authority=True, special="intermediate_path")
_add("issuer.path.select", {"caId":"@authorityId", "issuerId":"@issuerId", "pathId":"@pathId", "reason":"@justification"}, phase=89, authority=True)
_add("ca.intermediate.create", {"formatId":"x509", "issuerCaId":"@authorityId", "subjectRef":"@intermediateSubject", "profileId":"intermediate-ca", "keyRef":"@intermediateKeyRef"}, phase=85, authority=True,
     captures={"intermediateCaId":"caId"}, special="create_intermediate")
_add("ca.intermediate.issue", {"formatId":"x509", "issuerCaId":"@authorityId", "subjectCaId":"@intermediateCaId", "profileId":"intermediate-ca"}, phase=86, authority=True)
_add("ca.rollover", {"caId":"@authorityId"}, phase=87, authority=True)
_add("ca.rotate", {"caId":"@authorityId", "newKeyRef":"@rotationKeyRef"}, phase=91, authority=True, special="rotate_ca")
_add("ca.transition", {"caId":"@authorityId", "state":"DISABLED", "reason":"@justification"}, phase=99, authority=True, expected={"state":"DISABLED"}, special="disable_owned_ca")

# Governance objects are newly named, never the bootstrap identity or an existing grant.
_add("security.principal.register", {"principalId":"@principalId", "type":"USER", "displayName":"Disposable catalog actor", "enabled":True}, phase=10, expected={"principalId":"@principalId"})
_add("security.principal.inspect", {"principalId":"@principalId"}, phase=11, expected={"principalId":"@principalId", "enabled":True})
_add("security.principal.disable", {"principalId":"@principalId"}, phase=96, expected={"enabled":False})
_add("security.principal.enable", {"principalId":"@principalId"}, phase=97, expected={"enabled":True})
_add("security.grant.create", {"grantId":"@grantId", "principalId":"@principalId", "effect":"ALLOW", "action":"REALM_READ", "resourceType":"REALM", "relationship":"ANY", "dataView":"METADATA_REDACTED"}, phase=12, expected={"grantId":"@grantId"})
_add("security.grant.inspect", {"grantId":"@grantId"}, phase=13, expected={"grantId":"@grantId"})
_add("security.grant.revoke", {"grantId":"@grantId"}, phase=96, expected={"grantId":"@grantId","enabled":False})
_add("security.role-template.inspect", {"templateId":"auditor", "version":1}, phase=10, expected={"templateId":"auditor"})
_add("security.role-assignment.create", {"assignmentId":"@assignmentId", "principalId":"@principalId", "templateId":"auditor", "templateVersion":1}, phase=14, expected={"assignmentId":"@assignmentId"})
_add("security.role-assignment.inspect", {"assignmentId":"@assignmentId"}, phase=15, expected={"assignmentId":"@assignmentId"})
_add("security.role-assignment.revoke", {"assignmentId":"@assignmentId"}, phase=95, expected={"assignmentId":"@assignmentId","enabled":False})
_add("security.authorization.evaluate", {"principalId":"@principalId", "action":"REALM_READ", "resourceType":"REALM", "relationship":"ANY", "dataView":"METADATA_REDACTED"}, phase=16)
_add("security.break-glass.create", {"breakGlassId":"@breakGlassId", "principalId":"@principalId", "grantId":"@emergencyGrantId", "action":"REALM_READ", "resourceType":"REALM", "reason":"@justification", "expiresAt":"@future"}, phase=17)
_add("security.break-glass.activate", {"breakGlassId":"@breakGlassId"}, phase=18, expected={"state":"ACTIVE"})
_add("security.break-glass.inspect", {"breakGlassId":"@breakGlassId"}, phase=19, expected={"breakGlassId":"@breakGlassId"})
_add("security.break-glass.revoke", {"breakGlassId":"@breakGlassId"}, phase=95, expected={"breakGlassId":"@breakGlassId","state":"REVOKED"})
_add("security.approval.request", {"approvalId":"@approvalId", "targetOperation":"ca.transition", "targetArguments":{"caId":"@authorityId", "state":"ACTIVE", "reason":"@justification"}, "targetAuthorityId":"@authorityId"}, phase=53, expected={"state":"PENDING"})
_add("security.approval.inspect", {"approvalId":"@approvalId"}, phase=54, expected={"approvalId":"@approvalId"})
_add("security.approval.approve", {"approvalId":"@approvalId", "justification":"@justification"}, phase=55, expected={"state":"APPROVED"})
_add("security.approval.reject", phase=56, special="reject_approval")
_add("security.approval.cancel", phase=57, special="cancel_approval")
_add("security.disclosure.inspect", {"objectId":"@credentialId"}, phase=58, authority=True)
_add("security.disclosure.set", {"objectId":"@credentialId", "policy":"PUBLIC_UNLISTED"}, phase=59, authority=True, expected={"policy":"PUBLIC_UNLISTED"})
_add("security.disclosure.capability.issue", {"objectId":"@credentialId", "expiresAt":"@future"}, phase=60, authority=True, captures={"capabilityId":"capabilityId"})
_add("security.disclosure.capability.list", {"objectId":"@credentialId"}, phase=61, authority=True)
_add("security.disclosure.capability.revoke", {"capabilityId":"@capabilityId"}, phase=62, authority=True, expected={"capabilityId":"@capabilityId","revoked":True})
for _operation in ("security.audit-view.inspect-full", "security.audit-view.inspect-pii", "security.audit-view.inspect-redacted"):
    _add(_operation, {"objectId":"@credentialId", **({"reasonReference":"@justification"} if _operation.endswith("inspect-pii") else {})}, phase=63, authority=True)

_add("enrollment.profile.register", {"id":"@enrollmentProfileId", "displayName":"Disposable enrollment", "certificateProfileId":"@catalogProfileId", "allowedAuthorityIds":["@authorityId"], "requireApproval":True}, phase=24)
_add("enrollment.profile.inspect", {"id":"@enrollmentProfileId"}, phase=25, expected={"id":"@enrollmentProfileId"})
_add("enrollment.profile.update", {"id":"@enrollmentProfileId", "displayName":"Updated disposable enrollment", "certificateProfileId":"@catalogProfileId", "allowedAuthorityIds":["@authorityId"], "requireApproval":True}, phase=26)
_add("enrollment.profile.activate", {"id":"@enrollmentProfileId"}, phase=27, expected={"state":"ACTIVE"})
_add("enrollment.profile.suspend", {"id":"@enrollmentProfileId"}, phase=94, expected={"state":"SUSPENDED"})
_add("enrollment.request.inspect", {"id":"@enrollmentApproveId"}, phase=65, captures={"enrollmentApproveCommitment":"commitment"}, special="seed_enrollment")
_add("enrollment.request.approve", {"id":"@enrollmentApproveId", "expectedCommitment":"@enrollmentApproveCommitment", "justification":"@justification"}, phase=66, special="approve_enrollment")
_add("enrollment.request.reject", {"id":"@enrollmentRejectId", "expectedCommitment":"@enrollmentRejectCommitment", "justification":"@justification"}, phase=67)

for _protocol in ("est", "scep", "cmp"):
    _args = {"label":"@endpointLabel", "authorityId":"@protocolAuthorityId", "profileId":"server-tls", "enrollmentProfileId":"@protocolEnrollmentProfileId"}
    if _protocol == "scep": _args["challengePasswordHash"] = "@challengePasswordHash"
    if _protocol == "cmp": _args["protectionPolicy"] = "SIGNATURE_BASED"
    _add(_protocol+".endpoint.register", _args, phase=64, authority=True)
    _add(_protocol+".endpoint.inspect", {"label":"@endpointLabel"}, phase=65)
    _add(_protocol+".endpoint.deregister", {"label":"@endpointLabel"}, phase=93)
_add("acme.directory.register", {"alias":"@directoryAlias", "authorityId":"@protocolAuthorityId", "profileId":"server-tls", "enrollmentProfileId":"@protocolEnrollmentProfileId", "dnsNamespaces":"@acmeDnsNamespaces", "maximumValidityMillis":3600000, "publicKeyAlgorithms":"@protocolPublicKeyAlgorithms", "x509BindingPolicies":"@protocolX509BindingPolicies", "challengeTypes":["DNS_01"], "challengeProviderIds":"@challengeProviderIds", "eabRequired":False}, phase=64, authority=True, captures={"directoryId":"directoryId"})
_add("acme.directory.inspect", {"directoryId":"@directoryId"}, phase=65)
_add("acme.directory.activate", {"directoryId":"@directoryId"}, phase=66, expected={"status":"ACTIVE"})
_add("acme.directory.deactivate", {"directoryId":"@directoryId"}, phase=93)
_add("acme.account.inspect", {"accountId":"@accountId"}, phase=68, special="seed_acme_account")
_add("acme.account.deactivate", {"accountId":"@accountId"}, phase=92)
_add("ocsp.responder.issue-certificate", phase=68, authority=True, special="issue_managed_responder",
     captures={"managedResponderCredentialId":"credentialId"})
_add("ocsp.responder.register", {"responderId":"@responderId", "alias":"@responderAlias", "authorityId":"@authorityId", "issuerId":"@issuerId", "signingMode":"ISSUER_SIGNED", "responderCredentialId":"@caCredentialId", "signingKeyRef":"@rootKeyRef", "chainPathId":"@pathId", "signatureAlgorithm":"@signatureAlgorithm", "signatureBindingCommitment":"@signatureBindingCommitment", "responderIdForm":"BY_NAME", "responseValidityMillis":3600000, "noncePolicy":"OPTIONAL_ECHO", "maximumNonceBytes":32, "acceptedHashes":["SHA256"], "maximumRequestBytes":65536, "maximumEntries":1, "cacheLifetimeMillis":60000, "requestAuthenticationMode":"UNSIGNED_ONLY"}, phase=69, authority=True)
_add("ocsp.responder.inspect", {"responderId":"@responderId"}, phase=70)
_add("ocsp.responder.activate", {"responderId":"@responderId"}, phase=71, expected={"state":"ACTIVE"}, special="ocsp_wire")
_add("ocsp.responder.deactivate", {"responderId":"@responderId"}, phase=94)

for _operation in ("backup.export", "backup.verify", "backup.stream.export", "backup.stream.download", "backup.stream.reserve", "backup.stream.upload", "backup.stream.verify", "backup.stream.status", "backup.stream.acknowledge", "backup.stream.restore"):
    _add(_operation, phase=1 if _operation in {"backup.export","backup.verify"} else 102 if _operation=="backup.stream.acknowledge" else 101 if _operation=="backup.stream.restore" else 100, special="backup_transfer")


def recipe_ids():
    """Return the finite reviewed operation IDs; unknown available additions fail planning."""
    return set(_RECIPES)


def plan(schema, descriptors, context=None):
    """Return an ordered executable graph and explicit discovery omissions.

    Args: schema is the actual schema list; descriptors maps discovered operation
    identifiers to runtime descriptors; context is optional fixture information.
    Returns the ordered steps, omitted IDs and schema commitment.
    Raises CatalogFailure for an unknown available operation. Runtime
    omissions are not counted as executed or as positive qualification.
    """
    del context
    static = {row["operationId"]:row for row in schema}
    unknown = {key for key,row in static.items() if row.get("available",True) and key not in _RECIPES}
    if unknown: raise CatalogFailure("Available operations lack reviewed recipes: " + ",".join(sorted(unknown)))
    if set(descriptors)-set(static): raise CatalogFailure("Runtime descriptors are absent from the schema")
    unavailable = sorted(key for key,row in static.items() if row.get("available") is False)
    steps = [dict(_RECIPES[key]) for key in descriptors if key not in unavailable]
    steps.sort(key=lambda step:(step["phase"],step["operation"]))
    return {"steps":steps, "not_discovered":sorted(set(_RECIPES)-set(descriptors)), "unavailable":unavailable,
            "schemaSha256":hashlib.sha256(json.dumps(schema,sort_keys=True,separators=(",",":")).encode()).hexdigest()}


def _values(node, key):
    if isinstance(node,dict):
        if key in node: yield node[key]
        for child in node.values(): yield from _values(child,key)
    elif isinstance(node,list):
        for child in node: yield from _values(child,key)


def assert_result(result, expected, operation):
    """Require a nonempty typed result and every independently expected result value.

    Parameters are the adapter's terminal result, expected key/value subset, and
    operation name for safe diagnostics. None means a required non-null field.
    Raises CatalogFailure instead of accepting an empty or contradictory receipt.
    """
    if not isinstance(result,dict) or not result: raise CatalogFailure("No typed result for " + operation)
    for key,value in expected.items():
        candidates = list(_values(result,key))
        if not candidates or not any(candidate is not None if value is None else type(candidate) is type(value) and candidate==value for candidate in candidates):
            raise CatalogFailure("Result assertion failed for " + operation + ": " + key)


def _resolve(value, values):
    if isinstance(value,str) and value.startswith("@"):
        key=value[1:]
        if key not in values or values[key] is None: raise CatalogFailure("Missing owned fixture prerequisite: " + key)
        return values[key]
    if isinstance(value,list): return [_resolve(item,values) for item in value]
    if isinstance(value,dict): return {key:_resolve(item,values) for key,item in value.items()}
    return value


def _arguments(recipe, schema, values):
    arguments=_resolve(recipe["arguments"],values)
    defaults={"limit":100,"offset":0}
    for field in schema["fields"]:
        if field["required"] and field["name"] not in arguments:
            if field["name"] not in defaults: raise CatalogFailure("Missing recipe argument: " + recipe["operation"] + ":" + field["name"])
            arguments[field["name"]]=defaults[field["name"]]
    unknown=set(arguments)-{field["name"] for field in schema["fields"]}
    if unknown: raise CatalogFailure("Recipe no longer matches schema: " + recipe["operation"] + ":" + ",".join(sorted(unknown)))
    return arguments



def _authority(arguments, recipe, values, specification=None):
    """Use canonical CA arguments or the owned CA, never an issuer/credential ID."""
    if specification is not None and specification.get("scope")!="authority": return None
    explicit=next((arguments[key] for key in ("authorityId","issuerCaId","caId") if key in arguments),None)
    return explicit if explicit is not None else values.get("authorityId") if specification is not None or recipe["authority"] else None


def _owned(exercise, context):
    verifier=context.get("assert_disposable")
    if not callable(verifier): raise CatalogFailure("A live disposable deployment verifier is required")
    verifier(exercise.api.origin,exercise.state["runId"])


def _initial_values(exercise, context):
    run_id=exercise.state["runId"]
    if not isinstance(run_id,str) or len(run_id)!=32 or any(c not in "0123456789abcdef" for c in run_id):
        raise CatalogFailure("Invalid exercise ownership nonce")
    prefix="exercise-"+run_id+"-"
    values=dict(context.get("objects",exercise.state.get("objects",{})))
    # Basic demo identities are historical evidence, never fallback mutation targets.
    for key in ("authorityId","credentialId","caCredentialId","issuerId","pathId","requestId"):
        values.pop(key,None)
    values.update(exercise.state.setdefault("catalogObjects",{}))
    for key in ("protocolAuthorityId","protocolEnrollmentProfileId","enrollmentApproveId","enrollmentRejectId","enrollmentRejectCommitment","accountId","challengeProviderIds","protocolPublicKeyAlgorithms","protocolX509BindingPolicies"):
        if key in context: values[key]=context[key]
    for key in ("signatureAlgorithm","publicationTargetId"):
        if key in context:values[key]=context[key]
    values.setdefault("acmeDnsNamespaces",[context.get("acmeDnsNamespace","example.invalid")])
    for name,suffix in {"principalId":"user","grantId":"grant","assignmentId":"role","breakGlassId":"emergency","emergencyGrantId":"emergency-grant","approvalId":"approval","publicationId":"publication","enrollmentProfileId":"enrollment","endpointLabel":"endpoint","directoryAlias":"directory","responderId":"ocsp","responderAlias":"ocsp-alias","catalogProfileId":"leaf-profile"}.items():
        values.setdefault(name,prefix+suffix)
    values.setdefault("managedGenerationId",prefix+"managed-key")
    values.setdefault("managedParameters","ECDSA_P384")
    values.setdefault("rootProfileId",context.get("rootProfileId","root-ca"))
    values.setdefault("rootKeyRef",context.get("rootKeyRef","zeroecho-lib:root.prv"))
    values.setdefault("intermediateKeyRef",context.get("intermediateKeyRef","zeroecho-lib:intermediate.prv"))
    values.setdefault("rotationKeyRef",context.get("rotationKeyRef","zeroecho-lib:rotation.prv"))
    values.setdefault("administrator",context.get("adminPrincipalId",context.get("administrator","bootstrap-admin")))
    values.setdefault("caSubject","CN=Disposable Catalog "+run_id)
    values.setdefault("intermediateSubject","CN=Disposable Intermediate "+run_id)
    values.setdefault("justification","Disposable deployment catalog exercise "+run_id)
    values.setdefault("future",(datetime.now(timezone.utc)+timedelta(minutes=45)).isoformat().replace("+00:00","Z"))
    values.setdefault("challengePasswordHash",hashlib.sha256((prefix+"scep").encode()).hexdigest())
    csr=exercise.directory/"catalog-client.csr.der" if hasattr(exercise,"directory") else None
    if csr is not None and not csr.exists() and (exercise.directory/"client.key").is_file():
        completed=subprocess.run(["openssl","req","-new","-key",str(exercise.directory/"client.key"),"-outform","DER",
            "-subj","/CN=Catalog "+run_id,"-addext","subjectAltName=email:catalog-"+run_id+"@example.invalid"],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=30)
        if completed.returncode: raise CatalogFailure("Own catalog CSR construction failed")
        descriptor=os.open(csr,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,"wb") as output: output.write(completed.stdout)
    if csr is not None and csr.is_file(): values.setdefault("csrBase64",base64.b64encode(csr.read_bytes()).decode())
    profile_path=Path(__file__).resolve().parents[1]/"pki/src/main/resources/zeroecho/pki/profiles/v1/vpn-client.json"
    if "profileDocument" not in values and profile_path.is_file():
        document=json.loads(profile_path.read_text())
        document["profileId"]=values["catalogProfileId"]
        document["displayName"]="Disposable catalog client "+run_id
        values["profileDocument"]=base64.b64encode(json.dumps(document,separators=(",",":")).encode()).decode()
    return values


def run(exercise, context=None):
    """Execute discovered recipes through the caller's actual receipt-checking adapter.

    exercise supplies schema/descriptors, operation/job/dedicated, checkpoint state,
    API origin and save(). The context mapping supplies assert_disposable(origin,runId), owned
    objects and special protocol/stream scenario callbacks. Every mutator rechecks
    live ownership. Missing prerequisites and failed state oracles remain failures;
    no HTTP error is reclassified as positive coverage. Returns a strict report.
    Raises CatalogFailure before requests if discovery or live ownership is invalid.
    """
    context=dict(context or {})
    graph=plan(list(exercise.schema.values()),exercise.descriptors,context)
    if any(exercise.schema[step["operation"]].get("mutating") for step in graph["steps"]): _owned(exercise,context)
    values=_initial_values(exercise,context)
    state=exercise.state.setdefault("catalog",{"receipts":{},"failed":{}})
    report={"executed":[],"failed":{},"not_discovered":graph["not_discovered"],"unavailable":graph["unavailable"],"schemaSha256":graph["schemaSha256"]}
    for recipe in graph["steps"]:
        operation=recipe["operation"]
        try:
            spec=exercise.schema[operation]
            if spec.get("mutating"): _owned(exercise,context)
            if operation in state["receipts"] and state["receipts"][operation].get("asserted") is True:
                report["executed"].append(operation)
                continue
            if recipe["special"]:
                callback=context.get("scenarios",{}).get(recipe["special"])
                if not callable(callback): callback=_DEFAULT_SCENARIOS.get(recipe["special"])
                if not callable(callback): raise CatalogFailure("Missing executable scenario prerequisite: "+recipe["special"])
                result=callback(exercise,operation,values,context)
                if exercise.state["coverage"].get(operation,{}).get("state")!="EXECUTED":
                    raise CatalogFailure("Scenario has no actual operation receipt: "+operation)
            else:
                arguments=_arguments(recipe,spec,values)
                authority=_authority(arguments,recipe,values,spec)
                if spec.get("mutating"):
                    method=exercise.job if exercise.descriptors[operation].get("durableRequest") is True else exercise.dedicated
                    result=method("catalog-"+operation.replace(".","-"),operation,arguments,authority)
                else: result=exercise.operation(operation,arguments,authority)
            if operation=="security.disclosure.capability.issue":
                tokens=list(_values(result,"token"))
                if len(tokens)!=1 or not isinstance(tokens[0],str) or not tokens[0]:
                    raise CatalogFailure("Capability issuance omitted its one-time bearer")
                # Deliberately discard the bearer before callbacks, captures or checkpoints.
                result={key:value for key,value in result.items() if key!="token"}
                tokens.clear()
            assert_result(result,_resolve(recipe["expected"],values),operation)
            _postconditions(exercise,context,operation,result,values)
            if operation=="algorithm.binding.list":
                bindings=list(_values(result,"bindings"))
                if bindings and bindings[0]: values.setdefault("bindingId",bindings[0][0]["bindingId"])
                commitment=list(_values(result,"registryCommitment"))
                if commitment: values.setdefault("signatureBindingCommitment",commitment[0])
            for key,path in recipe["captures"].items():
                if path=="$result": values[key]=result
                else:
                    candidates=list(_values(result,path))
                    if not candidates: raise CatalogFailure("Result omitted prerequisite: "+operation+":"+path)
                    values[key]=candidates[0]
            state["receipts"][operation]={"asserted":True,"phase":recipe["phase"]}
            state["failed"].pop(operation,None)
            report["executed"].append(operation)
            exercise.state["coverage"][operation]={"state":"EXECUTED","reason":"Positive terminal HTTP receipt and catalog state oracle"}
        except Exception as error:
            if getattr(error,"waiting_external_restart",False):
                exercise.state["catalogObjects"]=values
                exercise.save()
                raise
            # Safe bounded diagnostics omit payloads, credentials, capability bearers and file contents.
            reason=type(error).__name__
            if isinstance(error,CatalogFailure): reason=str(error)
            elif type(error).__name__=="ExerciseFailure" and len(str(error))<=256 and not any(character in str(error) for character in "\r\n{}"):
                # Adapter contract guarantees its diagnostics omit request/response bodies.
                reason=str(error)
            report["failed"][operation]=reason
            state["failed"][operation]=reason
            exercise.state["coverage"][operation]={"state":"BLOCKED" if reason.startswith("BLOCKED:") or "Missing " in reason or getattr(error,"status",0)==403 else "FAILED","reason":reason}
        exercise.state["catalogObjects"]=values
        exercise.save()
    report["qualified"]=not report["failed"] and not graph["not_discovered"] and len(report["executed"])==len(_RECIPES)
    state["report"]=report
    exercise.save()
    return report


def _call(exercise, context, name, operation, arguments, authority=None):
    """Execute one auxiliary positive step with the same mutation ownership guard."""
    if operation not in exercise.descriptors:
        raise CatalogFailure("Required scenario operation is not offered: "+operation)
    if exercise.schema[operation].get("scope")!="authority": authority=None
    if exercise.schema[operation].get("mutating"):
        _owned(exercise,context)
        method=exercise.job if exercise.descriptors[operation].get("durableRequest") is True else exercise.dedicated
        return method("catalog-aux-"+name,operation,arguments,authority)
    return exercise.operation(operation,arguments,authority)


def _create_ca(exercise, operation, values, context):
    recipe=_RECIPES[operation]
    result=_call(exercise,context,"ca",operation,_arguments(recipe,exercise.schema[operation],values))
    credential=result.get("credentialId")
    if not isinstance(credential,str): raise CatalogFailure("CA signing receipt omitted its credential")
    matches=[]
    cursor=None
    while True:
        args={"limit":100}
        if cursor: args["after"]=cursor
        page=_call(exercise,context,"resolve-ca","ca.list",args)
        for ca in page.get("authorities",[]):
            ca_id=ca.get("caId")
            generations=_call(exercise,context,"resolve-generation","issuer.generation.list",{"limit":100},ca_id)
            if any(row.get("credentialId")==credential for row in generations.get("generations",[])):
                matches.append(ca)
        if page.get("truncated") is not True: break
        following=page.get("nextCursor")
        if not following or following==cursor: raise CatalogFailure("CA resolution cursor did not advance")
        cursor=following
    if len(matches)!=1: raise CatalogFailure("CA signing receipt does not identify exactly one authoritative CA")
    return {**result, "caId":matches[0]["caId"], "issuerId":matches[0]["currentIssuanceIssuerId"]}


def _current_path(exercise, operation, values, context):
    result=_call(exercise,context,"path-list",operation,{"issuerId":values["issuerId"]},values["authorityId"])
    paths=result.get("paths",[])
    if not paths: raise CatalogFailure("Current issuer has no registered chain path")
    selected=[row for row in paths if row.get("issuerId")==values["issuerId"]]
    if len(selected)!=1: raise CatalogFailure("Current issuer path is ambiguous")
    values["pathId"]=selected[0]["pathId"]
    return result


def _holder_proof(exercise, operation, values, context):
    challenge=values.get("challenge")
    if not isinstance(challenge,dict) or challenge.get("credentialId")!=values.get("credentialId"):
        raise CatalogFailure("Holder challenge is not bound to the owned catalog credential")
    key=exercise.directory/"client.key"
    metadata=key.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_uid!=os.geteuid():
        raise CatalogFailure("Holder key is not a private owned regular file")
    proof_key="catalogProofResponse"
    response=exercise.state.get(proof_key)
    if response is None:
        encoded=challenge["presentation"]
        payload=base64.urlsafe_b64decode(encoded+"="*((-len(encoded))%4))
        completed=subprocess.run(["openssl","dgst","-sha256","-sign",str(key)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=30)
        if completed.returncode: raise CatalogFailure("Local holder signature failed")
        response=base64.urlsafe_b64encode(completed.stdout).decode().rstrip("=")
        exercise.state[proof_key]=response
        exercise.save()
    args={name:challenge[name] for name in ("credentialId","expectedLifecycleRevision","expectedLifecycleRecordCommitment","expectedChallengeRecordCommitment")}
    args["response"]=response
    result=_call(exercise,context,"holder-proof",operation,args,values["authorityId"])
    assert_result(result,{"confirmationResult":"CONFIRMED"},operation)
    return result


def _decision(exercise, operation, values, context):
    suffix="reject" if operation.endswith("reject") else "cancel"
    approval=values["approvalId"]+"-"+suffix
    target={"approvalId":approval,"targetOperation":"ca.transition","targetArguments":{"caId":values["authorityId"],"state":"ACTIVE","reason":values["justification"]},"targetAuthorityId":values["authorityId"]}
    created=_call(exercise,context,"approval-"+suffix,"security.approval.request",target)
    assert_result(created,{"approvalId":approval,"state":"PENDING"},"security.approval.request")
    args={"approvalId":approval}
    if suffix=="reject": args["justification"]=values["justification"]
    result=_call(exercise,context,"decision-"+suffix,operation,args)
    assert_result(result,{"approvalId":approval,"state":"REJECTED" if suffix=="reject" else "CANCELLED"},operation)
    return result


def _confirmation_commitment(policy, seconds):
    parts=[]
    def text(raw): parts.append(struct.pack('>I',len(raw))+raw)
    text(b'zeroecho:credential-confirmation-policy:v1')
    code={"PUBLIC":1,"PUBLIC_UNLISTED":2,"AUTHENTICATED":3,"OWNER_ONLY":4,"RESTRICTED":5}[policy["disclosurePolicy"]]
    parts.append(struct.pack('>IqI',code,seconds,0))
    text(policy["proofSuiteId"].encode('ascii'))
    text(policy["proofSuiteCommitment"].encode('ascii'))
    return hashlib.sha256(b''.join(parts)).hexdigest()


def _overdue(exercise, operation, values, context):
    document=json.loads(base64.b64decode(values["profileDocument"]))
    document["profileId"]=values["catalogProfileId"]+"-pending"
    document["confirmationPolicy"]["confirmationWindow"]="PT1S"
    document["confirmationPolicy"]["policyCommitment"]=_confirmation_commitment(document["confirmationPolicy"],1)
    encoded=base64.b64encode(json.dumps(document,separators=(",",":")).encode()).decode()
    _call(exercise,context,"pending-profile","profile.register",{"document":encoded})
    _call(exercise,context,"pending-profile-active","profile.activate",{"profileId":document["profileId"],"profileVersion":1},values["authorityId"])
    issued=_call(exercise,context,"pending-client","credential.issue",{"issuerCaId":values["authorityId"],"requestId":values["requestId"],"profileId":document["profileId"]},values["authorityId"])
    credential=issued.get("credentialId")
    if not credential: raise CatalogFailure("Pending issuance omitted its credential")
    _call(exercise,context,"pending-enroll","certificate.publication.enroll",{"credentialId":credential,"ownerPrincipalId":values["administrator"]},values["authorityId"])
    deadline=exercise.clock()+10
    review=None
    while exercise.clock()<deadline:
        page=_call(exercise,context,"pending-page","credential.confirmation.pending.list",{"cutoffInclusive":values["future"],"limit":100},values["authorityId"])
        rows=[row for row in page.get("reviews",[]) if row.get("credentialId")==credential]
        if rows:
            review=rows[0].get("confirmationReviewAt")
            if review and datetime.now(timezone.utc)>datetime.fromisoformat(review.replace("Z","+00:00")): break
        exercise.sleep(0.1)
    else: raise CatalogFailure("Owned pending credential did not become overdue within its configured window")
    result=_call(exercise,context,"pending-revoke",operation,{"credentialId":credential,"justification":values["justification"]},values["authorityId"])
    assert_result(result,{"state":"PERMANENTLY_REVOKED"},operation)
    return result


def _intermediate_path(exercise, operation, values, context):
    ca=_call(exercise,context,"inspect-intermediate","ca.inspect",{"caId":values["intermediateCaId"]},values["intermediateCaId"])
    issuer=ca["currentIssuanceIssuerId"]
    values["intermediateIssuerId"]=issuer
    parent=_call(exercise,context,"inspect-rolled-parent","ca.inspect",{"caId":values["authorityId"]},values["authorityId"])
    parent_issuer=parent["currentIssuanceIssuerId"]
    paths=_call(exercise,context,"rolled-parent-paths","issuer.path.list",{"issuerId":parent_issuer},values["authorityId"])
    candidates=[row for row in paths.get("paths",[]) if row.get("issuerId")==parent_issuer]
    if len(candidates)!=1 or candidates[0]["pathId"]==values["pathId"]:
        raise CatalogFailure("Alternate path requires the distinct rolled-over parent generation")
    result=_call(exercise,context,"register-intermediate-path",operation,{"caId":values["intermediateCaId"],"issuerId":issuer,"parentPathId":candidates[0]["pathId"]},values["intermediateCaId"])
    assert_result(result,{"authorityId":values["intermediateCaId"],"issuerId":issuer},operation)
    path=result.get("pathId")
    observed=_call(exercise,context,"inspect-alternate-path","issuer.path.inspect",{"pathId":path},values["intermediateCaId"])
    assert_result(observed,{"pathId":path},operation+" committed path")
    return result


_DEFAULT_SCENARIOS={"create_ca":_create_ca,"select_current_path":_current_path,"holder_proof":_holder_proof,
                    "reject_approval":_decision,"cancel_approval":_decision,"overdue_confirmation":_overdue,
                    "intermediate_path":_intermediate_path}


def _create_intermediate(exercise, operation, values, context):
    recipe=_RECIPES[operation]
    result=_call(exercise,context,"intermediate",operation,_arguments(recipe,exercise.schema[operation],values),values["authorityId"])
    credential=result.get("credentialId")
    if not credential: raise CatalogFailure("Intermediate signing receipt omitted its credential")
    page=_call(exercise,context,"resolve-intermediate","ca.list",{"limit":100})
    matches=[]
    for ca in page.get("authorities",[]):
        generations=_call(exercise,context,"resolve-intermediate-generation","issuer.generation.list",{"limit":100},ca["caId"])
        if any(row.get("credentialId")==credential for row in generations.get("generations",[])): matches.append(ca)
    if len(matches)!=1: raise CatalogFailure("Intermediate signing receipt did not resolve one exact authority")
    ca_id=matches[0]["caId"]
    inspected=_call(exercise,context,"inspect-created-intermediate","ca.inspect",{"caId":ca_id},ca_id)
    values["intermediateIssuerId"]=inspected["currentIssuanceIssuerId"]
    return {**result,"caId":ca_id}


def _publication_recovery(exercise, operation, values, context):
    retry=operation.endswith("retry")
    prepared=context.get("preparedPublications",{}).get("retry" if retry else "reconcile")
    if not isinstance(prepared,dict) or not isinstance(prepared.get("publicationId"),str) or not re.fullmatch(r"[0-9a-f]{64}",prepared.get("sourceSha256","")):
        raise CatalogFailure("BLOCKED: publication failure state must be prepared by the deployment script")
    publication=prepared["publicationId"]
    state="RETRYABLE_FAILURE" if retry else "OUTCOME_UNKNOWN"
    before=_call(exercise,context,"inspect-"+state.lower(),"publication.inspect",{"publicationId":publication},prepared.get("authorityId"))
    assert_result(before,{"publicationId":publication,"status":state,"sourceType":"STATUS_OBJECT"},"publication.inspect")
    _publication_http_evidence(exercise,context,before,prepared["sourceSha256"],prepared.get("authorityId"))
    result=_call(exercise,context,"recover-"+state.lower(),operation,{"publicationId":publication},prepared.get("authorityId"))
    assert_result(result,{"publicationId":publication,"status":"SUCCEEDED"},operation)
    return result


def _publication_http_evidence(exercise, context, publication, expected_hash, authority):
    source=_call(exercise,context,"publication-source-"+publication["publicationId"],"status.inspect",{"statusObjectId":publication["sourceId"]},authority)
    assert_result(source,{"contentSha256":expected_hash},"publication source HTTP metadata")
    exercise.state.setdefault("publicationEvidence",{})[publication["publicationId"]]={"sourceSha256":expected_hash,"oracle":"Authoritative HTTP publication state and source hash; no server filesystem access"}


_DEFAULT_SCENARIOS.update({"create_intermediate":_create_intermediate,"publication_retry":_publication_recovery,
                           "publication_reconcile":_publication_recovery})


def _public_binding_tuple(binding):
    """Compare immutable C03.5 public roles, ignoring reference aliases and certificate hashes."""
    if not isinstance(binding,dict) or not isinstance(binding.get("primary"),dict):
        raise CatalogFailure("Rotation requires authoritative pre/post public signing bindings")
    roles=[]
    for name in ("primary","alternative"):
        if name not in binding:
            roles.append(None)
            continue
        role=binding[name]
        fields=("subjectSpkiSha256","publicKeyAlgorithmId","signatureAlgorithmId","signatureAlgorithmIdentifierDer")
        if not isinstance(role,dict) or any(not isinstance(role.get(field),str) or not role[field] for field in fields):
            raise CatalogFailure("Rotation signing-role public tuple is incomplete")
        roles.append(tuple(role[field] for field in fields))
    return tuple(roles)


def _rotate_ca(exercise, operation, values, context):
    """Retain the active head before requesting a changed-key candidate, without activation."""
    if "rotationHeadBefore" not in values:
        values["rotationHeadBefore"]=_call(exercise,context,"rotation-head-before","ca.inspect",{"caId":values["authorityId"]},values["authorityId"])
        exercise.state["catalogObjects"]=values
        exercise.save()
    if "rotationBindingBefore" not in values:
        before=_call(exercise,context,"rotation-binding-before","issuer.generation.inspect",
            {"issuerId":values["rotationHeadBefore"]["currentIssuanceIssuerId"]},values["authorityId"])
        values["rotationBindingBefore"]=before["cryptographicBinding"]
        _public_binding_tuple(values["rotationBindingBefore"])
        exercise.state["catalogObjects"]=values
        exercise.save()
    recipe=_RECIPES[operation]
    return _call(exercise,context,"rotate-ca",operation,_arguments(recipe,exercise.schema[operation],values),values["authorityId"])


_DEFAULT_SCENARIOS["rotate_ca"]=_rotate_ca


def _postconditions(exercise, context, operation, result, values):
    """Read authoritative committed identities after signing and verify materialized files.

    Extra reads are real HTTP observations, not reconstructed signing receipts.
    Raises CatalogFailure on a missing committed credential or changed CA lineage.
    """
    if operation=="key.generate":
        _generated_key(result, values["managedGenerationId"], values["managedParameters"])
    signing={"credential.issue","credential.renew","credential.replace","credential.reissue","ca.rollover","ca.rotate","ca.intermediate.issue"}
    if operation in signing:
        identifiers=list(_values(result,"credentialId"))
        if len(identifiers)!=1 or not isinstance(identifiers[0],str):
            raise CatalogFailure("Signing receipt has no unique credential identity: "+operation)
        credential=identifiers[0]
        if operation.startswith("credential."):
            inspected=_call(exercise,context,"inspect-output-"+operation,"credential.inspect",{"credentialId":credential},values["authorityId"])
            assert_result(inspected,{"credentialId":credential},operation+" committed credential")
        if operation in {"ca.rollover","ca.rotate"}:
            ca=_call(exercise,context,"inspect-ca-"+operation,"ca.inspect",{"caId":values["authorityId"]},values["authorityId"])
            if operation=="ca.rotate" and ca.get("kind")=="ROOT" and result.get("activationState")=="PENDING_ACTIVATION":
                before=values.get("rotationHeadBefore",{})
                if not before or any(ca.get(field)!=before.get(field) for field in ("currentIssuanceIssuerId","selectedPathId","headEpoch")):
                    raise CatalogFailure("Changed-root rotation advanced the active head before activation")
                assert_result(result,{"activationState":"PENDING_ACTIVATION","candidateCredentialId":credential},operation+" candidate receipt")
                issuer=result.get("candidateIssuerId")
                path=result.get("candidatePathId")
                if not isinstance(issuer,str) or not isinstance(path,str):
                    raise CatalogFailure("Changed-root candidate omitted exact issuer/path")
                candidate=_call(exercise,context,"inspect-rotation-candidate","issuer.generation.inspect",{"issuerId":issuer},values["authorityId"])
                assert_result(candidate,{"authorityId":values["authorityId"],"issuerId":issuer,"credentialId":credential,"activationState":"PENDING_ACTIVATION"},operation+" candidate generation")
                if _public_binding_tuple(candidate.get("cryptographicBinding"))==_public_binding_tuple(values.get("rotationBindingBefore")):
                    raise CatalogFailure("Same-key root rotation unexpectedly requires candidate activation")
                if candidate.get("cryptographicBinding",{}).get("primary",{}).get("keyRef")!=values["rotationKeyRef"]:
                    raise CatalogFailure("Changed-root candidate differs from selected rotation key")
                selected=_call(exercise,context,"inspect-rotation-candidate-path","issuer.path.inspect",{"pathId":path},values["authorityId"])
                assert_result(selected,{"issuerId":issuer,"pathId":path},operation+" candidate path")
                if not selected.get("orderedCredentialIds") or selected["orderedCredentialIds"][0]!=credential:
                    raise CatalogFailure("Changed-root candidate path differs from candidate credential")
                return
            issuers=list(_values(ca,"currentIssuanceIssuerId"))
            if len(issuers)!=1: raise CatalogFailure("CA has no unique current issuer after "+operation)
            generation=_call(exercise,context,"inspect-generation-"+operation,"issuer.generation.inspect",{"issuerId":issuers[0]},values["authorityId"])
            assert_result(generation,{"credentialId":credential},operation+" current issuer")
            if operation=="ca.rotate" and ca.get("kind")=="ROOT":
                if _public_binding_tuple(generation.get("cryptographicBinding"))!=_public_binding_tuple(values.get("rotationBindingBefore")):
                    raise CatalogFailure("Changed-root public binding became active without candidate activation")
                selected=_call(exercise,context,"inspect-same-key-rotation-path","issuer.path.inspect",{"pathId":ca["selectedPathId"]},values["authorityId"])
                assert_result(selected,{"issuerId":issuers[0],"pathId":ca["selectedPathId"]},operation+" active path")
                if not selected.get("orderedCredentialIds") or selected["orderedCredentialIds"][0]!=credential:
                    raise CatalogFailure("Same-key rotation path differs from completed credential")
    if operation=="publication.process":
        assert_result(result,{"publicationId":values["publicationId"],"status":"SUCCEEDED"},operation)
        publication=_call(exercise,context,"publication-http-state","publication.inspect",{"publicationId":values["publicationId"]},values["authorityId"])
        assert_result(publication,{"status":"SUCCEEDED","sourceType":"STATUS_OBJECT","sourceId":values["statusObjectId"]},"publication.inspect")
        _publication_http_evidence(exercise,context,publication,values["statusContentSha256"],values["authorityId"])


def _disable_owned_ca(exercise, operation, values, context):
    """Provision a bounded explicit suspend grant, then disable only the owned CA.

    Bootstrap's catalog-derived AUTHORITY_ACTIVATE grant cannot authorize a
    DISABLED transition, whose effective permission is AUTHORITY_SUSPEND. The
    operator uses the ordinary audited grant API; gateway policy stays unchanged.
    """
    existing=False
    for offset in range(0,1000,100):
        page=exercise.operation("security.grant.list",{"offset":offset,"limit":100})
        rows=page.get("grants",[])
        existing=existing or any(row.get("principalId")==values["administrator"] and row.get("action")=="AUTHORITY_SUSPEND" and row.get("enabled") is True for row in rows)
        if len(rows)<100: break
    else: raise CatalogFailure("Owned grant inventory exceeds the fixture bound")
    exercise.state.setdefault("catalogPrerequisites",{})["suspendGrantPreviouslyPresent"]=existing
    arguments={"grantId":"exercise-"+exercise.state["runId"]+"-suspend-owned-ca",
        "principalId":values["administrator"],"effect":"ALLOW","action":"AUTHORITY_SUSPEND",
        "resourceType":"AUTHORITY","relationship":"ANY","dataView":"METADATA_REDACTED",
        "conditions":[],"expiresAt":values["future"]}
    _owned(exercise,context)
    method=exercise.job if exercise.descriptors["security.grant.create"].get("durableRequest") is True else exercise.dedicated
    granted=method("catalog-aux-suspend-grant","security.grant.create",arguments,values["authorityId"])
    assert_result(granted,{"grantId":arguments["grantId"],"action":"AUTHORITY_SUSPEND","enabled":True},"security.grant.create")
    return _call(exercise,context,"disable-owned-ca",operation,{"caId":values["authorityId"],"state":"DISABLED","reason":values["justification"]},values["authorityId"])

_DEFAULT_SCENARIOS["disable_owned_ca"]=_disable_owned_ca


def _generated_key(result, generation, parameters):
    """Reject changed generation/parameter identities or non-public generation outputs."""
    required={"generationId", "parameters", "keyRef", "subjectPublicKeyInfo"}
    if set(result)!=required or result.get("generationId")!=generation or result.get("parameters")!=parameters:
        raise CatalogFailure("Managed generation receipt differs from explicit public target")
    if not isinstance(result["keyRef"],str) or not result["keyRef"]:
        raise CatalogFailure("Managed generation receipt omitted its key reference")
    try:
        spki=base64.b64decode(result["subjectPublicKeyInfo"],validate=True)
        if not spki or base64.b64encode(spki).decode()!=result["subjectPublicKeyInfo"]: raise ValueError()
    except (ValueError,TypeError) as error:
        raise CatalogFailure("Managed generation receipt omitted canonical public SPKI") from error


# Exact built-in canonical identities from BootstrapAlgorithmIdentities; no aliases.
_OCSP_PRIMARY_SIGNATURE="zealg:2:9:signature8:zeroecho5:ecdsa16:zeroecho.builtin"+str(len(base64.urlsafe_b64encode(b"digest=zeroecho.sha2-384.none").decode().rstrip("=")))+":"+base64.urlsafe_b64encode(b"digest=zeroecho.sha2-384.none").decode().rstrip("=")
_OCSP_ALTERNATIVE_SIGNATURE="zealg:2:9:signature8:zeroecho9:ml-dsa-8716:zeroecho.builtin6:bm9uZQ"


def _issue_managed_responder(exercise, operation, values, context):
    """Provision dedicated managed dual roles through existing HTTP contracts only.

    Reuses durable auxiliary job identities and freezes absolute validity before
    sending. No responder registration, listener change or private-key export.
    """
    prefix="exercise-"+exercise.state["runId"]+"-ocsp-"
    keys={}
    for role,parameters in (("issuer","ECDSA_P384"),("issuer-alt","ML_DSA_87"),
                            ("responder","ECDSA_P384"),("responder-alt","ML_DSA_87")):
        generation=prefix+role
        keys[role]=_call(exercise,context,"ocsp-key-"+role,"key.generate",{"generationId":generation,"parameters":parameters})
        _generated_key(keys[role],generation,parameters)
    if len({key["keyRef"] for key in keys.values()})!=4:
        raise CatalogFailure("Dedicated OCSP signing roles reuse a managed key")
    root=json.loads((Path(__file__).parent/"pki-server/profiles/root-ca.json").read_text())
    root.update(profileId=prefix+"root-profile",displayName="Disposable OCSP hybrid root")
    root["caCertificate"]["allowedSubjectKeyAlgorithms"]=["ECDSA"]
    root["hybridMode"]={"type":"ALT_SIGNATURE","altSignatureAlgorithmId":_OCSP_ALTERNATIVE_SIGNATURE,"altKeyRef":keys["issuer-alt"]["keyRef"]}
    profile=json.loads((Path(__file__).parent/"pki-server/profiles/vpn-client.json").read_text())
    profile.update(profileId=prefix+"responder-profile",displayName="Disposable managed OCSP responder",maxValidity="PT24H",approvalRequirement="SINGLE")
    profile["subject"]["allowEmpty"]=False
    profile["subject"]["rules"][0]["minimumOccurrences"]=1
    profile["subjectAlternativeNames"].update(minimumTotal=0,maximumTotal=0,rules=[])
    profile["leafCertificate"].update(allowedKeyAlgorithms=["ECDSA"],extendedKeyUsage=["1.3.6.1.5.5.7.3.9"])
    profile["hybridMode"]={"type":"ALT_SIGNATURE","altSignatureAlgorithmId":_OCSP_ALTERNATIVE_SIGNATURE,"altKeyRef":keys["responder-alt"]["keyRef"]}
    references={}
    for role,document in (("issuer",root),("responder",profile)):
        encoded=base64.b64encode(json.dumps(document,separators=(",",":")).encode()).decode()
        references[role]=_call(exercise,context,"ocsp-profile-"+role,"profile.register",{"document":encoded})
        _call(exercise,context,"ocsp-profile-active-"+role,"profile.activate",{"profileId":document["profileId"],"profileVersion":1},values["authorityId"])
    created=_call(exercise,context,"ocsp-root","ca.create",{"formatId":"x509","subjectRef":"CN=Disposable OCSP Root "+exercise.state["runId"],
        "profileId":root["profileId"],"keyRef":keys["issuer"]["keyRef"],"signatureAlgorithmId":_OCSP_PRIMARY_SIGNATURE})
    from exercise_algorithms import _created_generation
    generation=_created_generation(exercise,created["credentialId"])
    authority=generation["authorityId"]
    binding=generation["cryptographicBinding"]
    for role,bound in (("issuer",binding["primary"]),("issuer-alt",binding["alternative"])):
        if bound["signatureAlgorithmId"]!=(_OCSP_PRIMARY_SIGNATURE if role=="issuer" else _OCSP_ALTERNATIVE_SIGNATURE) or bound["keyRef"]!=keys[role]["keyRef"] or bound["subjectSpkiSha256"]!=hashlib.sha256(base64.b64decode(keys[role]["subjectPublicKeyInfo"],validate=True)).hexdigest():
            raise CatalogFailure("OCSP issuer generation differs from selected managed signing roles")
    ca=_call(exercise,context,"ocsp-ca-inspect","ca.inspect",{"caId":authority},authority)
    path=_call(exercise,context,"ocsp-path-inspect","issuer.path.inspect",{"pathId":ca["selectedPathId"]},authority)
    assert_result(path,{"issuerId":generation["issuerId"]},"OCSP issuer path")
    if "managedResponderValidity" not in values:
        now=datetime.now(timezone.utc).replace(microsecond=0)
        values["managedResponderValidity"]={"notBefore":now.isoformat().replace("+00:00","Z"),
            "notAfter":(now+timedelta(hours=12)).isoformat().replace("+00:00","Z")}
        exercise.state["catalogObjects"]=values
        exercise.save()
    arguments={"authorityId":authority,"issuerId":generation["issuerId"],"primaryKeyRef":keys["responder"]["keyRef"],
        "alternativeKeyRef":keys["responder-alt"]["keyRef"],"subject":{"rdns":[{"type":"COMMON_NAME","value":"Disposable OCSP "+exercise.state["runId"]}]},
        "profileId":profile["profileId"],"profileVersion":1,"profileSha256":references["responder"]["canonicalSha256"],
        "chainPathId":path["pathId"],"chainPathCommitment":path["pathCommitment"],**values["managedResponderValidity"]}
    result=_call(exercise,context,"managed-ocsp-responder",operation,arguments,authority)
    credential=result.get("credentialId")
    if not isinstance(credential,str) or not credential:
        raise CatalogFailure("Managed responder signing receipt omitted its credential")
    inspected=_call(exercise,context,"managed-ocsp-output","credential.inspect",{"credentialId":credential},authority)
    assert_result(inspected,{"credentialId":credential},"managed responder committed credential")
    values["managedResponderTarget"]=arguments
    values["managedResponderKeys"]=keys
    return result


_DEFAULT_SCENARIOS["issue_managed_responder"]=_issue_managed_responder
