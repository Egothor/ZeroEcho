/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.server.schema;

import java.util.List;
import java.util.Map;
import zeroecho.pki.server.schema.OperationDescriptorCatalog.FieldSemantics;
import zeroecho.pki.server.schema.OperationDescriptorCatalog.Presentation;
import zeroecho.pki.server.schema.OperationDescriptorCatalog.TransportSemantics;

/** Reviewed request semantics and presentation for every canonical operation. */
final class OperationPresentationDefinitions {
    private static final String TEXT_WIDGET = "text";
    private static final String PARAM_JUSTIFICATION = "justification";
    private static final String REVOCATION_SECTION = "revocation";
    private static final String BACKUP_SECTION = "backup";
    private static final String PARAM_ARTIFACT_HANDLE = "artifactHandle";

    private static final String TEXT_PROFILES = "profiles";
    private static final String TEXT_REALM = "realm";
    private static final String TEXT_LIMIT = "limit";
    private static final String TEXT_INTEGER = "integer";
    private static final String TEXT_AFTER = "after";
    private static final String TEXT_TEXT = TEXT_WIDGET;
    private static final String TEXT_AUTHORITY = "authority";
    private static final String TEXT_ENUM = "enum";
    private static final String TEXT_ISSUERS = "issuers";
    private static final String TEXT_DISCLOSURE = "disclosure";
    private static final String TEXT_OBJECT_ID = "objectId";
    private static final String TEXT_PKI_ID = "pkiId";
    private static final String TEXT_OBJECT = "object";
    private static final String TEXT_AUTHORITIES = "authorities";
    private static final String TEXT_CA_ID = "caId";
    private static final String TEXT_FORMAT_ID = "formatId";
    private static final String TEXT_PROFILE_ID = "profileId";
    private static final String TEXT_PROFILE = "profile";
    private static final String TEXT_ISSUER_CA_ID = "issuerCaId";
    private static final String TEXT_INSTANT = "instant";
    private static final String TEXT_ISSUER_ID = "issuerId";
    private static final String TEXT_ISSUER = "issuer";
    private static final String TEXT_LONG = "long";
    private static final String TEXT_CREDENTIAL_ID = "credentialId";
    private static final String TEXT_CREDENTIAL = "credential";
    private static final String TEXT_STATUS = "status";
    private static final String TEXT_PUBLICATION = "publication";
    private static final String TEXT_PRINCIPAL_ID = "principalId";
    private static final String TEXT_PRINCIPAL = "principal";
    private static final String TEXT_OFFSET = "offset";
    private static final String TEXT_ACCESS = "access";
    private static final String TEXT_APPROVALS = "approvals";
    private static final String TEXT_AUTHORITY_ID = "authorityId";
    private static final String TEXT_ACME = "acme";
    private static final String TEXT_LABEL = "label";
    private static final String TEXT_ENROLLMENT = "enrollment";

    private OperationPresentationDefinitions() { }
    /* default */ static List<Presentation> definitions() {
        return List.of(
                new Presentation("profile.list-all", "List certificate profiles", "Browse registered certificate profiles.", TEXT_PROFILES,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("request.list", "List certificate requests", "Browse stored certificate requests.", "requests",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("credential.search", "Browse certificates", "Browse certificates issued by an authority.", "issuance",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry("subjectFilter", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Case-insensitive substring match on subject DN (e.g. CN=, O=, OU=).", "")),
                                Map.entry("serialFilter", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Case-insensitive substring match on serial number.", "")),
                                Map.entry("fingerprintFilter", new FieldSemantics(TEXT_TEXT, "", false, false, false, "Credential ID prefix", "Case-insensitive credential ID prefix; this is not a certificate digest.", "")),
                                Map.entry("sanFilter", new FieldSemantics(TEXT_TEXT, "", false, false, false, "Subject alternative name", "Exact typed issued-certificate SAN: DNS_NAME, IP_ADDRESS, URI or RFC822_NAME, followed by a colon and value.", "DNS_NAME:api.example.test")),
                                Map.entry("statusFilter", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "Filter by credential status.", "")),
                                Map.entry("profileIdFilter", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Exact profile logical ID.", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("issuer.generation.list", "List issuer generations", "Browse all issuer generations of an authority.", TEXT_ISSUERS,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("configuration.choices", "Available configuration choices", "Inspect available formats, signing keys and providers.", "configuration",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("security.disclosure.capability.list", "List disclosure capabilities", "Browse disclosure capabilities for an object.", TEXT_DISCLOSURE,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OBJECT_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_OBJECT, false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("ca.list", "List authorities", "List certificate authorities in the realm.", TEXT_AUTHORITIES,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "Maximum number of authorities to return.", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("ca.inspect", "Inspect authority", "Show one authority in detail.", TEXT_AUTHORITIES,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", ""))
                        ))),
                new Presentation("ca.create", "Create root authority", "Create a new root certificate authority.", TEXT_AUTHORITIES,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_FORMAT_ID, new FieldSemantics(TEXT_TEXT, "format", false, false, false, "", "", "")),
                                Map.entry("subjectRef", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("keyRef", new FieldSemantics(TEXT_TEXT, "key", true, false, false, "", "", ""))
                        ))),
                new Presentation("ca.transition", "Transition authority state", "Change the lifecycle state of an authority.", TEXT_AUTHORITIES,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("state", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("reason", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("ca.intermediate.create", "Create intermediate CA", "Create a subordinate certificate authority.", TEXT_AUTHORITIES,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_ISSUER_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_FORMAT_ID, new FieldSemantics(TEXT_TEXT, "format", false, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("subjectRef", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("keyRef", new FieldSemantics(TEXT_TEXT, "key", true, false, false, "", "", ""))
                        ))),
                new Presentation("ca.intermediate.issue", "Issue intermediate certificate", "Issue a CA certificate for a subordinate authority.", TEXT_AUTHORITIES,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_ISSUER_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_FORMAT_ID, new FieldSemantics(TEXT_TEXT, "format", false, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("subjectCaId", new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("notBefore", new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "Optional; supply with notAfter.", "")),
                                Map.entry("notAfter", new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "Optional; supply with notBefore.", ""))
                        ))),
                new Presentation("ca.rollover", "Roll over CA certificate", "Roll the CA certificate to a new generation.", TEXT_AUTHORITIES,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", ""))
                        ))),
                new Presentation("ca.rotate", "Rotate CA key", "Rotate the signing key of an authority.", TEXT_AUTHORITIES,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("newKeyRef", new FieldSemantics(TEXT_TEXT, "key", true, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", ""))
                        ))),
                new Presentation("issuer.generation.inspect", "Inspect issuer generation", "Show one issuer generation.", TEXT_ISSUERS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_ISSUER_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_ISSUER, false, false, false, "", "", ""))
                        ))),
                new Presentation("issuer.path.inspect", "Inspect chain path", "Show one issuer chain path.", TEXT_ISSUERS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("pathId", new FieldSemantics(TEXT_PKI_ID, "path", false, false, false, "", "", ""))
                        ))),
                new Presentation("issuer.path.list", "List chain paths", "List chain paths for an issuer generation.", TEXT_ISSUERS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_ISSUER_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_ISSUER, false, false, false, "", "", ""))
                        ))),
                new Presentation("issuer.path.select", "Select issuance path", "Select the active issuance path for an authority.", TEXT_ISSUERS,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_ISSUER, false, false, false, "", "", "")),
                                Map.entry("pathId", new FieldSemantics(TEXT_PKI_ID, "path", false, false, false, "", "", "")),
                                Map.entry("reason", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("issuer.path.register", "Register chain path", "Register a new issuer chain path.", TEXT_ISSUERS,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_ISSUER, false, false, false, "", "", "")),
                                Map.entry("parentPathId", new FieldSemantics(TEXT_PKI_ID, "parentPath", false, false, false, "", "", ""))
                        ))),
                new Presentation("profile.list", "List profile versions", "List versions of a certificate profile.", TEXT_PROFILES,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", ""))
                        ))),
                new Presentation("profile.inspect", "Inspect profile", "Show one certificate profile version.", TEXT_PROFILES,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("profileVersion", new FieldSemantics(TEXT_LONG, "profileVersion", false, false, false, "", "", ""))
                        ))),
                new Presentation("profile.activate", "Activate profile", "Activate a certificate profile version.", TEXT_PROFILES,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("profileVersion", new FieldSemantics(TEXT_LONG, "profileVersion", false, false, false, "", "", ""))
                        ))),
                new Presentation("profile.register", "Register profile", "Register a certificate profile document (DER/JSON, base64).", TEXT_PROFILES,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("document", new FieldSemantics("base64", "", false, false, false, "", "Base64-encoded profile document.", ""))
                        ))),
                new Presentation("profile.validate", "Validate profile", "Validate a certificate profile document without registering it.", TEXT_PROFILES,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("document", new FieldSemantics("base64", "", false, false, false, "", "Base64-encoded profile document.", ""))
                        ))),
                new Presentation("request.inspect", "Inspect request", "Show one certification request.", "requests",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("requestId", new FieldSemantics(TEXT_PKI_ID, "request", false, false, false, "", "", ""))
                        ))),
                new Presentation("request.import", "Import request (CSR)", "Import a DER certification request (base64).", "requests",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_FORMAT_ID, new FieldSemantics(TEXT_TEXT, "format", false, false, false, "", "", "")),
                                Map.entry("encoded", new FieldSemantics("base64", "", false, false, false, "", "Base64-encoded DER CSR.", ""))
                        ))),
                new Presentation("request.verify", "Verify request", "Verify a certification request (proof of possession).", "requests",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("requestId", new FieldSemantics(TEXT_PKI_ID, "request", false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.inspect", "Inspect credential", "Show one issued credential.", "issuance",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.issue", "Issue credential", "Issue a credential from a request and profile.", "issuance",
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_ISSUER_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_ISSUER_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("requestId", new FieldSemantics(TEXT_PKI_ID, "request", false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.renew", "Renew credential", "Renew an existing credential.", "lifecycle",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.replace", "Replace credential", "Replace a credential with a new request and profile.", "lifecycle",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry("existingCredentialId", new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry("requestId", new FieldSemantics(TEXT_PKI_ID, "request", false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.reissue", "Reissue credential", "Reissue a credential (same key).", "lifecycle",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.confirmation.pending.list", "List pending confirmations", "List pending credential confirmations for an authority.", "confirmations",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("cutoffInclusive", new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "", "")),
                                Map.entry("afterExclusive", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.confirmation.challenge.issue", "Issue confirmation challenge", "Issue a proof-of-possession challenge for a credential.", "confirmations",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.confirmation.proof.complete", "Complete confirmation proof", "Complete a proof-of-possession challenge.", "confirmations",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry("expectedLifecycleRevision", new FieldSemantics(TEXT_LONG, "", false, false, true, "", "", "")),
                                Map.entry("expectedLifecycleRecordCommitment", new FieldSemantics(TEXT_TEXT, "", false, false, true, "", "", "")),
                                Map.entry("expectedChallengeRecordCommitment", new FieldSemantics(TEXT_TEXT, "", false, false, true, "", "", "")),
                                Map.entry("response", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Canonical unpadded Base64url proof response.", ""))
                        ))),
                new Presentation("credential.confirmation.pending.revoke", "Revoke pending confirmation", "Revoke a pending credential confirmation.", "confirmations",
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry(PARAM_JUSTIFICATION, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.hold", "Hold credential", "Temporarily hold an issued credential.", REVOCATION_SECTION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry(PARAM_JUSTIFICATION, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.unhold", "Release credential hold", "Release a temporary hold without reversing permanent revocation.", REVOCATION_SECTION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry(PARAM_JUSTIFICATION, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("credential.revoke", "Revoke credential", "Revoke an issued credential.", REVOCATION_SECTION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry("reason", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry(PARAM_JUSTIFICATION, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("revocation.inspect", "Inspect revocation", "Show the revocation state of a credential.", REVOCATION_SECTION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("revocation.history", "Revocation history", "Read the revocation history of a credential.", REVOCATION_SECTION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("revocation.snapshot", "Snapshot revocations", "Take a realm-wide revocation snapshot.", REVOCATION_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("status.inspect", "Inspect status object", "Show one status object (CRL/delta).", TEXT_STATUS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("statusObjectId", new FieldSemantics(TEXT_PKI_ID, TEXT_STATUS, false, false, false, "", "", ""))
                        ))),
                new Presentation("inventory.status", "List status objects", "List status objects for an issuer.", TEXT_STATUS,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_ISSUER_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_ISSUER_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("status.generate", "Generate status object", "Generate a CRL or delta CRL.", TEXT_STATUS,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_ISSUER_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_ISSUER_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("type", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_FORMAT_ID, new FieldSemantics(TEXT_TEXT, "format", false, false, false, "", "", ""))
                        ))),
                new Presentation("status.schedule.set", "Set status schedule", "Create or replace the automatic generation schedule for a status type.", TEXT_STATUS,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("statusType", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_FORMAT_ID, new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("interval", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "ISO-8601 duration (e.g. PT4H).", "")),
                                Map.entry("graceSeconds", new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry("enabled", new FieldSemantics("boolean", "", false, false, false, "", "", "")),
                                Map.entry("targetType", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("targetId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("status.schedule.inspect", "Inspect status schedule", "Show the generation schedule for one status type.", TEXT_STATUS,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("statusType", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("status.schedule.list", "List status schedules", "List all active automatic generation schedules.", TEXT_STATUS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("publication.list", "List publications", "List publication records in the realm.", TEXT_PUBLICATION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("publication.inspect", "Inspect publication", "Show one publication record.", TEXT_PUBLICATION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry("publicationId", new FieldSemantics(TEXT_PKI_ID, TEXT_PUBLICATION, false, false, false, "", "", ""))
                        ))),
                new Presentation("publication.register", "Register publication", "Register a publication of a credential or status object.", TEXT_PUBLICATION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry("publicationId", new FieldSemantics(TEXT_PKI_ID, "", false, false, false, "", "", "")),
                                Map.entry("sourceType", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("sourceId", new FieldSemantics(TEXT_PKI_ID, "sourceObject", false, false, false, "", "", "")),
                                Map.entry("targetType", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("targetId", new FieldSemantics(TEXT_TEXT, "publicationTarget", false, false, false, "", "", ""))
                        ))),
                new Presentation("publication.process", "Process publication", "Process a pending publication.", TEXT_PUBLICATION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry("publicationId", new FieldSemantics(TEXT_PKI_ID, TEXT_PUBLICATION, false, false, false, "", "", ""))
                        ))),
                new Presentation("publication.retry", "Retry publication", "Retry a failed publication.", TEXT_PUBLICATION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry("publicationId", new FieldSemantics(TEXT_PKI_ID, TEXT_PUBLICATION, false, false, false, "", "", ""))
                        ))),
                new Presentation("publication.reconcile", "Reconcile publication", "Reconcile a publication record.", TEXT_PUBLICATION,
                        new TransportSemantics(TEXT_AUTHORITY, "", Map.ofEntries(
                                Map.entry("publicationId", new FieldSemantics(TEXT_PKI_ID, TEXT_PUBLICATION, false, false, false, "", "", ""))
                        ))),
                new Presentation("configuration.validate", "Validate configuration", "Validate the active PKI configuration.", "configuration",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries())),
                new Presentation("algorithm.binding.list", "List algorithm bindings", "List algorithm bindings.", "configuration",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("origin", new FieldSemantics(TEXT_TEXT, "algorithmOrigin", false, false, false, "", "", "")),
                                Map.entry("role", new FieldSemantics(TEXT_TEXT, "algorithmRole", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_TEXT, "", false, true, false, "", "", ""))
                        ))),
                new Presentation("algorithm.binding.inspect", "Inspect algorithm binding", "Show one algorithm binding.", "configuration",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("bindingId", new FieldSemantics(TEXT_TEXT, "algorithmBinding", false, false, false, "", "", ""))
                        ))),
                new Presentation("algorithm.binding.validate", "Validate algorithm bindings", "Validate algorithm bindings.", "configuration",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("bindingId", new FieldSemantics(TEXT_TEXT, "algorithmBinding", false, false, false, "", "", "")),
                                Map.entry("expectedCommitment", new FieldSemantics(TEXT_TEXT, "", false, false, true, "", "", ""))
                        ))),
                new Presentation("security.principal.register", "Register principal", "Register a security principal.", "principals",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_PRINCIPAL_ID, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("type", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("displayName", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("enabled", new FieldSemantics("boolean", "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.principal.inspect", "Inspect principal", "Show one security principal.", "principals",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_PRINCIPAL_ID, new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("security.principal.list", "List principals", "List security principals.", "principals",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.principal.enable", "Enable principal", "Enable a security principal.", "principals",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_PRINCIPAL_ID, new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("security.principal.disable", "Disable principal", "Disable a security principal.", "principals",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_PRINCIPAL_ID, new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("security.role-template.list", "List role templates", "List available role templates.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries())),
                new Presentation("security.role-template.inspect", "Inspect role template", "Show one role template version.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("templateId", new FieldSemantics(TEXT_TEXT, "roleTemplate", false, false, false, "", "", "")),
                                Map.entry("version", new FieldSemantics(TEXT_INTEGER, "templateVersion", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.role-assignment.create", "Create role assignment", "Assign a role template to a principal.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("assignmentId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_PRINCIPAL_ID, new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", "")),
                                Map.entry("templateId", new FieldSemantics(TEXT_TEXT, "roleTemplate", false, false, false, "", "", "")),
                                Map.entry("templateVersion", new FieldSemantics(TEXT_INTEGER, "templateVersion", false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("expiresAt", new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.role-assignment.inspect", "Inspect role assignment", "Show one role assignment.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("assignmentId", new FieldSemantics(TEXT_TEXT, "roleAssignment", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.role-assignment.list", "List role assignments", "List role assignments.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.role-assignment.revoke", "Revoke role assignment", "Revoke a role assignment.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("assignmentId", new FieldSemantics(TEXT_TEXT, "roleAssignment", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.grant.create", "Create grant", "Create an explicit authorization grant.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("grantId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_PRINCIPAL_ID, new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", "")),
                                Map.entry("effect", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("action", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("resourceType", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_ISSUER, false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("responderId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("relationship", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("dataView", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("conditions", new FieldSemantics("enumSet", "", false, false, false, "", "", "")),
                                Map.entry("expiresAt", new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.grant.inspect", "Inspect grant", "Show one authorization grant.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("grantId", new FieldSemantics(TEXT_TEXT, "grant", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.grant.list", "List grants", "List authorization grants.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.grant.revoke", "Revoke grant", "Revoke an authorization grant.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("grantId", new FieldSemantics(TEXT_TEXT, "grant", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.authorization.evaluate", "Evaluate authorization", "Evaluate whether a principal is authorized for an action.", TEXT_ACCESS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_PRINCIPAL_ID, new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", "")),
                                Map.entry("action", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("resourceType", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("relationship", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("dataView", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.approval.request", "Request approval", "Create a durable approval for a HIGH_RISK target operation.", TEXT_APPROVALS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("approvalId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("targetOperation", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Operation id being approved.", "")),
                                Map.entry("targetArguments", new FieldSemantics("json", "", false, false, false, "", "JSON object of the target operation arguments.", "")),
                                Map.entry("targetAuthorityId", new FieldSemantics(TEXT_TEXT, TEXT_AUTHORITY, false, false, false, "", "", ""))
                        ))),
                new Presentation("security.approval.inspect", "Inspect approval", "Show one approval.", TEXT_APPROVALS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("approvalId", new FieldSemantics(TEXT_TEXT, "approval", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.approval.list", "List approvals", "List approvals, optionally filtered.", TEXT_APPROVALS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry("state", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("requesterPrincipalId", new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", "")),
                                Map.entry("targetOperationId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.approval.approve", "Approve", "Approve a pending approval.", TEXT_APPROVALS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("approvalId", new FieldSemantics(TEXT_TEXT, "approval", false, false, false, "", "", "")),
                                Map.entry(PARAM_JUSTIFICATION, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.approval.reject", "Reject", "Reject a pending approval.", TEXT_APPROVALS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("approvalId", new FieldSemantics(TEXT_TEXT, "approval", false, false, false, "", "", "")),
                                Map.entry(PARAM_JUSTIFICATION, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.approval.cancel", "Cancel approval", "Cancel a pending approval.", TEXT_APPROVALS,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("approvalId", new FieldSemantics(TEXT_TEXT, "approval", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.break-glass.create", "Create break-glass", "Create a break-glass emergency grant.", "break-glass",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("breakGlassId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_PRINCIPAL_ID, new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", "")),
                                Map.entry("grantId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("action", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("resourceType", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("reason", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("expiresAt", new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.break-glass.activate", "Activate break-glass", "Activate a break-glass grant.", "break-glass",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("breakGlassId", new FieldSemantics(TEXT_TEXT, "breakGlass", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.break-glass.inspect", "Inspect break-glass", "Show one break-glass grant.", "break-glass",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("breakGlassId", new FieldSemantics(TEXT_TEXT, "breakGlass", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.break-glass.list", "List break-glass", "List break-glass grants.", "break-glass",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.break-glass.revoke", "Revoke break-glass", "Revoke a break-glass grant.", "break-glass",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("breakGlassId", new FieldSemantics(TEXT_TEXT, "breakGlass", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.disclosure.inspect", "Inspect disclosure", "Show the disclosure policy of an object.", TEXT_DISCLOSURE,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OBJECT_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_OBJECT, false, false, false, "", "", ""))
                        ))),
                new Presentation("security.disclosure.set", "Set disclosure", "Set the disclosure policy of an object.", TEXT_DISCLOSURE,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OBJECT_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_OBJECT, false, false, false, "", "", "")),
                                Map.entry("policy", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("certificate.publication.enroll", "Enroll credential publication", "Enroll a credential for publication.", TEXT_DISCLOSURE,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_CREDENTIAL_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry("ownerPrincipalId", new FieldSemantics(TEXT_TEXT, TEXT_PRINCIPAL, false, false, false, "", "", ""))
                        ))),
                new Presentation("security.disclosure.capability.issue", "Issue disclosure capability", "Issue a time-bounded disclosure capability.", TEXT_DISCLOSURE,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OBJECT_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_OBJECT, false, false, false, "", "", "")),
                                Map.entry("expiresAt", new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.disclosure.capability.revoke", "Revoke disclosure capability", "Revoke a disclosure capability.", TEXT_DISCLOSURE,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("capabilityId", new FieldSemantics(TEXT_TEXT, "capability", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.audit-view.inspect-redacted", "Inspect audit (redacted)", "Inspect an audit record (redacted view).", "audit",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OBJECT_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_OBJECT, false, false, false, "", "", "")),
                                Map.entry("reasonReference", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.audit-view.inspect-full", "Inspect audit (full)", "Inspect an audit record (full metadata view).", "audit",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OBJECT_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_OBJECT, false, false, false, "", "", "")),
                                Map.entry("reasonReference", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.audit-view.inspect-pii", "Inspect audit (PII)", "Inspect an audit record (PII view).", "audit",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OBJECT_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_OBJECT, false, false, false, "", "", "")),
                                Map.entry("reasonReference", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.audit.search", "Search audit", "Search the audit trail.", "audit",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("category", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("action", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AFTER, new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "", "")),
                                Map.entry("before", new FieldSemantics(TEXT_INSTANT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_OBJECT_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_OBJECT, false, false, false, "", "", "")),
                                Map.entry("principalName", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("security.audit.verify-integrity", "Verify audit integrity", "Verify the audit chain integrity.", "audit",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("sequence", new FieldSemantics(TEXT_LONG, "", false, false, false, "", "Optional chain head sequence.", "")),
                                Map.entry("recordHash", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Optional chain head record hash (supply with sequence).", ""))
                        ))),
                new Presentation("repository.alias.inspect", "Inspect repository alias", "Show a repository alias for an authority.", "repository",
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_AUTHORITY_ID, Map.ofEntries(
                                Map.entry(TEXT_AUTHORITY_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("type", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("repository.alias.list", "List repository aliases", "List repository aliases.", "repository",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("repository.alias.set", "Set repository alias", "Set a repository alias target.", "repository",
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_AUTHORITY_ID, Map.ofEntries(
                                Map.entry(TEXT_AUTHORITY_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("type", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("targetObjectId", new FieldSemantics(TEXT_PKI_ID, "aliasTarget", false, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_ISSUER, false, false, false, "", "", "")),
                                Map.entry("expectedCurrentCommitment", new FieldSemantics(TEXT_TEXT, "", false, false, true, "", "", ""))
                        ))),
                new Presentation("repository.alias.remove", "Remove repository alias", "Remove a repository alias.", "repository",
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_AUTHORITY_ID, Map.ofEntries(
                                Map.entry(TEXT_AUTHORITY_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry("type", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("expectedCurrentCommitment", new FieldSemantics(TEXT_TEXT, "", false, false, true, "", "", ""))
                        ))),
                new Presentation("acme.directory.register", "Register ACME directory", "Register an ACME directory.", TEXT_ACME,
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_AUTHORITY_ID, Map.ofEntries(
                                Map.entry("alias", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AUTHORITY_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("dnsNamespaces", new FieldSemantics("stringSet", "", false, false, false, "", "", "")),
                                Map.entry("maximumValidityMillis", new FieldSemantics(TEXT_LONG, "", false, false, false, "", "", "")),
                                Map.entry("publicKeyAlgorithms", new FieldSemantics("stringSet", "", false, false, true, "", "", "")),
                                Map.entry("x509BindingPolicies", new FieldSemantics("stringSet", "", false, false, true, "", "", "")),
                                Map.entry("challengeTypes", new FieldSemantics("enumSet", "", false, false, false, "", "", "")),
                                Map.entry("challengeProviderIds", new FieldSemantics("stringSet", "challengeProvider", false, false, false, "", "", "")),
                                Map.entry("eabProviderId", new FieldSemantics(TEXT_TEXT, "eabProvider", false, false, false, "", "", "")),
                                Map.entry("eabRequired", new FieldSemantics("boolean", "", false, false, false, "", "", ""))
                        ))),
                new Presentation("acme.directory.inspect", "Inspect ACME directory", "Show one ACME directory.", TEXT_ACME,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("directoryId", new FieldSemantics(TEXT_TEXT, "acmeDirectory", false, false, false, "", "", ""))
                        ))),
                new Presentation("acme.directory.list", "List ACME directories", "List ACME directories.", TEXT_ACME,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("acme.directory.activate", "Activate ACME directory", "Activate an ACME directory.", TEXT_ACME,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("directoryId", new FieldSemantics(TEXT_TEXT, "acmeDirectory", false, false, false, "", "", ""))
                        ))),
                new Presentation("acme.directory.deactivate", "Deactivate ACME directory", "Deactivate an ACME directory.", TEXT_ACME,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("directoryId", new FieldSemantics(TEXT_TEXT, "acmeDirectory", false, false, false, "", "", ""))
                        ))),
                new Presentation("acme.account.inspect", "Inspect ACME account", "Show one ACME account.", TEXT_ACME,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("accountId", new FieldSemantics(TEXT_TEXT, "acmeAccount", false, false, false, "", "", ""))
                        ))),
                new Presentation("acme.account.list", "List ACME accounts", "List ACME accounts.", TEXT_ACME,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("acme.account.deactivate", "Deactivate ACME account", "Deactivate an ACME account.", TEXT_ACME,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("accountId", new FieldSemantics(TEXT_TEXT, "acmeAccount", false, false, false, "", "", ""))
                        ))),
                new Presentation("ocsp.responder.register", "Register OCSP responder", "Register an OCSP responder.", "ocsp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("responderId", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("alias", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AUTHORITY_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_ISSUER_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_ISSUER, false, false, false, "", "", "")),
                                Map.entry("signingMode", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("responderCredentialId", new FieldSemantics(TEXT_PKI_ID, TEXT_CREDENTIAL, false, false, false, "", "", "")),
                                Map.entry("signingKeyRef", new FieldSemantics(TEXT_TEXT, "key", true, false, false, "", "", "")),
                                Map.entry("chainPathId", new FieldSemantics(TEXT_PKI_ID, "path", false, false, false, "", "", "")),
                                Map.entry("signatureAlgorithm", new FieldSemantics(TEXT_TEXT, "signatureAlgorithm", false, false, false, "", "", "")),
                                Map.entry("signatureBindingId", new FieldSemantics(TEXT_TEXT, "algorithmBinding", false, false, false, "", "", "")),
                                Map.entry("signatureBindingCommitment", new FieldSemantics(TEXT_TEXT, "", false, false, true, "", "", "")),
                                Map.entry("responderIdForm", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("responseValidityMillis", new FieldSemantics(TEXT_LONG, "", false, false, false, "", "", "")),
                                Map.entry("noncePolicy", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("maximumNonceBytes", new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry("acceptedHashes", new FieldSemantics("enumSet", "", false, false, false, "", "", "")),
                                Map.entry("maximumRequestBytes", new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry("maximumEntries", new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry("cacheLifetimeMillis", new FieldSemantics(TEXT_LONG, "", false, false, false, "", "", "")),
                                Map.entry("requestAuthenticationMode", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("requesterTrustPolicy", new FieldSemantics("json", "", false, false, false, "", "Optional JSON requester trust policy.", ""))
                        ))),
                new Presentation("ocsp.responder.inspect", "Inspect OCSP responder", "Show one OCSP responder.", "ocsp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("responderId", new FieldSemantics(TEXT_TEXT, "ocspResponder", false, false, false, "", "", ""))
                        ))),
                new Presentation("ocsp.responder.list", "List OCSP responders", "List OCSP responders.", "ocsp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("ocsp.responder.activate", "Activate OCSP responder", "Activate an OCSP responder.", "ocsp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("responderId", new FieldSemantics(TEXT_TEXT, "ocspResponder", false, false, false, "", "", ""))
                        ))),
                new Presentation("ocsp.responder.deactivate", "Deactivate OCSP responder", "Deactivate an OCSP responder.", "ocsp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("responderId", new FieldSemantics(TEXT_TEXT, "ocspResponder", false, false, false, "", "", ""))
                        ))),
                new Presentation("scep.endpoint.register", "Register SCEP endpoint", "Register a SCEP enrollment endpoint.", "scep",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AUTHORITY_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("challengePasswordHash", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "SHA-256 challenge digest in endpoint metadata. The exact signed CSR retains its challenge in the protected request store and backups; ordinary request projections omit it.", ""))
                        ))),
                new Presentation("scep.endpoint.inspect", "Inspect SCEP endpoint", "Show one SCEP endpoint.", "scep",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "scepEndpoint", false, false, false, "", "", ""))
                        ))),
                new Presentation("scep.endpoint.list", "List SCEP endpoints", "List SCEP enrollment endpoints.", "scep",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("scep.endpoint.deregister", "Deregister SCEP endpoint", "Remove a SCEP enrollment endpoint.", "scep",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "scepEndpoint", false, false, false, "", "", ""))
                        ))),
                new Presentation("cmp.endpoint.register", "Register CMP endpoint", "Register a CMP enrollment endpoint.", "cmp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AUTHORITY_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("protectionPolicy", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "SHARED_SECRET uses a pre-shared password; SIGNATURE requires a client certificate.", ""))
                        ))),
                new Presentation("cmp.endpoint.inspect", "Inspect CMP endpoint", "Show one CMP endpoint.", "cmp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "cmpEndpoint", false, false, false, "", "", ""))
                        ))),
                new Presentation("cmp.endpoint.list", "List CMP endpoints", "List CMP enrollment endpoints.", "cmp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("cmp.endpoint.deregister", "Deregister CMP endpoint", "Remove a CMP enrollment endpoint.", "cmp",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "cmpEndpoint", false, false, false, "", "", ""))
                        ))),
                new Presentation("est.endpoint.register", "Register EST endpoint", "Register an EST enrollment endpoint.", "est",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_AUTHORITY_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", "")),
                                Map.entry(TEXT_PROFILE_ID, new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("keygen", new FieldSemantics("json", "", false, false, false, "", "Server-keygen policy (omit entirely to disable). Fields: enabled (bool), permittedAlgorithms (string array of JCA key algorithm names), maximumKeySizeBits (int ≥ 256), storeGeneratedKeys (bool — true escrows the private key in the CA keyring).", "{\"enabled\":true,\"permittedAlgorithms\":[\"RSA\",\"EC\"],\"maximumKeySizeBits\":4096,\"storeGeneratedKeys\":false}"))
                        ))),
                new Presentation("est.endpoint.inspect", "Inspect EST endpoint", "Show one EST endpoint.", "est",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "estEndpoint", false, false, false, "", "", ""))
                        ))),
                new Presentation("est.endpoint.list", "List EST endpoints", "List EST enrollment endpoints.", "est",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("est.endpoint.deregister", "Deregister EST endpoint", "Remove an EST enrollment endpoint.", "est",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "estEndpoint", false, false, false, "", "", ""))
                        ))),
                new Presentation("enrollment.profile.register", "Register enrollment profile", "Register a new enrollment profile.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("id", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "URL-safe profile identity, unique within the realm.", "")),
                                Map.entry("displayName", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("certificateProfileId", new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "Certificate profile applied to issued credentials.", "")),
                                Map.entry("subjectDnPattern", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Regex the requested Subject DN must match (omit = unconstrained).", "")),
                                Map.entry("requireApproval", new FieldSemantics("boolean", "", false, false, false, "", "Require out-of-band approval before issuance.", ""))
                        ))),
                new Presentation("enrollment.profile.update", "Update enrollment profile", "Replace all mutable fields of an enrollment profile.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("id", new FieldSemantics(TEXT_TEXT, "enrollmentProfile", false, false, false, "", "", "")),
                                Map.entry("displayName", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("state", new FieldSemantics(TEXT_ENUM, "", false, false, false, "", "", "")),
                                Map.entry("certificateProfileId", new FieldSemantics(TEXT_TEXT, TEXT_PROFILE, false, false, false, "", "", "")),
                                Map.entry("subjectDnPattern", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")),
                                Map.entry("requireApproval", new FieldSemantics("boolean", "", false, false, false, "", "", ""))
                        ))),
                new Presentation("enrollment.profile.inspect", "Inspect enrollment profile", "Show one enrollment profile.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("id", new FieldSemantics(TEXT_TEXT, "enrollmentProfile", false, false, false, "", "", ""))
                        ))),
                new Presentation("enrollment.profile.list", "List enrollment profiles", "List registered enrollment profiles.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")),
                                Map.entry(TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("enrollment.profile.activate", "Activate enrollment profile", "Transition a suspended enrollment profile back to ACTIVE.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("id", new FieldSemantics(TEXT_TEXT, "enrollmentProfile", false, false, false, "", "", ""))
                        ))),
                new Presentation("enrollment.request.inspect", "Inspect enrollment request", "Inspect the frozen protocol request and approval state.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.of("id", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")))),
                new Presentation("enrollment.request.list", "List enrollment requests", "List retained protocol requests in the authorized scope.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.of(
                                TEXT_OFFSET, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", ""),
                                TEXT_LIMIT, new FieldSemantics(TEXT_INTEGER, "", false, false, false, "", "", "")))),
                new Presentation("enrollment.request.approve", "Approve enrollment request", "Approve the exact inspected record using the authenticated administrator's credential.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.of(
                                "id", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""),
                                "expectedCommitment", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Commitment returned by inspection.", ""),
                                PARAM_JUSTIFICATION, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")))),
                new Presentation("enrollment.request.reject", "Reject enrollment request", "Reject the exact inspected protocol request.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.of(
                                "id", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""),
                                "expectedCommitment", new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "Commitment returned by inspection.", ""),
                                PARAM_JUSTIFICATION, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", "")))),
                new Presentation("enrollment.profile.suspend", "Suspend enrollment profile", "Suspend an active enrollment profile; enrollment requests will be rejected.", TEXT_ENROLLMENT,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("id", new FieldSemantics(TEXT_TEXT, "enrollmentProfile", false, false, false, "", "", ""))
                        ))),
                new Presentation("dashboard.authority", "Authority metrics", "Issuer-generation states and chain depth for one CA.", "dashboard",
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", ""))
                        ))),
                new Presentation("dashboard.certificate", "Certificate metrics", "Active, expiring, expired, and revoked certificate counts for one CA; pending-request lifecycle measurement is unavailable.", "dashboard",
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", ""))
                        ))),
                new Presentation("dashboard.revocation", "Revocation metrics", "Revocation count and CRL freshness for one CA.", "dashboard",
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", ""))
                        ))),
                new Presentation("dashboard.publication", "Publication metrics", "Pending and failing publication counts for one CA.", "dashboard",
                        new TransportSemantics(TEXT_AUTHORITY, TEXT_CA_ID, Map.ofEntries(
                                Map.entry(TEXT_CA_ID, new FieldSemantics(TEXT_PKI_ID, TEXT_AUTHORITY, false, false, false, "", "", ""))
                        ))),
                new Presentation("dashboard.server", "Server metrics", "JVM heap, approval queue depth, admin requests, audit health, and schedule-worker health, with explicit unavailable or failed measurement states.", "dashboard",
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries())),
                new Presentation("backup.stream.reserve", "Reserve backup upload", "Reserve backup upload using explicitly configured bounded transfer storage.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(Map.entry("backupId", new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", "")), Map.entry("length", new FieldSemantics("integer", "", false, false, false, "", "", "")), Map.entry("sha256", new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", ""))))),
                new Presentation("backup.stream.export", "Export streaming backup", "Export streaming backup using explicitly configured bounded transfer storage.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(Map.entry("label", new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", ""))))),
                new Presentation("backup.stream.upload", "Upload backup archive", "Upload backup archive using explicitly configured bounded transfer storage.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(Map.entry(PARAM_ARTIFACT_HANDLE, new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", ""))))),
                new Presentation("backup.stream.download", "Download backup archive", "Download backup archive using explicitly configured bounded transfer storage.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(Map.entry(PARAM_ARTIFACT_HANDLE, new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", ""))))),
                new Presentation("backup.stream.verify", "Verify uploaded archive", "Verify uploaded archive using explicitly configured bounded transfer storage.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(Map.entry(PARAM_ARTIFACT_HANDLE, new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", ""))))),
                new Presentation("backup.stream.restore", "Stage backup restoration", "Stage backup restoration using explicitly configured bounded transfer storage.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(Map.entry(PARAM_ARTIFACT_HANDLE, new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", ""))))),
                new Presentation("backup.stream.status", "Inspect restore workflow", "Inspect restore workflow using explicitly configured bounded transfer storage.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(Map.entry(PARAM_ARTIFACT_HANDLE, new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", ""))))),
                new Presentation("backup.stream.acknowledge", "Acknowledge restore outcome", "Acknowledge restore outcome using explicitly configured bounded transfer storage.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(Map.entry(PARAM_ARTIFACT_HANDLE, new FieldSemantics(TEXT_WIDGET, "", false, false, false, "", "", ""))))),
                new Presentation("backup.export", "Export backup", "Export a logical PKI backup.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry(TEXT_LABEL, new FieldSemantics(TEXT_TEXT, "", false, false, false, "", "", ""))
                        ))),
                new Presentation("backup.verify", "Verify backup", "Verify a logical PKI backup.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("backupId", new FieldSemantics(TEXT_PKI_ID, "", false, false, false, "", "", "")),
                                Map.entry("payload", new FieldSemantics("base64", "", false, false, false, "", "", ""))
                        ))),
                new Presentation("backup.restore", "Restore backup", "Remote restoration is unavailable.", BACKUP_SECTION,
                        new TransportSemantics(TEXT_REALM, "", Map.ofEntries(
                                Map.entry("backupId", new FieldSemantics(TEXT_PKI_ID, "", false, false, false, "", "", "")),
                                Map.entry("payload", new FieldSemantics("base64", "", false, false, false, "", "", ""))
                        ))));
    }
}
