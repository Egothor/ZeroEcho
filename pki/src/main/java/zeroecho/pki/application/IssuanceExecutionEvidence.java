/* *****************************************************************************
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
package zeroecho.pki.application;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

/**
 * Immutable, server-derived evidence co-committed with a successful end-entity issuance.
 *
 * <p>The evidence is written into the issued {@code Credential}'s universal attribute set in the
 * same atomic durable write as the credential itself, so a committed credential always carries its
 * authenticated issuance provenance. Native credential fields remain the authority for identity,
 * issuer, profile, validity, and status; this evidence records only the authenticated actor and
 * authorization path that produced it. It mirrors {@link RevocationExecutionEvidence} so the two
 * families project through the same generic audit-projection framework.</p>
 *
 * @param actorType authenticated actor classification
 * @param actorId authenticated administrative or protocol requester identifier
 * @param realmId realm identity
 * @param requestId trusted originating invocation correlation identifier
 * @param authentication authentication classification
 * @param authorization authorization classification
 * @param authorizationPath exact administrative or enrollment path (absent for legacy ACME ownership evidence)
 * @param operationCommitment exact durable operation commitment (absent for legacy ACME ownership evidence)
 * @param issuerCaId issuing authority identity
 * @param profileId frozen certificate-profile identity governing issuance
 * @param outcome outcome committed atomically with the credential
 */
public record IssuanceExecutionEvidence(ActorType actorType, String actorId, String realmId, String requestId,
        Authentication authentication, Authorization authorization, Optional<AuthorizationPath> authorizationPath,
        Optional<String> operationCommitment, String issuerCaId, String profileId, Outcome outcome) {

    /** Stable evidence actor classifications. */
    public enum ActorType {
        /** Authenticated administrative principal. */
        ADMIN_PRINCIPAL,
        /** Protocol-native ACME account. */
        ACME_ACCOUNT,
        /** Authenticated EST certificate holder. */ EST_CLIENT,
        /** Verified SCEP CMS signer. */ SCEP_SIGNER,
        /** Trusted CMP message signature identity. */ CMP_SIGNER,
        /** Explicitly provisioned CMP PBM requester identity. */ CMP_PBM
    }
    /** Stable evidence authentication classifications. */
    public enum Authentication {
        /** Direct mutual-TLS client authentication. */
        DIRECT_MTLS,
        /** Identity asserted by a trusted reverse proxy. */
        TRUSTED_REVERSE_PROXY,
        /** ACME account JSON Web Signature authentication. */
        ACME_ACCOUNT_JWS,
        /** EST protocol client certificate authentication. */ EST_MTLS,
        /** Verified SCEP CMS message signature. */ SCEP_CMS,
        /** Verified authority-scoped CMP signature protection. */ CMP_SIGNATURE,
        /** Verified authority-scoped CMP password-based MAC. */ CMP_PBM
    }
    /** Stable evidence authorization classifications. */
    public enum Authorization {
        /** Administrative policy allowed issuance. */
        ALLOWED,
        /** ACME account ownership authorized issuance. */
        ACME_OWNERSHIP,
        /** Exact durable enrollment policy admitted this protocol request. */ ENROLLMENT_POLICY
    }
    /** Exact administrative or enrollment authorization path; administrative break-glass takes precedence. */
    public enum AuthorizationPath {
        /** Ordinary administrative grant. */
        ORDINARY_GRANT,
        /** Explicit approval workflow. */
        APPROVAL,
        /** Audited emergency break-glass path. */
        BREAK_GLASS,
        /** Enrollment policy explicitly permits issuance without administrative approval. */ ENROLLMENT_POLICY
    }
    /** Outcome committed atomically with the credential. */
    public enum Outcome {
        /** Credential and evidence committed atomically. */
        ISSUED
    }

    /** Evidence attribute vocabulary. */
    public static final AttributeId ACTOR_TYPE = id("actor-type");
    /** Evidence attribute vocabulary. */
    public static final AttributeId ACTOR_ID = id("actor-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId REALM_ID = id("realm-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId REQUEST_ID = id("request-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId AUTHENTICATION = id("authentication");
    /** Evidence attribute vocabulary. */
    public static final AttributeId AUTHORIZATION = id("authorization");
    /** Evidence attribute vocabulary. */
    public static final AttributeId AUTHORIZATION_PATH = id("authorization-path");
    /** Evidence attribute vocabulary. */
    public static final AttributeId OPERATION_COMMITMENT = id("operation-commitment");
    /** Evidence attribute vocabulary. */
    public static final AttributeId ISSUER_CA_ID = id("issuer-ca-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId PROFILE_ID = id("profile-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId OUTCOME = id("outcome");

    private static final String EVIDENCE_PREFIX = "urn:zeroecho:pki:issuance-evidence:";
    private static final String EVIDENCE_V1_SUFFIX = ":v1";
    private static final Set<AttributeId> EVIDENCE_V1 = Set.of(ACTOR_TYPE, ACTOR_ID, REALM_ID, REQUEST_ID,
            AUTHENTICATION, AUTHORIZATION, AUTHORIZATION_PATH, OPERATION_COMMITMENT, ISSUER_CA_ID, PROFILE_ID,
            OUTCOME);

    /** Validates the closed evidence model. */
    public IssuanceExecutionEvidence {
        Objects.requireNonNull(actorType, "actorType");
        requireBounded(actorId, "actor ID");
        requireBounded(realmId, "realm ID");
        requireBounded(requestId, "request ID");
        Objects.requireNonNull(authentication, "authentication");
        Objects.requireNonNull(authorization, "authorization");
        authorizationPath = Objects.requireNonNull(authorizationPath, "authorizationPath");
        operationCommitment = Objects.requireNonNull(operationCommitment, "operationCommitment");
        operationCommitment.ifPresent(IssuanceExecutionEvidence::requireCommitment);
        requireBounded(issuerCaId, "issuer CA ID");
        requireBounded(profileId, "profile ID");
        Objects.requireNonNull(outcome, "outcome");
        boolean administrative = actorType == ActorType.ADMIN_PRINCIPAL
                && (authentication == Authentication.DIRECT_MTLS || authentication == Authentication.TRUSTED_REVERSE_PROXY)
                && authorization == Authorization.ALLOWED
                && authorizationPath.isPresent() && authorizationPath.orElseThrow() != AuthorizationPath.ENROLLMENT_POLICY
                && operationCommitment.isPresent();
        boolean acme = actorType == ActorType.ACME_ACCOUNT
                && authentication == Authentication.ACME_ACCOUNT_JWS
                && authorization == Authorization.ACME_OWNERSHIP
                && authorizationPath.isEmpty() && operationCommitment.isEmpty();
        boolean enrollmentAuthentication = switch (actorType) {
            case ADMIN_PRINCIPAL -> false;
            case ACME_ACCOUNT -> authentication == Authentication.ACME_ACCOUNT_JWS;
            case EST_CLIENT -> authentication == Authentication.EST_MTLS;
            case SCEP_SIGNER -> authentication == Authentication.SCEP_CMS;
            case CMP_SIGNER -> authentication == Authentication.CMP_SIGNATURE;
            case CMP_PBM -> authentication == Authentication.CMP_PBM;
        };
        boolean enrollment = enrollmentAuthentication && authorization == Authorization.ENROLLMENT_POLICY
                && operationCommitment.isPresent() && authorizationPath.filter(path ->
                        path == AuthorizationPath.APPROVAL || path == AuthorizationPath.ENROLLMENT_POLICY).isPresent();
        if (!administrative && !acme && !enrollment) {
            throw new IllegalArgumentException("Issuance evidence classification is inconsistent");
        }
    }

    /**
     * Creates authoritative administrative issuance evidence.
     *
     * @param principalId bounded authenticated administrator identifier
     * @param realmId bounded authorization realm identifier
     * @param requestId trusted originating invocation correlation identifier
     * @param authentication direct mutual TLS or trusted reverse-proxy mutual TLS
     * @param path administrative grant, approval, or break-glass path
     * @param operationCommitment lowercase 64-hex-character operation commitment
     * @param issuerCaId issuing authority identifier
     * @param profileId frozen certificate-profile identifier
     * @return validated immutable administrative evidence
     */
    @SuppressWarnings("PMD.UseObjectForClearerAPI")
    public static IssuanceExecutionEvidence administrative(String principalId, String realmId, String requestId,
            Authentication authentication, AuthorizationPath path, String operationCommitment, String issuerCaId,
            String profileId) {
        return new IssuanceExecutionEvidence(ActorType.ADMIN_PRINCIPAL, principalId, realmId, requestId,
                authentication, Authorization.ALLOWED, Optional.of(Objects.requireNonNull(path, "path")),
                Optional.of(operationCommitment), issuerCaId, profileId, Outcome.ISSUED);
    }

    /**
     * Creates authoritative protocol-native ACME issuance evidence.
     *
     * @param accountId bounded ACME account identifier
     * @param realmId bounded authorization realm identifier
     * @param requestId trusted originating invocation correlation identifier
     * @param issuerCaId issuing authority identifier
     * @param profileId frozen certificate-profile identifier
     * @return validated immutable ACME ownership evidence
     */
    // Stable protocol factory retained for source compatibility; grouping parameters would change the public API.
    @SuppressWarnings("PMD.UseObjectForClearerAPI")
    public static IssuanceExecutionEvidence acme(String accountId, String realmId, String requestId,
            String issuerCaId, String profileId) {
        return new IssuanceExecutionEvidence(ActorType.ACME_ACCOUNT, accountId, realmId, requestId,
                Authentication.ACME_ACCOUNT_JWS, Authorization.ACME_OWNERSHIP, Optional.empty(), Optional.empty(),
                issuerCaId, profileId, Outcome.ISSUED);
    }

    /**
     * Creates evidence for a verified protocol requester admitted through an
     * exact durable enrollment policy and, when required, independent approval.
     * This factory grants no authority and cannot represent an administrator.
     * @param actorType protocol-native requester classification
     * @param actorId authenticated protocol identity
     * @param realmId owning realm
     * @param requestId durable enrollment request identity
     * @param authentication matching verified protocol mechanism
     * @param approved whether the frozen policy required and obtained approval
     * @param operationCommitment complete frozen enrollment intent commitment
     * @param issuerCaId frozen issuing authority
     * @param profileId frozen certificate profile
     * @return immutable evidence suitable for exact signing-context validation
     */
    // Preserves the public source/binary contract for named persisted identity coordinates.
    @SuppressWarnings("PMD.UseObjectForClearerAPI")
    public static IssuanceExecutionEvidence enrollment(ActorType actorType, String actorId, String realmId, String requestId,
            Authentication authentication, boolean approved, String operationCommitment, String issuerCaId, String profileId) {
        return new IssuanceExecutionEvidence(actorType, actorId, realmId, requestId, authentication, Authorization.ENROLLMENT_POLICY,
                Optional.of(approved ? AuthorizationPath.APPROVAL : AuthorizationPath.ENROLLMENT_POLICY),
                Optional.of(operationCommitment), issuerCaId, profileId, Outcome.ISSUED);
    }

    /**
     * Returns an immutable set containing only the closed evidence vocabulary.
     *
     * @return canonical version-one evidence attributes
     */
    public AttributeSet attributes() {
        SimpleAttributeSet.Builder builder = SimpleAttributeSet.builder()
                .put(ACTOR_TYPE, text(actorType.name())).put(ACTOR_ID, text(actorId)).put(REALM_ID, text(realmId))
                .put(REQUEST_ID, text(requestId)).put(AUTHENTICATION, text(authentication.name()))
                .put(AUTHORIZATION, text(authorization.name())).put(ISSUER_CA_ID, text(issuerCaId))
                .put(PROFILE_ID, text(profileId)).put(OUTCOME, text(outcome.name()));
        authorizationPath.ifPresent(value -> builder.put(AUTHORIZATION_PATH, text(value.name())));
        operationCommitment.ifPresent(value -> builder.put(OPERATION_COMMITMENT, text(value)));
        return builder.build();
    }

    /**
     * Strictly decodes the closed version-one evidence vocabulary.
     *
     * @param attributes credential attributes to inspect
     * @return empty only when no version-one evidence attribute is present
     * @throws IllegalArgumentException if evidence is unknown, partial, duplicated, mistyped, or
     *         semantically inconsistent
     */
    @SuppressWarnings("PMD.PreserveStackTrace") // untrusted evidence values must not escape through causes
    public static Optional<IssuanceExecutionEvidence> decode(AttributeSet attributes) {
        AttributeSet source = Objects.requireNonNull(attributes, "attributes");
        boolean present = false;
        for (AttributeId attributeId : source.ids()) {
            String value = attributeId.value();
            if (value.startsWith(EVIDENCE_PREFIX)) {
                present = true;
                if (!value.endsWith(EVIDENCE_V1_SUFFIX) || !EVIDENCE_V1.contains(attributeId)) {
                    throw invalidEvidence();
                }
            }
        }
        if (!present) {
            return Optional.empty();
        }
        try {
            ActorType actorType = enumValue(ActorType.class, requiredText(source, ACTOR_TYPE));
            String actorId = requiredText(source, ACTOR_ID);
            String realmId = requiredText(source, REALM_ID);
            String requestId = requiredText(source, REQUEST_ID);
            Authentication authentication = enumValue(Authentication.class, requiredText(source, AUTHENTICATION));
            Authorization authorization = enumValue(Authorization.class, requiredText(source, AUTHORIZATION));
            Optional<AuthorizationPath> path = optionalText(source, AUTHORIZATION_PATH)
                    .map(value -> enumValue(AuthorizationPath.class, value));
            Optional<String> operation = optionalText(source, OPERATION_COMMITMENT);
            String issuerCaId = requiredText(source, ISSUER_CA_ID);
            String profileId = requiredText(source, PROFILE_ID);
            Outcome outcome = enumValue(Outcome.class, requiredText(source, OUTCOME));
            return Optional.of(new IssuanceExecutionEvidence(actorType, actorId, realmId, requestId,
                    authentication, authorization, path, operation, issuerCaId, profileId, outcome));
        } catch (IllegalArgumentException | NullPointerException invalid) {
            throw invalidEvidence();
        }
    }

    /**
     * Decodes a feed payload containing UTF-8 canonical unpadded base64url attributes.
     * The encoded byte count is bounded before allocation; the existing attribute
     * decoder enforces canonical framing and its decoded-byte and entry limits.
     *
     * @param payload exact evidence-feed bytes, borrowed for this call
     * @return empty only when this evidence family's vocabulary is absent
     * @throws IllegalArgumentException if framing or this family's vocabulary is invalid
     */
    @SuppressWarnings("PMD.PreserveStackTrace") // Feed values must not escape through exception causes.
    public static Optional<IssuanceExecutionEvidence> decode(byte[] payload) {
        try {
            return decode(EvidencePayloadEncoding.decode(payload));
        } catch (IllegalArgumentException invalid) {
            throw invalidEvidence();
        }
    }

    private static AttributeId id(String name) {
        return new AttributeId("urn:zeroecho:pki:issuance-evidence:" + name + ":v1");
    }

    private static AttributeValue.StringValue text(String value) { return new AttributeValue.StringValue(value); }

    private static String requiredText(AttributeSet attributes, AttributeId id) {
        return optionalText(attributes, id).orElseThrow(IssuanceExecutionEvidence::invalidEvidence);
    }

    private static Optional<String> optionalText(AttributeSet attributes, AttributeId id) {
        List<AttributeValue> values = attributes.getAll(id);
        if (values.isEmpty()) {
            return Optional.empty();
        }
        if (values.size() != 1 || !(values.getFirst() instanceof AttributeValue.StringValue textValue)) {
            throw invalidEvidence();
        }
        return Optional.of(textValue.value());
    }

    @SuppressWarnings("PMD.PreserveStackTrace") // enum failure messages contain the rejected untrusted value
    private static <T extends Enum<T>> T enumValue(Class<T> type, String value) {
        try {
            return Enum.valueOf(type, value);
        } catch (IllegalArgumentException invalid) {
            throw invalidEvidence();
        }
    }

    private static IllegalArgumentException invalidEvidence() {
        return new IllegalArgumentException("Issuance execution evidence is invalid");
    }

    private static void requireBounded(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 256) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static void requireCommitment(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Evidence commitment is invalid");
        }
    }
}
