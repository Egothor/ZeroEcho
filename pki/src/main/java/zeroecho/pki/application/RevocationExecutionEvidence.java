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
package zeroecho.pki.application;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

/**
 * Immutable, server-derived evidence co-committed with a revocation transition.
 * Native transition fields remain the authority for credential, reason, time,
 * revision, and state.
 *
 * @param actorType administrative or protocol-native actor classification
 * @param actorId bounded stable principal or ACME account identifier
 * @param realmId bounded realm in which authorization was evaluated
 * @param requestId bounded transport request identifier
 * @param authentication authentication mechanism that established the actor
 * @param authorization authorization decision classification
 * @param authorizationPath optional administrative authorization path
 * @param operationCommitment optional administrative operation commitment
 * @param justificationCommitment optional administrative justification commitment
 * @param outcome atomically committed revocation outcome
 */
public record RevocationExecutionEvidence(ActorType actorType, String actorId, String realmId, String requestId,
        Authentication authentication, Authorization authorization, Optional<AuthorizationPath> authorizationPath,
        Optional<String> operationCommitment, Optional<String> justificationCommitment, Outcome outcome) {

    /** Stable evidence actor classifications. */
    public enum ActorType {
        /** Authenticated administrative principal. */
        ADMIN_PRINCIPAL,
        /** Protocol-native ACME account. */
        ACME_ACCOUNT
    }
    /** Stable evidence authentication classifications. */
    public enum Authentication {
        /** Direct mutual-TLS client authentication. */
        DIRECT_MTLS,
        /** Identity asserted by a trusted reverse proxy. */
        TRUSTED_REVERSE_PROXY,
        /** ACME account JSON Web Signature authentication. */
        ACME_ACCOUNT_JWS
    }
    /** Stable evidence authorization classifications. */
    public enum Authorization {
        /** Administrative policy allowed the operation. */
        ALLOWED,
        /** ACME account ownership authorized the operation. */
        ACME_OWNERSHIP
    }
    /** Administrative authorization path, with break-glass taking precedence. */
    public enum AuthorizationPath {
        /** Ordinary administrative grant. */
        ORDINARY_GRANT,
        /** Explicit approval workflow. */
        APPROVAL,
        /** Audited emergency break-glass path. */
        BREAK_GLASS
    }
    /** Outcome committed atomically with the transition. */
    public enum Outcome {
        /** Revocation transition and evidence committed atomically. */
        COMMITTED
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
    public static final AttributeId JUSTIFICATION_COMMITMENT = id("justification-commitment");
    /** Evidence attribute vocabulary. */
    public static final AttributeId OUTCOME = id("outcome");

    private static final String EVIDENCE_PREFIX = "urn:zeroecho:pki:revocation-evidence:";
    private static final String EVIDENCE_V1_SUFFIX = ":v1";
    private static final Set<AttributeId> EVIDENCE_V1 = Set.of(ACTOR_TYPE, ACTOR_ID, REALM_ID, REQUEST_ID,
            AUTHENTICATION, AUTHORIZATION, AUTHORIZATION_PATH, OPERATION_COMMITMENT, JUSTIFICATION_COMMITMENT,
            OUTCOME);

    private static final byte[] JUSTIFICATION_DOMAIN =
            "ZEROECHO-REVOCATION-JUSTIFICATION-V1\0".getBytes(StandardCharsets.US_ASCII);

    /** Validates the closed evidence model. */
    public RevocationExecutionEvidence {
        Objects.requireNonNull(actorType, "actorType");
        requireBounded(actorId, "actor ID");
        requireBounded(realmId, "realm ID");
        requireBounded(requestId, "request ID");
        Objects.requireNonNull(authentication, "authentication");
        Objects.requireNonNull(authorization, "authorization");
        authorizationPath = Objects.requireNonNull(authorizationPath, "authorizationPath");
        operationCommitment = Objects.requireNonNull(operationCommitment, "operationCommitment");
        justificationCommitment = Objects.requireNonNull(justificationCommitment, "justificationCommitment");
        operationCommitment.ifPresent(RevocationExecutionEvidence::requireCommitment);
        justificationCommitment.ifPresent(RevocationExecutionEvidence::requireCommitment);
        Objects.requireNonNull(outcome, "outcome");
        boolean administrative = actorType == ActorType.ADMIN_PRINCIPAL
                && authentication != Authentication.ACME_ACCOUNT_JWS
                && authorization == Authorization.ALLOWED
                && authorizationPath.isPresent() && operationCommitment.isPresent()
                && justificationCommitment.isPresent();
        boolean acme = actorType == ActorType.ACME_ACCOUNT
                && authentication == Authentication.ACME_ACCOUNT_JWS
                && authorization == Authorization.ACME_OWNERSHIP
                && authorizationPath.isEmpty() && operationCommitment.isEmpty()
                && justificationCommitment.isEmpty();
        if (!administrative && !acme) {
            throw new IllegalArgumentException("Revocation evidence classification is inconsistent");
        }
    }

    /**
     * Creates authoritative administrative evidence.
     *
     * @param principalId bounded authenticated administrator identifier
     * @param realmId bounded authorization realm identifier
     * @param requestId bounded transport request identifier
     * @param authentication non-ACME authentication mechanism
     * @param path administrative grant, approval, or break-glass path
     * @param operationCommitment lowercase 64-hex-character operation commitment
     * @param operatorJustification optional plaintext justification committed but not retained
     * @return validated immutable administrative evidence
     */
    @SuppressWarnings("PMD.UseObjectForClearerAPI")
    public static RevocationExecutionEvidence administrative(String principalId, String realmId, String requestId,
            Authentication authentication, AuthorizationPath path, String operationCommitment,
            Optional<String> operatorJustification) {
        Objects.requireNonNull(operatorJustification, "operatorJustification");
        return new RevocationExecutionEvidence(ActorType.ADMIN_PRINCIPAL, principalId, realmId, requestId,
                authentication, Authorization.ALLOWED, Optional.of(Objects.requireNonNull(path, "path")),
                Optional.of(operationCommitment), Optional.of(commitJustification(operatorJustification)),
                Outcome.COMMITTED);
    }

    /**
     * Creates authoritative protocol-native ACME evidence.
     *
     * @param accountId bounded ACME account identifier
     * @param realmId bounded authorization realm identifier
     * @param requestId bounded transport request identifier
     * @return validated immutable ACME ownership evidence
     */
    public static RevocationExecutionEvidence acme(String accountId, String realmId, String requestId) {
        return new RevocationExecutionEvidence(ActorType.ACME_ACCOUNT, accountId, realmId, requestId,
                Authentication.ACME_ACCOUNT_JWS, Authorization.ACME_OWNERSHIP, Optional.empty(), Optional.empty(),
                Optional.empty(), Outcome.COMMITTED);
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
                .put(AUTHORIZATION, text(authorization.name())).put(OUTCOME, text(outcome.name()));
        authorizationPath.ifPresent(value -> builder.put(AUTHORIZATION_PATH, text(value.name())));
        operationCommitment.ifPresent(value -> builder.put(OPERATION_COMMITMENT, text(value)));
        justificationCommitment.ifPresent(value -> builder.put(JUSTIFICATION_COMMITMENT, text(value)));
        return builder.build();
    }

    /**
     * Strictly decodes the closed version-one evidence vocabulary.
     *
     * @param attributes transition attributes to inspect
     * @return empty only when no version-one evidence attribute is present
     * @throws IllegalArgumentException if evidence is unknown, partial, duplicated,
     *         mistyped, or semantically inconsistent
     */
    @SuppressWarnings("PMD.PreserveStackTrace") // untrusted evidence values must not escape through causes
    public static Optional<RevocationExecutionEvidence> decode(AttributeSet attributes) {
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
            Optional<String> justification = optionalText(source, JUSTIFICATION_COMMITMENT);
            Outcome outcome = enumValue(Outcome.class, requiredText(source, OUTCOME));
            return Optional.of(new RevocationExecutionEvidence(actorType, actorId, realmId, requestId,
                    authentication, authorization, path, operation, justification, outcome));
        } catch (IllegalArgumentException | NullPointerException invalid) {
            throw invalidEvidence();
        }
    }

    /**
     * Commits exact optional justification presence and UTF-8 bytes without retaining plaintext.
     *
     * @param operatorJustification optional operator justification or ticket text
     * @return lowercase SHA-256 commitment over presence and exact UTF-8 bytes
     */
    public static String commitJustification(Optional<String> operatorJustification) {
        Objects.requireNonNull(operatorJustification, "operatorJustification");
        byte[] value = operatorJustification.map(text -> text.getBytes(StandardCharsets.UTF_8)).orElseGet(() -> new byte[0]);
        MessageDigest digest = sha256();
        digest.update(JUSTIFICATION_DOMAIN);
        digest.update((byte) (operatorJustification.isPresent() ? 1 : 0));
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
        return HexFormat.of().formatHex(digest.digest());
    }

    private static AttributeId id(String name) {
        return new AttributeId("urn:zeroecho:pki:revocation-evidence:" + name + ":v1");
    }

    private static AttributeValue.StringValue text(String value) { return new AttributeValue.StringValue(value); }

    private static String requiredText(AttributeSet attributes, AttributeId id) {
        return optionalText(attributes, id).orElseThrow(RevocationExecutionEvidence::invalidEvidence);
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
        return new IllegalArgumentException("Revocation execution evidence is invalid");
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("Required SHA-256 digest is unavailable", impossible);
        }
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
