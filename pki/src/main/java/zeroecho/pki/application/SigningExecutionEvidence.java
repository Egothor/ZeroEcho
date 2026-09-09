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

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

/**
 * Immutable, server-derived evidence for the terminal outcome of one signing operation (CA private-key
 * usage).
 *
 * <p>Every issuance, status object, CA certificate, and CRL is produced by a signing operation, so this
 * evidence provides the key-usage audit dimension: which signing namespace and key fingerprint produced a
 * terminal outcome, under whose ownership, with which outcome classification. It is recorded when a signing
 * record reaches a terminal state ({@code SIGNED}, {@code FAILED}, {@code CANCELLED}, {@code EXPIRED}) and
 * is derivable entirely from that terminal record. Because signing records are retired after downstream
 * publication, the evidence is appended in the append-ordered signing-evidence log so a bounded,
 * crash-consistent audit projector can reconstruct every key use independently of record retirement.</p>
 *
 * @param namespace signing namespace
 * @param fingerprint signing-key fingerprint
 * @param ownerType signing-owner principal type
 * @param ownerId signing-owner principal identity
 * @param detailCode safe terminal detail classification, when present
 * @param outcome terminal outcome
 */
public record SigningExecutionEvidence(String namespace, String fingerprint, String ownerType, String ownerId,
        Optional<String> detailCode, Outcome outcome) {

    /** Terminal signing outcomes. */
    public enum Outcome {
        /** The signing operation produced a signature. */
        SIGNED,
        /** The signing operation failed. */
        FAILED,
        /** The signing operation was cancelled. */
        CANCELLED,
        /** The signing operation expired before completion. */
        EXPIRED
    }

    /** Evidence attribute vocabulary. */
    public static final AttributeId NAMESPACE = id("namespace");
    /** Evidence attribute vocabulary. */
    public static final AttributeId FINGERPRINT = id("fingerprint");
    /** Evidence attribute vocabulary. */
    public static final AttributeId OWNER_TYPE = id("owner-type");
    /** Evidence attribute vocabulary. */
    public static final AttributeId OWNER_ID = id("owner-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId DETAIL_CODE = id("detail-code");
    /** Evidence attribute vocabulary. */
    public static final AttributeId OUTCOME = id("outcome");

    private static final String EVIDENCE_PREFIX = "urn:zeroecho:pki:signing-evidence:";
    private static final String EVIDENCE_V1_SUFFIX = ":v1";
    private static final Set<AttributeId> EVIDENCE_V1 = Set.of(NAMESPACE, FINGERPRINT, OWNER_TYPE, OWNER_ID,
            DETAIL_CODE, OUTCOME);

    /** Validates the closed evidence model. */
    public SigningExecutionEvidence {
        requireBounded(namespace, "namespace");
        requireBounded(fingerprint, "fingerprint");
        requireBounded(ownerType, "owner type");
        requireBounded(ownerId, "owner ID");
        detailCode = Objects.requireNonNull(detailCode, "detailCode");
        detailCode.ifPresent(value -> requireBounded(value, "detail code"));
        Objects.requireNonNull(outcome, "outcome");
    }

    /**
     * Creates authoritative terminal signing evidence.
     *
     * @param namespace signing namespace
     * @param fingerprint signing-key fingerprint
     * @param ownerType signing-owner principal type
     * @param ownerId signing-owner principal identifier
     * @param detailCode optional safe terminal detail classification
     * @param outcome terminal outcome
     * @return validated terminal evidence
     */
    // Stable evidence factory retained for source compatibility; grouping parameters would change the public API.
    @SuppressWarnings("PMD.UseObjectForClearerAPI")
    public static SigningExecutionEvidence terminal(String namespace, String fingerprint, String ownerType,
            String ownerId, Optional<String> detailCode, Outcome outcome) {
        return new SigningExecutionEvidence(namespace, fingerprint, ownerType, ownerId, detailCode, outcome);
    }

    /**
     * Returns an immutable set containing only the closed evidence vocabulary.
     *
     * @return canonical evidence attributes
     */
    public AttributeSet attributes() {
        SimpleAttributeSet.Builder builder = SimpleAttributeSet.builder()
                .put(NAMESPACE, text(namespace)).put(FINGERPRINT, text(fingerprint))
                .put(OWNER_TYPE, text(ownerType)).put(OWNER_ID, text(ownerId))
                .put(OUTCOME, text(outcome.name()));
        detailCode.ifPresent(value -> builder.put(DETAIL_CODE, text(value)));
        return builder.build();
    }

    /**
     * Strictly decodes the closed version-one evidence vocabulary.
     *
     * @param attributes attributes to inspect
     * @return empty only when no version-one evidence attribute is present
     * @throws IllegalArgumentException if evidence is unknown, partial, duplicated, or mistyped
     */
    @SuppressWarnings("PMD.PreserveStackTrace") // untrusted evidence values must not escape through causes
    public static Optional<SigningExecutionEvidence> decode(AttributeSet attributes) {
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
            String namespace = requiredText(source, NAMESPACE);
            String fingerprint = requiredText(source, FINGERPRINT);
            String ownerType = requiredText(source, OWNER_TYPE);
            String ownerId = requiredText(source, OWNER_ID);
            Optional<String> detailCode = optionalText(source, DETAIL_CODE);
            Outcome outcome = enumValue(requiredText(source, OUTCOME));
            return Optional.of(new SigningExecutionEvidence(namespace, fingerprint, ownerType, ownerId, detailCode,
                    outcome));
        } catch (IllegalArgumentException | NullPointerException invalid) {
            throw invalidEvidence();
        }
    }

    private static AttributeId id(String name) {
        return new AttributeId("urn:zeroecho:pki:signing-evidence:" + name + ":v1");
    }

    private static AttributeValue.StringValue text(String value) { return new AttributeValue.StringValue(value); }

    private static String requiredText(AttributeSet attributes, AttributeId id) {
        return optionalText(attributes, id).orElseThrow(SigningExecutionEvidence::invalidEvidence);
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
    private static Outcome enumValue(String value) {
        try {
            return Outcome.valueOf(value);
        } catch (IllegalArgumentException invalid) {
            throw invalidEvidence();
        }
    }

    private static IllegalArgumentException invalidEvidence() {
        return new IllegalArgumentException("Signing execution evidence is invalid");
    }

    private static void requireBounded(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 256) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }
}
