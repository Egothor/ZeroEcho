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
 * Immutable, server-derived evidence for the terminal outcome of one publication operation.
 *
 * <p>Unlike issuance and status objects (immutable at creation), a publication record is mutable: it is
 * created {@code PENDING} and reaches a terminal outcome ({@code SUCCEEDED} or {@code TERMINAL_FAILURE})
 * later. The evidence is therefore recorded when the terminal transition commits and is fully derivable
 * from the terminal record: source, configured target, attempt count, publisher outcome classification,
 * and (on failure) the safe failure classification. It is appended to the append-ordered
 * publication-evidence log so a bounded, crash-consistent audit projector can reconstruct every terminal
 * dispatch exactly as the other families do.</p>
 *
 * @param sourceType authoritative source-object type
 * @param sourceId authoritative source-object identity
 * @param targetType configured destination type
 * @param targetId configured destination identity
 * @param attemptNumber terminal attempt number
 * @param responseEvidence publisher outcome-evidence classification, when present
 * @param failure safe failure classification, present exactly for a terminal failure
 * @param outcome terminal outcome
 */
public record PublicationExecutionEvidence(String sourceType, String sourceId, String targetType, String targetId,
        long attemptNumber, Optional<String> responseEvidence, Optional<String> failure, Outcome outcome) {

    /** Terminal publication outcomes. */
    public enum Outcome {
        /** Publication completed successfully. */
        SUCCEEDED,
        /** Publication ended in a non-retryable failure. */
        TERMINAL_FAILURE
    }

    /** Evidence attribute vocabulary. */
    public static final AttributeId SOURCE_TYPE = id("source-type");
    /** Evidence attribute vocabulary. */
    public static final AttributeId SOURCE_ID = id("source-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId TARGET_TYPE = id("target-type");
    /** Evidence attribute vocabulary. */
    public static final AttributeId TARGET_ID = id("target-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId ATTEMPT_NUMBER = id("attempt-number");
    /** Evidence attribute vocabulary. */
    public static final AttributeId RESPONSE_EVIDENCE = id("response-evidence");
    /** Evidence attribute vocabulary. */
    public static final AttributeId FAILURE = id("failure");
    /** Evidence attribute vocabulary. */
    public static final AttributeId OUTCOME = id("outcome");

    private static final String EVIDENCE_PREFIX = "urn:zeroecho:pki:publication-evidence:";
    private static final String EVIDENCE_V1_SUFFIX = ":v1";
    private static final Set<AttributeId> EVIDENCE_V1 = Set.of(SOURCE_TYPE, SOURCE_ID, TARGET_TYPE, TARGET_ID,
            ATTEMPT_NUMBER, RESPONSE_EVIDENCE, FAILURE, OUTCOME);

    /** Validates the closed evidence model. */
    public PublicationExecutionEvidence {
        requireBounded(sourceType, "source type");
        requireBounded(sourceId, "source ID");
        requireBounded(targetType, "target type");
        requireBounded(targetId, "target ID");
        if (isNegative(attemptNumber)) {
            throw new IllegalArgumentException("attempt number is invalid");
        }
        responseEvidence = Objects.requireNonNull(responseEvidence, "responseEvidence");
        responseEvidence.ifPresent(value -> requireBounded(value, "response evidence"));
        failure = Objects.requireNonNull(failure, "failure");
        failure.ifPresent(value -> requireBounded(value, "failure"));
        Objects.requireNonNull(outcome, "outcome");
        if (outcome == Outcome.TERMINAL_FAILURE != failure.isPresent()) {
            throw new IllegalArgumentException("Publication failure classification is inconsistent with the outcome");
        }
    }

    private static boolean isNegative(long value) {
        return value < 0L;
    }

    /**
     * Creates authoritative terminal publication evidence.
     *
     * @param sourceType authoritative source-object type
     * @param sourceId authoritative source-object identifier
     * @param targetType configured destination type
     * @param targetId configured destination identifier
     * @param attemptNumber nonnegative terminal attempt number
     * @param responseEvidence optional publisher outcome classification
     * @param failure optional safe failure classification; present exactly for terminal failure
     * @param outcome terminal outcome
     * @return validated terminal evidence
     */
    @SuppressWarnings("PMD.UseObjectForClearerAPI")
    public static PublicationExecutionEvidence terminal(String sourceType, String sourceId, String targetType,
            String targetId, long attemptNumber, Optional<String> responseEvidence, Optional<String> failure,
            Outcome outcome) {
        return new PublicationExecutionEvidence(sourceType, sourceId, targetType, targetId, attemptNumber,
                responseEvidence, failure, outcome);
    }

    /**
     * Returns an immutable set containing only the closed evidence vocabulary.
     *
     * @return canonical evidence attributes
     */
    public AttributeSet attributes() {
        SimpleAttributeSet.Builder builder = SimpleAttributeSet.builder()
                .put(SOURCE_TYPE, text(sourceType)).put(SOURCE_ID, text(sourceId))
                .put(TARGET_TYPE, text(targetType)).put(TARGET_ID, text(targetId))
                .put(ATTEMPT_NUMBER, new AttributeValue.IntegerValue(attemptNumber))
                .put(OUTCOME, text(outcome.name()));
        responseEvidence.ifPresent(value -> builder.put(RESPONSE_EVIDENCE, text(value)));
        failure.ifPresent(value -> builder.put(FAILURE, text(value)));
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
    public static Optional<PublicationExecutionEvidence> decode(AttributeSet attributes) {
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
            String sourceType = requiredText(source, SOURCE_TYPE);
            String sourceId = requiredText(source, SOURCE_ID);
            String targetType = requiredText(source, TARGET_TYPE);
            String targetId = requiredText(source, TARGET_ID);
            long attemptNumber = requiredInteger(source, ATTEMPT_NUMBER);
            Optional<String> responseEvidence = optionalText(source, RESPONSE_EVIDENCE);
            Optional<String> failure = optionalText(source, FAILURE);
            Outcome outcome = enumValue(requiredText(source, OUTCOME));
            return Optional.of(new PublicationExecutionEvidence(sourceType, sourceId, targetType, targetId,
                    attemptNumber, responseEvidence, failure, outcome));
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
    public static Optional<PublicationExecutionEvidence> decode(byte[] payload) {
        try {
            return decode(EvidencePayloadEncoding.decode(payload));
        } catch (IllegalArgumentException invalid) {
            throw invalidEvidence();
        }
    }

    private static AttributeId id(String name) {
        return new AttributeId("urn:zeroecho:pki:publication-evidence:" + name + ":v1");
    }

    private static AttributeValue.StringValue text(String value) { return new AttributeValue.StringValue(value); }

    private static String requiredText(AttributeSet attributes, AttributeId id) {
        return optionalText(attributes, id).orElseThrow(PublicationExecutionEvidence::invalidEvidence);
    }

    private static long requiredInteger(AttributeSet attributes, AttributeId id) {
        List<AttributeValue> values = attributes.getAll(id);
        if (values.size() != 1 || !(values.getFirst() instanceof AttributeValue.IntegerValue integer)) {
            throw invalidEvidence();
        }
        return integer.value();
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
        return new IllegalArgumentException("Publication execution evidence is invalid");
    }

    private static void requireBounded(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 256) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }
}
