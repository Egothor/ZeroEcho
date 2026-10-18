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
 * Immutable, server-derived evidence co-committed with a successfully generated status object (CRL,
 * delta CRL, or persistent OCSP response).
 *
 * <p>Status generation is a system action with no authenticated external actor, so the evidence is
 * fully derivable from the produced status object: its type, issuing authority, encoding, and the
 * validity window it publishes. It is recorded in the append-ordered status-evidence log so a bounded,
 * crash-consistent audit projector can reconstruct every generation exactly as the issuance and
 * revocation slices do. It mirrors {@link IssuanceExecutionEvidence} so all families project through
 * the same generic framework.</p>
 *
 * @param statusObjectType generated status object type
 * @param issuerCaId issuing authority identity
 * @param formatId status object format identity
 * @param thisUpdate the produced status object's {@code thisUpdate}
 * @param nextUpdate the produced status object's {@code nextUpdate}, when present
 * @param outcome outcome committed atomically with the status object
 */
public record StatusGenerationEvidence(String statusObjectType, String issuerCaId, String formatId,
        String thisUpdate, Optional<String> nextUpdate, Outcome outcome) {

    /** Outcome committed with the status object. */
    public enum Outcome {
        /** The status object was generated successfully. */
        GENERATED
    }

    /** Evidence attribute vocabulary. */
    public static final AttributeId STATUS_TYPE = id("status-type");
    /** Evidence attribute vocabulary. */
    public static final AttributeId ISSUER_CA_ID = id("issuer-ca-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId FORMAT_ID = id("format-id");
    /** Evidence attribute vocabulary. */
    public static final AttributeId THIS_UPDATE = id("this-update");
    /** Evidence attribute vocabulary. */
    public static final AttributeId NEXT_UPDATE = id("next-update");
    /** Evidence attribute vocabulary. */
    public static final AttributeId OUTCOME = id("outcome");

    private static final String EVIDENCE_PREFIX = "urn:zeroecho:pki:status-evidence:";
    private static final String EVIDENCE_V1_SUFFIX = ":v1";
    private static final Set<AttributeId> EVIDENCE_V1 = Set.of(STATUS_TYPE, ISSUER_CA_ID, FORMAT_ID, THIS_UPDATE,
            NEXT_UPDATE, OUTCOME);

    /** Validates the closed evidence model. */
    public StatusGenerationEvidence {
        requireBounded(statusObjectType, "status type");
        requireBounded(issuerCaId, "issuer CA ID");
        requireBounded(formatId, "format ID");
        requireBounded(thisUpdate, "thisUpdate");
        nextUpdate = Objects.requireNonNull(nextUpdate, "nextUpdate");
        nextUpdate.ifPresent(value -> requireBounded(value, "nextUpdate"));
        Objects.requireNonNull(outcome, "outcome");
    }

    /**
     * Creates authoritative system status-generation evidence.
     *
     * @param statusObjectType generated status-object type
     * @param issuerCaId issuing authority identifier
     * @param formatId status-object format identifier
     * @param thisUpdate encoded issue time of the generated object
     * @param nextUpdate optional encoded expiry time of the generated object
     * @return validated evidence with a {@link Outcome#GENERATED} outcome
     */
    // Stable evidence factory retained for source compatibility; grouping parameters would change the public API.
    @SuppressWarnings("PMD.UseObjectForClearerAPI")
    public static StatusGenerationEvidence system(String statusObjectType, String issuerCaId, String formatId,
            String thisUpdate, Optional<String> nextUpdate) {
        return new StatusGenerationEvidence(statusObjectType, issuerCaId, formatId, thisUpdate, nextUpdate,
                Outcome.GENERATED);
    }

    /**
     * Returns an immutable set containing only the closed evidence vocabulary.
     *
     * @return canonical evidence attributes
     */
    public AttributeSet attributes() {
        SimpleAttributeSet.Builder builder = SimpleAttributeSet.builder()
                .put(STATUS_TYPE, text(statusObjectType)).put(ISSUER_CA_ID, text(issuerCaId))
                .put(FORMAT_ID, text(formatId)).put(THIS_UPDATE, text(thisUpdate))
                .put(OUTCOME, text(outcome.name()));
        nextUpdate.ifPresent(value -> builder.put(NEXT_UPDATE, text(value)));
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
    public static Optional<StatusGenerationEvidence> decode(AttributeSet attributes) {
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
            String statusObjectType = requiredText(source, STATUS_TYPE);
            String issuerCaId = requiredText(source, ISSUER_CA_ID);
            String formatId = requiredText(source, FORMAT_ID);
            String thisUpdate = requiredText(source, THIS_UPDATE);
            Optional<String> nextUpdate = optionalText(source, NEXT_UPDATE);
            Outcome outcome = enumValue(requiredText(source, OUTCOME));
            return Optional.of(new StatusGenerationEvidence(statusObjectType, issuerCaId, formatId, thisUpdate,
                    nextUpdate, outcome));
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
    public static Optional<StatusGenerationEvidence> decode(byte[] payload) {
        try {
            return decode(EvidencePayloadEncoding.decode(payload));
        } catch (IllegalArgumentException invalid) {
            throw invalidEvidence();
        }
    }

    private static AttributeId id(String name) {
        return new AttributeId("urn:zeroecho:pki:status-evidence:" + name + ":v1");
    }

    private static AttributeValue.StringValue text(String value) { return new AttributeValue.StringValue(value); }

    private static String requiredText(AttributeSet attributes, AttributeId id) {
        return optionalText(attributes, id).orElseThrow(StatusGenerationEvidence::invalidEvidence);
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
        return new IllegalArgumentException("Status generation evidence is invalid");
    }

    private static void requireBounded(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 256) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }
}
