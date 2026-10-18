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

package zeroecho.pki.impl.core.continuation;

import java.util.List;
import java.util.Objects;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;

/**
 * Bounded immutable revocation provenance shared by full-CRL publication and validation.
 * Public visibility bridges unexported implementation packages; this value grants no authority.
 * @param sourceStoreId source identity captured by the prepared snapshot
 * @param revision captured global revision, including zero for genesis
 * @param boundary captured authoritative byte boundary
 * @param commitment captured lowercase SHA-256 global commitment
 */
public record FullCrlSnapshotProvenance(MetadataStoreId sourceStoreId, long revision, long boundary,
        String commitment) {
    private static final int SINGLE_ATTRIBUTE_VALUE = 1;
    private static final AttributeId SOURCE = new AttributeId("zeroecho.pki.full-crl.snapshot-source-store-id");
    private static final AttributeId REVISION = new AttributeId("zeroecho.pki.full-crl.snapshot-revision");
    private static final AttributeId BOUNDARY = new AttributeId("zeroecho.pki.full-crl.snapshot-boundary");
    private static final AttributeId COMMITMENT = new AttributeId("zeroecho.pki.full-crl.snapshot-commitment");

    /** Validates bounded canonical provenance without consulting a store. */
    public FullCrlSnapshotProvenance {
        Objects.requireNonNull(sourceStoreId, "sourceStoreId");
        if (revision < 0 || boundary < 0 || commitment == null || commitment.length() != 64
                || !commitment.matches("[0-9a-f]{64}")) {
            throw invalid();
        }
    }

    /**
     * Reads the exact frozen coordinates from the current full-CRL command.
     * @param command current canonical full-CRL command
     * @return immutable captured coordinates
     * @throws IllegalArgumentException if provenance fields or field count are invalid
     */
    public static FullCrlSnapshotProvenance from(DomainCommandEncoding.Decoded command) {
        command.requireFields(FullCrlSigningCommand.DELTA_OPERATION.equals(command.operation()) ? 36 : 31);
        if (!FullCrlSigningCommand.supports(command.operation())) { throw invalid(); }
        return new FullCrlSnapshotProvenance(source(command.field(30)), nonnegative(command.field(20)),
                nonnegative(command.field(21)), command.field(22));
    }

    /**
     * Encodes exactly four typed scalar attributes; no payload or workflow reference is retained.
     * @return canonical source, integer revision/boundary and commitment attributes
     */
    public AttributeSet attributes() {
        return SimpleAttributeSet.builder()
                .put(SOURCE, new AttributeValue.StringValue(sourceStoreId.value()))
                .put(REVISION, new AttributeValue.IntegerValue(revision))
                .put(BOUNDARY, new AttributeValue.IntegerValue(boundary))
                .put(COMMITMENT, new AttributeValue.StringValue(commitment)).build();
    }

    /**
     * Decodes exactly one correctly typed value for each provenance attribute.
     * Other status attributes are left untouched. Work is O(A) for the existing
     * list-backed attribute set and auxiliary memory is constant.
     * @param attributes immutable published status metadata
     * @return exact bounded provenance
     * @throws IllegalArgumentException if any coordinate is absent, duplicated, mistyped or noncanonical
     */
    public static FullCrlSnapshotProvenance decode(AttributeSet attributes) {
        AttributeValue source = single(attributes, SOURCE);
        AttributeValue revision = single(attributes, REVISION);
        AttributeValue boundary = single(attributes, BOUNDARY);
        AttributeValue commitment = single(attributes, COMMITMENT);
        if (!(source instanceof AttributeValue.StringValue sourceText)
                || !(revision instanceof AttributeValue.IntegerValue revisionNumber)
                || !(boundary instanceof AttributeValue.IntegerValue boundaryNumber)
                || !(commitment instanceof AttributeValue.StringValue commitmentText)) { throw invalid(); }
        return new FullCrlSnapshotProvenance(source(sourceText.value()), revisionNumber.value(),
                boundaryNumber.value(), commitmentText.value());
    }

    private static AttributeValue single(AttributeSet attributes, AttributeId id) {
        List<AttributeValue> values = Objects.requireNonNull(attributes, "attributes").getAll(id);
        if (values.size() != SINGLE_ATTRIBUTE_VALUE) { throw invalid(); }
        return values.getFirst();
    }

    private static MetadataStoreId source(String value) {
        if (value.length() != 32 || !value.matches("[0-9a-f]{32}")) { throw invalid(); }
        return new MetadataStoreId(value);
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private static long nonnegative(String value) {
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0 || !Long.toString(parsed).equals(value)) { throw invalid(); }
            return parsed;
        } catch (NumberFormatException invalidNumber) { throw invalid(); }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Full CRL snapshot provenance is invalid");
    }
}
