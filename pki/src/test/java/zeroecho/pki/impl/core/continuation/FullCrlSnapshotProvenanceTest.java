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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;

final class FullCrlSnapshotProvenanceTest {
    private static final MetadataStoreId SOURCE = new MetadataStoreId("102030405060708090a0b0c0d0e0f001");

    @Test void roundTripsCanonicalTypedScalarsIncludingGenesisAndMaximumRevision() {
        for (long revision : new long[] {0, 1, Long.MAX_VALUE}) {
            FullCrlSnapshotProvenance value = new FullCrlSnapshotProvenance(SOURCE, revision, Long.MAX_VALUE,
                    "a".repeat(64));
            assertEquals(4, value.attributes().ids().size());
            assertEquals(value, FullCrlSnapshotProvenance.decode(value.attributes()));
            AttributeSet withCommand = SimpleAttributeSet.builder().putAll(value.attributes())
                    .put(new AttributeId("zeroecho.pki.full-crl.command-sha256"), new AttributeValue.StringValue("b".repeat(64)))
                    .build();
            assertEquals(value, FullCrlSnapshotProvenance.decode(withCommand));
        }
    }

    @Test void rejectsMissingDuplicateMistypedNegativeAndNoncanonicalCoordinates() {
        AttributeSet valid = new FullCrlSnapshotProvenance(SOURCE, 0, 32, "a".repeat(64)).attributes();
        for (AttributeId id : valid.ids()) {
            AttributeValue value = valid.getAll(id).getFirst();
            assertThrows(IllegalArgumentException.class, () -> FullCrlSnapshotProvenance.decode(replace(valid, id, List.of())));
            assertThrows(IllegalArgumentException.class, () -> FullCrlSnapshotProvenance.decode(replace(valid, id, List.of(value, value))));
            AttributeValue wrongType = value instanceof AttributeValue.StringValue
                    ? new AttributeValue.IntegerValue(1) : new AttributeValue.StringValue("0");
            assertThrows(IllegalArgumentException.class, () -> FullCrlSnapshotProvenance.decode(replace(valid, id, List.of(wrongType))));
            if (value instanceof AttributeValue.IntegerValue) {
                assertThrows(IllegalArgumentException.class, () -> FullCrlSnapshotProvenance.decode(
                        replace(valid, id, List.of(new AttributeValue.IntegerValue(-1)))));
            } else {
                for (String invalid : List.of("", "A".repeat(id.value().endsWith("commitment") ? 64 : 32),
                        "0".repeat(31), "0".repeat(65), " ", "g".repeat(64))) {
                    assertThrows(IllegalArgumentException.class, () -> FullCrlSnapshotProvenance.decode(
                            replace(valid, id, List.of(new AttributeValue.StringValue(invalid)))));
                }
            }
        }
    }

    private static AttributeSet replace(AttributeSet original, AttributeId changed, List<AttributeValue> values) {
        List<SimpleAttributeSet.Entry> entries = new ArrayList<>();
        for (AttributeId id : original.ids()) {
            if (!id.equals(changed) || !values.isEmpty()) {
                entries.add(new SimpleAttributeSet.Entry(id, id.equals(changed) ? values : original.getAll(id)));
            }
        }
        return new SimpleAttributeSet(entries);
    }
}
