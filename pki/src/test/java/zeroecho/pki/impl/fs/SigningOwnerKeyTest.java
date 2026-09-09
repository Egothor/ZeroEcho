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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;

final class SigningOwnerKeyTest {
    private static final String CONTENT_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final String OTHER_CONTENT_ID = "123e4567-e89b-42d3-a456-426614174001";
    private static final PkiId SUBMISSION_ID = new PkiId(
            "zsign:v1:test:1767225600000:00000000000000000000000000000001");

    @Test
    void exactKeyRoundTripsAndContentRangeIsExact() {
        DurableContentReference reference = reference(CONTENT_ID);
        MetadataKey exact = SigningOwnerKey.exact(reference, SUBMISSION_ID);

        SigningOwnerKey.Parsed parsed = SigningOwnerKey.parse(exact);
        MetadataSnapshot.KeyRange range = SigningOwnerKey.contentRange(reference);

        assertEquals(CONTENT_ID, parsed.contentId());
        assertEquals(SUBMISSION_ID, parsed.submissionId());
        assertTrue(range.contains(exact));
        assertTrue(range.contains(new MetadataKey(SigningOwnerKey.NAMESPACE,
                CONTENT_ID + ":zsign:v1:test:1767225600000:00000000000000000000000000000002")));
        assertFalse(range.contains(SigningOwnerKey.exact(reference(OTHER_CONTENT_ID), SUBMISSION_ID)));
    }

    @Test
    void malformedAndLegacyKeysFailClosed() {
        assertThrows(IllegalArgumentException.class, () -> SigningOwnerKey.parse(
                new MetadataKey(SigningOwnerKey.NAMESPACE, SUBMISSION_ID.value())));
        assertThrows(IllegalArgumentException.class, () -> SigningOwnerKey.parse(
                new MetadataKey(SigningOwnerKey.NAMESPACE,
                        CONTENT_ID.toUpperCase(java.util.Locale.ROOT) + ':' + SUBMISSION_ID.value())));
        assertThrows(IllegalArgumentException.class, () -> SigningOwnerKey.parse(
                new MetadataKey(SigningOwnerKey.NAMESPACE,
                        CONTENT_ID + '-' + SUBMISSION_ID.value())));
        assertThrows(IllegalArgumentException.class, () -> SigningOwnerKey.parse(
                new MetadataKey(SigningOwnerKey.NAMESPACE, CONTENT_ID + ":not-a-submission")));
        assertThrows(IllegalArgumentException.class, () -> SigningOwnerKey.parse(
                new MetadataKey("io.zeroecho.pki.other-owner",
                        CONTENT_ID + ':' + SUBMISSION_ID.value())));
        assertThrows(IllegalArgumentException.class, () -> SigningOwnerKey.exact(
                reference("123e4567-e89b-12d3-a456-426614174000"), SUBMISSION_ID));
    }

    private static DurableContentReference reference(String contentId) {
        return new TestReference("0".repeat(32), contentId, Encoding.BINARY, 1L,
                "0".repeat(64), DurableContentReference.Lifecycle.OPERATION);
    }

    private record TestReference(String storeId, String contentId, Encoding encoding,
            long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference {
    }
}
