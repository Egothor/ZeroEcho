/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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
package zeroecho.pki.spi.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

final class MetadataKeyTest {

    @Test
    void canonicalExtensionIdentityRoundTrips() {
        System.out.print("canonicalExtensionIdentityRoundTrips ");
        MetadataKey key = new MetadataKey("example.audit", "zsign:v1:tenant:42:nonce");
        assertEquals("example.audit", key.namespace());
        assertEquals("zsign:v1:tenant:42:nonce", key.key());
        assertEquals(key, MetadataKey.parse(key.canonical()));
        assertEquals(key.canonical(), key.toString());
        System.out.println("...ok");
    }

    @Test
    void reservedAndAmbiguousIdentitiesFail() {
        System.out.print("reservedAndAmbiguousIdentitiesFail ");
        assertThrows(IllegalArgumentException.class, () -> new MetadataKey("zeroecho", "a"));
        assertThrows(IllegalArgumentException.class, () -> new MetadataKey("zeroecho.audit", "a"));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse("mk1:13:1:Example.audita"));
        assertThrows(IllegalArgumentException.class, () -> new MetadataKey("example.audit", "a/b"));
        assertThrows(IllegalArgumentException.class, () -> new MetadataKey("example.audit", "é"));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse("example.audit:a"));
        System.out.println("...ok");
    }

    @Test
    void orderingAndPrefixRangesAreTotal() {
        System.out.print("orderingAndPrefixRangesAreTotal ");
        List<MetadataKey> sorted = List.of(
                        new MetadataKey("example.audit", "a~"),
                        new MetadataKey("example.audit", ":"),
                        new MetadataKey("example.audit", ":child"),
                        new MetadataKey("example.audit", "abc"),
                        new MetadataKey("example.audit", "~"))
                .stream()
                .sorted()
                .toList();
        assertEquals(":", sorted.get(0).key());
        assertEquals(":child", sorted.get(1).key());
        assertEquals("abc", sorted.get(2).key());
        MetadataSnapshot.KeyRange ordinary =
                MetadataSnapshot.KeyRange.prefix("example.audit", "abc");
        assertEquals("abd", ordinary.upperExclusive().orElseThrow());
        MetadataSnapshot.KeyRange trailing =
                MetadataSnapshot.KeyRange.prefix("example.audit", "a~");
        assertEquals("b", trailing.upperExclusive().orElseThrow());
        assertEquals(
                "a/",
                MetadataSnapshot.KeyRange.prefix("example.audit", "a.")
                        .upperExclusive()
                        .orElseThrow());
        assertEquals(
                "a\\",
                MetadataSnapshot.KeyRange.prefix("example.audit", "a[")
                        .upperExclusive()
                        .orElseThrow());
        assertEquals(
                "b",
                MetadataSnapshot.KeyRange.prefix("example.audit", "a~~")
                        .upperExclusive()
                        .orElseThrow());
        assertTrue(MetadataSnapshot.KeyRange.prefix("example.audit", "~")
                .upperExclusive()
                .isEmpty());
        assertTrue(MetadataSnapshot.KeyRange.prefix("example.audit", "")
                .lowerInclusive()
                .isEmpty());
        assertFalse(ordinary.contains(new MetadataKey("example.audit", "abd")));
        MetadataSnapshot.KeyRange exactAndDescendants =
                MetadataSnapshot.KeyRange.prefix("example.audit", "a");
        assertTrue(exactAndDescendants.contains(new MetadataKey("example.audit", "a")));
        assertTrue(exactAndDescendants.contains(new MetadataKey("example.audit", "a.child")));
        assertFalse(exactAndDescendants.contains(new MetadataKey("example.audit", "b")));
        System.out.println("...ok");
    }

    @Test
    void canonicalUtf8LimitsAreExactAcrossConstructionAndParsing() {
        System.out.print("canonicalUtf8LimitsAreExactAcrossConstructionAndParsing ");
        String maximumNamespace = "n".repeat(255);
        String maximumKey = "k".repeat(4096);
        MetadataKey boundary = new MetadataKey(maximumNamespace, maximumKey);
        assertEquals(boundary, MetadataKey.parse(boundary.canonical()));
        String oversizedNamespace = "n".repeat(256);
        String oversizedKey = "k".repeat(4097);
        assertThrows(IllegalArgumentException.class,
                () -> new MetadataKey(oversizedNamespace, "key"));
        assertThrows(IllegalArgumentException.class,
                () -> MetadataKey.parse("mk1:256:3:" + oversizedNamespace + "key"));
        assertThrows(IllegalArgumentException.class,
                () -> new MetadataKey("example.audit", oversizedKey));
        assertThrows(IllegalArgumentException.class,
                () -> MetadataKey.parse("mk1:13:4097:example.audit" + oversizedKey));
        System.out.println("...ok");
    }

    @Test
    void malformedLengthFramingFailsClosed() {
        System.out.print("malformedLengthFramingFailsClosed ");
        MetadataKey key = new MetadataKey("example.audit", "zsign:v1:a:b:c");
        String canonical = key.canonical();
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse("mk2:13:1:example.audita"));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse("mk1:013:1:example.audita"));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse("mk1:13:2:example.audita"));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse(canonical.substring(0, canonical.length() - 1)));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse(canonical + "x"));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse("mk1:999999999999:1:xz"));
        System.out.println("...ok");
    }
}
