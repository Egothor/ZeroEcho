/*
 * Copyright (c) 2025 ZeroEcho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
        MetadataKey key = MetadataKey.parse("example.audit:Record-01");
        assertEquals("example.audit", key.namespace());
        assertEquals("Record-01", key.key());
        assertEquals(key, MetadataKey.parse(key.canonical()));
        System.out.println("...ok");
    }

    @Test
    void reservedAndAmbiguousIdentitiesFail() {
        System.out.print("reservedAndAmbiguousIdentitiesFail ");
        assertThrows(IllegalArgumentException.class, () -> new MetadataKey("zeroecho", "a"));
        assertThrows(IllegalArgumentException.class, () -> new MetadataKey("zeroecho.audit", "a"));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse("Example.audit:a"));
        assertThrows(IllegalArgumentException.class, () -> new MetadataKey("example.audit", "a/b"));
        assertThrows(IllegalArgumentException.class, () -> new MetadataKey("example.audit", "é"));
        assertThrows(IllegalArgumentException.class, () -> MetadataKey.parse("example.audit:a:b"));
        System.out.println("...ok");
    }

    @Test
    void orderingAndPrefixRangesAreTotal() {
        System.out.print("orderingAndPrefixRangesAreTotal ");
        List<MetadataKey> sorted = List.of(
                        new MetadataKey("example.audit", "a~"),
                        new MetadataKey("example.audit", "abc"),
                        new MetadataKey("example.audit", "~"))
                .stream()
                .sorted()
                .toList();
        assertEquals("abc", sorted.get(0).key());
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
                () -> MetadataKey.parse(oversizedNamespace + ":key"));
        assertThrows(IllegalArgumentException.class,
                () -> new MetadataKey("example.audit", oversizedKey));
        assertThrows(IllegalArgumentException.class,
                () -> MetadataKey.parse("example.audit:" + oversizedKey));
        System.out.println("...ok");
    }
}
