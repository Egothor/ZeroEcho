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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

final class DomainAttributeEncodingTest {
    @Test void sharedLargeValuesRejectDuringBoundedPreflight() {
        AttributeId id = new AttributeId("urn:test:large");
        AttributeValue shared = new AttributeValue.StringValue("x".repeat(131_072));
        java.util.concurrent.atomic.AtomicInteger reads = new java.util.concurrent.atomic.AtomicInteger();
        List<AttributeValue> values = new java.util.AbstractList<>() {
            @Override public int size() { return 4096; }
            @Override public AttributeValue get(int index) {
                if (reads.incrementAndGet() > 6) { throw new AssertionError("Preflight must stop at the aggregate bound"); }
                return shared;
            }
        };
        AttributeSet source = new AttributeSet() {
            @Override public java.util.Set<AttributeId> ids() { return java.util.Set.of(id); }
            @Override public java.util.Optional<AttributeValue> get(AttributeId ignored) { return java.util.Optional.of(shared); }
            @Override public List<AttributeValue> getAll(AttributeId ignored) { return values; }
        };
        assertThrows(IllegalArgumentException.class, () -> DomainAttributeEncoding.encode(source));
        assertEquals(6, reads.get());
    }

    @Test
    void exactClosedValuesRoundTripCanonically() {
        AttributeId binary = new AttributeId("urn:test:binary");
        AttributeId values = new AttributeId("urn:test:values");
        List<AttributeValue> ordered = List.of(new AttributeValue.StringValue("text"),
                new AttributeValue.BooleanValue(true), new AttributeValue.BooleanValue(false),
                new AttributeValue.IntegerValue(7),
                new AttributeValue.InstantValue(Instant.parse("2026-08-20T10:00:00Z")));
        AttributeSet source = new SimpleAttributeSet(List.of(
                new SimpleAttributeSet.Entry(binary,
                        List.of(new AttributeValue.BytesValue(new byte[] { 1, 2, 3 }))),
                new SimpleAttributeSet.Entry(values, ordered),
                new SimpleAttributeSet.Entry(new AttributeId("urn:test:empty"), List.of())));

        String first = DomainAttributeEncoding.encode(source);
        assertEquals(Base64.getUrlDecoder().decode(first).length, DomainAttributeEncoding.encodedSize(source));
        AttributeSet decoded = DomainAttributeEncoding.decode(first);

        assertEquals(first, DomainAttributeEncoding.encode(decoded));
        assertArrayEquals(new byte[] { 1, 2, 3 },
                ((AttributeValue.BytesValue) decoded.get(binary).orElseThrow()).value());
        assertEquals(source.getAll(values), decoded.getAll(values));
        assertEquals(ordered, decoded.getAll(values));
        assertEquals(List.of(), decoded.getAll(new AttributeId("urn:test:empty")));
    }

    @Test
    void rejectsNonCanonicalBooleanAndInstantEncodings() {
        assertThrows(IllegalArgumentException.class,
                () -> DomainAttributeEncoding.decode(hostileValue(2, new byte[] { 2 })));
        assertThrows(IllegalArgumentException.class,
                () -> DomainAttributeEncoding.decode(hostileValue(4,
                        "2026-08-20T10:00:00.000Z".getBytes(StandardCharsets.US_ASCII))));
    }

    private static String hostileValue(int type, byte[] value) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(1);
                output.writeInt(1);
                byte[] id = "urn:test:hostile".getBytes(StandardCharsets.UTF_8);
                output.writeInt(id.length);
                output.write(id);
                output.writeInt(1);
                output.writeByte(type);
                if (type == 2) {
                    output.write(value);
                } else {
                    output.writeInt(value.length);
                    output.write(value);
                }
            }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.toByteArray());
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }
}
