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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.profile.CertificateProfile;

/**
 * Tests for {@link FsCodec}.
 *
 * <p>
 * This suite intentionally covers all compact tags and the fallback string
 * path. FsCodec is security-relevant (durable persistence), so we test
 * determinism, round-trips, and failure modes.
 * </p>
 */
public final class FsCodecTest {

    @Test
    void booleanEncodingIsCompactAndDecodesIntoPrimitiveExpectation() {
        System.out.println("booleanEncodingIsCompactAndDecodesIntoPrimitiveExpectation");

        byte[] data = FsCodec.encode(Boolean.TRUE);

        System.out.println("...encoded length=" + data.length);
        System.out.println("...hex=" + hexPrefix(data));
        assertTrue(data.length <= 5);

        Boolean b = FsCodec.decode(data, Boolean.class);
        assertEquals(Boolean.TRUE, b);

        Object any = FsCodec.decode(data, Object.class);
        assertEquals(Boolean.TRUE, any);

        System.out.println("booleanEncodingIsCompactAndDecodesIntoPrimitiveExpectation...ok");
    }

    @Test
    void scalarRoundTrip_stringIntLongBytes() {
        System.out.println("scalarRoundTrip_stringIntLongBytes");

        String s = "hello";
        byte[] sData = FsCodec.encode(s);
        System.out.println("...string encoded length=" + sData.length);
        assertEquals(s, FsCodec.decode(sData, String.class));

        Integer i = Integer.valueOf(123456);
        byte[] iData = FsCodec.encode(i);
        System.out.println("...int encoded length=" + iData.length);
        assertEquals(i, FsCodec.decode(iData, Integer.class));

        Long l = Long.valueOf(9876543210L);
        byte[] lData = FsCodec.encode(l);
        System.out.println("...long encoded length=" + lData.length);
        assertEquals(l, FsCodec.decode(lData, Long.class));

        byte[] bytes = new byte[] { (byte) 0x00, (byte) 0x7F, (byte) 0x80, (byte) 0xFF };
        byte[] bData = FsCodec.encode(bytes);
        System.out.println("...bytes encoded length=" + bData.length);
        byte[] decoded = FsCodec.decode(bData, byte[].class);
        assertArrayEquals(bytes, decoded);

        System.out.println("scalarRoundTrip_stringIntLongBytes...ok");
    }

    @Test
    void timeRoundTrip_instantAndDuration() {
        System.out.println("timeRoundTrip_instantAndDuration");

        Instant instant = Instant.ofEpochSecond(1700000000L, 123456789);
        byte[] iData = FsCodec.encode(instant);
        Instant i2 = FsCodec.decode(iData, Instant.class);
        System.out.println("...instant=" + instant);
        assertEquals(instant, i2);

        Duration duration = Duration.ofSeconds(12345L, 77);
        byte[] dData = FsCodec.encode(duration);
        Duration d2 = FsCodec.decode(dData, Duration.class);
        System.out.println("...duration=" + duration);
        assertEquals(duration, d2);

        System.out.println("timeRoundTrip_instantAndDuration...ok");
    }

    @Test
    void enumRoundTrip_isStable() {
        System.out.println("enumRoundTrip_isStable");

        TestEnum v = TestEnum.BETA;
        byte[] data = FsCodec.encode(v);
        System.out.println("...encoded length=" + data.length);

        TestEnum decoded = FsCodec.decode(data, TestEnum.class);
        assertEquals(v, decoded);

        System.out.println("enumRoundTrip_isStable...ok");
    }

    @Test
    void recordRoundTrip_usesCompactEncoding() {
        System.out.println("recordRoundTrip_usesCompactEncoding");

        CertificateProfile p = new CertificateProfile("profile-a", new FormatId("fmt-x509"), "Profile A",
                List.of(new AttributeId("req-1")), List.of(new AttributeId("opt-1")), Optional.of(Duration.ofDays(365)),
                true);

        byte[] data = FsCodec.encode(p);
        System.out.println("...encoded length=" + data.length);
        assertTrue(data.length > 0);

        CertificateProfile decoded = FsCodec.decode(data, CertificateProfile.class);
        assertEquals(p, decoded);

        System.out.println("recordRoundTrip_usesCompactEncoding...ok");
    }

    @Test
    void recordRoundTrip_nestedRecordAndCollections() {
        System.out.println("recordRoundTrip_nestedRecordAndCollections");

        NestedRecord v = new NestedRecord("n1", Instant.ofEpochSecond(1700000001L, 9), Optional.of(Integer.valueOf(7)),
                List.of("a", "b"), Set.of("x", "y"));

        byte[] data = FsCodec.encode(v);
        System.out.println("...encoded length=" + data.length);
        NestedRecord decoded = FsCodec.decode(data, NestedRecord.class);
        assertEquals(v, decoded);

        System.out.println("recordRoundTrip_nestedRecordAndCollections...ok");
    }

    @Test
    void listSetOptional_roundTrip_usesCompactEncoding() {
        System.out.println("listSetOptional_roundTrip_usesCompactEncoding");

        List<String> list = List.of("a", "b");
        byte[] listData = FsCodec.encode(list);
        Object decodedList = FsCodec.decode(listData, Object.class);
        assertEquals(list, decodedList);

        Set<Integer> set = Set.of(Integer.valueOf(3), Integer.valueOf(1), Integer.valueOf(2));
        byte[] setData = FsCodec.encode(set);
        Object decodedSet = FsCodec.decode(setData, Object.class);
        assertEquals(set, decodedSet);

        Optional<Integer> opt = Optional.of(Integer.valueOf(7));
        byte[] optData = FsCodec.encode(opt);
        Object decodedOpt = FsCodec.decode(optData, Object.class);
        assertEquals(opt, decodedOpt);

        Optional<Object> empty = Optional.empty();
        byte[] emptyData = FsCodec.encode(empty);
        Object decodedEmpty = FsCodec.decode(emptyData, Object.class);
        assertEquals(Optional.empty(), decodedEmpty);

        System.out.println("listSetOptional_roundTrip_usesCompactEncoding...ok");
    }

    @Test
    void setEncoding_isDeterministicForSameElements() {
        System.out.println("setEncoding_isDeterministicForSameElements");

        // Different construction orders should yield the same encoding.
        Set<String> a = Set.of("b", "a", "c");
        Set<String> b = Set.of("c", "b", "a");

        byte[] ea = FsCodec.encode(a);
        byte[] eb = FsCodec.encode(b);

        System.out.println("...lenA=" + ea.length);
        System.out.println("...lenB=" + eb.length);
        System.out.println("...hexA=" + hexPrefix(ea));
        System.out.println("...hexB=" + hexPrefix(eb));

        assertArrayEquals(ea, eb);

        System.out.println("setEncoding_isDeterministicForSameElements...ok");
    }

    @Test
    void fallbackStringDecode_worksForOfValueOfAndCtor() {
        System.out.println("fallbackStringDecode_worksForOfValueOfAndCtor");

        TestOf a = TestOf.of("x");
        TestValueOf b = TestValueOf.valueOf("y");
        TestCtor c = new TestCtor("z");

        byte[] da = FsCodec.encode(a);
        byte[] db = FsCodec.encode(b);
        byte[] dc = FsCodec.encode(c);

        TestOf a2 = FsCodec.decode(da, TestOf.class);
        TestValueOf b2 = FsCodec.decode(db, TestValueOf.class);
        TestCtor c2 = FsCodec.decode(dc, TestCtor.class);

        assertEquals(a, a2);
        assertEquals(b, b2);
        assertEquals(c, c2);

        System.out.println("fallbackStringDecode_worksForOfValueOfAndCtor...ok");
    }

    @Test
    void fallbackStringDecode_failsWithoutFactory() {
        System.out.println("fallbackStringDecode_failsWithoutFactory");

        TestNoFactory v = new TestNoFactory("boom");
        byte[] data = FsCodec.encode(v);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> FsCodec.decode(data, TestNoFactory.class));
        System.out.println("...ex=" + ex.getMessage());

        assertTrue(ex.getMessage().contains("unsupported value type"));

        System.out.println("fallbackStringDecode_failsWithoutFactory...ok");
    }

    private static String hexPrefix(byte[] bytes) {
        int len = Math.min(bytes.length, 16);
        byte[] p = new byte[len];
        System.arraycopy(bytes, 0, p, 0, len);
        String s = HexFormat.of().formatHex(p);
        return bytes.length > len ? s + "..." : s;
    }

    private enum TestEnum {
        ALPHA, BETA, GAMMA
    }

    public static record NestedRecord(String id, Instant at, Optional<Integer> n, List<String> list, Set<String> set) {
        public NestedRecord {
            if (id == null) {
                throw new IllegalArgumentException("id");
            }
            if (at == null) {
                throw new IllegalArgumentException("at");
            }
            if (n == null) {
                throw new IllegalArgumentException("n");
            }
            if (list == null) {
                throw new IllegalArgumentException("list");
            }
            if (set == null) {
                throw new IllegalArgumentException("set");
            }
        }
    }

    /**
     * Fallback-string: decoded via static of(String).
     */
    public static final class TestOf {

        private final String v;

        private TestOf(String v) {
            this.v = Objects.requireNonNull(v, "v");
        }

        public static TestOf of(String s) {
            return new TestOf(s);
        }

        @Override
        public String toString() {
            return v;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof TestOf other)) {
                return false;
            }
            return v.equals(other.v);
        }

        @Override
        public int hashCode() {
            return v.hashCode();
        }
    }

    /**
     * Fallback-string: decoded via static valueOf(String).
     */
    public static final class TestValueOf {

        private final String v;

        private TestValueOf(String v) {
            this.v = Objects.requireNonNull(v, "v");
        }

        public static TestValueOf valueOf(String s) {
            return new TestValueOf(s);
        }

        @Override
        public String toString() {
            return v;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof TestValueOf other)) {
                return false;
            }
            return v.equals(other.v);
        }

        @Override
        public int hashCode() {
            return v.hashCode();
        }
    }

    /**
     * Fallback-string: decoded via public ctor(String).
     */
    public static final class TestCtor {

        private final String v;

        public TestCtor(String v) {
            this.v = Objects.requireNonNull(v, "v");
        }

        @Override
        public String toString() {
            return v;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof TestCtor other)) {
                return false;
            }
            return v.equals(other.v);
        }

        @Override
        public int hashCode() {
            return v.hashCode();
        }
    }

    /**
     * Fallback-string: has no of/valueOf/ctor(String) and must fail to decode.
     */
    public static final class TestNoFactory {

        private final String v;

        private TestNoFactory(String v) {
            this.v = Objects.requireNonNull(v, "v");
        }

        @Override
        public String toString() {
            return v;
        }
    }
}
