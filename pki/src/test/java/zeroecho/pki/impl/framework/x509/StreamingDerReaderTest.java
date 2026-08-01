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
package zeroecho.pki.impl.framework.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.impl.framework.x509.StreamingDerReader.SignedObjectKind;
import zeroecho.pki.impl.framework.x509.StreamingDerReader.SignedObjectLayout;

final class StreamingDerReaderTest {

    private static final byte[] CRL = {
            0x30, 0x26,
            0x30, 0x1a,
            0x02, 0x01, 0x01,
            0x30, 0x04, 0x06, 0x02, 0x2a, 0x03,
            0x30, 0x00,
            0x17, 0x0d, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x30, 0x04, 0x06, 0x02, 0x2a, 0x03,
            0x03, 0x02, 0x00, (byte) 0xaa
    };

    @Test
    void validatesCanonicalCrlAndLocatesSignedFields() throws Exception {
        System.out.println("validatesCanonicalCrlAndLocatesSignedFields");
        StreamingDerReader reader = new StreamingDerReader();
        ImmutableByteContent content = new ImmutableByteContent(CRL);
        SignedObjectLayout layout = reader.inspectSignedObject(content, SignedObjectKind.CRL,
                CancellationSignal.NONE);
        System.out.println("...encodedLength=" + reader.validate(content, CancellationSignal.NONE));
        assertEquals(2L, layout.tbsOffset());
        assertEquals(28L, layout.tbsLength());
        assertEquals(7L, layout.tbsAlgorithmOffset());
        assertEquals(6L, layout.tbsAlgorithmLength());
        assertEquals(30L, layout.outerAlgorithmOffset());
        assertEquals(6L, layout.outerAlgorithmLength());
        assertEquals(39L, layout.signatureOffset());
        assertEquals(1L, layout.signatureLength());
        System.out.println("validatesCanonicalCrlAndLocatesSignedFields...ok");
    }

    @Test
    void rejectsTrailingIndefiniteAndNonMinimalLength() {
        System.out.println("rejectsTrailingIndefiniteAndNonMinimalLength");
        StreamingDerReader reader = new StreamingDerReader();
        assertThrows(IOException.class, () -> reader.validate(
                new ImmutableByteContent(Arrays.copyOf(CRL, CRL.length + 1)), CancellationSignal.NONE));
        byte[] indefinite = { 0x30, (byte) 0x80, 0x00, 0x00 };
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(indefinite), CancellationSignal.NONE));
        byte[] nonMinimal = { 0x30, (byte) 0x81, 0x00 };
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(nonMinimal), CancellationSignal.NONE));
        System.out.println("...rejected=3");
        System.out.println("rejectsTrailingIndefiniteAndNonMinimalLength...ok");
    }

    @Test
    void rejectsNonCanonicalPrimitiveForms() {
        System.out.println("rejectsNonCanonicalPrimitiveForms");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] integer = { 0x02, 0x02, 0x00, 0x01 };
        byte[] oid = { 0x06, 0x01, (byte) 0x80 };
        byte[] bitString = { 0x03, 0x02, 0x01, 0x01 };
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(integer), CancellationSignal.NONE));
        assertThrows(IOException.class, () -> reader.validate(new ImmutableByteContent(oid), CancellationSignal.NONE));
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(bitString), CancellationSignal.NONE));
        System.out.println("...rejected=3");
        System.out.println("rejectsNonCanonicalPrimitiveForms...ok");
    }

    @Test
    void enforcesCanonicalSetOrdering() throws Exception {
        System.out.println("enforcesCanonicalSetOrdering");
        StreamingDerReader reader = new StreamingDerReader();
        byte[] canonical = { 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 };
        byte[] reversed = { 0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01 };
        assertEquals(canonical.length,
                reader.validate(new ImmutableByteContent(canonical), CancellationSignal.NONE));
        assertThrows(IOException.class,
                () -> reader.validate(new ImmutableByteContent(reversed), CancellationSignal.NONE));
        System.out.println("...rejected=reversed SET");
        System.out.println("enforcesCanonicalSetOrdering...ok");
    }

    @Test
    void setOrderingUsesFixedSourcePasses() throws Exception {
        System.out.println("setOrderingUsesFixedSourcePasses");
        byte[] encoded = repeatedIntegerSet(128);
        CountingContent content = new CountingContent(encoded);
        StreamingDerReader reader = new StreamingDerReader();

        assertEquals(encoded.length, reader.validate(content, CancellationSignal.NONE));
        assertEquals(3, content.openCount());
        assertEquals(3, content.closeCount());
        System.out.println("...sourcePasses=" + content.openCount());
        System.out.println("setOrderingUsesFixedSourcePasses...ok");
    }

    private static byte[] repeatedIntegerSet(int count) {
        int valueLength = Math.multiplyExact(count, 3);
        byte[] encoded = new byte[Math.addExact(valueLength, 4)];
        encoded[0] = 0x31;
        encoded[1] = (byte) 0x82;
        encoded[2] = (byte) (valueLength >>> 8);
        encoded[3] = (byte) valueLength;
        for (int index = 4; index < encoded.length; index += 3) {
            encoded[index] = 0x02;
            encoded[index + 1] = 0x01;
            encoded[index + 2] = 0x01;
        }
        return encoded;
    }

    /** Repeatable test content that accounts for every fixed comparison pass. */
    private static final class CountingContent implements RepeatableContent {
        private final byte[] encoded;
        private final AtomicInteger opens = new AtomicInteger();
        private final AtomicInteger closes = new AtomicInteger();

        private CountingContent(byte[] encoded) {
            this.encoded = encoded.clone();
        }

        @Override
        public InputStream openStream() {
            opens.incrementAndGet();
            return new FilterInputStream(new ByteArrayInputStream(encoded)) {
                @Override
                public void close() throws IOException {
                    super.close();
                    closes.incrementAndGet();
                }
            };
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(encoded.length);
        }

        @Override
        public String contentId() {
            return "test:counting-set";
        }

        @Override
        public void close() {
            // The immutable test value owns no external resource.
        }

        private int openCount() {
            return opens.get();
        }

        private int closeCount() {
            return closes.get();
        }
    }
}
