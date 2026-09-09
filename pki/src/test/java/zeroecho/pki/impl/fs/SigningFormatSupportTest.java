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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.junit.jupiter.api.Test;

final class SigningFormatSupportTest {

    @Test
    void partialReadAndWriteChannelsMakeCompleteProgress() throws Exception {
        byte[] bytes = "bounded-content".getBytes(StandardCharsets.US_ASCII);
        PartialWritable writable = new PartialWritable();
        SigningFormatSupport.writeFully(writable, ByteBuffer.wrap(bytes));
        assertArrayEquals(bytes, writable.bytes());

        ByteBuffer target = ByteBuffer.allocate(bytes.length);
        assertEquals(bytes.length, SigningFormatSupport.readAvailable(
                new PartialReadable(bytes), target));
        assertArrayEquals(bytes, target.array());
    }

    @Test
    void streamingCommitmentUsesBoundedPartialReads() throws Exception {
        byte[] bytes = "commitment".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = MessageDigest.getInstance("SHA-256").digest(bytes);
        assertArrayEquals(expected, SigningFileCommitment.sha256(new PartialReadable(bytes)));
    }

    @Test
    void zeroProgressFailsInsteadOfSpinning() {
        ZeroProgressChannel channel = new ZeroProgressChannel();
        assertThrows(IOException.class, () -> SigningFormatSupport.writeFully(
                channel, ByteBuffer.wrap(new byte[] { 1 })));
        assertThrows(IOException.class, () -> SigningFormatSupport.readAvailable(
                channel, ByteBuffer.allocate(1)));
    }

    @Test
    void strictUtf8RejectsMalformedUtf16AndRoundTripsCanonicalText() throws Exception {
        for (String invalid : new String[] { "high\ud800", "low\udc00", "e\u0301" }) {
            assertThrows(IllegalArgumentException.class,
                    () -> SigningFormatSupport.strictUtf8(invalid, 32));
        }
        String canonical = "é-key";
        byte[] encoded = SigningFormatSupport.strictUtf8(canonical, 32);
        assertEquals(canonical, SigningFormatSupport.decodeUtf8(encoded));
        assertArrayEquals(encoded, SigningFormatSupport.strictUtf8(
                SigningFormatSupport.decodeUtf8(encoded), 32));
        assertThrows(IllegalArgumentException.class,
                () -> SigningFormatSupport.strictUtf8("abc", 2));
    }

    private static final class PartialReadable implements ReadableByteChannel {
        private final byte[] bytes;
        private int offset;
        private boolean open = true;

        private PartialReadable(byte[] bytes) {
            this.bytes = bytes.clone();
        }

        @Override
        public int read(ByteBuffer destination) {
            if (offset == bytes.length) {
                return -1;
            }
            destination.put(bytes[offset++]);
            return 1;
        }

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void close() {
            open = false;
        }
    }

    private static final class PartialWritable implements WritableByteChannel {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private boolean open = true;

        @Override
        public int write(ByteBuffer source) {
            output.write(source.get());
            return 1;
        }

        private byte[] bytes() {
            return output.toByteArray();
        }

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void close() {
            open = false;
        }
    }

    private static final class ZeroProgressChannel implements ReadableByteChannel, WritableByteChannel {
        @Override
        public int read(ByteBuffer target) {
            return 0;
        }

        @Override
        public int write(ByteBuffer source) {
            return 0;
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
            // no resources
        }
    }
}
