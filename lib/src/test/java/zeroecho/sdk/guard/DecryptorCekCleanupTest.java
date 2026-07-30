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
package zeroecho.sdk.guard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.Util;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;

class DecryptorCekCleanupTest {

    @Test
    void rejectedOversizedCekIsCleared() throws Exception {
        System.out.println("rejectedOversizedCekIsCleared");
        byte[] rejected = new byte[17];
        RecipientOpener opener = (entryId, entryBlob, material) -> rejected;
        Decryptor decryptor = decryptor(opener);
        decryptor.setInput(() -> new ByteArrayInputStream(envelopeHeader()));

        assertThrows(IOException.class, decryptor::getStream);

        assertArrayEquals(new byte[rejected.length], rejected);
        System.out.println("...rejectedBytesCleared=17");
        System.out.println("rejectedOversizedCekIsCleared...ok");
    }

    @Test
    void acceptedCekIsClearedWhenCiphertextHeaderIsTruncated() throws Exception {
        System.out.println("acceptedCekIsClearedWhenCiphertextHeaderIsTruncated");
        byte[] accepted = new byte[16];
        RecipientOpener opener = (entryId, entryBlob, material) -> accepted;
        Decryptor decryptor = decryptor(opener);
        decryptor.setInput(() -> new ByteArrayInputStream(envelopeHeader()));

        assertThrows(IOException.class, decryptor::getStream);
        assertArrayEquals(new byte[accepted.length], accepted);

        System.out.println("...acceptedBytesCleared=16");
        System.out.println("acceptedCekIsClearedWhenCiphertextHeaderIsTruncated...ok");
    }

    @Test
    void acceptedCekIsClearedWhenPayloadSetupFails() throws Exception {
        System.out.println("acceptedCekIsClearedWhenPayloadSetupFails");
        byte[] accepted = new byte[16];
        RecipientOpener opener = (entryId, entryBlob, material) -> accepted;
        Decryptor decryptor = new Decryptor(List.of(opener), new UnlockMaterial.Password(new char[] { 'p' }), null,
                null, 16, 4, 128);
        decryptor.setInput(() -> new ByteArrayInputStream(envelopeHeader()));

        assertThrows(NullPointerException.class, decryptor::getStream);

        assertArrayEquals(new byte[accepted.length], accepted);
        System.out.println("...failurePathCleared=true");
        System.out.println("acceptedCekIsClearedWhenPayloadSetupFails...ok");
    }

    @Test
    void preReturnFailureClosesUpstreamStream() throws Exception {
        System.out.println("preReturnFailureClosesUpstreamStream");
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        Util.writePack7I(header, 5);
        TrackingInputStream input = new TrackingInputStream(header.toByteArray(), false);
        Decryptor decryptor = decryptor((entryId, entryBlob, material) -> null);
        decryptor.setInput(() -> input);

        assertThrows(IOException.class, decryptor::getStream);
        assertTrue(input.closed);

        System.out.println("...upstreamClosed=true");
        System.out.println("preReturnFailureClosesUpstreamStream...ok");
    }

    @Test
    void cleanupFailureIsSuppressedOnPrimaryFailure() throws Exception {
        System.out.println("cleanupFailureIsSuppressedOnPrimaryFailure");
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        Util.writePack7I(header, 5);
        TrackingInputStream input = new TrackingInputStream(header.toByteArray(), true);
        Decryptor decryptor = decryptor((entryId, entryBlob, material) -> null);
        decryptor.setInput(() -> input);

        IOException failure = assertThrows(IOException.class, decryptor::getStream);
        assertEquals(1, failure.getSuppressed().length);
        assertTrue(input.closed);

        System.out.println("...suppressedCleanupFailures=1");
        System.out.println("cleanupFailureIsSuppressedOnPrimaryFailure...ok");
    }

    private static Decryptor decryptor(RecipientOpener opener) {
        AesDataContentBuilder aes = AesDataContentBuilder.builder(new ZeroEchoSession()).withHeader().modeGcm(128);
        return new Decryptor(List.of(opener), new UnlockMaterial.Password(new char[] { 'p' }), aes, null, 16, 4, 128);
    }

    private static byte[] envelopeHeader() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Util.writePack7I(output, 1);
        Util.writeUTF8(output, "controlled");
        Util.write(output, new byte[] { 1 });
        return output.toByteArray();
    }

    private static final class TrackingInputStream extends InputStream {
        private final ByteArrayInputStream delegate;
        private final boolean failClose;
        private boolean closed;

        private TrackingInputStream(byte[] bytes, boolean failClose) {
            this.delegate = new ByteArrayInputStream(bytes);
            this.failClose = failClose;
        }

        @Override
        public int read() {
            return delegate.read();
        }

        @Override
        public void close() throws IOException {
            closed = true;
            if (failClose) {
                throw new IOException("controlled close failure");
            }
            delegate.close();
        }
    }
}
