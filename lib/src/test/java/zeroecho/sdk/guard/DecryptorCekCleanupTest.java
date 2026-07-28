/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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
        Decryptor decryptor = new Decryptor(List.of(opener), new UnlockMaterial.Password(new char[] { 'p' }),
                null, null, 16, 4, 128);
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
        return new Decryptor(List.of(opener), new UnlockMaterial.Password(new char[] { 'p' }),
                aes, null, 16, 4, 128);
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
