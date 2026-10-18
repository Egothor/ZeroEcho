/* *****************************************************************************
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
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.IntFunction;

import org.junit.jupiter.api.Test;

import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;

class EncryptorCekAllocationTest {
    private static final int KEY_BYTES = 16;

    @Test
    void noDecoysGenerateOnlyPayloadCek() throws Exception {
        System.out.print("EncryptorCekAllocation/noDecoysGenerateOnlyPayloadCek...");
        RecordingRandomFactory randomFactory = new RecordingRandomFactory();
        CapturingRecipient first = new CapturingRecipient(false);
        CapturingRecipient second = new CapturingRecipient(false);

        openEncryptor(List.of(first, second), randomFactory).close();

        assertEquals(1, randomFactory.calls());
        assertArrayEquals(repeated((byte) 1), first.cek);
        assertArrayEquals(first.cek, second.cek);
        assertAllCleared(randomFactory.outputs);
        System.out.println("...factoryCalls=" + randomFactory.calls());
        System.out.println("ok");
    }

    @Test
    void oneDecoyGeneratesOneLazyDecoyCek() throws Exception {
        System.out.print("EncryptorCekAllocation/oneDecoyGeneratesOneLazyDecoyCek...");
        RecordingRandomFactory randomFactory = new RecordingRandomFactory();
        CapturingRecipient decoy = new CapturingRecipient(true);

        openEncryptor(List.of(decoy), randomFactory).close();

        assertEquals(2, randomFactory.calls());
        assertArrayEquals(repeated((byte) 2), decoy.cek);
        assertAllCleared(randomFactory.outputs);
        System.out.println("...factoryCalls=" + randomFactory.calls());
        System.out.println("ok");
    }

    @Test
    void mixedDecoysGenerateOneLazyCekAndReuseItInOrder() throws Exception {
        System.out.print("EncryptorCekAllocation/mixedDecoysGenerateOneLazyCekAndReuseItInOrder...");
        RecordingRandomFactory randomFactory = new RecordingRandomFactory();
        CapturingRecipient realBefore = new CapturingRecipient(false);
        CapturingRecipient firstDecoy = new CapturingRecipient(true);
        CapturingRecipient realAfter = new CapturingRecipient(false);
        CapturingRecipient secondDecoy = new CapturingRecipient(true);

        openEncryptor(List.of(realBefore, firstDecoy, realAfter, secondDecoy), randomFactory).close();

        assertEquals(2, randomFactory.calls());
        assertArrayEquals(repeated((byte) 1), realBefore.cek);
        assertArrayEquals(realBefore.cek, realAfter.cek);
        assertArrayEquals(repeated((byte) 2), firstDecoy.cek);
        assertArrayEquals(firstDecoy.cek, secondDecoy.cek);
        assertAllCleared(randomFactory.outputs);
        System.out.println("...factoryCalls=" + randomFactory.calls());
        System.out.println("ok");
    }

    @Test
    void recipientLimitIsCheckedBeforeCekGeneration() {
        System.out.print("EncryptorCekAllocation/recipientLimitIsCheckedBeforeCekGeneration...");
        RecordingRandomFactory randomFactory = new RecordingRandomFactory();
        Encryptor encryptor = newEncryptor(List.of(new CapturingRecipient(false), new CapturingRecipient(false)), 1,
                randomFactory);
        encryptor.setInput(() -> new ByteArrayInputStream(new byte[0]));

        assertThrows(IOException.class, encryptor::getStream);
        assertEquals(0, randomFactory.calls());
        System.out.println("...factoryCalls=0");
        System.out.println("ok");
    }

    @Test
    void recipientFailureClearsGenuineAndDecoyCeks() {
        System.out.print("EncryptorCekAllocation/recipientFailureClearsGenuineAndDecoyCeks...");
        RecordingRandomFactory randomFactory = new RecordingRandomFactory();
        Encryptor encryptor = newEncryptor(List.of(new CapturingRecipient(false), new FailingRecipient(true)), 8,
                randomFactory);
        encryptor.setInput(() -> new ByteArrayInputStream(new byte[0]));

        assertThrows(IOException.class, encryptor::getStream);
        assertEquals(2, randomFactory.calls());
        assertAllCleared(randomFactory.outputs);
        System.out.println("...factoryCalls=" + randomFactory.calls());
        System.out.println("ok");
    }

    @Test
    void successfulRecipientProcessingDestroysOwnedPassword() throws Exception {
        System.out.print("EncryptorCekAllocation/successfulRecipientProcessingDestroysOwnedPassword...");
        PasswordRecipient passwordRecipient = passwordRecipient();

        openEncryptor(List.of(passwordRecipient), new RecordingRandomFactory()).close();

        assertTrue(passwordRecipient.isDestroyed());
        System.out.println("...passwordDestroyed=true");
        System.out.println("ok");
    }

    @Test
    void failedRecipientProcessingDestroysOwnedPassword() {
        System.out.print("EncryptorCekAllocation/failedRecipientProcessingDestroysOwnedPassword...");
        PasswordRecipient passwordRecipient = passwordRecipient();
        Encryptor encryptor = newEncryptor(List.of(passwordRecipient, new FailingRecipient(false)), 8,
                new RecordingRandomFactory());
        encryptor.setInput(() -> new ByteArrayInputStream(new byte[0]));

        assertThrows(IOException.class, encryptor::getStream);
        assertTrue(passwordRecipient.isDestroyed());
        System.out.println("...passwordDestroyed=true");
        System.out.println("ok");
    }

    private static InputStream openEncryptor(List<Recipient> recipients, IntFunction<byte[]> randomFactory)
            throws IOException {
        Encryptor encryptor = newEncryptor(recipients, 8, randomFactory);
        encryptor.setInput(() -> new ByteArrayInputStream(new byte[] { 1, 2, 3 }));
        return encryptor.getStream();
    }

    private static Encryptor newEncryptor(List<Recipient> recipients, int maxRecipients,
            IntFunction<byte[]> randomFactory) {
        return new Encryptor(recipients, AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128),
                null, KEY_BYTES, maxRecipients, 1024, randomFactory);
    }

    private static byte[] repeated(byte value) {
        byte[] result = new byte[KEY_BYTES];
        Arrays.fill(result, value);
        return result;
    }

    private static PasswordRecipient passwordRecipient() {
        return new PasswordRecipient(new char[] { 'p' }, Pbkdf2Limits.MINIMUM, 16, 32, false,
                new Pbkdf2Limits(20_000, 30_000));
    }

    private static void assertAllCleared(List<byte[]> arrays) {
        for (byte[] array : arrays) {
            assertTrue(Arrays.equals(new byte[array.length], array));
        }
    }

    private static class CapturingRecipient implements Recipient {
        private final boolean decoy;
        private byte[] cek;

        private CapturingRecipient(boolean decoy) {
            this.decoy = decoy;
        }

        @Override
        public boolean decoy() {
            return decoy;
        }

        @Override
        public String id() {
            return decoy ? "test-decoy" : "test-real";
        }

        @Override
        public byte[] buildRecipientEntry(byte[] inputCek) throws GeneralSecurityException {
            cek = inputCek.clone();
            return new byte[] { 1 };
        }
    }

    private static final class FailingRecipient extends CapturingRecipient {
        private FailingRecipient(boolean decoy) {
            super(decoy);
        }

        @Override
        public byte[] buildRecipientEntry(byte[] inputCek) throws GeneralSecurityException {
            throw new GeneralSecurityException("controlled recipient failure");
        }
    }

    private static final class RecordingRandomFactory implements IntFunction<byte[]> {
        private final List<byte[]> outputs = new ArrayList<>();

        @Override
        public byte[] apply(int length) {
            byte[] result = new byte[length];
            Arrays.fill(result, (byte) (outputs.size() + 1));
            outputs.add(result);
            return result;
        }

        private int calls() {
            return outputs.size();
        }
    }
}
