/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.sdk.guard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Key;
import java.util.List;

import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.NullKey;
import zeroecho.core.context.KemContext;
import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;

class KemRecipientLifecycleTest {
    private static final CryptoAlgorithm ALGORITHM = new TestAlgorithm();

    @Test
    void supportedKekSizesClearSenderSharedSecrets() throws Exception {
        System.out.println("supportedKekSizesClearSenderSharedSecrets");
        for (int kekBytes : new int[] { 16, 32 }) {
            byte[] senderSecret = filled(32, (byte) 0x41);
            ControlledKemContext sender = new ControlledKemContext(senderSecret);
            byte[] cek = filled(32, (byte) 0x52);

            byte[] entry = new KemCtxRecipient(sender, kekBytes, 16).buildRecipientEntry(cek);
            assertTrue(entry.length > cek.length);
            assertArrayEquals(new byte[senderSecret.length], senderSecret);
            assertTrue(sender.closed);
            System.out.println("...kekBytes=" + kekBytes);
        }
        System.out.println("...senderSecretsCleared=true");
        System.out.println("supportedKekSizesClearSenderSharedSecrets...ok");
    }

    @Test
    void constructorsAndBuilderRejectUnsupportedKekBeforeOwnershipTransfer() throws Exception {
        System.out.println("constructorsAndBuilderRejectUnsupportedKekBeforeOwnershipTransfer");
        int[] invalidValues = { -1, 0, 1, 15, 17, 24, 31, 33, Integer.MAX_VALUE };
        ZeroEchoSession session = new ZeroEchoSession()
                .withPbkdf2Limits(new Pbkdf2Limits(20_000, 30_000));
        MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)
                .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader());
        for (int kekBytes : invalidValues) {
            ControlledKemContext direct = new ControlledKemContext(filled(32, (byte) 0x11));
            assertThrows(IllegalArgumentException.class,
                    () -> new KemCtxRecipient(direct, kekBytes, 16));
            assertFalse(direct.closed);
            direct.close();

            ControlledKemContext normal = new ControlledKemContext(filled(32, (byte) 0x22));
            assertThrows(IllegalArgumentException.class,
                    () -> builder.addRecipient(normal, kekBytes, 16));
            assertEquals(0, recipients(builder).size());
            assertFalse(normal.closed);
            normal.close();

            ControlledKemContext decoy = new ControlledKemContext(filled(32, (byte) 0x33));
            assertThrows(IllegalArgumentException.class,
                    () -> builder.addRecipientDecoy(decoy, kekBytes, 16));
            assertEquals(0, recipients(builder).size());
            assertFalse(decoy.closed);
            decoy.close();
        }
        builder.close();
        System.out.println("...recipientCount=0");
        System.out.println("constructorsAndBuilderRejectUnsupportedKekBeforeOwnershipTransfer...ok");
    }

    @Test
    void wrapFailureClearsSharedSecretAndClosesContext() {
        System.out.println("wrapFailureClearsSharedSecretAndClosesContext");
        byte[] sharedSecret = filled(32, (byte) 0x33);
        ControlledKemContext context = new ControlledKemContext(sharedSecret, ALGORITHM, null);

        assertThrows(NullPointerException.class,
                () -> new KemCtxRecipient(context, 16, 16).buildRecipientEntry(new byte[32]));
        assertArrayEquals(new byte[sharedSecret.length], sharedSecret);
        assertTrue(context.closed);
        System.out.println("...failureCleanup=true");
        System.out.println("wrapFailureClearsSharedSecretAndClosesContext...ok");
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        java.util.Arrays.fill(result, value);
        return result;
    }

    private static final class TestAlgorithm extends CryptoAlgorithm {
        private TestAlgorithm() {
            super("TEST-KEM", "Test KEM");
        }
    }

    private static final class ControlledKemContext implements KemContext {
        private final byte[] sharedSecret;
        private final CryptoAlgorithm algorithm;
        private final byte[] ciphertext;
        private boolean closed;

        private ControlledKemContext(byte[] sharedSecret) {
            this(sharedSecret, ALGORITHM, new byte[] { 1, 2, 3 });
        }

        private ControlledKemContext(byte[] sharedSecret, CryptoAlgorithm algorithm, byte[] ciphertext) {
            this.sharedSecret = sharedSecret;
            this.algorithm = algorithm;
            this.ciphertext = ciphertext;
        }

        @Override
        public KemResult encapsulate() {
            return new KemResult(ciphertext, sharedSecret);
        }

        @Override
        public byte[] decapsulate(byte[] ciphertext) {
            return sharedSecret;
        }

        @Override
        public CryptoAlgorithm algorithm() {
            return algorithm;
        }

        @Override
        public Key key() {
            return NullKey.INSTANCE;
        }

        @Override
        public void close() throws IOException {
            closed = true;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Recipient> recipients(MultiRecipientDataSourceBuilder builder) throws Exception {
        Field field = MultiRecipientDataSourceBuilder.class.getDeclaredField("recipients");
        field.setAccessible(true);
        return (List<Recipient>) field.get(builder);
    }
}
