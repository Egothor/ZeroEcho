/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.spi.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;

final class SignRequestCleanupTest {

    @Test
    void fingerprintClearsPayloadAndDigestCopiesAfterSuccessAndRepeatedUse() throws Exception {
        System.out.println("fingerprintClearsPayloadAndDigestCopiesAfterSuccessAndRepeatedUse");
        List<byte[]> cleared = new ArrayList<>();
        String first = fingerprint(MessageDigest.getInstance("SHA-256"), cleared);
        String second = fingerprint(MessageDigest.getInstance("SHA-256"), cleared);
        System.out.println("...fingerprint=" + first.substring(0, 20) + "...");
        assertEquals(first, second);
        assertEquals(4, cleared.size());
        assertTrue(cleared.stream().allMatch(SignRequestCleanupTest::isCleared));
        System.out.println("fingerprintClearsPayloadAndDigestCopiesAfterSuccessAndRepeatedUse...ok");
    }

    @Test
    void fingerprintClearsPayloadCopyAfterDigestFailure() {
        System.out.println("fingerprintClearsPayloadCopyAfterDigestFailure");
        List<byte[]> cleared = new ArrayList<>();
        assertThrows(IllegalStateException.class, () -> fingerprint(new FailingDigest(), cleared));
        assertEquals(1, cleared.size());
        assertTrue(isCleared(cleared.get(0)));
        System.out.println("...clearedBuffers=" + cleared.size());
        System.out.println("fingerprintClearsPayloadCopyAfterDigestFailure...ok");
    }

    private static String fingerprint(MessageDigest digest, List<byte[]> cleared) {
        AccessContext context = new AccessContext(new Principal("SYSTEM", "cleanup"), new Purpose("SIGN"),
                Optional.of(new PkiId("cleanup-operation")), Optional.empty());
        return SignatureWorkflow.SignRequest.fingerprintWithDigest("cleanup.namespace", context,
                new KeyRef("provider:key"), "SHA256withRSA",
                new EncodedObject(Encoding.BINARY, new byte[] { 1, 2, 3, 4 }), Optional.of(Encoding.BINARY),
                Optional.of(Instant.parse("2026-08-01T00:00:00Z")), digest, cleared::add);
    }

    private static boolean isCleared(byte[] bytes) {
        for (byte value : bytes) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    private static final class FailingDigest extends MessageDigest {
        private FailingDigest() {
            super("FAILING");
        }

        @Override
        protected void engineUpdate(byte input) {
            throw new IllegalStateException("controlled digest failure");
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int length) {
            throw new IllegalStateException("controlled digest failure");
        }

        @Override
        protected byte[] engineDigest() {
            return new byte[32];
        }

        @Override
        protected void engineReset() {
            // No state.
        }
    }
}
