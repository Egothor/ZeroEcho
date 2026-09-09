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
package zeroecho.pki.spi.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;

final class SignRequestCleanupTest {

    @Test
    void fingerprintClearsDigestCopiesWithoutMaterializingContent() throws Exception {
        System.out.println("fingerprintClearsDigestCopiesWithoutMaterializingContent");
        List<byte[]> cleared = new ArrayList<>();
        String first = fingerprint(MessageDigest.getInstance("SHA-256"), cleared);
        String second = fingerprint(MessageDigest.getInstance("SHA-256"), cleared);
        System.out.println("...fingerprint=" + first.substring(0, 20) + "...");
        assertEquals(first, second);
        assertEquals(4, cleared.size());
        assertTrue(cleared.stream().allMatch(SignRequestCleanupTest::isCleared));
        System.out.println("fingerprintClearsDigestCopiesWithoutMaterializingContent...ok");
    }

    @Test
    void fingerprintFailureCreatesNoPayloadCopy() {
        System.out.println("fingerprintFailureCreatesNoPayloadCopy");
        List<byte[]> cleared = new ArrayList<>();
        assertThrows(IllegalStateException.class, () -> fingerprint(new FailingDigest(), cleared));
        assertEquals(1, cleared.size());
        System.out.println("...clearedBuffers=" + cleared.size());
        System.out.println("fingerprintFailureCreatesNoPayloadCopy...ok");
    }

    @Test
    void fingerprintBindsExactCommitmentAndNotContentIdentifier() {
        AccessContext context = new AccessContext(new Principal("SYSTEM", "commitment"), new Purpose("SIGN"),
                Optional.empty(), Optional.empty());
        SignatureWorkflow.ContentCommitment first = SignatureWorkflow.ContentCommitment
                .sha256(new byte[] { 1, 2, 3 });
        SignatureWorkflow.ContentCommitment second = SignatureWorkflow.ContentCommitment
                .sha256(new byte[] { 1, 2, 4 });
        SignatureWorkflow.ConfigurationCommitment configuration = configurationCommitment(1);
        String firstFingerprint = SignatureWorkflow.SignRequest.fingerprint(configuration, "store.provider", context,
                new KeyRef("provider:key"), "SHA256withRSA", first, Optional.of(Encoding.BINARY), Optional.empty());
        String secondFingerprint = SignatureWorkflow.SignRequest.fingerprint(configuration, "store.provider", context,
                new KeyRef("provider:key"), "SHA256withRSA", second, Optional.of(Encoding.BINARY), Optional.empty());
        assertTrue(firstFingerprint.startsWith("signfp:v3:"));
        assertNotEquals(firstFingerprint, secondFingerprint);
        assertNotEquals(firstFingerprint, SignatureWorkflow.SignRequest.fingerprint(configurationCommitment(2),
                "store.provider", context, new KeyRef("provider:key"), "SHA256withRSA", first,
                Optional.of(Encoding.BINARY), Optional.empty()));
    }

    private static String fingerprint(MessageDigest digest, List<byte[]> cleared) {
        AccessContext context = new AccessContext(new Principal("SYSTEM", "cleanup"), new Purpose("SIGN"),
                Optional.of(new PkiId("cleanup-operation")), Optional.empty());
        return SignatureWorkflow.SignRequest.fingerprintWithDigest(configurationCommitment(1),
                "cleanup.namespace", context,
                new KeyRef("provider:key"), "SHA256withRSA",
                SignatureWorkflow.ContentCommitment.sha256(new byte[] { 1, 2, 3, 4 }),
                Optional.of(Encoding.BINARY),
                Optional.of(Instant.parse("2026-08-01T00:00:00Z")), digest, cleared::add);
    }

    private static SignatureWorkflow.ConfigurationCommitment configurationCommitment(int marker) {
        byte[] bytes = new byte[SignatureWorkflow.ConfigurationCommitment.BYTE_LENGTH];
        bytes[0] = (byte) marker;
        return new SignatureWorkflow.ConfigurationCommitment(bytes);
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
