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
package zeroecho.pki.spi.confirmation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;

final class KeyPossessionProofContractsTest {
    private static final String SUITE_ID = "zeroecho.signature-pop.v1";
    private static final ConfirmationProofSuiteRef SUITE_REF = new ConfirmationProofSuiteRef(
            SUITE_ID, "a".repeat(64));
    private static final ConfirmationProofSuiteBinding BINDING =
            new ConfirmationProofSuiteBinding(SUITE_REF, 8_192);

    @Test
    void descriptorRequiresExactPortableAndResponseBounds() {
        KeyPossessionProofDescriptor descriptor = new KeyPossessionProofDescriptor(BINDING,
                CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES, 1_024);
        assertEquals(BINDING, descriptor.proofSuiteBinding());
        assertEquals(32, descriptor.challengeBytes());
        assertEquals(1_024, descriptor.maximumResponseBytes());
        assertEquals(KeyPossessionProofResponse.MAXIMUM_BYTES,
                new KeyPossessionProofDescriptor(
                        new ConfirmationProofSuiteBinding(SUITE_REF, 16_384), 32,
                        KeyPossessionProofResponse.MAXIMUM_BYTES).maximumResponseBytes());

        assertThrows(NullPointerException.class,
                () -> new KeyPossessionProofDescriptor(null, 32, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new KeyPossessionProofDescriptor(BINDING, 31, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new KeyPossessionProofDescriptor(BINDING, 33, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new KeyPossessionProofDescriptor(BINDING, 32, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new KeyPossessionProofDescriptor(BINDING, 32,
                        KeyPossessionProofResponse.MAXIMUM_BYTES + 1));
    }

    @Test
    void splitCredentialAndChallengeContextsOwnNonceAndRedactKey() {
        byte[] nonce = bytes(32, 7);
        PublicKey publicKey = new TestPublicKey("RSA", bytes(64, 11));
        KeyPossessionProofChallengeContext context = context(nonce);
        KeyPossessionProofChallengeContext equal = context(bytes(32, 7));
        KeyPossessionProofCredential credential = credential(publicKey);
        KeyPossessionProofCredential equalCredential = credential(publicKey);

        nonce[0] = 99;
        assertArrayEquals(bytes(32, 7), context.rawChallenge());
        byte[] returnedNonce = context.rawChallenge();
        returnedNonce[0] = 98;
        assertArrayEquals(bytes(32, 7), context.rawChallenge());
        assertEquals(context, equal);
        assertEquals(context.hashCode(), equal.hashCode());
        assertEquals(credential, equalCredential);
        assertEquals(credential.hashCode(), equalCredential.hashCode());
        assertNotEquals(context, context(bytes(32, 8)));
        assertNotEquals(credential, new KeyPossessionProofCredential(BINDING,
                new PkiId("other-credential"), publicKey));
        assertEquals(new PkiId("credential"), credential.credentialId());
        assertEquals(publicKey, credential.publicKey());
        assertTrue(context.toString().contains("rawChallenge=<32 bytes>"));
        assertTrue(credential.toString().contains("publicKey=<redacted>"));
        assertFalse(context.toString().contains(Arrays.toString(bytes(32, 7))));
        assertFalse(credential.toString().contains(Arrays.toString(bytes(64, 11))));
        assertEquals(512, context("a".repeat(512), new PkiId("credential"), BINDING,
                bytes(32, 1), Instant.ofEpochSecond(100L)).serverAudience().length());
    }

    @Test
    void splitContextsRejectEveryNullAndBoundViolation() {
        assertThrows(NullPointerException.class, () -> new KeyPossessionProofChallengeContext(null,
                "https://pki.example.test", new PkiId("credential"), BINDING,
                bytes(32, 1), Instant.ofEpochSecond(100L)));
        assertThrows(NullPointerException.class, () -> new KeyPossessionProofChallengeContext(
                new ConfirmationRealmBinding("realm"), null, new PkiId("credential"), BINDING,
                bytes(32, 1), Instant.ofEpochSecond(100L)));
        assertThrows(IllegalArgumentException.class, () -> context("", new PkiId("credential"),
                BINDING, bytes(32, 1), Instant.ofEpochSecond(100L)));
        assertThrows(IllegalArgumentException.class, () -> context("line\nbreak", new PkiId("credential"),
                BINDING, bytes(32, 1), Instant.ofEpochSecond(100L)));
        assertThrows(IllegalArgumentException.class, () -> context("\ud800", new PkiId("credential"),
                BINDING, bytes(32, 1), Instant.ofEpochSecond(100L)));
        assertThrows(IllegalArgumentException.class, () -> context("a".repeat(513),
                new PkiId("credential"), BINDING, bytes(32, 1),
                Instant.ofEpochSecond(100L)));
        assertThrows(IllegalArgumentException.class, () -> context("audience",
                new PkiId("a".repeat(257)), BINDING, bytes(32, 1),
                Instant.ofEpochSecond(100L)));
        assertThrows(NullPointerException.class, () -> context("audience", new PkiId("credential"),
                null, bytes(32, 1), Instant.ofEpochSecond(100L)));
        assertThrows(IllegalArgumentException.class, () -> context("audience", new PkiId("credential"),
                BINDING, bytes(31, 1), Instant.ofEpochSecond(100L)));
        assertThrows(IllegalArgumentException.class, () -> context("audience", new PkiId("credential"),
                BINDING, null, Instant.ofEpochSecond(100L)));
        assertThrows(NullPointerException.class, () -> context("audience", new PkiId("credential"),
                BINDING, bytes(32, 1), null));
        assertThrows(IllegalArgumentException.class, () -> context("audience", new PkiId("credential"),
                BINDING, bytes(32, 1), Instant.ofEpochSecond(100L, 1L)));
        assertThrows(IllegalArgumentException.class, () -> context("audience", new PkiId("credential"),
                BINDING, bytes(32, 1), Instant.ofEpochSecond(-1L)));
        assertThrows(IllegalArgumentException.class, () -> context("audience", new PkiId("credential"),
                BINDING, bytes(32, 1), Instant.ofEpochSecond(253_402_300_800L)));
        PublicKey publicKey = new TestPublicKey("RSA", bytes(64, 1));
        assertThrows(NullPointerException.class, () -> new KeyPossessionProofCredential(
                null, new PkiId("credential"), publicKey));
        assertThrows(NullPointerException.class, () -> new KeyPossessionProofCredential(
                BINDING, null, publicKey));
        assertThrows(IllegalArgumentException.class, () -> new KeyPossessionProofCredential(
                BINDING, new PkiId("a".repeat(257)), publicKey));
        assertThrows(NullPointerException.class, () -> new KeyPossessionProofCredential(
                BINDING, new PkiId("credential"), null));
    }

    @Test
    void presentationAndResponseOwnBoundedBytesAndRedactThem() {
        byte[] presentationInput = bytes(2, 3);
        KeyPossessionProofPresentation presentation =
                new KeyPossessionProofPresentation(presentationInput);
        presentationInput[0] = 9;
        assertArrayEquals(bytes(2, 3), presentation.canonicalBytes());
        assertEquals(presentation, new KeyPossessionProofPresentation(bytes(2, 3)));
        assertTrue(presentation.toString().contains("<2 bytes>"));

        byte[] responseInput = bytes(3, 4);
        KeyPossessionProofResponse response = new KeyPossessionProofResponse(responseInput);
        responseInput[0] = 9;
        assertArrayEquals(bytes(3, 4), response.bytes());
        assertEquals(response, new KeyPossessionProofResponse(bytes(3, 4)));
        assertTrue(response.toString().contains("<3 bytes>"));
        assertEquals(KeyPossessionProofPresentation.MAXIMUM_BYTES,
                new KeyPossessionProofPresentation(
                        new byte[KeyPossessionProofPresentation.MAXIMUM_BYTES]).canonicalBytes().length);
        assertEquals(KeyPossessionProofResponse.MAXIMUM_BYTES,
                new KeyPossessionProofResponse(
                        new byte[KeyPossessionProofResponse.MAXIMUM_BYTES]).bytes().length);

        assertThrows(IllegalArgumentException.class,
                () -> new KeyPossessionProofPresentation(null));
        assertThrows(IllegalArgumentException.class,
                () -> new KeyPossessionProofPresentation(new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> new KeyPossessionProofPresentation(
                        new byte[KeyPossessionProofPresentation.MAXIMUM_BYTES + 1]));
        assertThrows(IllegalArgumentException.class, () -> new KeyPossessionProofResponse(null));
        assertThrows(IllegalArgumentException.class, () -> new KeyPossessionProofResponse(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new KeyPossessionProofResponse(
                new byte[KeyPossessionProofResponse.MAXIMUM_BYTES + 1]));
    }

    @Test
    void trustedProviderFakeUsesOnlyImmutableBoundedContracts() {
        KeyPossessionProofProvider provider = new FakeProvider();
        KeyPossessionProofChallengeContext context = context(bytes(32, 5));
        KeyPossessionProofCredential credential = credential(new TestPublicKey("RSA", bytes(64, 6)));

        assertEquals(SUITE_ID, provider.suiteId());
        assertEquals(8_192, provider.descriptor(8_192).proofSuiteBinding().rsaMaximumModulusBits());
        provider.validateCredential(credential);
        assertArrayEquals(new byte[] { 42 }, provider.createChallenge(context).canonicalBytes());
        assertEquals(KeyPossessionProofVerification.VERIFIED,
                provider.verify(context, credential,
                        new KeyPossessionProofResponse(new byte[] { 42 })));
        assertEquals(KeyPossessionProofVerification.REJECTED,
                provider.verify(context, credential,
                        new KeyPossessionProofResponse(new byte[] { 41 })));
    }

    private static KeyPossessionProofChallengeContext context(byte[] nonce) {
        return context("https://pki.example.test/confirmation", new PkiId("credential"),
                BINDING, nonce, Instant.ofEpochSecond(100L));
    }

    private static KeyPossessionProofChallengeContext context(String audience, PkiId credentialId,
            ConfirmationProofSuiteBinding binding, byte[] nonce, Instant expiresAt) {
        return new KeyPossessionProofChallengeContext(new ConfirmationRealmBinding("realm"), audience,
                credentialId, binding, nonce, expiresAt);
    }

    private static KeyPossessionProofCredential credential(PublicKey publicKey) {
        return new KeyPossessionProofCredential(BINDING, new PkiId("credential"), publicKey);
    }

    private static byte[] bytes(int length, int value) {
        byte[] result = new byte[length];
        Arrays.fill(result, (byte) value);
        return result;
    }

    private static final class FakeProvider implements KeyPossessionProofProvider {
        @Override
        public String suiteId() {
            return SUITE_ID;
        }

        @Override
        public KeyPossessionProofDescriptor descriptor(int rsaMaximumModulusBits) {
            return new KeyPossessionProofDescriptor(
                    new ConfirmationProofSuiteBinding(SUITE_REF, rsaMaximumModulusBits), 32, 2_048);
        }

        @Override
        public void validateCredential(KeyPossessionProofCredential credential) {
            Objects.requireNonNull(credential, "credential");
        }

        @Override
        public KeyPossessionProofPresentation createChallenge(KeyPossessionProofChallengeContext context) {
            Objects.requireNonNull(context, "context");
            return new KeyPossessionProofPresentation(new byte[] { 42 });
        }

        @Override
        public KeyPossessionProofVerification verify(KeyPossessionProofChallengeContext context,
                KeyPossessionProofCredential credential, KeyPossessionProofResponse response) {
            Objects.requireNonNull(context, "context");
            Objects.requireNonNull(credential, "credential");
            if (!context.credentialId().equals(credential.credentialId())
                    || !context.proofSuiteBinding().equals(credential.proofSuiteBinding())) {
                throw new IllegalArgumentException("context and credential differ");
            }
            return Arrays.equals(Objects.requireNonNull(response, "response").bytes(), new byte[] { 42 })
                    ? KeyPossessionProofVerification.VERIFIED
                    : KeyPossessionProofVerification.REJECTED;
        }
    }

    private record TestPublicKey(String algorithm, byte[] encoded) implements PublicKey {
        private static final long serialVersionUID = 1L;

        private TestPublicKey {
            encoded = encoded.clone();
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return encoded.clone();
        }
    }
}
