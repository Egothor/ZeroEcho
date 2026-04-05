/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.sdk.builders;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.security.KeyPair;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.sdk.hybrid.kex.HybridKexContext;
import zeroecho.sdk.hybrid.kex.HybridKexPolicy;
import zeroecho.sdk.hybrid.kex.HybridKexProfile;
import zeroecho.sdk.hybrid.kex.HybridKexTranscript;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Professional unit and regression tests for {@link HybridKexBuilder}.
 *
 * <p>
 * These tests verify both supported classic-leg construction modes,
 * builder-side validation failures, policy enforcement, transcript binding, and
 * mode-switch behavior. The builder is exercised strictly through its public
 * fluent API so that validation and resulting hybrid context construction are
 * covered together.
 * </p>
 */
class HybridKexBuilderTest {

    @BeforeAll
    static void setup() {
        try {
            BouncyCastleActivator.init();
        } catch (Throwable ignore) {
            // Keep tests runnable even when BC is not present.
        }
    }

    @Test
    void buildInitiatorResponderClassicAgreementRoundTrip() throws Exception {
        System.out.println("buildInitiatorResponderClassicAgreementRoundTrip");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);
        HybridKexTranscript transcript = new HybridKexTranscript().addUtf8("suite", "X25519+ML-KEM-768").addUtf8("role",
                "builder-test");

        KeyPair aliceClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobPqc = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        HybridKexContext alice = null;
        HybridKexContext bob = null;

        try {
            alice = HybridKexBuilder.builder().profile(profile).transcript(transcript).classicAgreement()
                    .algorithm("Xdh").spec(XdhSpec.X25519).privateKey(aliceClassic.getPrivate())
                    .peerPublic(bobClassic.getPublic()).pqcKem().algorithm("ML-KEM").peerPublic(bobPqc.getPublic())
                    .buildInitiator();

            bob = HybridKexBuilder.builder().profile(profile).transcript(transcript).classicAgreement().algorithm("Xdh")
                    .spec(XdhSpec.X25519).privateKey(bobClassic.getPrivate()).peerPublic(aliceClassic.getPublic())
                    .pqcKem().algorithm("ML-KEM").privateKey(bobPqc.getPrivate()).buildResponder();

            byte[] aliceMessage = alice.getPeerMessage();
            System.out.println("...aliceMessage(" + lens(aliceMessage) + ")=" + hex(aliceMessage));

            bob.setPeerMessage(aliceMessage);

            byte[] secretAlice = alice.deriveSecret();
            byte[] secretBob = bob.deriveSecret();

            System.out.println("...secretAlice=" + hex(secretAlice));
            System.out.println("...secretBob=" + hex(secretBob));

            assertNotNull(secretAlice);
            assertNotNull(secretBob);
            assertArrayEquals(secretAlice, secretBob);
            assertEquals(profile.outLenBytes(), secretAlice.length);
        } finally {
            closeQuietly(alice);
            closeQuietly(bob);
        }

        System.out.println("buildInitiatorResponderClassicAgreementRoundTrip...ok");
    }

    @Test
    void buildInitiatorResponderPairMessageRoundTrip() throws Exception {
        System.out.println("buildInitiatorResponderPairMessageRoundTrip");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        KeyPair aliceClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobPqc = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        HybridKexContext alice = null;
        HybridKexContext bob = null;

        try {
            alice = HybridKexBuilder.builder().profile(profile).classicPairMessage().algorithm("Xdh")
                    .spec(XdhSpec.X25519).keyPair(new KeyPairKey(aliceClassic)).pqcKem().algorithm("ML-KEM")
                    .peerPublic(bobPqc.getPublic()).buildInitiator();

            bob = HybridKexBuilder.builder().profile(profile).classicPairMessage().algorithm("Xdh").spec(XdhSpec.X25519)
                    .keyPair(new KeyPairKey(bobClassic)).pqcKem().algorithm("ML-KEM").privateKey(bobPqc.getPrivate())
                    .buildResponder();

            byte[] messageA = alice.getPeerMessage();
            System.out.println("...messageA(" + lens(messageA) + ")=" + hex(messageA));
            bob.setPeerMessage(messageA);

            byte[] messageB = bob.getPeerMessage();
            System.out.println("...messageB(" + lens(messageB) + ")=" + hex(messageB));
            alice.setPeerMessage(messageB);

            byte[] secretAlice = alice.deriveSecret();
            byte[] secretBob = bob.deriveSecret();

            System.out.println("...secretAlice=" + hex(secretAlice));
            System.out.println("...secretBob=" + hex(secretBob));

            assertNotNull(secretAlice);
            assertNotNull(secretBob);
            assertArrayEquals(secretAlice, secretBob);
            assertEquals(profile.outLenBytes(), secretAlice.length);
        } finally {
            closeQuietly(alice);
            closeQuietly(bob);
        }

        System.out.println("buildInitiatorResponderPairMessageRoundTrip...ok");
    }

    @Test
    void buildInitiatorWithoutProfileFails() throws Exception {
        System.out.println("buildInitiatorWithoutProfileFails");

        KeyPair aliceClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobPqc = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            HybridKexBuilder.builder().classicAgreement().algorithm("Xdh").spec(XdhSpec.X25519)
                    .privateKey(aliceClassic.getPrivate()).peerPublic(bobClassic.getPublic()).pqcKem()
                    .algorithm("ML-KEM").peerPublic(bobPqc.getPublic()).buildInitiator();
        });

        System.out.println("...exception=" + exception.getMessage());
        assertEquals("profile must be set", exception.getMessage());

        System.out.println("buildInitiatorWithoutProfileFails...ok");
    }

    @Test
    void buildInitiatorWithoutClassicModeFails() throws Exception {
        System.out.println("buildInitiatorWithoutClassicModeFails");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);
        KeyPair bobPqc = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            HybridKexBuilder.builder().profile(profile).pqcKem().algorithm("ML-KEM").peerPublic(bobPqc.getPublic())
                    .buildInitiator();
        });

        System.out.println("...exception=" + exception.getMessage());
        assertEquals("classic mode must be selected", exception.getMessage());

        System.out.println("buildInitiatorWithoutClassicModeFails...ok");
    }

    @Test
    void buildInitiatorClassicAgreementWithoutPeerPublicFails() throws Exception {
        System.out.println("buildInitiatorClassicAgreementWithoutPeerPublicFails");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);
        KeyPair aliceClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobPqc = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            HybridKexBuilder.builder().profile(profile).classicAgreement().algorithm("Xdh").spec(XdhSpec.X25519)
                    .privateKey(aliceClassic.getPrivate()).pqcKem().algorithm("ML-KEM").peerPublic(bobPqc.getPublic())
                    .buildInitiator();
        });

        System.out.println("...exception=" + exception.getMessage());
        assertEquals("classic private key and peer public must be set for CLASSIC_AGREEMENT", exception.getMessage());

        System.out.println("buildInitiatorClassicAgreementWithoutPeerPublicFails...ok");
    }

    @Test
    void buildResponderPairMessageWithoutKeyPairFails() throws Exception {
        System.out.println("buildResponderPairMessageWithoutKeyPairFails");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);
        KeyPair bobPqc = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            HybridKexBuilder.builder().profile(profile).classicPairMessage().algorithm("Xdh").spec(XdhSpec.X25519)
                    .pqcKem().algorithm("ML-KEM").privateKey(bobPqc.getPrivate()).buildResponder();
        });

        System.out.println("...exception=" + exception.getMessage());
        assertEquals("classic key pair must be set for PAIR_MESSAGE", exception.getMessage());

        System.out.println("buildResponderPairMessageWithoutKeyPairFails...ok");
    }

    @Test
    void buildInitiatorWithoutPqcPeerPublicFails() throws Exception {
        System.out.println("buildInitiatorWithoutPqcPeerPublicFails");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);
        KeyPair aliceClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            HybridKexBuilder.builder().profile(profile).classicAgreement().algorithm("Xdh").spec(XdhSpec.X25519)
                    .privateKey(aliceClassic.getPrivate()).peerPublic(bobClassic.getPublic()).pqcKem()
                    .algorithm("ML-KEM").buildInitiator();
        });

        System.out.println("...exception=" + exception.getMessage());
        assertEquals("pqc peer public must be set for initiator", exception.getMessage());

        System.out.println("buildInitiatorWithoutPqcPeerPublicFails...ok");
    }

    @Test
    void buildResponderWithoutPqcPrivateFails() throws Exception {
        System.out.println("buildResponderWithoutPqcPrivateFails");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);
        KeyPair bobClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair aliceClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            HybridKexBuilder.builder().profile(profile).classicAgreement().algorithm("Xdh").spec(XdhSpec.X25519)
                    .privateKey(bobClassic.getPrivate()).peerPublic(aliceClassic.getPublic()).pqcKem()
                    .algorithm("ML-KEM").buildResponder();
        });

        System.out.println("...exception=" + exception.getMessage());
        assertEquals("pqc private key must be set for responder", exception.getMessage());

        System.out.println("buildResponderWithoutPqcPrivateFails...ok");
    }

    @Test
    void buildInitiatorRejectsPolicyWhenOkmTooShort() throws Exception {
        System.out.println("buildInitiatorRejectsPolicyWhenOkmTooShort");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(16);
        HybridKexPolicy policy = new HybridKexPolicy(0, 0, 32);

        KeyPair aliceClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobPqc = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            HybridKexBuilder.builder().profile(profile).policy(policy).classicAgreement().algorithm("Xdh")
                    .spec(XdhSpec.X25519).privateKey(aliceClassic.getPrivate()).peerPublic(bobClassic.getPublic())
                    .pqcKem().algorithm("ML-KEM").peerPublic(bobPqc.getPublic()).buildInitiator();
        });

        System.out.println("...exception=" + exception.getMessage());
        assertEquals("Hybrid OKM length too small: 16 < 32", exception.getMessage());

        System.out.println("buildInitiatorRejectsPolicyWhenOkmTooShort...ok");
    }

    @Test
    void switchingClassicModeClearsConflictingStateAndBuildsPairMessage() throws Exception {
        System.out.println("switchingClassicModeClearsConflictingStateAndBuildsPairMessage");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);
        KeyPair agreementKeyPair = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair pairMessageKeyPair = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobPqc = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        HybridKexContext context = null;
        try {
            HybridKexBuilder builder = HybridKexBuilder.builder().profile(profile);

            builder.classicAgreement().algorithm("Xdh").spec(XdhSpec.X25519).privateKey(agreementKeyPair.getPrivate())
                    .peerPublic(agreementKeyPair.getPublic());

            context = builder.classicPairMessage().algorithm("Xdh").spec(XdhSpec.X25519)
                    .keyPair(new KeyPairKey(pairMessageKeyPair)).pqcKem().algorithm("ML-KEM")
                    .peerPublic(bobPqc.getPublic()).buildInitiator();

            byte[] peerMessage = context.getPeerMessage();
            System.out.println("...peerMessage(" + lens(peerMessage) + ")=" + hex(peerMessage));

            assertNotNull(context);
            assertNotNull(peerMessage);
        } finally {
            closeQuietly(context);
        }

        System.out.println("switchingClassicModeClearsConflictingStateAndBuildsPairMessage...ok");
    }

    @Test
    void transcriptChangesDerivedSecret() throws Exception {
        System.out.println("transcriptChangesDerivedSecret");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        KeyPair aliceClassicA = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassicA = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobPqcA = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        KeyPair aliceClassicB = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassicB = CryptoAlgorithms.generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobPqcB = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        HybridKexTranscript transcriptA = new HybridKexTranscript().addUtf8("context", "A");
        HybridKexTranscript transcriptB = new HybridKexTranscript().addUtf8("context", "B");

        byte[] secretA;
        byte[] secretB;

        HybridKexContext aliceA = null;
        HybridKexContext bobA = null;
        HybridKexContext aliceB = null;
        HybridKexContext bobB = null;

        try {
            aliceA = HybridKexBuilder.builder().profile(profile).transcript(transcriptA).classicAgreement()
                    .algorithm("Xdh").spec(XdhSpec.X25519).privateKey(aliceClassicA.getPrivate())
                    .peerPublic(bobClassicA.getPublic()).pqcKem().algorithm("ML-KEM").peerPublic(bobPqcA.getPublic())
                    .buildInitiator();

            bobA = HybridKexBuilder.builder().profile(profile).transcript(transcriptA).classicAgreement()
                    .algorithm("Xdh").spec(XdhSpec.X25519).privateKey(bobClassicA.getPrivate())
                    .peerPublic(aliceClassicA.getPublic()).pqcKem().algorithm("ML-KEM").privateKey(bobPqcA.getPrivate())
                    .buildResponder();

            bobA.setPeerMessage(aliceA.getPeerMessage());
            secretA = aliceA.deriveSecret();
            byte[] responderA = bobA.deriveSecret();
            System.out.println("...secretA=" + hex(secretA));
            System.out.println("...responderA=" + hex(responderA));
            assertArrayEquals(secretA, responderA);

            aliceB = HybridKexBuilder.builder().profile(profile).transcript(transcriptB).classicAgreement()
                    .algorithm("Xdh").spec(XdhSpec.X25519).privateKey(aliceClassicB.getPrivate())
                    .peerPublic(bobClassicB.getPublic()).pqcKem().algorithm("ML-KEM").peerPublic(bobPqcB.getPublic())
                    .buildInitiator();

            bobB = HybridKexBuilder.builder().profile(profile).transcript(transcriptB).classicAgreement()
                    .algorithm("Xdh").spec(XdhSpec.X25519).privateKey(bobClassicB.getPrivate())
                    .peerPublic(aliceClassicB.getPublic()).pqcKem().algorithm("ML-KEM").privateKey(bobPqcB.getPrivate())
                    .buildResponder();

            bobB.setPeerMessage(aliceB.getPeerMessage());
            secretB = aliceB.deriveSecret();
            byte[] responderB = bobB.deriveSecret();
            System.out.println("...secretB=" + hex(secretB));
            System.out.println("...responderB=" + hex(responderB));
            assertArrayEquals(secretB, responderB);

            if (Arrays.equals(secretA, secretB)) {
                throw new AssertionError("Transcript-bound secrets should differ for different transcripts");
            }
        } finally {
            closeQuietly(aliceA);
            closeQuietly(bobA);
            closeQuietly(aliceB);
            closeQuietly(bobB);
        }

        System.out.println("transcriptChangesDerivedSecret...ok");
    }

    private static void closeQuietly(HybridKexContext context) {
        if (context == null) {
            return;
        }
        try {
            context.close();
        } catch (Exception ignore) {
            // Cleanup only.
        }
    }

    private static String hex(byte[] value) {
        if (value == null) {
            return "null";
        }
        StringBuilder builder = new StringBuilder(value.length * 2);
        for (int index = 0; index < value.length; index++) {
            if (builder.length() >= 30) {
                builder.append("...");
                break;
            }
            int current = value[index] & 0xFF;
            if (current < 16) {
                builder.append('0');
            }
            builder.append(Integer.toHexString(current));
        }
        return builder.toString();
    }

    private static String lens(byte[] message) {
        if (message == null || message.length < 8) {
            return "classicLen=?, pqcLen=?";
        }
        try {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(message));
            int classicLength = input.readInt();
            int pqcLength = 0;
            if (message.length >= 8 + Math.max(0, classicLength)) {
                if (classicLength > 0) {
                    input.skipBytes(classicLength);
                }
                pqcLength = input.readInt();
            }
            return "classicLen=" + classicLength + ", pqcLen=" + pqcLength;
        } catch (Exception exception) {
            return "classicLen=?, pqcLen=?";
        }
    }
}