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
package demo;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.sdk.builders.HybridKexBuilder;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainBytesBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.hybrid.derived.HybridDerived;
import zeroecho.sdk.hybrid.kex.HybridKexContext;
import zeroecho.sdk.hybrid.kex.HybridKexExporter;
import zeroecho.sdk.hybrid.kex.HybridKexProfile;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.hybrid.kex.HybridKexTranscript;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Demonstration of hybrid-derived AEAD encryption and decryption.
 *
 * <p>
 * This sample is intentionally structured in two variants:
 * </p>
 * <ul>
 * <li><b>Condensed</b> - compact fluent chains suitable for everyday use.</li>
 * <li><b>Expanded</b> - the same operations, step-by-step, for explanatory
 * documentation.</li>
 * </ul>
 *
 * <p>
 * The hybrid combination (classic + PQC) happens in {@link HybridKexContext}.
 * The derived layer ({@link HybridDerived}) consumes the exporter output (OKM +
 * HKDF salt) and injects key/IV/AAD into existing streaming builders.
 * </p>
 */
class HybridDerivedAesDemoTest {
    private final ZeroEchoSession session = new ZeroEchoSession();

    private static final Logger LOG = Logger.getLogger(HybridDerivedAesDemoTest.class.getName());

    @BeforeAll
    static void setup() {
        // Optional: enable BC if you use BC-only algorithms in the broader test suite.
        try {
            BouncyCastleActivator.init();
        } catch (Throwable ignore) {
            // Keep samples runnable without BC if not present.
        }
    }

    @Test
    void hybridDerived_aes_gcm_condensed() throws Exception {
        System.out.println("hybridDerived_aes_gcm_condensed()");
        LOG.info("Hybrid-derived AES-GCM demo (condensed form)");

        // ...Select a standard hybrid KEX profile (HKDF info/salt + OKM length).
        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        // ...Prepare plaintext.
        byte[] msg = randomBytes(1024);

        // ...Prepare transcript (public context bound into HKDF info and derived
        // labels).
        HybridKexTranscript transcript = new HybridKexTranscript().addUtf8("suite", "X25519+MLKEM768").addUtf8("demo",
                "hybrid-derived-aes-gcm-condensed");

        // ...Generate classic key pairs for X25519 (Xdh + XdhSpec.X25519).
        KeyPair aliceClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);

        // ...Generate PQC key pair for ML-KEM-768 (recipient; used by Bob side to
        // decapsulate).
        KeyPair bobPqc = session.keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        // ...Build Alice initiator: classic agreement (out-of-band peer pub) + PQC
        // encapsulation.
        HybridKexContext alice = HybridKexBuilder.builder(session)
                // ...Set mandatory profile.
                .profile(profile)
                // ...Bind builder HKDF info to transcript.
                .transcript(transcript)
                // ...Select classic mode: peer public key is out-of-band.
                .classicAgreement()
                // ...Select classic algorithm id (Xdh).
                .algorithm("Xdh")
                // ...Select classic spec (X25519).
                .spec(XdhSpec.X25519)
                // ...Set Alice classic private key.
                .privateKey(aliceClassic.getPrivate())
                // ...Set Bob classic public key.
                .peerPublic(bobClassic.getPublic())
                // ...Switch to PQC KEM configuration.
                .pqcKem()
                // ...Select PQC algorithm id (ML-KEM).
                .algorithm("ML-KEM")
                // ...Set recipient PQC public key for encapsulation.
                .peerPublic(bobPqc.getPublic())
                // ...Build initiator context.
                .buildInitiator();

        // ...Build Bob responder: classic agreement + PQC decapsulation.
        HybridKexContext bob = HybridKexBuilder.builder(session)
                // ...Set mandatory profile.
                .profile(profile)
                // ...Bind builder HKDF info to transcript.
                .transcript(transcript)
                // ...Select classic mode: peer public key is out-of-band.
                .classicAgreement()
                // ...Select classic algorithm id (Xdh).
                .algorithm("Xdh")
                // ...Select classic spec (X25519).
                .spec(XdhSpec.X25519)
                // ...Set Bob classic private key.
                .privateKey(bobClassic.getPrivate())
                // ...Set Alice classic public key.
                .peerPublic(aliceClassic.getPublic())
                // ...Switch to PQC KEM configuration.
                .pqcKem()
                // ...Select PQC algorithm id (ML-KEM).
                .algorithm("ML-KEM")
                // ...Set recipient PQC private key for decapsulation.
                .privateKey(bobPqc.getPrivate())
                // ...Build responder context.
                .buildResponder();

        try {
            // ...Alice produces peer message (PQC ciphertext; classic is out-of-band in
            // this mode).
            byte[] peerMsg = alice.getPeerMessage();
            System.out.println("...peerMsg " + lens(peerMsg) + " " + shortHex(peerMsg, 48));

            // ...Bob consumes the peer message to complete the PQC leg.
            bob.setPeerMessage(peerMsg);

            // ...Derive OKM on both sides (must match for a valid hybrid exchange).
            byte[] okmA = alice.deriveSecret();
            byte[] okmB = bob.deriveSecret();
            System.out.println("...okmEqual " + Arrays.equals(okmA, okmB));
            if (!Arrays.equals(okmA, okmB)) {
                throw new IllegalStateException("Hybrid KEX mismatch");
            }

            // ...Create exporter directly from OKM and profile salt (avoid exporterFromOkm
            // validation requirements).
            HybridKexExporter exporter = new HybridKexExporter(okmA, profile.hkdfSalt());

            // ...Choose explicit AAD (public) for AEAD; must match on decrypt.
            byte[] aad = "aad:demo".getBytes(StandardCharsets.UTF_8);

            // ...Encrypt: build pipeline in compact form with inline derived injection.
            DataContent enc = DataContentChainBuilder.encrypt()
                    // ...Input: plaintext bytes.
                    .add(PlainBytesBuilder.builder().bytes(msg))
                    // ...AEAD: derive key/IV/AAD and inject into AES-GCM builder.
                    .add(HybridDerived.from(exporter)
                            // ...Purpose separation label for AEAD encryption.
                            .label("app/enc/aes-gcm")
                            // ...Bind derivation to transcript bytes (public).
                            .transcript(transcript.toByteArray())
                            // ...Inject explicit AAD.
                            .aad(aad)
                            // ...Apply derived key(256b) and IV(12B) to AES-GCM with header.
                            .applyToAesGcm(AesDataContentBuilder.builder(session)
                                    // ...Store IV in header for decrypt side.
                                    .withHeader()
                                    // ...Use AES-GCM with 128-bit authentication tag.
                                    .modeGcm(128), 256, 12))
                    // ...Finalize pipeline.
                    .build();

            byte[] ciphertext;
            try (InputStream in = enc.getStream()) {
                ciphertext = readAll(in);
            }
            System.out.println("...ciphertext " + lens(ciphertext) + " " + shortHex(ciphertext, 48));

            // ...Decrypt: rebuild the same derived inputs and run decrypt pipeline.
            DataContent dec = DataContentChainBuilder.decrypt()
                    // ...Input: ciphertext bytes.
                    .add(PlainBytesBuilder.builder().bytes(ciphertext))
                    // ...AEAD: apply the same label/transcript/AAD to get identical key/IV.
                    .add(HybridDerived.from(exporter)
                            // ...Same purpose label as encryption.
                            .label("app/enc/aes-gcm")
                            // ...Same transcript binding as encryption.
                            .transcript(transcript.toByteArray())
                            // ...Same explicit AAD as encryption.
                            .aad(aad)
                            // ...Apply derived key and IV to AES-GCM with header.
                            .applyToAesGcm(AesDataContentBuilder.builder(session)
                                    // ...Parse IV from header.
                                    .withHeader()
                                    // ...Use AES-GCM with 128-bit authentication tag.
                                    .modeGcm(128), 256, 12))
                    // ...Finalize pipeline.
                    .build();

            byte[] out;
            try (InputStream in = dec.getStream()) {
                out = readAll(in);
            }
            System.out.println("...plaintextEqual " + Arrays.equals(msg, out));
            if (!Arrays.equals(msg, out)) {
                throw new IllegalStateException("Roundtrip mismatch");
            }

            System.out.println("hybridDerived_aes_gcm_condensed...ok");
        } finally {
            closeQuiet(alice);
            closeQuiet(bob);
        }
    }

    @Test
    void hybridDerived_aes_gcm_expanded() throws Exception {
        System.out.println("hybridDerived_aes_gcm_expanded()");
        LOG.info("Hybrid-derived AES-GCM demo (expanded form)");

        // ...Select a standard hybrid KEX profile (HKDF info/salt + OKM length).
        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        // ...Prepare plaintext.
        byte[] msg = randomBytes(1024);

        // ...Prepare transcript (public context bound into HKDF info and derived
        // labels).
        HybridKexTranscript transcript = new HybridKexTranscript().addUtf8("suite", "X25519+MLKEM768").addUtf8("demo",
                "hybrid-derived-aes-gcm-expanded");

        // ...Generate classic key pairs for X25519.
        KeyPair aliceClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);

        // ...Generate PQC key pair for ML-KEM-768.
        KeyPair bobPqc = session.keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        // ...Build Alice initiator in a step-by-step manner.
        HybridKexBuilder aliceBuilder = HybridKexBuilder.builder(session);
        // ...Set mandatory profile.
        aliceBuilder.profile(profile);
        // ...Bind builder HKDF info to transcript.
        aliceBuilder.transcript(transcript);

        // ...Select classic mode: peer public key is out-of-band.
        HybridKexBuilder.ClassicAgreement aliceClassicCfg = aliceBuilder.classicAgreement();
        // ...Select classic algorithm id (Xdh).
        aliceClassicCfg.algorithm("Xdh");
        // ...Select classic spec (X25519).
        aliceClassicCfg.spec(XdhSpec.X25519);
        // ...Set Alice classic private key.
        aliceClassicCfg.privateKey(aliceClassic.getPrivate());
        // ...Set Bob classic public key.
        aliceClassicCfg.peerPublic(bobClassic.getPublic());

        // ...Switch to PQC KEM configuration.
        HybridKexBuilder.PqcKem alicePqcCfg = aliceClassicCfg.pqcKem();
        // ...Select PQC algorithm id (ML-KEM).
        alicePqcCfg.algorithm("ML-KEM");
        // ...Set recipient PQC public key for encapsulation.
        alicePqcCfg.peerPublic(bobPqc.getPublic());

        // ...Build initiator context.
        HybridKexContext alice = alicePqcCfg.buildInitiator();

        // ...Build Bob responder in a step-by-step manner.
        HybridKexBuilder bobBuilder = HybridKexBuilder.builder(session);
        // ...Set mandatory profile.
        bobBuilder.profile(profile);
        // ...Bind builder HKDF info to transcript.
        bobBuilder.transcript(transcript);

        // ...Select classic mode: peer public key is out-of-band.
        HybridKexBuilder.ClassicAgreement bobClassicCfg = bobBuilder.classicAgreement();
        // ...Select classic algorithm id (Xdh).
        bobClassicCfg.algorithm("Xdh");
        // ...Select classic spec (X25519).
        bobClassicCfg.spec(XdhSpec.X25519);
        // ...Set Bob classic private key.
        bobClassicCfg.privateKey(bobClassic.getPrivate());
        // ...Set Alice classic public key.
        bobClassicCfg.peerPublic(aliceClassic.getPublic());

        // ...Switch to PQC KEM configuration.
        HybridKexBuilder.PqcKem bobPqcCfg = bobClassicCfg.pqcKem();
        // ...Select PQC algorithm id (ML-KEM).
        bobPqcCfg.algorithm("ML-KEM");
        // ...Set recipient PQC private key for decapsulation.
        bobPqcCfg.privateKey(bobPqc.getPrivate());

        // ...Build responder context.
        HybridKexContext bob = bobPqcCfg.buildResponder();

        try {
            // ...Alice produces peer message (PQC ciphertext in this classic mode).
            byte[] peerMsg = alice.getPeerMessage();
            System.out.println("...peerMsg " + lens(peerMsg) + " " + shortHex(peerMsg, 48));

            // ...Bob consumes peer message to complete the PQC leg.
            bob.setPeerMessage(peerMsg);

            // ...Derive OKM and ensure both sides match.
            byte[] okmA = alice.deriveSecret();
            byte[] okmB = bob.deriveSecret();
            System.out.println("...okmEqual " + Arrays.equals(okmA, okmB));
            if (!Arrays.equals(okmA, okmB)) {
                throw new IllegalStateException("Hybrid KEX mismatch");
            }

            // ...Create exporter directly from OKM and profile salt.
            HybridKexExporter exporter = new HybridKexExporter(okmA, profile.hkdfSalt());

            // ...Choose explicit AAD (public) for AEAD.
            byte[] aad = "aad:demo:expanded".getBytes(StandardCharsets.UTF_8);

            // ...Prepare AES builder for encryption.
            AesDataContentBuilder aesEnc = AesDataContentBuilder.builder(session);
            // ...Store IV in header.
            aesEnc.withHeader();
            // ...Use AES-GCM with 128-bit authentication tag.
            aesEnc.modeGcm(128);

            // ...Inject derived key/IV/AAD into AES builder.
            HybridDerived.from(exporter)
                    // ...Purpose separation label for AEAD.
                    .label("app/enc/aes-gcm")
                    // ...Bind derivation to transcript bytes.
                    .transcript(transcript.toByteArray())
                    // ...Inject explicit AAD.
                    .aad(aad)
                    // ...Apply derived key(256b) and IV(12B).
                    .applyToAesGcm(aesEnc, 256, 12);

            // ...Build encryption pipeline.
            DataContent enc = DataContentChainBuilder.encrypt()
                    // ...Input: plaintext bytes.
                    .add(PlainBytesBuilder.builder().bytes(msg))
                    // ...AES encryption stage.
                    .add(aesEnc)
                    // ...Finalize.
                    .build();

            byte[] ciphertext;
            try (InputStream in = enc.getStream()) {
                ciphertext = readAll(in);
            }
            System.out.println("...ciphertext " + lens(ciphertext) + " " + shortHex(ciphertext, 48));

            // ...Prepare AES builder for decryption.
            AesDataContentBuilder aesDec = AesDataContentBuilder.builder(session);
            // ...Parse IV from header.
            aesDec.withHeader();
            // ...Use AES-GCM with 128-bit authentication tag.
            aesDec.modeGcm(128);

            // ...Inject the same derived key/IV/AAD into decryption builder.
            HybridDerived.from(exporter)
                    // ...Same purpose label.
                    .label("app/enc/aes-gcm")
                    // ...Same transcript binding.
                    .transcript(transcript.toByteArray())
                    // ...Same explicit AAD.
                    .aad(aad)
                    // ...Apply the same derived key and IV.
                    .applyToAesGcm(aesDec, 256, 12);

            // ...Build decryption pipeline.
            DataContent dec = DataContentChainBuilder.decrypt()
                    // ...Input: ciphertext bytes.
                    .add(PlainBytesBuilder.builder().bytes(ciphertext))
                    // ...AES decryption stage.
                    .add(aesDec)
                    // ...Finalize.
                    .build();

            byte[] out;
            try (InputStream in = dec.getStream()) {
                out = readAll(in);
            }
            System.out.println("...plaintextEqual " + Arrays.equals(msg, out));
            if (!Arrays.equals(msg, out)) {
                throw new IllegalStateException("Roundtrip mismatch");
            }

            System.out.println("hybridDerived_aes_gcm_expanded...ok");
        } finally {
            closeQuiet(alice);
            closeQuiet(bob);
        }
    }

    @Test
    void hybridDerived_aes_gcm_local_self_recipient() throws Exception {
        System.out.println("hybridDerived_aes_gcm_local_self_recipient()");
        LOG.info("Hybrid-derived AES-GCM demo (local self-recipient)");

        // ...Select a standard hybrid KEX profile (HKDF info/salt + OKM length).
        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        // ...Prepare plaintext.
        byte[] msg = randomBytes(1024);

        // ...Prepare transcript (public context bound into KDF and derived labels).
        HybridKexTranscript transcript = new HybridKexTranscript()
                // ...Identify the suite used by this envelope.
                .addUtf8("suite", "X25519+MLKEM768")
                // ...Identify that this is a local/self-recipient envelope.
                .addUtf8("mode", "local-self");

        // ...Choose explicit AAD (public) for AEAD; must match on decrypt.
        byte[] aad = "aad:local-self".getBytes(StandardCharsets.UTF_8);

        // ...Generate classic identity keys (X25519).
        KeyPair selfClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);

        // ...Generate PQC identity keys (ML-KEM-768).
        KeyPair selfPqc = session.keyBuilders().asymmetric()
                .generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        // ...Build local initiator (encapsulation) against our own public keys.
        HybridKexContext encKex = HybridKexBuilder.builder(session)
                // ...Set mandatory profile.
                .profile(profile)
                // ...Bind derivation to transcript.
                .transcript(transcript)
                // ...Select classic mode: peer public key is known out-of-band (here: our own
                // public key).
                .classicAgreement()
                // ...Classic algorithm id (X25519).
                .algorithm("Xdh")
                // ...Classic spec (X25519).
                .spec(XdhSpec.X25519)
                // ...Use our private key.
                .privateKey(selfClassic.getPrivate())
                // ...Use our public key as the peer public key (self-recipient).
                .peerPublic(selfClassic.getPublic())
                // ...Switch to PQC KEM.
                .pqcKem()
                // ...PQC algorithm id (ML-KEM).
                .algorithm("ML-KEM")
                // ...Use our PQC public key as the recipient key for encapsulation.
                .peerPublic(selfPqc.getPublic())
                // ...Build initiator.
                .buildInitiator();

        // ...Produce the envelope header (peer message); must be stored next to
        // ciphertext.
        byte[] peerMsg = encKex.getPeerMessage();
        System.out.println("...peerMsg " + lens(peerMsg) + " " + shortHex(peerMsg, 48));

        // ...Derive OKM for this local envelope.
        byte[] okm = encKex.deriveSecret();
        System.out.println("...okm " + shortHex(okm, 48));

        // ...Create exporter directly from OKM and profile salt.
        HybridKexExporter exporter = new HybridKexExporter(okm, profile.hkdfSalt());

        // ...Encrypt: build pipeline; derived key/IV/AAD are injected into AES-GCM.
        DataContent enc = DataContentChainBuilder.encrypt()
                // ...Input: plaintext bytes.
                .add(PlainBytesBuilder.builder().bytes(msg))
                // ...AEAD: inject derived material into AES-GCM builder.
                .add(HybridDerived.from(exporter)
                        // ...Purpose separation label for AEAD encryption.
                        .label("app/local/aes-gcm")
                        // ...Bind derivation to transcript bytes.
                        .transcript(transcript.toByteArray())
                        // ...Inject explicit AAD.
                        .aad(aad)
                        // ...Apply derived key(256b) and IV(12B) to AES-GCM with header.
                        .applyToAesGcm(AesDataContentBuilder.builder(session)
                                // ...Store IV in header for decrypt side.
                                .withHeader()
                                // ...Use AES-GCM with 128-bit authentication tag.
                                .modeGcm(128), 256, 12))
                // ...Finalize pipeline.
                .build();

        byte[] ciphertext;
        try (InputStream in = enc.getStream()) {
            ciphertext = readAll(in);
        }
        System.out.println("...ciphertext " + lens(ciphertext) + " " + shortHex(ciphertext, 48));

        // ...Build local responder (decapsulation) using our own private keys and
        // stored peer message.
        HybridKexContext decKex = HybridKexBuilder.builder(session)
                // ...Set mandatory profile.
                .profile(profile)
                // ...Bind derivation to transcript.
                .transcript(transcript)
                // ...Select classic mode: peer public key is known out-of-band (here: our own
                // public key).
                .classicAgreement()
                // ...Classic algorithm id (X25519).
                .algorithm("Xdh")
                // ...Classic spec (X25519).
                .spec(XdhSpec.X25519)
                // ...Use our private key.
                .privateKey(selfClassic.getPrivate())
                // ...Use our public key as the peer public key (self-recipient).
                .peerPublic(selfClassic.getPublic())
                // ...Switch to PQC KEM.
                .pqcKem()
                // ...PQC algorithm id (ML-KEM).
                .algorithm("ML-KEM")
                // ...Use our PQC private key for decapsulation.
                .privateKey(selfPqc.getPrivate())
                // ...Build responder.
                .buildResponder();

        try {
            // ...Provide the stored peer message (envelope header) to complete
            // decapsulation.
            decKex.setPeerMessage(peerMsg);

            // ...Derive the same OKM and create the exporter.
            byte[] okmDec = decKex.deriveSecret();
            System.out.println("...okmEqual " + Arrays.equals(okm, okmDec));
            if (!Arrays.equals(okm, okmDec)) {
                throw new IllegalStateException("Local hybrid envelope mismatch");
            }

            HybridKexExporter exporterDec = new HybridKexExporter(okmDec, profile.hkdfSalt());

            // ...Decrypt: rebuild the same derived inputs and run decrypt pipeline.
            DataContent dec = DataContentChainBuilder.decrypt()
                    // ...Input: ciphertext bytes.
                    .add(PlainBytesBuilder.builder().bytes(ciphertext))
                    // ...AEAD: apply the same label/transcript/AAD to get identical key/IV.
                    .add(HybridDerived.from(exporterDec)
                            // ...Same purpose label as encryption.
                            .label("app/local/aes-gcm")
                            // ...Same transcript binding.
                            .transcript(transcript.toByteArray())
                            // ...Same explicit AAD.
                            .aad(aad)
                            // ...Apply derived key and IV to AES-GCM with header.
                            .applyToAesGcm(AesDataContentBuilder.builder(session)
                                    // ...Parse IV from header.
                                    .withHeader()
                                    // ...Use AES-GCM with 128-bit authentication tag.
                                    .modeGcm(128), 256, 12))
                    // ...Finalize pipeline.
                    .build();

            byte[] out;
            try (InputStream in = dec.getStream()) {
                out = readAll(in);
            }

            System.out.println("...plaintextEqual " + Arrays.equals(msg, out));
            if (!Arrays.equals(msg, out)) {
                throw new IllegalStateException("Roundtrip mismatch");
            }

            System.out.println("hybridDerived_aes_gcm_local_self_recipient...ok");
        } finally {
            closeQuiet(encKex);
            closeQuiet(decKex);
        }
    }

    // helpers

    private static byte[] randomBytes(int len) {
        byte[] data = new byte[len];
        new SecureRandom().nextBytes(data);
        return data;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            in.transferTo(out);
            out.flush();
            return out.toByteArray();
        }
    }

    private static String lens(byte[] b) {
        if (b == null) {
            return "len=null";
        }
        return "len=" + b.length;
    }

    private static String shortHex(byte[] data, int maxBytes) {
        if (data == null) {
            return "null";
        }
        int n = Math.min(data.length, Math.max(0, maxBytes));
        StringBuilder sb = new StringBuilder(n * 2 + 3);
        for (int i = 0; i < n; i++) {
            int v = data[i] & 0xFF;
            sb.append(Character.forDigit((v >>> 4) & 0x0F, 16));
            sb.append(Character.forDigit(v & 0x0F, 16));
        }
        if (data.length > n) {
            sb.append("...");
        }
        return sb.toString();
    }

    private static void closeQuiet(HybridKexContext ctx) {
        if (ctx == null) {
            return;
        }
        try {
            ctx.close();
        } catch (Exception ignore) {
            // ignore
        }
    }
}
