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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.hybrid.kex.HybridKexContext;
import zeroecho.sdk.hybrid.kex.HybridKexContexts;
import zeroecho.sdk.hybrid.kex.HybridKexProfile;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Demonstration of hybrid key exchange (KEX) usage in ZeroEcho.
 *
 * <p>
 * Hybrid KEX in this project means:
 * </p>
 * <ul>
 * <li>A <b>classic agreement</b> leg (DH/ECDH/XDH), and</li>
 * <li>A <b>post-quantum</b> leg implemented as a message-based agreement (KEM
 * adapter, e.g. ML-KEM).</li>
 * </ul>
 *
 * <p>
 * The two independent secrets are combined using HKDF-SHA256 in the SDK hybrid
 * layer. The application consumes only the final derived keying material (OKM),
 * not the raw leg secrets.
 * </p>
 *
 * <h2>Available hybrid variants</h2>
 * <p>
 * The classic leg can be wired in two ways:
 * </p>
 * <ul>
 * <li><b>CLASSIC_AGREEMENT + KEM_ADAPTER</b> (most common in practice):
 * <ul>
 * <li>Classic peer public key is supplied out-of-band
 * (certificate/directory/session state).</li>
 * <li>The hybrid message carries only the PQC payload (KEM ciphertext).</li>
 * </ul>
 * </li>
 * <li><b>PAIR_MESSAGE + KEM_ADAPTER</b> (fully message-oriented hybrid):
 * <ul>
 * <li>Classic public keys are carried explicitly as messages (SPKI
 * encodings).</li>
 * <li>The hybrid message carries both: classic public-key message and PQC
 * ciphertext.</li>
 * <li>Responder may reply with a classic message only (PQC part empty),
 * depending on PQC role.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Note on resource management</h2>
 * <p>
 * These examples intentionally avoid {@code try-with-resources}. Agreement
 * contexts represent protocol-level state rather than traditional I/O
 * resources; in real protocols their lifecycle often spans multiple
 * send/receive steps and does not naturally fit a single lexical scope. Using
 * explicit close blocks keeps the handshake lifecycle visible to the reader.
 * </p>
 */
@Tag("sample")
class HybridKexDemoTest {
    private final ZeroEchoSession session = new ZeroEchoSession();

    private static final Logger LOG = Logger.getLogger(HybridKexDemoTest.class.getName());

    @BeforeAll
    static void setup() {
        // Optional: enable BC/BCPQC if present.
        try {
            BouncyCastleActivator.init();
        } catch (Throwable ignore) {
            // keep runnable without BC if not present
        }
    }

    @Test
    void x25519_classicAgreement_plus_mlKem768_kemAdapter() throws Exception {
        logBegin("CLASSIC_AGREEMENT + KEM_ADAPTER", "Xdh/X25519 + ML-KEM-768", "HKDF-SHA256", "OKM=32B");

        // Classic leg keys (Xdh + XdhSpec.X25519).
        KeyPair aliceClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);

        // PQC leg: Bob is the KEM recipient (has ML-KEM keypair).
        KeyPair bobPqc = session.keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        // Hybrid profile: default HKDF label, 32-byte output suitable for symmetric
        // keys.
        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        HybridKexContext alice = null;
        HybridKexContext bob = null;

        try {
            // Alice (initiator): classic uses Alice private + Bob classic public
            // (out-of-band).
            // ...PQC uses Bob PQC public and will produce a KEM ciphertext.
            alice = HybridKexContexts.initiator(session, profile, "Xdh", aliceClassic.getPrivate(),
                    bobClassic.getPublic(), XdhSpec.X25519, "ML-KEM", bobPqc.getPublic(), null);

            // Bob (responder): classic uses Bob private + Alice classic public
            // (out-of-band).
            // ...PQC uses Bob PQC private and will consume Alice's ciphertext.
            bob = HybridKexContexts.responder(session, profile, "Xdh", bobClassic.getPrivate(),
                    aliceClassic.getPublic(), XdhSpec.X25519, "ML-KEM", bobPqc.getPrivate(), null);

            // Alice -> Bob: hybrid message carries PQC ciphertext; classic part is empty.
            byte[] msgA = alice.getPeerMessage();
            System.out.println("...msgA " + lens(msgA) + " " + shortHex(msgA));

            bob.setPeerMessage(msgA);

            // Both derive the final hybrid OKM (HKDF output).
            byte[] okmA = alice.deriveSecret();
            byte[] okmB = bob.deriveSecret();

            System.out.println("...okmA " + shortHex(okmA));
            System.out.println("...okmB " + shortHex(okmB));
            System.out.println("...equal " + Arrays.equals(okmA, okmB));

            // Application would now feed OKM into symmetric key schedule / AEAD keys / etc.
        } finally {
            closeQuiet(alice);
            closeQuiet(bob);
        }

        logEnd();
    }

    @Test
    void x25519_pairMessage_plus_mlKem768_kemAdapter() throws Exception {
        logBegin("PAIR_MESSAGE + KEM_ADAPTER", "Xdh/X25519 + ML-KEM-768", "HKDF-SHA256", "OKM=32B");

        // Classic leg keys (Xdh + XdhSpec.X25519).
        KeyPair aliceClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);

        // PQC leg: Bob is the KEM recipient (has ML-KEM keypair).
        KeyPair bobPqc = session.keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        HybridKexContext alice = null;
        HybridKexContext bob = null;

        try {
            // Alice classic leg is message-based (PAIR_MESSAGE): it will emit her public
            // key as SPKI bytes.
            // ...PQC leg (KEM initiator) will emit ciphertext.
            alice = HybridKexContexts.initiatorPairMessage(session, profile, "Xdh", new KeyPairKey(aliceClassic),
                    XdhSpec.X25519, "ML-KEM", bobPqc.getPublic(), null);

            // Bob classic leg is message-based (PAIR_MESSAGE): it will emit his public key
            // as SPKI bytes.
            // ...PQC leg (KEM responder) consumes ciphertext and typically does not emit a
            // PQC message.
            bob = HybridKexContexts.responderPairMessage(session, profile, "Xdh", new KeyPairKey(bobClassic),
                    XdhSpec.X25519, "ML-KEM", bobPqc.getPrivate(), null);

            // Alice -> Bob: hybrid message carries classic SPKI + PQC ciphertext.
            byte[] msgA = alice.getPeerMessage();
            System.out.println("...msgA " + lens(msgA) + " " + shortHex(msgA));
            bob.setPeerMessage(msgA);

            // Bob -> Alice: hybrid message carries classic SPKI; PQC part may be empty
            // (depends on PQC role).
            byte[] msgB = bob.getPeerMessage();
            System.out.println("...msgB " + lens(msgB) + " " + shortHex(msgB));
            alice.setPeerMessage(msgB);

            // Both derive the final hybrid OKM (HKDF output).
            byte[] okmA = alice.deriveSecret();
            byte[] okmB = bob.deriveSecret();

            System.out.println("...okmA " + shortHex(okmA));
            System.out.println("...okmB " + shortHex(okmB));
            System.out.println("...equal " + Arrays.equals(okmA, okmB));
        } finally {
            closeQuiet(alice);
            closeQuiet(bob);
        }

        logEnd();
    }

    @Test
    void builder_x25519_classicAgreement_plus_mlKem768() throws Exception {
        logBegin("Builder", "CLASSIC_AGREEMENT + KEM_ADAPTER", "Xdh/X25519 + ML-KEM-768", "HKDF-SHA256", "OKM=32B");

        // ...Generate classic leg keys (Xdh + XdhSpec.X25519).
        java.security.KeyPair aliceClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh",
                zeroecho.core.alg.xdh.XdhSpec.X25519);
        java.security.KeyPair bobClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh",
                zeroecho.core.alg.xdh.XdhSpec.X25519);

        // ...Generate PQC (recipient) keys (ML-KEM-768).
        java.security.KeyPair bobPqc = session.keyBuilders().asymmetric().generateKeyPair("ML-KEM",
                zeroecho.core.alg.kyber.KyberKeyGenSpec.kyber768());

        // ...Create a profile for HKDF (output length 32 bytes).
        zeroecho.sdk.hybrid.kex.HybridKexProfile profile = zeroecho.sdk.hybrid.kex.HybridKexProfile.defaultProfile(32);

        // ...Build a transcript to bind HKDF info to public handshake context.
        zeroecho.sdk.hybrid.kex.HybridKexTranscript transcript = new zeroecho.sdk.hybrid.kex.HybridKexTranscript()
                .addUtf8("suite", "X25519+MLKEM768").addUtf8("role", "demo");

        // ...Define a minimum-strength policy (example: classic >= 128, PQC >= 192, OKM
        // >= 32 bytes).
        zeroecho.sdk.hybrid.kex.HybridKexPolicy policy = new zeroecho.sdk.hybrid.kex.HybridKexPolicy(128, 192, 32);

        // ...Start the builder.
        zeroecho.sdk.builders.HybridKexBuilder b = zeroecho.sdk.builders.HybridKexBuilder.builder(session)
                // ...Set HKDF profile (salt/info/outLen).
                .profile(profile)
                // ...Bind HKDF info to transcript (protocol context).
                .transcript(transcript)
                // ...Enable hybrid policy gating for this build.
                .policy(policy);

        // ...Select classic mode where peer public key is known out-of-band.
        zeroecho.sdk.builders.HybridKexBuilder.ClassicAgreement classicCfg = b.classicAgreement()
                // ...Set classic algorithm id (X25519 is represented as "Xdh" with
                // XdhSpec.X25519).
                .algorithm("Xdh")
                // ...Set classic parameters (X25519 curve spec).
                .spec(zeroecho.core.alg.xdh.XdhSpec.X25519)
                // ...Set local classic private key (Alice).
                .privateKey(aliceClassic.getPrivate())
                // ...Set peer classic public key (Bob).
                .peerPublic(bobClassic.getPublic());

        // ...Continue with PQC KEM adapter configuration for initiator role.
        zeroecho.sdk.hybrid.kex.HybridKexContext alice = classicCfg.pqcKem()
                // ...Set PQC algorithm id (ML-KEM).
                .algorithm("ML-KEM")
                // ...Set PQC recipient public key (Bob).
                .peerPublic(bobPqc.getPublic())
                // ...Build initiator-side hybrid context.
                .buildInitiator();

        // ...Build responder-side context (Bob) with symmetric configuration (note: PQC
        // uses private key).
        zeroecho.sdk.hybrid.kex.HybridKexContext bob = zeroecho.sdk.builders.HybridKexBuilder.builder(session)
                // ...Set the same HKDF profile to derive the same OKM.
                .profile(profile)
                // ...Bind the same transcript to ensure both sides derive the same OKM.
                .transcript(transcript)
                // ...Enable the same policy gate.
                .policy(policy)
                // ...Select classic agreement mode (peer public is out-of-band).
                .classicAgreement()
                // ...Set classic algorithm id.
                .algorithm("Xdh")
                // ...Set classic parameters.
                .spec(zeroecho.core.alg.xdh.XdhSpec.X25519)
                // ...Set local classic private key (Bob).
                .privateKey(bobClassic.getPrivate())
                // ...Set peer classic public key (Alice).
                .peerPublic(aliceClassic.getPublic())
                // ...Continue to PQC configuration.
                .pqcKem()
                // ...Set PQC algorithm id.
                .algorithm("ML-KEM")
                // ...Set PQC recipient private key (Bob).
                .privateKey(bobPqc.getPrivate())
                // ...Build responder-side hybrid context.
                .buildResponder();

        try {
            // ...Alice produces the hybrid message (PQC ciphertext; classic part is empty
            // in this mode).
            byte[] msgA = alice.getPeerMessage();
            System.out.println("...msgA " + lens(msgA) + " " + shortHex(msgA));

            // ...Bob consumes Alice message.
            bob.setPeerMessage(msgA);

            // ...Both sides derive identical OKM.
            byte[] okmA = alice.deriveSecret();
            byte[] okmB = bob.deriveSecret();

            System.out.println("...okmA " + shortHex(okmA));
            System.out.println("...okmB " + shortHex(okmB));
            System.out.println("...equal " + java.util.Arrays.equals(okmA, okmB));

            // ...Use exporter to derive purpose-specific keys bound to transcript.
            zeroecho.sdk.hybrid.kex.HybridKexExporter exporterA = b.exporterFromOkm(okmA);
            byte[] txA = exporterA.export("app/tx", transcript.toByteArray(), 32);
            byte[] rxA = exporterA.export("app/rx", transcript.toByteArray(), 32);

            System.out.println("...txA " + shortHex(txA));
            System.out.println("...rxA " + shortHex(rxA));
        } finally {
            closeQuiet(alice);
            closeQuiet(bob);
        }

        logEnd();
    }

    @Test
    void builder_x25519_pairMessage_plus_mlKem768() throws Exception {
        logBegin("Builder", "PAIR_MESSAGE + KEM_ADAPTER", "Xdh/X25519 + ML-KEM-768", "HKDF-SHA256", "OKM=32B");

        // ...Generate classic leg keys (Xdh + XdhSpec.X25519).
        KeyPair aliceClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobClassic = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);

        // ...Generate PQC (recipient) keys (ML-KEM-768).
        KeyPair bobPqc = session.keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber768());

        // ...Create a profile for HKDF (output length 32 bytes).
        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        // ...Build a transcript to bind HKDF info to public handshake context.
        // ...(Use identical transcript on both sides to derive the same OKM.)
        zeroecho.sdk.hybrid.kex.HybridKexTranscript transcript = new zeroecho.sdk.hybrid.kex.HybridKexTranscript()
                .addUtf8("suite", "X25519+MLKEM768").addUtf8("mode", "PAIR_MESSAGE").addUtf8("role", "demo");

        // ...Define a minimum-strength policy (example: classic >= 128, PQC >= 192, OKM
        // >= 32 bytes).
        zeroecho.sdk.hybrid.kex.HybridKexPolicy policy = new zeroecho.sdk.hybrid.kex.HybridKexPolicy(128, 192, 32);

        // ...Start the initiator builder.
        zeroecho.sdk.builders.HybridKexBuilder initBuilder = zeroecho.sdk.builders.HybridKexBuilder.builder(session)
                // ...Set HKDF profile (salt/info/outLen).
                .profile(profile)
                // ...Bind HKDF info to transcript (protocol context).
                .transcript(transcript)
                // ...Enable hybrid policy gating for this build.
                .policy(policy);

        // ...Select classic mode where the public key is carried in-band as a classic
        // message (PAIR_MESSAGE).
        zeroecho.sdk.hybrid.kex.HybridKexContext alice = initBuilder
                // ...Switch classic leg to PAIR_MESSAGE mode.
                .classicPairMessage()
                // ...Set classic algorithm id (X25519 is represented as "Xdh" with
                // XdhSpec.X25519).
                .algorithm("Xdh")
                // ...Set classic parameters (X25519 curve spec).
                .spec(XdhSpec.X25519)
                // ...Set local classic key pair wrapper (Alice).
                .keyPair(new KeyPairKey(aliceClassic))
                // ...Continue with PQC KEM adapter configuration.
                .pqcKem()
                // ...Set PQC algorithm id (ML-KEM).
                .algorithm("ML-KEM")
                // ...Set PQC recipient public key (Bob).
                .peerPublic(bobPqc.getPublic())
                // ...Build initiator-side hybrid context.
                .buildInitiator();

        // ...Start the responder builder.
        zeroecho.sdk.builders.HybridKexBuilder respBuilder = zeroecho.sdk.builders.HybridKexBuilder.builder(session)
                // ...Set the same HKDF profile to derive the same OKM.
                .profile(profile)
                // ...Bind the same transcript to ensure both sides derive the same OKM.
                .transcript(transcript)
                // ...Enable the same policy gate.
                .policy(policy);

        // ...Build responder-side context (Bob).
        zeroecho.sdk.hybrid.kex.HybridKexContext bob = respBuilder
                // ...Switch classic leg to PAIR_MESSAGE mode.
                .classicPairMessage()
                // ...Set classic algorithm id.
                .algorithm("Xdh")
                // ...Set classic parameters.
                .spec(XdhSpec.X25519)
                // ...Set local classic key pair wrapper (Bob).
                .keyPair(new KeyPairKey(bobClassic))
                // ...Continue with PQC KEM adapter configuration.
                .pqcKem()
                // ...Set PQC algorithm id.
                .algorithm("ML-KEM")
                // ...Set PQC recipient private key (Bob).
                .privateKey(bobPqc.getPrivate())
                // ...Build responder-side hybrid context.
                .buildResponder();

        try {
            // ...Alice produces the hybrid message: classic SPKI + PQC ciphertext.
            byte[] msgA = alice.getPeerMessage();
            System.out.println("...msgA " + lens(msgA) + " " + shortHex(msgA));

            // ...Bob consumes Alice message (learns Alice classic public + decapsulates PQC
            // ciphertext).
            bob.setPeerMessage(msgA);

            // ...Bob produces response message: classic SPKI; PQC part may be empty
            // (role-dependent).
            byte[] msgB = bob.getPeerMessage();
            System.out.println("...msgB " + lens(msgB) + " " + shortHex(msgB));

            // ...Alice consumes Bob message (learns Bob classic public).
            alice.setPeerMessage(msgB);

            // ...Both sides derive identical OKM.
            byte[] okmA = alice.deriveSecret();
            byte[] okmB = bob.deriveSecret();

            System.out.println("...okmA " + shortHex(okmA));
            System.out.println("...okmB " + shortHex(okmB));
            System.out.println("...equal " + Arrays.equals(okmA, okmB));

            // ...Use exporter to derive purpose-specific keys bound to transcript.
            zeroecho.sdk.hybrid.kex.HybridKexExporter exporterA = initBuilder.exporterFromOkm(okmA);
            byte[] txA = exporterA.export("app/tx", transcript.toByteArray(), 32);
            byte[] rxA = exporterA.export("app/rx", transcript.toByteArray(), 32);

            System.out.println("...txA " + shortHex(txA));
            System.out.println("...rxA " + shortHex(rxA));
        } finally {
            closeQuiet(alice);
            closeQuiet(bob);
        }

        logEnd();
    }

    // -------------------------------------------------------------------------
    // helpers (JUnit output conventions)
    // -------------------------------------------------------------------------

    private static void logBegin(Object... params) {
        String thisClass = HybridKexDemoTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = HybridKexDemoTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    private static void closeQuiet(HybridKexContext ctx) {
        if (ctx == null) {
            return;
        }
        try {
            ctx.close();
        } catch (Exception e) {
            LOG.fine("close failed: " + e.getClass().getName());
        }
    }

    private static String shortHex(byte[] b) {
        if (b == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) {
            if (sb.length() == 80) {
                sb.append("...");
                break;
            }
            if ((v & 0xFF) < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v & 0xFF));
        }
        return sb.toString();
    }

    private static String lens(byte[] msg) {
        if (msg == null || msg.length < 8) {
            return "[classicLen=?, pqcLen=?]";
        }
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(msg));
            int classicLen = in.readInt();
            if (classicLen < 0) {
                return "[classicLen=?, pqcLen=?]";
            }
            if (classicLen > 0) {
                in.skipBytes(classicLen);
            }
            int pqcLen = in.readInt();
            return "[classicLen=" + classicLen + ", pqcLen=" + pqcLen + "]";
        } catch (Exception e) {
            return "[classicLen=?, pqcLen=?]";
        }
    }
}
