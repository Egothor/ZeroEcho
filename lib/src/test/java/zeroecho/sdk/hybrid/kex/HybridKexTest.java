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
package zeroecho.sdk.hybrid.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.security.KeyPair;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Hybrid KEX tests.
 */
public class HybridKexTest {

    @BeforeAll
    static void setup() {
        // Optional: enable BC if you use BC-only modes in KEM payloads (EAX/OCB/CCM,
        // etc.)
        try {
            BouncyCastleActivator.init();
        } catch (Throwable ignore) {
            // keep tests runnable without BC if not present
        }
    }

    private static void logBegin(Object... params) {
        String thisClass = HybridKexTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = HybridKexTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    private static String hex(byte[] b) {
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
            return "classicLen=?, pqcLen=?";
        }
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(msg));
            int classicLen = in.readInt();
            int pqcLen = 0;
            if (msg.length >= 8 + Math.max(0, classicLen)) {
                if (classicLen > 0) {
                    in.skipBytes(classicLen);
                }
                pqcLen = in.readInt();
            }
            return "classicLen=" + classicLen + ", pqcLen=" + pqcLen;
        } catch (Exception e) {
            return "classicLen=?, pqcLen=?";
        }
    }

    @Test
    void hybrid_x25519_mlkem_roundtrip() throws Exception {
        logBegin("CLASSIC_AGREEMENT + KEM_ADAPTER", "Xdh/X25519 + ML-KEM(768)", "HKDF-SHA256", "32 bytes");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        // Classic: X25519 key pairs (Xdh + XdhSpec.X25519)
        KeyPair aliceClassic = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("Xdh",
                XdhSpec.X25519);
        KeyPair bobClassic = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("Xdh",
                XdhSpec.X25519);

        // PQC: ML-KEM key pair (Kyber variant)
        KeyPair bobPqc = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-KEM",
                KyberKeyGenSpec.kyber768());

        HybridKexContext alice = null;
        HybridKexContext bob = null;

        try {
            // Initiator: classic uses Alice private + Bob classic public; PQC uses Bob PQC
            // public
            alice = HybridKexContexts.initiator(new zeroecho.sdk.ZeroEchoSession(), profile, "Xdh",
                    aliceClassic.getPrivate(), bobClassic.getPublic(), XdhSpec.X25519, "ML-KEM", bobPqc.getPublic(),
                    null);

            // Responder: classic uses Bob private + Alice classic public; PQC uses Bob PQC
            // private
            bob = HybridKexContexts.responder(new zeroecho.sdk.ZeroEchoSession(), profile, "Xdh",
                    bobClassic.getPrivate(), aliceClassic.getPublic(), XdhSpec.X25519, "ML-KEM", bobPqc.getPrivate(),
                    null);

            // Alice produces message (contains PQC ciphertext; classic part is empty here)
            byte[] aliceMsg = alice.getPeerMessage();
            System.out.println("...aliceMsg(" + lens(aliceMsg) + ")=" + hex(aliceMsg));

            // Bob consumes message
            bob.setPeerMessage(aliceMsg);

            byte[] kA = alice.deriveSecret();
            byte[] kB = bob.deriveSecret();

            System.out.println("...kA=" + hex(kA));
            System.out.println("...kB=" + hex(kB));

            assertNotNull(kA);
            assertNotNull(kB);
            assertArrayEquals(kA, kB);
        } finally {
            if (alice != null) {
                try {
                    alice.close();
                } catch (Exception ignore) {
                }
            }
            if (bob != null) {
                try {
                    bob.close();
                } catch (Exception ignore) {
                }
            }
        }

        logEnd();
    }

    @Test
    void hybrid_x25519_pairmessage_mlkem_roundtrip() throws Exception {
        logBegin("PAIR_MESSAGE + KEM_ADAPTER", "Xdh/X25519 + ML-KEM(768)", "HKDF-SHA256", "32 bytes");

        HybridKexProfile profile = HybridKexProfile.defaultProfile(32);

        // Classic: X25519 key pairs (Xdh + XdhSpec.X25519)
        KeyPair aliceClassic = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("Xdh",
                XdhSpec.X25519);
        KeyPair bobClassic = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("Xdh",
                XdhSpec.X25519);

        // PQC: ML-KEM key pair (recipient/responder)
        KeyPair bobPqc = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair("ML-KEM",
                KyberKeyGenSpec.kyber768());

        HybridKexContext alice = null;
        HybridKexContext bob = null;

        try {
            // Classic leg is message-based on both sides (PAIR_MESSAGE capability:
            // KeyPairKey + ContextSpec).
            // PQC leg is KEM-style: initiator uses recipient public key; responder uses
            // recipient private key.
            alice = HybridKexContexts.initiatorPairMessage(new zeroecho.sdk.ZeroEchoSession(), profile, "Xdh",
                    new KeyPairKey(aliceClassic), XdhSpec.X25519, "ML-KEM", bobPqc.getPublic(), null);

            bob = HybridKexContexts.responderPairMessage(new zeroecho.sdk.ZeroEchoSession(), profile, "Xdh",
                    new KeyPairKey(bobClassic), XdhSpec.X25519, "ML-KEM", bobPqc.getPrivate(), null);

            // Step 1: Alice -> Bob (classic SPKI + PQC ciphertext)
            byte[] msgA = alice.getPeerMessage();
            System.out.println("...msgA(" + lens(msgA) + ")=" + hex(msgA));
            bob.setPeerMessage(msgA);

            // Step 2: Bob -> Alice (classic SPKI only; PQC part is empty)
            byte[] msgB = bob.getPeerMessage();
            System.out.println("...msgB(" + lens(msgB) + ")=" + hex(msgB));
            alice.setPeerMessage(msgB);

            // Both sides derive the final hybrid OKM.
            byte[] kA = alice.deriveSecret();
            byte[] kB = bob.deriveSecret();

            System.out.println("...kA=" + hex(kA));
            System.out.println("...kB=" + hex(kB));

            assertNotNull(kA);
            assertNotNull(kB);
            assertArrayEquals(kA, kB);
        } finally {
            if (alice != null) {
                try {
                    alice.close();
                } catch (Exception ignore) {
                }
            }
            if (bob != null) {
                try {
                    bob.close();
                } catch (Exception ignore) {
                }
            }
        }

        logEnd();
    }
}
