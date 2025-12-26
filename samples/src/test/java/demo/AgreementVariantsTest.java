/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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
package demo;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spec.VoidSpec;
import zeroecho.core.util.Strings;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Demonstration of agreement usage variants in ZeroEcho.
 *
 * <p>
 * This sample illustrates three complementary models used in practice:
 * </p>
 * <ul>
 * <li><b>KEM_ADAPTER</b> (example: ML-KEM / Kyber): the initiator is
 * constructed with the recipient's {@link PublicKey} and produces an outbound
 * encapsulation message; the responder is constructed with the matching
 * {@link PrivateKey} and consumes that message.</li>
 * <li><b>CLASSIC_AGREEMENT</b> (example: XDH / X25519): both parties hold their
 * own {@link PrivateKey}, set the peer {@link PublicKey} explicitly, and derive
 * the same raw shared secret.</li>
 * <li><b>PAIR_MESSAGE</b> (example: XDH / X25519): both parties hold a key pair
 * and exchange messages that are simply the X.509 SPKI encodings of their
 * public keys. This yields a message-oriented handshake without changing the
 * underlying agreement primitive.</li>
 * </ul>
 *
 * <h2>Important note</h2>
 * <p>
 * All examples below produce a <em>raw</em> agreement secret (the direct output
 * of KEM decapsulation or Diffie–Hellman agreement). Real protocols should feed
 * the raw secret into a suitable KDF (typically HKDF) together with
 * transcript/context info before using it as key material.
 * </p>
 * 
 * <h2>Note on resource management</h2>
 * <p>
 * The examples in this class intentionally do <em>not</em> use the
 * {@code try-with-resources} construct when working with
 * {@link zeroecho.core.context.AgreementContext} and
 * {@link zeroecho.core.context.MessageAgreementContext}.
 * </p>
 *
 * <p>
 * Agreement contexts represent protocol-level state rather than traditional I/O
 * resources. In real-world applications their lifecycle often spans multiple
 * protocol steps (message send, receive, validation, key derivation) and may
 * cross method or thread boundaries. Using explicit {@code try/finally} blocks
 * in the examples makes this lifecycle visible and closer to how agreement
 * contexts are typically managed in production code.
 * </p>
 *
 * <p>
 * In short-lived, fully synchronous scenarios (such as unit tests),
 * {@code try-with-resources} is perfectly acceptable. It is omitted here purely
 * for didactic reasons.
 * </p>
 */
class AgreementVariantsTest {

    private static final Logger LOG = Logger.getLogger(AgreementVariantsTest.class.getName());

    @BeforeAll
    static void setup() {
        // Optional: activate BC/BCPQC if present.
        // Keeps tests runnable even when providers are missing.
        try {
            BouncyCastleActivator.init();
        } catch (Throwable ignore) {
            // ignore
        }
    }

    /**
     * KEM_ADAPTER example for ML-KEM (Kyber):
     *
     * <p>
     * This models a common "send one message, derive shared secret" pattern:
     * </p>
     * <ul>
     * <li>Initiator uses recipient {@link PublicKey} and produces an encapsulation
     * message.</li>
     * <li>Responder uses recipient {@link PrivateKey}, consumes the message, and
     * derives the same secret.</li>
     * </ul>
     */
    @Test
    void kemAdapter_mlKem_roundTrip() throws Exception {
        LOG.info("kemAdapter_mlKem_roundTrip - KEM_ADAPTER (ML-KEM)");

        KeyPair recipient = CryptoAlgorithms.generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber1024());

        MessageAgreementContext initiator = null;
        MessageAgreementContext responder = null;
        try {
            // Initiator: constructed with recipient's public key (encapsulation side).
            initiator = CryptoAlgorithms.create("ML-KEM", KeyUsage.AGREEMENT, recipient.getPublic(), VoidSpec.INSTANCE);

            // Responder: constructed with recipient's private key (decapsulation side).
            responder = CryptoAlgorithms.create("ML-KEM", KeyUsage.AGREEMENT, recipient.getPrivate(),
                    VoidSpec.INSTANCE);

            // One-shot outbound message: KEM ciphertext / encapsulation payload.
            byte[] enc = initiator.getPeerMessage();
            // Responder consumes ciphertext to derive its secret.
            responder.setPeerMessage(enc);

            byte[] s1 = initiator.deriveSecret();
            byte[] s2 = responder.deriveSecret();

            LOG.log(Level.INFO, "KEM_ADAPTER: ciphertext={0}", Strings.toShortHexString(enc));
            LOG.log(Level.INFO, "KEM_ADAPTER: initiatorSecret={0}", Strings.toShortHexString(s1));
            LOG.log(Level.INFO, "KEM_ADAPTER: responderSecret={0}", Strings.toShortHexString(s2));
            LOG.log(Level.INFO, "KEM_ADAPTER: secretsEqual={0}", Boolean.valueOf(Arrays.equals(s1, s2)));
        } finally {
            if (initiator != null) {
                try {
                    initiator.close();
                } catch (Exception ignore) {
                    // ignore
                }
            }
            if (responder != null) {
                try {
                    responder.close();
                } catch (Exception ignore) {
                    // ignore
                }
            }
        }
    }

    /**
     * CLASSIC_AGREEMENT example for XDH/X25519:
     *
     * <p>
     * This is the traditional Diffie–Hellman model: both parties generate their own
     * key pair, each side keeps a private key, and the peer public key is provided
     * out-of-band (protocol message or session state).
     * </p>
     */
    @Test
    void classicAgreement_x25519_roundTrip() throws Exception {
        LOG.info("classicAgreement_x25519_roundTrip - CLASSIC_AGREEMENT (X25519)");

        CryptoAlgorithm xdh = CryptoAlgorithms.require("Xdh");
        KeyPair alice = xdh.generateKeyPair();
        KeyPair bob = xdh.generateKeyPair();

        AgreementContext aCtx = null;
        AgreementContext bCtx = null;

        try {
            // Both contexts are built from local private keys.
            aCtx = CryptoAlgorithms.create("Xdh", KeyUsage.AGREEMENT, alice.getPrivate(), XdhSpec.X25519);
            bCtx = CryptoAlgorithms.create("Xdh", KeyUsage.AGREEMENT, bob.getPrivate(), XdhSpec.X25519);

            // The protocol layer provides peer public keys (here we use in-memory
            // exchange).
            aCtx.setPeerPublic(bob.getPublic());
            bCtx.setPeerPublic(alice.getPublic());

            byte[] s1 = aCtx.deriveSecret();
            byte[] s2 = bCtx.deriveSecret();

            LOG.log(Level.INFO, "CLASSIC_AGREEMENT: aliceSecret={0}", Strings.toShortHexString(s1));
            LOG.log(Level.INFO, "CLASSIC_AGREEMENT: bobSecret={0}", Strings.toShortHexString(s2));
            LOG.log(Level.INFO, "CLASSIC_AGREEMENT: secretsEqual={0}", Boolean.valueOf(Arrays.equals(s1, s2)));
        } finally {
            if (aCtx != null) {
                try {
                    aCtx.close();
                } catch (Exception ignore) {
                    // ignore
                }
            }
            if (bCtx != null) {
                try {
                    bCtx.close();
                } catch (Exception ignore) {
                    // ignore
                }
            }
        }
    }

    /**
     * PAIR_MESSAGE example for XDH/X25519:
     *
     * <p>
     * This demonstrates the "message-oriented" handshake for DH-style agreements.
     * Each party holds a key pair and the outbound message is simply the local
     * public key encoding (SPKI). The receiver imports the encoding and binds it as
     * the peer key.
     * </p>
     *
     * <p>
     * This model is particularly practical for protocol implementations because it
     * makes the "to-be-sent" artifact explicit (a byte array message), similarly to
     * KEM ciphertexts.
     * </p>
     */
    @Test
    void pairMessage_x25519_roundTrip() throws Exception {
        LOG.info("pairMessage_x25519_roundTrip - PAIR_MESSAGE (X25519)");

        CryptoAlgorithm xdh = CryptoAlgorithms.require("Xdh");
        KeyPair alice = xdh.generateKeyPair();
        KeyPair bob = xdh.generateKeyPair();

        // Wrapper is required because ZeroEcho capability dispatch uses Key (KeyPair is
        // not a Key).
        KeyPairKey aliceKey = new KeyPairKey(alice);
        KeyPairKey bobKey = new KeyPairKey(bob);

        MessageAgreementContext aCtx = null;
        MessageAgreementContext bCtx = null;

        try {
            aCtx = CryptoAlgorithms.create("Xdh", KeyUsage.AGREEMENT, aliceKey, XdhSpec.X25519);
            bCtx = CryptoAlgorithms.create("Xdh", KeyUsage.AGREEMENT, bobKey, XdhSpec.X25519);

            // Outbound messages: SPKI encodings of local public keys.
            byte[] aMsg = aCtx.getPeerMessage();
            byte[] bMsg = bCtx.getPeerMessage();

            LOG.log(Level.INFO, "PAIR_MESSAGE: aliceMsg={0}", Strings.toShortHexString(aMsg));
            LOG.log(Level.INFO, "PAIR_MESSAGE: bobMsg={0}", Strings.toShortHexString(bMsg));

            // Each side imports peer public key from message.
            aCtx.setPeerMessage(bMsg);
            bCtx.setPeerMessage(aMsg);

            byte[] s1 = aCtx.deriveSecret();
            byte[] s2 = bCtx.deriveSecret();

            LOG.log(Level.INFO, "PAIR_MESSAGE: aliceSecret={0}", Strings.toShortHexString(s1));
            LOG.log(Level.INFO, "PAIR_MESSAGE: bobSecret={0}", Strings.toShortHexString(s2));
            LOG.log(Level.INFO, "PAIR_MESSAGE: secretsEqual={0}", Boolean.valueOf(Arrays.equals(s1, s2)));
        } finally {
            if (aCtx != null) {
                try {
                    aCtx.close();
                } catch (Exception ignore) {
                    // ignore
                }
            }
            if (bCtx != null) {
                try {
                    bCtx.close();
                } catch (Exception ignore) {
                    // ignore
                }
            }
        }
    }
}
