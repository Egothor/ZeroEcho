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
package zeroecho.core.alg.common.agreement;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.Capability;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyOperation;
import zeroecho.core.KeyOperationInfo;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spec.VoidSpec;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.sdk.util.BouncyCastleActivator;

public class AgreementAlgorithmsRoundTripTest {

    // ----- logging helpers -----
    private static void logBegin(Object... params) {
        String thisClass = AgreementAlgorithmsRoundTripTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = AgreementAlgorithmsRoundTripTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    private static void printCapabilityHeader(String algId, String branch, Capability cap) {
        System.out.println("...algId=" + algId + ", branch=" + branch + ", ctxType=" + cap.contextType().getSimpleName()
                + ", keyType=" + cap.keyType().getSimpleName() + ", specType=" + cap.specType().getSimpleName());
    }

    private static String hex(byte[] b) {
        if (b == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            if (sb.length() == 80) {
                sb.append("...");
                break;
            }
            int v = b[i] & 0xFF;
            if (v < 16) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }

    private static String keyInfo(String who, Key key) {
        if (key == null) {
            return who + "=(null)";
        }
        String fmt = key.getFormat();
        byte[] enc = key.getEncoded();
        return who + "=(" + key.getAlgorithm() + ", format=" + fmt + ", encodedLen=" + (enc == null ? -1 : enc.length)
                + ")";
    }

    @BeforeAll
    static void setup() {
        // Optional: activate providers (e.g., BC/BCPQC) if present.
        // Keep tests runnable even if BC is absent.
        try {
            BouncyCastleActivator.init();
        } catch (Throwable ignore) {
            // ignore
        }
    }

    @Test
    void runAllAgreementAlgos() throws Exception {
        logBegin("AGREEMENT sweep");

        for (String id : CryptoAlgorithms.available()) {
            final CryptoAlgorithm alg;
            try {
                alg = CryptoAlgorithms.require(id);
            } catch (Throwable t) {
                continue;
            }

            final List<Capability> caps = alg.listCapabilities();
            for (Capability cap : caps) {
                if (cap.role() != KeyUsage.AGREEMENT) {
                    continue;
                }

                System.out.println("...algId=" + id + " - AGREEMENT capability found");

                final Class<?> ctxType = cap.contextType();
                final Class<?> keyType = cap.keyType();
                final Class<?> specType = cap.specType();

                // --------------------------------------------------------------------
                // MessageAgreementContext branch A: PAIR_MESSAGE (DH/XDH/ECDH-style)
                //
                // New extension:
                // - contextType: MessageAgreementContext
                // - keyType: KeyPairKey (wrapper for KeyPair, because capabilities require Key)
                // - specType: ContextSpec (algorithm-specific agreement spec)
                //
                // Semantics:
                // - getPeerMessage() returns local public key encoding (SPKI)
                // - setPeerMessage(...) imports peer public key encoding
                // --------------------------------------------------------------------
                if (MessageAgreementContext.class.isAssignableFrom(ctxType) && keyType == KeyPairKey.class
                        && ContextSpec.class.isAssignableFrom(specType)) {

                    printCapabilityHeader(alg.id(), "PAIR_MESSAGE", cap);

                    ContextSpec spec = null;
                    try {
                        spec = cap.defaultSpec();
                    } catch (Throwable ignore) {
                        spec = tryExtractContextSpec(alg);
                    }
                    if (spec == null) {
                        System.out.println("...spec=null (skip)");
                        continue;
                    }

                    KeyPair alice = generateKeyPair(alg);
                    KeyPair bob = generateKeyPair(alg);
                    if (alice == null || bob == null) {
                        System.out.println("...keypair=null (skip)");
                        continue;
                    }

                    System.out.println("...pair-message agreement roundtrip: algId=" + alg.id() + ", spec="
                            + spec.getClass().getSimpleName());
                    System.out.println("...Alice.public  " + keyInfo("key", alice.getPublic()));
                    System.out.println("...Alice.private " + keyInfo("key", alice.getPrivate()));
                    System.out.println("...Bob.public    " + keyInfo("key", bob.getPublic()));
                    System.out.println("...Bob.private   " + keyInfo("key", bob.getPrivate()));

                    KeyPairKey aliceKey = new KeyPairKey(alice);
                    KeyPairKey bobKey = new KeyPairKey(bob);

                    MessageAgreementContext aCtx = null;
                    MessageAgreementContext bCtx = null;

                    try {
                        aCtx = new zeroecho.sdk.ZeroEchoSession().createContext(alg.id(), KeyUsage.AGREEMENT, aliceKey,
                                spec);
                        bCtx = new zeroecho.sdk.ZeroEchoSession().createContext(alg.id(), KeyUsage.AGREEMENT, bobKey,
                                spec);

                        byte[] aMsg = aCtx.getPeerMessage();
                        byte[] bMsg = bCtx.getPeerMessage();

                        aCtx.setPeerMessage(bMsg);
                        bCtx.setPeerMessage(aMsg);

                        byte[] zA = aCtx.deriveSecret();
                        byte[] zB = bCtx.deriveSecret();

                        System.out.println("...Alice.msg     =" + hex(aMsg));
                        System.out.println("...Bob.msg       =" + hex(bMsg));
                        System.out.println("...Alice.secret  =" + hex(zA));
                        System.out.println("...Bob.secret    =" + hex(zB));

                        assertArrayEquals(zA, zB, alg.id() + ": PAIR_MESSAGE secrets mismatch");
                        System.out.println("...PAIR_MESSAGE...ok");
                    } finally {
                        if (aCtx != null) {
                            try {
                                aCtx.close();
                            } catch (Exception ignored) {
                                // ignore
                            }
                        }
                        if (bCtx != null) {
                            try {
                                bCtx.close();
                            } catch (Exception ignored) {
                                // ignore
                            }
                        }
                    }

                    // For a given algorithm, one AGREEMENT capability is sufficient for the sweep.
                    break;
                }

                // --------------------------------------------------------------------
                // MessageAgreementContext branch B: KEM_ADAPTER (KEM-style adapter)
                //
                // Existing behavior:
                // - initiator has recipient PublicKey (encapsulation)
                // - responder has PrivateKey (decapsulation)
                // - spec is VoidSpec
                // --------------------------------------------------------------------
                if (MessageAgreementContext.class.isAssignableFrom(ctxType)
                        && (keyType == PublicKey.class || keyType == PrivateKey.class)) {

                    printCapabilityHeader(alg.id(), "KEM_ADAPTER", cap);

                    KeyPair bob = generateKeyPair(alg);
                    if (bob == null) {
                        System.out.println("...keypair=null (skip)");
                        continue;
                    }

                    System.out.println("...kem-adapter agreement roundtrip: algId=" + alg.id() + ", spec=VoidSpec");
                    System.out.println("...Bob.public    " + keyInfo("key", bob.getPublic()));
                    System.out.println("...Bob.private   " + keyInfo("key", bob.getPrivate()));

                    MessageAgreementContext aliceCtx = null;
                    MessageAgreementContext bobCtx = null;

                    try {
                        // Alice (initiator): has Bob's public key
                        aliceCtx = new zeroecho.sdk.ZeroEchoSession().createContext(alg.id(), KeyUsage.AGREEMENT,
                                bob.getPublic(), VoidSpec.INSTANCE);

                        // Bob (responder): has his private key
                        bobCtx = new zeroecho.sdk.ZeroEchoSession().createContext(alg.id(), KeyUsage.AGREEMENT,
                                bob.getPrivate(), VoidSpec.INSTANCE);

                        // Initiator produces encapsulation message (ciphertext) to send
                        byte[] enc = aliceCtx.getPeerMessage();
                        // Responder consumes it
                        bobCtx.setPeerMessage(enc);

                        // Both derive the same shared secret
                        byte[] kA = aliceCtx.deriveSecret();
                        byte[] kB = bobCtx.deriveSecret();

                        System.out.println("...KEM.ciphertext=" + hex(enc));
                        System.out.println("...Alice.secret  =" + hex(kA));
                        System.out.println("...Bob.secret    =" + hex(kB));

                        assertArrayEquals(kA, kB, alg.id() + ": KEM_ADAPTER secrets mismatch");
                        System.out.println("...KEM_ADAPTER...ok");
                    } finally {
                        if (aliceCtx != null) {
                            try {
                                aliceCtx.close();
                            } catch (Exception ignored) {
                                // ignore
                            }
                        }
                        if (bobCtx != null) {
                            try {
                                bobCtx.close();
                            } catch (Exception ignored) {
                                // ignore
                            }
                        }
                    }

                    break;
                }

                // --------------------------------------------------------------------
                // AgreementContext branch C: CLASSIC_AGREEMENT (PrivateKey + ContextSpec)
                // --------------------------------------------------------------------
                if (AgreementContext.class.isAssignableFrom(ctxType) && keyType == PrivateKey.class
                        && ContextSpec.class.isAssignableFrom(specType)) {

                    printCapabilityHeader(alg.id(), "CLASSIC_AGREEMENT", cap);

                    ContextSpec spec = null;
                    try {
                        spec = cap.defaultSpec();
                    } catch (Throwable ignore) {
                        spec = tryExtractContextSpec(alg);
                    }
                    if (spec == null) {
                        System.out.println("...spec=null (skip)");
                        continue;
                    }

                    KeyPair alice = generateKeyPair(alg);
                    KeyPair bob = generateKeyPair(alg);

                    if (alice == null || bob == null) {
                        System.out.println("...keypair=null (skip)");
                        continue;
                    }

                    System.out.println("...classic agreement roundtrip: algId=" + alg.id() + ", spec="
                            + spec.getClass().getSimpleName());
                    System.out.println("...Alice.public  " + keyInfo("key", alice.getPublic()));
                    System.out.println("...Alice.private " + keyInfo("key", alice.getPrivate()));
                    System.out.println("...Bob.public    " + keyInfo("key", bob.getPublic()));
                    System.out.println("...Bob.private   " + keyInfo("key", bob.getPrivate()));

                    // Optional DH sanity check (only when both sides are DH keys).
                    try {
                        assertDhCompatible(alice.getPrivate(), bob.getPublic());
                        assertDhCompatible(bob.getPrivate(), alice.getPublic());
                    } catch (Throwable ignore) {
                        // not DH, or provider-specific checks not applicable; continue anyway
                    }

                    AgreementContext aCtx = null;
                    AgreementContext bCtx = null;

                    try {
                        aCtx = new zeroecho.sdk.ZeroEchoSession().createContext(alg.id(), KeyUsage.AGREEMENT,
                                alice.getPrivate(), spec);
                        bCtx = new zeroecho.sdk.ZeroEchoSession().createContext(alg.id(), KeyUsage.AGREEMENT,
                                bob.getPrivate(), spec);

                        aCtx.setPeerPublic(bob.getPublic());
                        bCtx.setPeerPublic(alice.getPublic());

                        byte[] zA = aCtx.deriveSecret();
                        byte[] zB = bCtx.deriveSecret();

                        System.out.println("...Alice.secret  =" + hex(zA));
                        System.out.println("...Bob.secret    =" + hex(zB));

                        assertArrayEquals(zA, zB, alg.id() + ": CLASSIC_AGREEMENT secrets mismatch");
                        System.out.println("...CLASSIC_AGREEMENT...ok");
                    } finally {
                        if (aCtx != null) {
                            try {
                                aCtx.close();
                            } catch (Exception ignored) {
                                // ignore
                            }
                        }
                        if (bCtx != null) {
                            try {
                                bCtx.close();
                            } catch (Exception ignored) {
                                // ignore
                            }
                        }
                    }

                    // do not break: a single algorithm may have multiple agreement capabilities
                }
            }
        }

        logEnd();
    }

    // ----- helpers -----
    private static KeyPair generateKeyPair(CryptoAlgorithm alg) {
        try {
            for (KeyOperationInfo bi : alg.keyOperations()) {
                if (bi.operation() != KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE || bi.defaultSpec() == null) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                Class<AlgorithmKeySpec> specType = (Class<AlgorithmKeySpec>) bi.specType();
                AsymmetricKeyPairGenerator<AlgorithmKeySpec> builder = alg.asymmetricKeyPairGenerator(specType);
                AlgorithmKeySpec spec = bi.defaultSpec();
                return builder.generateKeyPair(spec);
            }
        } catch (Throwable ignore) {
            // ignore
        }
        return null;
    }

    private static ContextSpec tryExtractContextSpec(CryptoAlgorithm alg) {
        try {
            for (Capability c : alg.listCapabilities()) {
                if (c.role() == KeyUsage.AGREEMENT && ContextSpec.class.isAssignableFrom(c.specType())) {
                    try {
                        return c.defaultSpec();
                    } catch (Throwable ignore) {
                        // continue searching
                    }
                }
            }
        } catch (Throwable ignore) {
            // ignore
        }
        return null;
    }

    public static void assertDhCompatible(PrivateKey priv, PublicKey pub) throws GeneralSecurityException {
        if (!(priv instanceof DHPrivateKey)) {
            throw new InvalidKeyException("Private key is not DH: " + (priv == null ? "null" : priv.getAlgorithm()));
        }
        if (!(pub instanceof DHPublicKey)) {
            throw new InvalidKeyException("Public key is not DH: " + (pub == null ? "null" : pub.getAlgorithm()));
        }

        DHPrivateKey dhPriv = (DHPrivateKey) priv;
        DHPublicKey dhPub = (DHPublicKey) pub;

        DHParameterSpec a = dhPriv.getParams();
        DHParameterSpec b = dhPub.getParams();
        if (a == null || b == null) {
            throw new InvalidKeyException("Missing DH parameters on one of the keys");
        }
        if (!a.getP().equals(b.getP()) || !a.getG().equals(b.getG())) {
            System.out.printf("...a.p=%s%n...b.p=%s%n...a.g=%s%n...b.g=%s%n", a.getP(), b.getP(), a.getG(), b.getG());
            throw new InvalidKeyException("Incompatible DH parameters: (p,g) differ");
        }
        int la = a.getL();
        int lb = b.getL();
        if (la != 0 && lb != 0 && la != lb) {
            throw new InvalidKeyException(
                    "Incompatible DH parameters: private value length (l) differs: " + la + " vs " + lb);
        }

        BigInteger p = a.getP();
        BigInteger y = dhPub.getY();
        if (y == null) {
            throw new InvalidKeyException("DH public key has null Y");
        }
        BigInteger TWO = BigInteger.valueOf(2);
        if (y.compareTo(TWO) < 0 || y.compareTo(p.subtract(TWO)) > 0) {
            throw new InvalidKeyException("DH public value Y out of range");
        }

        KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
        try {
            ka.init(priv);
            ka.doPhase(pub, true);
        } catch (InvalidKeyException e) {
            throw new InvalidKeyException("KeyAgreement.doPhase failed: " + e.getMessage(), e);
        }
    }
}
