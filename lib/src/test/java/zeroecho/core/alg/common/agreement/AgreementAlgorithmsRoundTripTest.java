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
package zeroecho.core.alg.common.agreement;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
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
import zeroecho.core.KeyUsage;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spec.VoidSpec;
import zeroecho.core.spi.AsymmetricKeyBuilder;
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
        // If needed, install/activate providers (e.g., BouncyCastlePQCProvider) here.
        BouncyCastleActivator.init();
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

                System.out.printf("   ...%s - AGREEMENT capability found", id);

                final Class<?> ctxType = cap.contextType();
                final Class<?> keyType = cap.keyType();
                final Class<?> specType = cap.specType();
                @SuppressWarnings("unused")
                final ContextSpec defVal = cap.defaultSpec().get();

                // System.out.printf(" ......type=[%s] key=[%s] spec=[%s] default=[%s]%n",
                // ctxType, keyType, specType, defVal);

                // AGREEMENT (KEM-style) via MessageAgreementContext adapter
                if (MessageAgreementContext.class.isAssignableFrom(ctxType)) {

                    KeyPair bob = generateKeyPair(alg);
                    if (bob == null) {
                        System.out.println("   ...bob=null");
                        continue;
                    }

                    System.out.println("runAgreement(" + alg.id() + ", VoidSpec)");
                    System.out.println("  Bob.public    " + keyInfo("key", bob.getPublic()));
                    System.out.println("  Bob.private   " + keyInfo("key", bob.getPrivate()));

                    // Alice (initiator): has Bob's public key
                    MessageAgreementContext aliceCtx = CryptoAlgorithms.create(alg.id(), KeyUsage.AGREEMENT,
                            bob.getPublic(), VoidSpec.INSTANCE);

                    // Bob (responder): has his private key
                    MessageAgreementContext bobCtx = CryptoAlgorithms.create(alg.id(), KeyUsage.AGREEMENT,
                            bob.getPrivate(), VoidSpec.INSTANCE);

                    // Initiator produces encapsulation message (ciphertext) to send
                    byte[] enc = aliceCtx.getPeerMessage();
                    // Responder consumes it
                    bobCtx.setPeerMessage(enc);

                    // Both derive the same shared secret
                    byte[] kA = aliceCtx.deriveSecret();
                    byte[] kB = bobCtx.deriveSecret();

                    System.out.println("  KEM.ciphertext=" + hex(enc));
                    System.out.println("  Alice.secret  =" + hex(kA));
                    System.out.println("  Bob.secret    =" + hex(kB));

                    assertArrayEquals(kA, kB, alg.id() + ": agreement secrets mismatch");
                    System.out.println("...ok");

                    try {
                        aliceCtx.close();
                    } catch (Exception ignored) {
                    }
                    try {
                        bobCtx.close();
                    } catch (Exception ignored) {
                    }

                    break;
                }

                // -------- Classic DH/XDH: AgreementContext + real ContextSpec --------
                else if (AgreementContext.class.isAssignableFrom(ctxType)
                        && ContextSpec.class.isAssignableFrom(specType) && keyType == PrivateKey.class) {

                    KeyPair alice;
                    KeyPair bob;

                    alice = generateKeyPair(alg);
                    bob = generateKeyPair(alg);

                    if (alice == null || bob == null) {
                        continue;
                    }

                    // Prefer the capability's default ContextSpec if provided
                    ContextSpec spec = null;
                    try {
                        ContextSpec def = cap.defaultSpec().get();
                        spec = def;
                    } catch (Throwable ignore) {
                        spec = tryExtractContextSpec(alg);
                    }
                    if (spec == null) {
                        continue;
                    }

                    System.out.println("runAgreement(" + alg.id() + ", " + spec.getClass().getSimpleName() + ")");
                    System.out.println("  Alice.public  " + keyInfo("key", alice.getPublic()));
                    System.out.println("  Alice.private " + keyInfo("key", alice.getPrivate()));
                    System.out.println("  Bob.public    " + keyInfo("key", bob.getPublic()));
                    System.out.println("  Bob.private   " + keyInfo("key", bob.getPrivate()));

                    // assertDhCompatible(alice.getPrivate(), bob.getPublic());
                    // assertDhCompatible(bob.getPrivate(), alice.getPublic());

                    AgreementContext aCtx = CryptoAlgorithms.create(alg.id(), KeyUsage.AGREEMENT, alice.getPrivate(),
                            spec);
                    AgreementContext bCtx = CryptoAlgorithms.create(alg.id(), KeyUsage.AGREEMENT, bob.getPrivate(),
                            spec);
                    aCtx.setPeerPublic(bob.getPublic());
                    bCtx.setPeerPublic(alice.getPublic());

                    byte[] zA = aCtx.deriveSecret();
                    byte[] zB = bCtx.deriveSecret();

                    System.out.println("  Alice.secret  =" + hex(zA));
                    System.out.println("  Bob.secret    =" + hex(zB));

                    assertArrayEquals(zA, zB, alg.id() + ": DH/XDH secrets mismatch");
                    System.out.println("...ok");

                    try {
                        aCtx.close();
                    } catch (IOException ignore) {
                    }
                    try {
                        bCtx.close();
                    } catch (IOException ignore) {
                    }
                }
            }
        }

        logEnd();
    }

    // ----- helpers -----
    private static KeyPair generateKeyPair(CryptoAlgorithm alg) {
        try {
            for (CryptoAlgorithm.AsymBuilderInfo bi : alg.asymmetricBuildersInfo()) {
                // System.out.println(" ...keyPair " + bi.getClass().getName());
                if (bi.defaultKeySpec == null) {
                    // System.out.println(" ......skip default = null --> it was for keyImport");
                    continue;
                }
                @SuppressWarnings("unchecked")
                Class<AlgorithmKeySpec> specType = (Class<AlgorithmKeySpec>) bi.specType;
                AsymmetricKeyBuilder<AlgorithmKeySpec> b = alg.asymmetricKeyBuilder(specType);
                AlgorithmKeySpec spec = (AlgorithmKeySpec) bi.defaultKeySpec;
                // System.out.println(" ......generated from " + spec);
                return b.generateKeyPair(spec);
            }
        } catch (Throwable ignore) {
        }
        return null;
    }

    private static ContextSpec tryExtractContextSpec(CryptoAlgorithm alg) {
        try {
            for (Capability c : alg.listCapabilities()) {
                if (c.role() == KeyUsage.AGREEMENT && ContextSpec.class.isAssignableFrom(c.specType())) {
                    try {
                        return c.defaultSpec().get();
                    } catch (Throwable ignore) {
                        // continue searching
                    }
                }
            }
        } catch (Throwable ignore) {
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

        // 1) Parameter compatibility: same p,g and l-compatible (0 means "unspecified")
        DHParameterSpec a = dhPriv.getParams();
        DHParameterSpec b = dhPub.getParams();
        if (a == null || b == null) {
            throw new InvalidKeyException("Missing DH parameters on one of the keys");
        }
        if (!a.getP().equals(b.getP()) || !a.getG().equals(b.getG())) {
            System.out.printf("   ...a.p=%s%n   ...b.p=%s%n   ...a.g=%s%n   ...b.g=%s%n", a.getP(), b.getP(), a.getG(),
                    b.getG());
            throw new InvalidKeyException("Incompatible DH parameters: (p,g) differ");
        }
        int la = a.getL();
        int lb = b.getL();
        if (la != 0 && lb != 0 && la != lb) {
            throw new InvalidKeyException(
                    "Incompatible DH parameters: private value length (l) differs: " + la + " vs " + lb);
        }

        // 2) Public value Y sanity check: 2 <= Y <= p-2 (reject trivial/small subgroup
        // values)
        BigInteger p = a.getP();
        BigInteger y = dhPub.getY();
        if (y == null) {
            throw new InvalidKeyException("DH public key has null Y");
        }
        BigInteger TWO = BigInteger.valueOf(2);
        if (y.compareTo(TWO) < 0 || y.compareTo(p.subtract(TWO)) > 0) {
            throw new InvalidKeyException("DH public value Y out of range");
        }

        // 3) Trial doPhase to prove the pair actually works with the provider
        KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
        try {
            ka.init(priv);
            ka.doPhase(pub, true); // if this throws, they are not operationally compatible
            // (we don't need the secret here; just proving doPhase succeeds)
        } catch (InvalidKeyException e) {
            throw new InvalidKeyException("KeyAgreement.doPhase failed: " + e.getMessage(), e);
        }
    }
}
