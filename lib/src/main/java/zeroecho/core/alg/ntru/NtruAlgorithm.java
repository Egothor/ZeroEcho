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
package zeroecho.core.alg.ntru;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.alg.common.agreement.KemMessageAgreementAdapter;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spec.VoidSpec;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.core.spi.PrivateKeyImporter;
import zeroecho.core.spi.PublicKeyImporter;

/**
 * NtruAlgorithm exposes the NTRU KEM from the Bouncy Castle PQC provider and
 * adapts it for both KEM and message-based agreement roles.
 *
 * <h2>Capabilities registered</h2>
 * <ul>
 * <li><b>KEM</b>:
 * <ul>
 * <li>{@link KeyUsage#ENCAPSULATE} with {@link PublicKey} producing a
 * {@link KemContext}.</li>
 * <li>{@link KeyUsage#DECAPSULATE} with {@link PrivateKey} producing a
 * {@link KemContext}.</li>
 * </ul>
 * </li>
 * <li><b>AGREEMENT</b>:
 * <ul>
 * <li>{@link KeyUsage#AGREEMENT} (initiator) using a {@link PublicKey}, exposed
 * as {@link MessageAgreementContext} via a KEM-to-agreement adapter.</li>
 * <li>{@link KeyUsage#AGREEMENT} (responder) using a {@link PrivateKey},
 * exposed as {@link MessageAgreementContext} via a KEM-to-agreement
 * adapter.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <p>
 * <b>KEM, initiator and responder</b>
 * </p>
 * <pre>{@code
 * NtruAlgorithm alg = new NtruAlgorithm();
 * // Generate a key pair (or import one). hrss701 is the default.
 * KeyPair kp = alg.asymmetricKeyPairGenerator(NtruKeyGenSpec.class)
 *                 .generateKeyPair(NtruKeyGenSpec.hrss701());
 *
 * // Initiator encapsulates using recipient's public key
 * KemContext enc = alg.createContext(KeyUsage.ENCAPSULATE, kp.getPublic(), VoidSpec.INSTANCE);
 * KemResult kem = enc.encapsulate();
 *
 * // Responder decapsulates using their private key
 * KemContext dec = alg.createContext(KeyUsage.DECAPSULATE, kp.getPrivate(), VoidSpec.INSTANCE);
 * byte[] secret = dec.decapsulate(kem.encapsulation());
 * }</pre>
 *
 * <p>
 * <b>Agreement over messages using the KEM adapter</b>
 * </p>
 * <pre>{@code
 * NtruAlgorithm alg = new NtruAlgorithm();
 * KeyPair kpBob = alg.asymmetricKeyPairGenerator(NtruKeyGenSpec.class)
 *                    .generateKeyPair(NtruKeyGenSpec.hrss701());
 *
 * // Alice (initiator) - has Bob's public key
 * MessageAgreementContext alice = alg.createContext(
 *     KeyUsage.AGREEMENT, kpBob.getPublic(), VoidSpec.INSTANCE);
 *
 * // Alice produces the peer message she must send to Bob
 * byte[] toBob = alice.getPeerMessage();
 *
 * // Bob (responder) - has his private key
 * MessageAgreementContext bob = alg.createContext(
 *     KeyUsage.AGREEMENT, kpBob.getPrivate(), VoidSpec.INSTANCE);
 *
 * // Bob supplies Alice's message so he can complete decapsulation
 * bob.setPeerMessage(toBob);
 *
 * // Both parties now hold the same derived secret via the AgreementContext API.
 * }</pre>
 *
 * <h2>Key builders</h2>
 * <ul>
 * <li>{@code NtruKeyGenSpec} - generates key pairs with a selected NTRU
 * parameter set (default: {@code hrss701}).</li>
 * <li>{@code NtruPublicKeySpec} - imports an X.509 SubjectPublicKeyInfo public
 * key.</li>
 * <li>{@code NtruPrivateKeySpec} - imports a PKCS#8 PrivateKeyInfo private
 * key.</li>
 * </ul>
 *
 * <h2>Provider requirements</h2>
 * <p>
 * This implementation uses {@code KeyPairGenerator} and {@code KeyFactory} with
 * the algorithm string {@code "NTRU"} from the Bouncy Castle PQC provider
 * ({@code BouncyCastlePQCProvider.PROVIDER_NAME}). If the provider is not
 * present, attempts to generate or import keys will fail with
 * {@link java.security.NoSuchProviderException}.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are stateless after construction and may be safely shared across
 * threads. Contexts returned from this algorithm are not guaranteed to be
 * thread-safe.
 * </p>
 *
 * @since 1.0
 * @see AlgorithmFamily
 * @see KeyUsage
 * @see KemContext
 * @see MessageAgreementContext
 */
public final class NtruAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Creates an algorithm instance that registers KEM and AGREEMENT roles and
     * wires asymmetric key builders for generation and X.509/PKCS#8 import.
     *
     * <p>
     * The default key generation spec is {@code NtruKeyGenSpec.hrss701()}.
     * </p>
     */
    public NtruAlgorithm() {
        super("NTRU", "NTRU (KEM)", BouncyCastlePQCProvider.PROVIDER_NAME);

        // KEM capabilities
        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new NtruKemContext(this, k), () -> VoidSpec.INSTANCE);

        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new NtruKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new NtruKemContext(this, recipient)).asInitiator()
                            .build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new NtruKemContext(this, myPriv)).asResponder()
                            .build();
                }, () -> VoidSpec.INSTANCE);

        // Keypair builder via BCPQC
        registerAsymmetricKeyPairGenerator(NtruKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            /**
             * Generates a new NTRU key pair using the requested parameter set.
             *
             * @param spec NTRU key generation parameters (e.g., HRSS701)
             * @return freshly generated key pair
             * @throws GeneralSecurityException if the provider is missing or initialization
             *                                  fails
             */
            @Override
            public KeyPair generateKeyPair(NtruKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", providerName());
                NTRUParameterSpec params = toParams(spec);
                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, NtruKeyGenSpec::hrss701); // sensible default

        // Public-key import (X.509)
        registerPublicKeyImporter(NtruPublicKeySpec.class, new PublicKeyImporter<>() {

            /**
             * Imports a public key from an X.509 SubjectPublicKeyInfo blob.
             *
             * @param spec holder of the X.509 encoded key bytes
             * @return imported {@link PublicKey}
             * @throws GeneralSecurityException if the provider is missing or decoding fails
             */
            @Override
            public PublicKey importPublic(NtruPublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("NTRU", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        // Private-key import (PKCS#8)
        registerPrivateKeyImporter(NtruPrivateKeySpec.class, new PrivateKeyImporter<>() {

            /**
             * Imports a private key from a PKCS#8 PrivateKeyInfo blob.
             *
             * @param spec holder of the PKCS#8 encoded key bytes
             * @return imported {@link PrivateKey}
             * @throws GeneralSecurityException if the provider is missing or decoding fails
             */
            @Override
            public PrivateKey importPrivate(NtruPrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("NTRU", providerName());
                byte[] encoded = spec.pkcs8();
                try {
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                } finally {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
        });
    }

    /**
     * Maps a high-level NTRU key generation spec to the corresponding Bouncy Castle
     * {@link NTRUParameterSpec}.
     *
     * @param s high-level NTRU key generation spec
     * @return provider parameter set matching {@code s}
     * @throws IllegalArgumentException if the variant is unknown
     */
    private static NTRUParameterSpec toParams(NtruKeyGenSpec s) {
        return switch (s.variant()) {
            case HPS2048_509 -> NTRUParameterSpec.ntruhps2048509;
            case HPS2048_677 -> NTRUParameterSpec.ntruhps2048677;
            case HPS4096_821 -> NTRUParameterSpec.ntruhps4096821;
            case HPS4096_1229 -> NTRUParameterSpec.ntruhps40961229;
            case HRSS701 -> NTRUParameterSpec.ntruhrss701;
            case HRSS1373 -> NTRUParameterSpec.ntruhrss1373;
        };
    }

    /**
     * Ensures the Bouncy Castle PQC provider is available before attempting JCA
     * operations.
     *
     * @throws NoSuchProviderException if
     *                                 {@code BouncyCastlePQCProvider.PROVIDER_NAME}
     *                                 is not registered
     */
    private static void ensureProvider() throws NoSuchProviderException {
        Provider p = Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME);
        if (p == null) {
            throw new NoSuchProviderException(
                    "BouncyCastle PQC provider not found. Add bcpqc-jdk18on to classpath and register it.");
        }
    }
}
