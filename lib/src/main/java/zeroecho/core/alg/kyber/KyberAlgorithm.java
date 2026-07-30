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
package zeroecho.core.alg.kyber;

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
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

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
 * Concrete CryptoAlgorithm implementation for the post-quantum key
 * encapsulation mechanism (KEM) Kyber, standardized as ML-KEM.
 *
 * <h2>Overview</h2> Kyber provides IND-CCA2 security based on module-LWE. This
 * implementation delegates cryptographic operations to the Bouncy Castle PQC
 * provider and exposes Kyber through the unified CryptoAlgorithm API surface.
 *
 * <h2>Declared capabilities</h2>
 * <ul>
 * <li>AlgorithmFamily.KEM:
 * <ul>
 * <li>KeyUsage.ENCAPSULATE with a PublicKey, returning a KemContext.</li>
 * <li>KeyUsage.DECAPSULATE with a PrivateKey, returning a KemContext.</li>
 * </ul>
 * </li>
 * <li>AlgorithmFamily.AGREEMENT (message-based):
 * <ul>
 * <li>Initiator: given the recipient PublicKey, wraps a Kyber KEM context in a
 * KemMessageAgreementAdapter to drive message agreement.</li>
 * <li>Responder: given the local PrivateKey, wraps a Kyber KEM context in the
 * same adapter to decapsulate and agree the shared secret.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Key builders</h2>
 * <ul>
 * <li>KyberKeyGenSpec: key pair generation for variants {@code KYBER512},
 * {@code KYBER768}, and {@code KYBER1024} via KeyPairGenerator configured with
 * KyberParameterSpec.</li>
 * <li>KyberPublicKeySpec: import of Kyber public keys from X.509
 * SubjectPublicKeyInfo.</li>
 * <li>KyberPrivateKeySpec: import of Kyber private keys from PKCS#8
 * PrivateKeyInfo.</li>
 * </ul>
 *
 * <h2>Provider dependency</h2> All operations require the Bouncy Castle PQC
 * provider to be present and registered in java.security.Security under the
 * name provided by BouncyCastlePQCProvider. The helper ensureProvider()
 * validates availability before key generation or import.
 *
 * <h2>Thread-safety</h2> Instances of KyberAlgorithm are immutable and safe to
 * share. Contexts created via the declared capabilities (KemContext,
 * MessageAgreementContext) are not necessarily thread-safe.
 *
 * <h2>Usage examples</h2> <pre>{@code
 * // Register provider once during bootstrap:
 * Security.addProvider(new BouncyCastlePQCProvider());
 *
 * // Construct the algorithm:
 * KyberAlgorithm kyber = new KyberAlgorithm();
 *
 * // Generate a Kyber-768 key pair:
 * KeyPair kp = kyber.asymmetricKeyPairGenerator(KyberKeyGenSpec.class)
 *                   .generateKeyPair(KyberKeyGenSpec.kyber768());
 *
 * // Encapsulation by initiator (recipient public key known):
 * KemContext enc = kyber.createContext(KeyUsage.ENCAPSULATE, kp.getPublic(), VoidSpec.INSTANCE);
 *
 * // Decapsulation by responder (own private key):
 * KemContext dec = kyber.createContext(KeyUsage.DECAPSULATE, kp.getPrivate(), VoidSpec.INSTANCE);
 *
 * // Message-style agreement (initiator):
 * MessageAgreementContext initCtx =
 *     kyber.createContext(KeyUsage.AGREEMENT, kp.getPublic(), VoidSpec.INSTANCE);
 *
 * // Message-style agreement (responder):
 * MessageAgreementContext respCtx =
 *     kyber.createContext(KeyUsage.AGREEMENT, kp.getPrivate(), VoidSpec.INSTANCE);
 * }</pre>
 */
public final class KyberAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Provides ML-KEM (Kyber) integration backed by the Bouncy Castle PQC provider
     * and registers capabilities and key builders required for KEM usage and
     * message agreement.
     *
     * <h4>Overview</h4>
     * <p>
     * This algorithm instance wires the following into the surrounding crypto
     * framework:
     * </p>
     * <ul>
     * <li>KEM roles: ENCAPSULATE with {@link java.security.PublicKey} and
     * DECAPSULATE with {@link java.security.PrivateKey}.</li>
     * <li>AGREEMENT role via {@code KemMessageAgreementAdapter} for initiator and
     * responder flows, reusing the underlying KEM context.</li>
     * <li>Asymmetric key builders for {@code KyberKeyGenSpec} generation and
     * X.509/PKCS#8 key import paths.</li>
     * </ul>
     *
     * <h4>Example</h4> <pre>{@code
     * Security.addProvider(new BouncyCastlePQCProvider());
     * KyberAlgorithm alg = new KyberAlgorithm();
     *
     * KeyPair kp = alg.asymmetricKeyPairGenerator(KyberKeyGenSpec.class)
     *                 .generateKeyPair(KyberKeyGenSpec.kyber768());
     * }</pre>
     */
    public KyberAlgorithm() {
        super("ML-KEM", "Kyber (ML-KEM)", BouncyCastlePQCProvider.PROVIDER_NAME);

        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new KyberKemContext(this, k), () -> VoidSpec.INSTANCE);

        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new KyberKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new KyberKemContext(this, recipient)).asInitiator()
                            .build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new KyberKemContext(this, myPriv)).asResponder()
                            .build();
                }, () -> VoidSpec.INSTANCE);

        // Keypair builder via BCPQC
        registerAsymmetricKeyPairGenerator(KyberKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            /**
             * Generates a Kyber key pair for the variant defined by the provided spec.
             *
             * @param spec the key generation spec selecting the Kyber variant.
             * @return a newly generated Kyber key pair.
             * @throws GeneralSecurityException if the provider is unavailable or key
             *                                  generation fails.
             */
            @Override
            public KeyPair generateKeyPair(KyberKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", providerName());
                KyberParameterSpec params = toParams(spec);
                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, KyberKeyGenSpec::kyber768);

        // Public-key import (X.509)
        registerPublicKeyImporter(KyberPublicKeySpec.class, new PublicKeyImporter<>() {

            /**
             * Imports a Kyber public key from an X.509 SubjectPublicKeyInfo encoding.
             *
             * @param spec the public key spec carrying X.509-encoded bytes.
             * @return the decoded Kyber public key.
             * @throws GeneralSecurityException if the provider is unavailable or the key
             *                                  cannot be decoded.
             */
            @Override
            public PublicKey importPublic(KyberPublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider(); // your existing helper
                // Pick the same algorithm/provider you use for keygen
                KeyFactory kf = KeyFactory.getInstance("Kyber", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        // Private-key import (PKCS#8)
        registerPrivateKeyImporter(KyberPrivateKeySpec.class, new PrivateKeyImporter<>() {

            /**
             * Imports a Kyber private key from a PKCS#8 PrivateKeyInfo encoding.
             *
             * @param spec the private key spec carrying PKCS#8-encoded bytes.
             * @return the decoded Kyber private key.
             * @throws GeneralSecurityException if the provider is unavailable or the key
             *                                  cannot be decoded.
             */
            @Override
            public PrivateKey importPrivate(KyberPrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("Kyber", providerName());
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
     * Maps a {@code KyberKeyGenSpec} to the corresponding
     * {@code KyberParameterSpec} constant.
     *
     * <h2>Example</h2> <pre>{@code
     * KyberParameterSpec params = KyberAlgorithm.toParams(KyberKeyGenSpec.kyber512());
     * }</pre>
     *
     * @param s key generation spec carrying the chosen Kyber variant.
     * @return the provider parameter set that matches the requested variant.
     * @throws IllegalArgumentException if the variant is not recognized.
     */
    private static KyberParameterSpec toParams(KyberKeyGenSpec s) {
        return switch (s.variant()) {
            case KYBER512 -> KyberParameterSpec.kyber512;
            case KYBER768 -> KyberParameterSpec.kyber768;
            case KYBER1024 -> KyberParameterSpec.kyber1024;
        };
    }

    /**
     * Ensures that the Bouncy Castle PQC provider is registered before accessing
     * JCA primitives.
     *
     * <p>
     * This method is a defensive check used by key generation and key import
     * implementations. It fails fast when the required provider is not available.
     * </p>
     *
     * <h2>Example</h2> <pre>{@code
     * Security.addProvider(new BouncyCastlePQCProvider());
     * KyberAlgorithm.ensureProvider(); // returns silently if available
     * }</pre>
     *
     * @throws NoSuchProviderException if the Bouncy Castle PQC provider is not
     *                                 present.
     */
    private static void ensureProvider() throws NoSuchProviderException {
        // Ensure BCPQC is registered; caller can add Security.addProvider in bootstrap
        // if desired.
        Provider p = Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME);
        if (p == null) {
            throw new NoSuchProviderException(
                    "BouncyCastle PQC provider not found. Add bcpqc-jdk18on to classpath and register provider.");
        }
    }
}
