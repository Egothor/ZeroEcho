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
package zeroecho.core.alg.elgamal;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
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

import org.bouncycastle.jce.spec.ElGamalParameterSpec;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * <h2>ElGamal Asymmetric Encryption Algorithm</h2>
 *
 * Concrete {@link zeroecho.core.CryptoAlgorithm} for the ElGamal public-key
 * encryption scheme.
 *
 * <p>
 * ElGamal is an asymmetric cryptosystem based on the hardness of the discrete
 * logarithm problem in a finite cyclic group. It provides semantic security
 * under chosen-plaintext attacks when combined with proper padding (e.g.,
 * PKCS#1 style). This implementation delegates to the Bouncy Castle provider
 * ({@code "BC"}) for underlying primitives and parameter generation.
 * </p>
 * 
 * <p>
 * <b>Note:</b> OAEP is not offered for ElGamal; for modern IND-CCA security
 * prefer KEM or KEM-DEM constructions such as DHIES, ECIES, or Cramer-Shoup, or
 * use a KEM provided elsewhere in the catalog.
 * </p>
 * 
 * <h2>Declared capabilities</h2>
 * <ul>
 * <li>{@link zeroecho.core.KeyUsage#ENCRYPT} using a
 * {@link java.security.PublicKey} and producing an
 * {@link zeroecho.core.context.EncryptionContext}.</li>
 * <li>{@link zeroecho.core.KeyUsage#DECRYPT} using a
 * {@link java.security.PrivateKey} and producing an
 * {@link zeroecho.core.context.EncryptionContext}.</li>
 * </ul>
 *
 * <h2>Key material</h2>
 * <ul>
 * <li>{@link ElgamalParamSpec} - wrapper for explicit ElGamal group/domain
 * parameters. Registered with a default of
 * {@link ElgamalParamSpec#ffdhe2048()}.</li>
 * <li>{@link ElgamalPublicKeySpec} - X.509-encoded public key import.</li>
 * <li>{@link ElgamalPrivateKeySpec} - PKCS#8-encoded private key import.</li>
 * <li>{@code ElgamalKeyGenSpec} is supported but disabled by default because
 * parameter generation is slow; prefer reusing standardized
 * {@link ElgamalParamSpec} instances.</li>
 * </ul>
 *
 * <h2>Provider requirements</h2> This implementation requires the Bouncy Castle
 * JCE provider to be registered under the name {@code "BC"}. If unavailable,
 * {@link #ensureBC()} will throw a
 * {@link java.security.NoSuchProviderException}.
 *
 * <h2>Thread-safety</h2> Instances of {@code ElgamalAlgorithm} are immutable
 * and may be safely shared across threads. Generated
 * {@link zeroecho.core.context.CryptoContext} instances are not necessarily
 * thread-safe.
 *
 * <h2>Example</h2> <pre>{@code
 * CryptoAlgorithm algo = new ElgamalAlgorithm();
 * KeyPair kp = algo.generateKeyPair(ElgamalParamSpec.ffdhe2048());
 *
 * EncryptionContext enc = algo.create(KeyUsage.ENCRYPT, kp.getPublic(),
 *                                     ElgamalEncSpec.pkcs1());
 * EncryptionContext dec = algo.create(KeyUsage.DECRYPT, kp.getPrivate(),
 *                                     ElgamalEncSpec.pkcs1());
 * }</pre>
 *
 * @since 1.0
 */
public final class ElgamalAlgorithm extends AbstractCryptoAlgorithm {
    private static final String EL_GAMAL = "ElGamal";

    /**
     * Constructs a new ElGamal algorithm instance bound to the {@code "ElGamal"}
     * identifier and backed by the Bouncy Castle provider.
     *
     * <p>
     * During construction, the algorithm registers:
     * <ul>
     * <li>Encryption and decryption capabilities,</li>
     * <li>Key builders for parameter-based, public, and private key specs,</li>
     * <li>Default parameter spec suppliers (e.g., ffdhe2048).</li>
     * </ul>
     */
    @SuppressWarnings("unused")
    public ElgamalAlgorithm() {
        super(EL_GAMAL, EL_GAMAL, "BC");

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.ENCRYPT, EncryptionContext.class, PublicKey.class,
                ElgamalEncSpec.class, (PublicKey k, ElgamalEncSpec s) -> new ElgamalCipherContext(this, k, s, true),
                ElgamalEncSpec::pkcs1);
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.DECRYPT, EncryptionContext.class, PrivateKey.class,
                ElgamalEncSpec.class, (PrivateKey k, ElgamalEncSpec s) -> new ElgamalCipherContext(this, k, s, false),
                ElgamalEncSpec::pkcs1);

        if (false) { // NOPMD
            // this key generation is slow
            registerAsymmetricKeyBuilder(ElgamalKeyGenSpec.class, new AsymmetricKeyBuilder<>() {
                @Override
                public KeyPair generateKeyPair(ElgamalKeyGenSpec spec) throws GeneralSecurityException {
                    ensureBC();
                    AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(EL_GAMAL, providerName());
                    apg.init(spec.keySize(), new SecureRandom());
                    AlgorithmParameters ap = apg.generateParameters();
                    ElGamalParameterSpec eg = ap.getParameterSpec(ElGamalParameterSpec.class);

                    KeyPairGenerator kpg = KeyPairGenerator.getInstance(EL_GAMAL, providerName());
                    kpg.initialize(eg, new SecureRandom());
                    return kpg.generateKeyPair();
                }

                @Override
                public PublicKey importPublic(ElgamalKeyGenSpec spec) {
                    throw new UnsupportedOperationException("Use ElgamalPublicKeySpec to import a public key.");
                }

                @Override
                public PrivateKey importPrivate(ElgamalKeyGenSpec spec) {
                    throw new UnsupportedOperationException("Use ElgamalPrivateKeySpec to import a private key.");
                }
            }, ElgamalKeyGenSpec::elgamal2048);
        }

        registerAsymmetricKeyBuilder(ElgamalParamSpec.class, new AsymmetricKeyBuilder<>() {
            @Override
            public KeyPair generateKeyPair(ElgamalParamSpec spec) throws GeneralSecurityException {
                ensureBC();
                ElGamalParameterSpec eg = spec.parameters();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(EL_GAMAL, providerName());
                kpg.initialize(eg, new SecureRandom());
                return kpg.generateKeyPair();
            }

            @Override
            public PublicKey importPublic(ElgamalParamSpec spec) {
                throw new UnsupportedOperationException("Use ElgamalPublicKeySpec to import a public key.");
            }

            @Override
            public PrivateKey importPrivate(ElgamalParamSpec spec) {
                throw new UnsupportedOperationException("Use ElgamalPrivateKeySpec to import a private key.");
            }
        }, ElgamalParamSpec::ffdhe2048);

        registerAsymmetricKeyBuilder(ElgamalPublicKeySpec.class, new AsymmetricKeyBuilder<>() {
            @Override
            public KeyPair generateKeyPair(ElgamalPublicKeySpec spec) {
                throw new UnsupportedOperationException("Generation not supported for encoded spec.");
            }

            @Override
            public PublicKey importPublic(ElgamalPublicKeySpec spec) throws GeneralSecurityException {
                ensureBC();
                KeyFactory kf = KeyFactory.getInstance(EL_GAMAL, providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.encoded()));
            }

            @Override
            public PrivateKey importPrivate(ElgamalPublicKeySpec spec) {
                throw new UnsupportedOperationException("Use ElgamalPrivateKeySpec for private keys.");
            }
        }, null);

        registerAsymmetricKeyBuilder(ElgamalPrivateKeySpec.class, new AsymmetricKeyBuilder<>() {
            @Override
            public KeyPair generateKeyPair(ElgamalPrivateKeySpec spec) {
                throw new UnsupportedOperationException("Generation not supported for encoded spec.");
            }

            @Override
            public PublicKey importPublic(ElgamalPrivateKeySpec spec) {
                throw new UnsupportedOperationException("Use ElgamalPublicKeySpec for public keys.");
            }

            @Override
            public PrivateKey importPrivate(ElgamalPrivateKeySpec spec) throws GeneralSecurityException {
                ensureBC();
                KeyFactory kf = KeyFactory.getInstance(EL_GAMAL, providerName());
                return kf.generatePrivate(new PKCS8EncodedKeySpec(spec.encoded()));
            }
        }, null);
    }

    /**
     * Ensures that the Bouncy Castle provider is available.
     *
     * @throws java.security.NoSuchProviderException if the provider {@code "BC"} is
     *                                               not registered with the JCA
     */
    private static void ensureBC() throws NoSuchProviderException {
        Provider p = Security.getProvider("BC");
        if (p == null) {
            throw new NoSuchProviderException("Bouncy Castle provider (BC) not registered");
        }
    }
}
