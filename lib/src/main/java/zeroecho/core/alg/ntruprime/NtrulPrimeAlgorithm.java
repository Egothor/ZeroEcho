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
package zeroecho.core.alg.ntruprime;

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
import org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec;

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
 * Configures and exposes the NTRU LPRime post-quantum KEM and a
 * message-agreement adapter backed by the Bouncy Castle PQC provider.
 *
 * <h2>Overview</h2> This algorithm wrapper wires Bouncy Castle's "NTRULPRime"
 * implementation into the ZeroEcho capability model. It registers two KEM
 * capabilities (encapsulation and decapsulation) and maps them to an
 * agreement-style API via a lightweight adapter so that callers can use a
 * single {@code MessageAgreementContext} for both initiator and responder
 * roles.
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li>{@code AlgorithmFamily.KEM / KeyUsage.ENCAPSULATE} - creates a
 * {@code KemContext} bound to a recipient public key.</li>
 * <li>{@code AlgorithmFamily.KEM / KeyUsage.DECAPSULATE} - creates a
 * {@code KemContext} bound to a holder's private key.</li>
 * <li>{@code AlgorithmFamily.AGREEMENT / KeyUsage.AGREEMENT} - provides a
 * {@code MessageAgreementContext} that delegates to a {@code KemContext} for
 * initiator and responder roles.</li>
 * </ul>
 *
 * <h2>Key material</h2> A default asymmetric key builder is registered for
 * {@code NtrulPrimeKeyGenSpec} with {@code ntrulpr1277} as the default variant.
 * Additional import builders are provided for X.509-encoded public keys and
 * PKCS#8-encoded private keys of the same algorithm.
 *
 * <h2>Provider requirements</h2> All key operations rely on
 * {@code BouncyCastlePQCProvider}. The provider must be installed in the
 * current JVM before use, otherwise key generation and import will fail with a
 * {@code NoSuchProviderException}. See {@link #ensureProvider()}.
 *
 * <h2>Example</h2> <pre>{@code
 * // Initialize the algorithm and generate a key pair
 * NtrulPrimeAlgorithm alg = new NtrulPrimeAlgorithm();
 * KeyPair kp = alg.asymmetricKeyPairGenerator(NtrulPrimeKeyGenSpec.class)
 *                 .generateKeyPair(NtrulPrimeKeyGenSpec.ntrulpr761());
 *
 * // Initiator (Alice) encapsulates to Bob's public key
 * MessageAgreementContext alice =
 *     alg.createContext(KeyUsage.AGREEMENT, kp.getPublic(), VoidSpec.INSTANCE);
 *
 * // Responder (Bob) decapsulates with his private key
 * MessageAgreementContext bob =
 *     alg.createContext(KeyUsage.AGREEMENT, kp.getPrivate(), VoidSpec.INSTANCE);
 * }</pre>
 *
 * @see KemContext
 * @see MessageAgreementContext
 * @see NtrulPrimeKeyGenSpec
 * @see VoidSpec
 */
public final class NtrulPrimeAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Creates a new algorithm wrapper for NTRU LPRime and registers its KEM and
     * agreement capabilities, together with key builders for generation and import.
     *
     * <p>
     * The constructor:
     * <ul>
     * <li>Declares the algorithm names used by the provider.</li>
     * <li>Registers KEM encapsulation and decapsulation capabilities.</li>
     * <li>Registers agreement capabilities that delegate to a KEM-based
     * adapter.</li>
     * <li>Registers an asymmetric key builder for {@code NtrulPrimeKeyGenSpec}
     * including the default variant.</li>
     * <li>Registers import builders for X.509 public keys and PKCS#8 private
     * keys.</li>
     * </ul>
     */
    public NtrulPrimeAlgorithm() {
        super("NTRULPRime", "NTRU LPRime", BouncyCastlePQCProvider.PROVIDER_NAME);

        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new NtrulPrimeKemContext(this, k), () -> VoidSpec.INSTANCE);
        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new NtrulPrimeKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new NtrulPrimeKemContext(this, recipient))
                            .asInitiator().build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new NtrulPrimeKemContext(this, myPriv))
                            .asResponder().build();
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(NtrulPrimeKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            @Override
            public KeyPair generateKeyPair(NtrulPrimeKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRULPRime", providerName());
                NTRULPRimeParameterSpec params = switch (spec.variant()) {
                    case NTRULPR653 -> NTRULPRimeParameterSpec.ntrulpr653;
                    case NTRULPR761 -> NTRULPRimeParameterSpec.ntrulpr761;
                    case NTRULPR857 -> NTRULPRimeParameterSpec.ntrulpr857;
                    case NTRULPR953 -> NTRULPRimeParameterSpec.ntrulpr953;
                    case NTRULPR1013 -> NTRULPRimeParameterSpec.ntrulpr1013;
                    case NTRULPR1277 -> NTRULPRimeParameterSpec.ntrulpr1277;
                };
                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, NtrulPrimeKeyGenSpec::ntrulpr1277);

        registerPublicKeyImporter(NtrulPrimePublicKeySpec.class, new PublicKeyImporter<>() {

            @Override
            public PublicKey importPublic(NtrulPrimePublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("NTRULPRime", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        registerPrivateKeyImporter(NtrulPrimePrivateKeySpec.class, new PrivateKeyImporter<>() {

            @Override
            public PrivateKey importPrivate(NtrulPrimePrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("NTRULPRime", providerName());
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
     * Ensures that the Bouncy Castle PQC provider is present in the current
     * {@code Security} providers list.
     *
     * @throws NoSuchProviderException if
     *                                 {@code BouncyCastlePQCProvider.PROVIDER_NAME}
     *                                 is not registered
     */
    private static void ensureProvider() throws NoSuchProviderException {
        Provider p = Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME);
        if (p == null) {
            throw new NoSuchProviderException("BCPQC provider not registered");
        }
    }
}
