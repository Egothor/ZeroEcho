/* *****************************************************************************
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
package zeroecho.core.alg.bike;

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

import java.util.List;

import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.SecurityLevel;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;

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
 * <h2>Integration of BIKE (Bit Flipping Key Encapsulation) algorithm</h2>
 *
 * Declares BIKE as a {@link zeroecho.core.alg.AbstractCryptoAlgorithm} and
 * registers its supported roles, contexts, and key builders within the ZeroEcho
 * framework.
 *
 * <h3>Capabilities</h3>
 * <ul>
 * <li><b>KEM</b> - encapsulation and decapsulation of shared secrets using
 * public and private keys.</li>
 * <li><b>Agreement</b> - initiator and responder flows for
 * {@link MessageAgreementContext} built on top of BIKE KEM.</li>
 * <li><b>Asymmetric key builders</b> - generation and import of BIKE keys from
 * {@link BikeKeyGenSpec}, {@link BikePublicKeySpec}, and
 * {@link BikePrivateKeySpec}.</li>
 * </ul>
 *
 * <h3>Provider</h3> Uses the BouncyCastle Post-Quantum provider
 * ({@code BCPQC}). The provider must be registered in the JCA {@link Security}
 * before use.
 *
 * <h3>Example</h3> <pre>{@code
 * BikeAlgorithm bike = new BikeAlgorithm();
 *
 * // Generate a key pair
 * KeyPair kp = bike.asymmetricKeyPairGenerator(BikeKeyGenSpec.class)
 *                  .generateKeyPair(BikeKeyGenSpec.bike256());
 *
 * // Encapsulation using recipient's public key
 * KemContext kemEnc = bike.createContext(KeyUsage.ENCAPSULATE, kp.getPublic(), VoidSpec.INSTANCE);
 *
 * // Decapsulation using private key
 * KemContext kemDec = bike.createContext(KeyUsage.DECAPSULATE, kp.getPrivate(), VoidSpec.INSTANCE);
 * }</pre>
 *
 * @since 1.0
 */
public final class BikeAlgorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());
    /**
     * Constructs and registers the BIKE algorithm with all its roles and key
     * builders.
     *
     * <p>
     * Registers:
     * </p>
     * <ul>
     * <li>KEM (encapsulate/decapsulate)</li>
     * <li>Agreement (initiator/responder)</li>
     * <li>Asymmetric key builders for BIKE key specifications</li>
     * </ul>
     */
    public BikeAlgorithm() {
        super("BIKE", "BIKE", BouncyCastlePQCProvider.PROVIDER_NAME);

        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new BikeKemContext(this, k), () -> VoidSpec.INSTANCE);
        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new BikeKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new BikeKemContext(this, recipient)).asInitiator()
                            .build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new BikeKemContext(this, myPriv)).asResponder()
                            .build();
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(BikeKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            @Override
            public KeyPair generateKeyPair(BikeKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("BIKE", providerName());
                BIKEParameterSpec params = switch (spec.variant()) {
                    case BIKE_128 -> BIKEParameterSpec.bike128;
                    case BIKE_192 -> BIKEParameterSpec.bike192;
                    case BIKE_256 -> BIKEParameterSpec.bike256;
                };
                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, BikeKeyGenSpec::bike256);

        registerPublicKeyImporter(BikePublicKeySpec.class, new PublicKeyImporter<>() {

            @Override
            public PublicKey importPublic(BikePublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("BIKE", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        registerPrivateKeyImporter(BikePrivateKeySpec.class, new PrivateKeyImporter<>() {

            @Override
            public PrivateKey importPrivate(BikePrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("BIKE", providerName());
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
     * Ensures that the BouncyCastle Post-Quantum provider is available.
     *
     * @throws NoSuchProviderException if the provider is not registered in
     *                                 {@link Security}
     */
    private static void ensureProvider() throws NoSuchProviderException {
        Provider p = Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME);
        if (p == null) {
            throw new NoSuchProviderException("BCPQC provider not registered");
        }
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>("BIKE-128", "BIKE-128 (NIST Level 1)", SecurityLevel.nist(1, 128), BikeKeyGenSpec.bike128()),
            new ParameterSetDescriptor.Concrete<>("BIKE-192", "BIKE-192 (NIST Level 3)", SecurityLevel.nist(3, 192), BikeKeyGenSpec.bike192()),
            new ParameterSetDescriptor.Concrete<>("BIKE-256", "BIKE-256 (NIST Level 5)", SecurityLevel.nist(5, 256), BikeKeyGenSpec.bike256())
        );
    }

}
