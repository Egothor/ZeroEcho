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

import java.util.List;

import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.SecurityLevel;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;

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
 * Configures and exposes the SNTRU Prime post-quantum KEM and a
 * message-agreement adapter backed by the Bouncy Castle PQC provider.
 *
 * <h2>Overview</h2> This algorithm wrapper integrates Bouncy Castle's
 * {@code "SNTRUPrime"} implementation into the ZeroEcho capability model. It
 * registers two KEM capabilities (encapsulation and decapsulation) and maps
 * them to an agreement-style API via a lightweight adapter so that callers can
 * use a single {@code MessageAgreementContext} for both initiator and responder
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
 * {@code SntruPrimeKeyGenSpec} with {@code sntrup1277} as the default variant.
 * Additional import builders are provided for X.509-encoded public keys and
 * PKCS#8-encoded private keys.
 *
 * <h2>Provider requirements</h2> All key operations rely on
 * {@code BouncyCastlePQCProvider}. The provider must be installed in the
 * current JVM before use, otherwise key generation and import will fail with a
 * {@code NoSuchProviderException}. See {@link #ensureProvider()}.
 *
 * <h2>Example</h2> <pre>{@code
 * // Initialize the algorithm and generate a key pair
 * SntruPrimeAlgorithm alg = new SntruPrimeAlgorithm();
 * KeyPair kp = alg.asymmetricKeyPairGenerator(SntruPrimeKeyGenSpec.class)
 *                 .generateKeyPair(SntruPrimeKeyGenSpec.sntrup761());
 *
 * // Initiator (Alice) encapsulates to Bob's public key
 * MessageAgreementContext alice = alg
 *     .context(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class,
 *              kp.getPublic(), VoidSpec.INSTANCE);
 *
 * // Responder (Bob) decapsulates with his private key
 * MessageAgreementContext bob = alg
 *     .context(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class,
 *              kp.getPrivate(), VoidSpec.INSTANCE);
 * }</pre>
 *
 * @see KemContext
 * @see MessageAgreementContext
 * @see SntruPrimeKeyGenSpec
 * @see VoidSpec
 */
public final class SntruPrimeAlgorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());
    /**
     * Creates a new algorithm wrapper for SNTRU Prime and registers its KEM and
     * agreement capabilities, together with key builders for generation and import.
     *
     * <p>
     * The constructor:
     * <ul>
     * <li>Declares the algorithm names used by the provider.</li>
     * <li>Registers KEM encapsulation and decapsulation capabilities.</li>
     * <li>Registers agreement capabilities that delegate to a KEM-based
     * adapter.</li>
     * <li>Registers an asymmetric key builder for {@code SntruPrimeKeyGenSpec}
     * including the default {@code sntrup1277} variant.</li>
     * <li>Registers import builders for X.509 public keys and PKCS#8 private
     * keys.</li>
     * </ul>
     */
    public SntruPrimeAlgorithm() {
        super("SNTRUPrime", "SNTRU Prime", BouncyCastlePQCProvider.PROVIDER_NAME);

        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new SntruPrimeKemContext(this, k), () -> VoidSpec.INSTANCE);
        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new SntruPrimeKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new SntruPrimeKemContext(this, recipient))
                            .asInitiator().build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new SntruPrimeKemContext(this, myPriv))
                            .asResponder().build();
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(SntruPrimeKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            @Override
            public KeyPair generateKeyPair(SntruPrimeKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", providerName());

                SNTRUPrimeParameterSpec params = switch (spec.variant()) {
                    case SNTRUP653 -> SNTRUPrimeParameterSpec.sntrup653;
                    case SNTRUP761 -> SNTRUPrimeParameterSpec.sntrup761;
                    case SNTRUP857 -> SNTRUPrimeParameterSpec.sntrup857;
                    case SNTRUP953 -> SNTRUPrimeParameterSpec.sntrup953;
                    case SNTRUP1013 -> SNTRUPrimeParameterSpec.sntrup1013;
                    case SNTRUP1277 -> SNTRUPrimeParameterSpec.sntrup1277;
                };
                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, SntruPrimeKeyGenSpec::sntrup1277);

        registerPublicKeyImporter(SntruPrimePublicKeySpec.class, new PublicKeyImporter<>() {

            @Override
            public PublicKey importPublic(SntruPrimePublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("SNTRUPrime", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        registerPrivateKeyImporter(SntruPrimePrivateKeySpec.class, new PrivateKeyImporter<>() {

            @Override
            public PrivateKey importPrivate(SntruPrimePrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("SNTRUPrime", providerName());
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

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>("SNTRUP653",  "SNTRU Prime 653 (128-bit)",  SecurityLevel.classical(128), SntruPrimeKeyGenSpec.of(SntruPrimeKeyGenSpec.Variant.SNTRUP653)),
            new ParameterSetDescriptor.Concrete<>("SNTRUP761",  "SNTRU Prime 761 (128-bit)",  SecurityLevel.classical(128), SntruPrimeKeyGenSpec.of(SntruPrimeKeyGenSpec.Variant.SNTRUP761)),
            new ParameterSetDescriptor.Concrete<>("SNTRUP857",  "SNTRU Prime 857 (192-bit)",  SecurityLevel.classical(192), SntruPrimeKeyGenSpec.of(SntruPrimeKeyGenSpec.Variant.SNTRUP857)),
            new ParameterSetDescriptor.Concrete<>("SNTRUP953",  "SNTRU Prime 953 (192-bit)",  SecurityLevel.classical(192), SntruPrimeKeyGenSpec.of(SntruPrimeKeyGenSpec.Variant.SNTRUP953)),
            new ParameterSetDescriptor.Concrete<>("SNTRUP1013", "SNTRU Prime 1013 (192-bit)", SecurityLevel.classical(192), SntruPrimeKeyGenSpec.of(SntruPrimeKeyGenSpec.Variant.SNTRUP1013)),
            new ParameterSetDescriptor.Concrete<>("SNTRUP1277", "SNTRU Prime 1277 (256-bit)", SecurityLevel.classical(256), SntruPrimeKeyGenSpec.of(SntruPrimeKeyGenSpec.Variant.SNTRUP1277))
        );
    }

}
