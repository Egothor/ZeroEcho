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
package zeroecho.core.alg.hqc;

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
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;

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
 * <h2>HQC (Hamming Quasi-Cyclic) Algorithm Integration</h2>
 *
 * Concrete {@link zeroecho.core.CryptoAlgorithm} implementation for the
 * post-quantum key encapsulation mechanism (KEM) HQC, as defined in the NIST
 * PQC standardization process.
 *
 * <p>
 * HQC is based on error-correcting codes and offers IND-CCA2 security against
 * quantum adversaries. This implementation delegates to the
 * {@code BouncyCastlePQCProvider} for actual cryptographic operations and
 * exposes HQC through the unified {@code CryptoAlgorithm} API surface.
 * </p>
 *
 * <h2>Declared capabilities</h2>
 * <ul>
 * <li>{@link zeroecho.core.AlgorithmFamily#KEM}:
 * <ul>
 * <li>{@link zeroecho.core.KeyUsage#ENCAPSULATE} with a
 * {@link java.security.PublicKey}, returning a
 * {@link zeroecho.core.context.KemContext}.</li>
 * <li>{@link zeroecho.core.KeyUsage#DECAPSULATE} with a
 * {@link java.security.PrivateKey}, returning a
 * {@link zeroecho.core.context.KemContext}.</li>
 * </ul>
 * </li>
 * <li>{@link zeroecho.core.AlgorithmFamily#AGREEMENT} (message-based):
 * <ul>
 * <li>Initiator: given recipient's {@link java.security.PublicKey}, wraps an
 * HQC KEM context in a
 * {@link zeroecho.core.alg.common.agreement.KemMessageAgreementAdapter}.</li>
 * <li>Responder: given own {@link java.security.PrivateKey}, wraps an HQC KEM
 * context in a {@code KemMessageAgreementAdapter}.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Key builders</h2>
 * <ul>
 * <li>{@link zeroecho.core.alg.hqc.HqcKeyGenSpec}: supports generation of key
 * pairs for the {@code HQC-128}, {@code HQC-192}, and {@code HQC-256} parameter
 * sets, via BouncyCastle's {@link java.security.KeyPairGenerator}.</li>
 * <li>{@link zeroecho.core.alg.hqc.HqcPublicKeySpec}: supports import of HQC
 * public keys from X.509-encoded form.</li>
 * <li>{@link zeroecho.core.alg.hqc.HqcPrivateKeySpec}: supports import of HQC
 * private keys from PKCS#8-encoded form.</li>
 * </ul>
 *
 * <h2>Provider dependency</h2>
 * <p>
 * All operations require the Bouncy Castle PQC provider
 * ({@code BouncyCastlePQCProvider}) to be registered in
 * {@link java.security.Security}. The private helper {@link #ensureProvider()}
 * validates provider availability before key generation or import.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances of {@code HqcAlgorithm} are immutable and safe to share. Contexts
 * created via capabilities (e.g., {@code KemContext},
 * {@code MessageAgreementContext}) are not necessarily thread-safe.
 * </p>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Generate an HQC key pair
 * HqcAlgorithm hqc = new HqcAlgorithm();
 * KeyPair kp = hqc.asymmetricKeyPairGenerator(HqcKeyGenSpec.class)
 *                  .generateKeyPair(HqcKeyGenSpec.hqc256());
 *
 * // Encapsulation by initiator
 * KemContext encapsCtx = hqc.createContext(KeyUsage.ENCAPSULATE, kp.getPublic(), VoidSpec.INSTANCE);
 *
 * // Decapsulation by responder
 * KemContext decapsCtx = hqc.createContext(KeyUsage.DECAPSULATE, kp.getPrivate(), VoidSpec.INSTANCE);
 * }</pre>
 *
 * @since 1.0
 */
public final class HqcAlgorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());
    /**
     * Constructs and registers the HQC algorithm with the BouncyCastle PQC
     * provider.
     *
     * <p>
     * During construction this algorithm:
     * </p>
     * <ul>
     * <li>Registers KEM encapsulation/decapsulation capabilities bound to
     * {@link java.security.PublicKey} and {@link java.security.PrivateKey}
     * respectively.</li>
     * <li>Registers message-based agreement roles (initiator/responder) using
     * {@link zeroecho.core.alg.common.agreement.KemMessageAgreementAdapter}
     * wrappers.</li>
     * <li>Registers asymmetric key builders for:
     * <ul>
     * <li>{@link zeroecho.core.alg.hqc.HqcKeyGenSpec} (for fresh key
     * generation),</li>
     * <li>{@link zeroecho.core.alg.hqc.HqcPublicKeySpec} (for importing X.509
     * public keys),</li>
     * <li>{@link zeroecho.core.alg.hqc.HqcPrivateKeySpec} (for importing PKCS#8
     * private keys).</li>
     * </ul>
     * </li>
     * </ul>
     *
     * <p>
     * The default key generation spec is
     * {@link zeroecho.core.alg.hqc.HqcKeyGenSpec#hqc256()}, corresponding to the
     * HQC-256 parameter set.
     * </p>
     *
     * @throws java.lang.IllegalStateException if BouncyCastle PQC provider is
     *                                         missing at runtime
     */
    public HqcAlgorithm() {
        super("HQC", "HQC", BouncyCastlePQCProvider.PROVIDER_NAME);

        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new HqcKemContext(this, k), () -> VoidSpec.INSTANCE);
        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new HqcKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new HqcKemContext(this, recipient)).asInitiator()
                            .build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new HqcKemContext(this, myPriv)).asResponder()
                            .build();
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(HqcKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            @Override
            public KeyPair generateKeyPair(HqcKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC", providerName());
                HQCParameterSpec params = switch (spec.variant()) {
                    case HQC_128 -> HQCParameterSpec.hqc128;
                    case HQC_192 -> HQCParameterSpec.hqc192;
                    case HQC_256 -> HQCParameterSpec.hqc256;
                };
                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, HqcKeyGenSpec::hqc256);

        registerPublicKeyImporter(HqcPublicKeySpec.class, new PublicKeyImporter<>() {

            @Override
            public PublicKey importPublic(HqcPublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("HQC", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        registerPrivateKeyImporter(HqcPrivateKeySpec.class, new PrivateKeyImporter<>() {

            @Override
            public PrivateKey importPrivate(HqcPrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("HQC", providerName());
                byte[] encoded = spec.pkcs8();
                try {
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                } finally {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
        });
    }

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
            new ParameterSetDescriptor.Concrete<>("HQC-128", "HQC-128 (NIST Level 1)", SecurityLevel.nist(1, 128), HqcKeyGenSpec.hqc128()),
            new ParameterSetDescriptor.Concrete<>("HQC-192", "HQC-192 (NIST Level 3)", SecurityLevel.nist(3, 192), HqcKeyGenSpec.hqc192()),
            new ParameterSetDescriptor.Concrete<>("HQC-256", "HQC-256 (NIST Level 5)", SecurityLevel.nist(5, 256), HqcKeyGenSpec.hqc256())
        );
    }

}
