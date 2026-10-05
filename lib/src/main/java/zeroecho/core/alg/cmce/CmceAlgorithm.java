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
package zeroecho.core.alg.cmce;

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

import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
 * <h2>Classic McEliece (CMCE) algorithm adapter</h2>
 *
 * <p>
 * Integrates the Bouncy Castle PQC CMCE primitives into the ZeroEcho SPI. This
 * algorithm publishes:
 * </p>
 *
 * <ul>
 * <li><b>KEM</b> capabilities:
 * <ul>
 * <li>{@code ENCAPSULATE} using a recipient {@link PublicKey}.</li>
 * <li>{@code DECAPSULATE} using a {@link PrivateKey}.</li>
 * </ul>
 * </li>
 * <li><b>Agreement</b> capability implemented via a KEM-backed adapter:
 * <ul>
 * <li>Initiator: constructs an agreement context that encapsulates to the peer
 * public key.</li>
 * <li>Responder: constructs an agreement context that decapsulates with the
 * local private key.</li>
 * </ul>
 * </li>
 * <li><b>Asymmetric key builders</b>:
 * <ul>
 * <li>Key generation from {@link CmceKeyGenSpec} variants.</li>
 * <li>Public key import from X.509 bytes.</li>
 * <li>Private key import from PKCS#8 bytes.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <p>
 * <b>Provider requirement:</b> the Bouncy Castle provider must be
 * registered under the standard name {@code "BC"} before use.
 * </p>
 *
 * <p>
 * Usage example:
 * </p>
 * <pre>{@code
 * // Register BC once at startup.
 * Security.addProvider(new BouncyCastleProvider());
 *
 * // Obtain contexts using the CMCE algorithm id.
 * CmceAlgorithm alg = new CmceAlgorithm();
 *
 * // Generate a key pair with a chosen CMCE variant.
 * KeyPair kp = alg.asymmetricKeyPairGenerator(CmceKeyGenSpec.class)
 *                 .generateKeyPair(CmceKeyGenSpec.mceliece8192128f());
 *
 * // Create a KEM encapsulation context with the recipient public key.
 * KemContext enc = alg.createContext(KeyUsage.ENCAPSULATE, kp.getPublic(), VoidSpec.INSTANCE);
 *
 * // Create an agreement initiator context backed by CMCE KEM.
 * MessageAgreementContext initiator =
 *     alg.createContext(KeyUsage.AGREEMENT, kp.getPublic(), VoidSpec.INSTANCE);
 * }</pre>
 *
 * @since 1.0
 */
public final class CmceAlgorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());
    /**
     * Constructs and registers CMCE capabilities and key builders.
     *
     * <p>
     * This constructor registers:
     * </p>
     * <ul>
     * <li>KEM roles for {@code ENCAPSULATE} and {@code DECAPSULATE}.</li>
     * <li>Agreement role wired through a KEM-backed initiator/responder
     * adapter.</li>
     * <li>Asymmetric key builder for {@link CmceKeyGenSpec} (generation), X.509
     * public key import, and PKCS#8 private key import.</li>
     * </ul>
     *
     * <p>
     * The algorithm id is {@code "CMCE"}, the display name is
     * {@code "Classic McEliece (CMCE)"}, and the provider name is taken from the
     * Bouncy Castle provider.
     * </p>
     */
    public CmceAlgorithm() {
        super("CMCE", "Classic McEliece (CMCE)", BouncyCastleProvider.PROVIDER_NAME);

        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new CmceKemContext(this, k), () -> VoidSpec.INSTANCE);
        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new CmceKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new CmceKemContext(this, recipient)).asInitiator()
                            .build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new CmceKemContext(this, myPriv)).asResponder()
                            .build();
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(CmceKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            @Override
            public KeyPair generateKeyPair(CmceKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", providerName());
                CMCEParameterSpec params = switch (spec.variant()) {
                    case MCELIECE_348864, MCELIECE_348864F ->
                        throw new GeneralSecurityException("McEliece-348864 removed in BC 1.86; use 460896 or larger");
                    case MCELIECE_460896 -> CMCEParameterSpec.mceliece460896;
                    case MCELIECE_460896F -> CMCEParameterSpec.mceliece460896f;
                    case MCELIECE_6688128 -> CMCEParameterSpec.mceliece6688128;
                    case MCELIECE_6688128F -> CMCEParameterSpec.mceliece6688128f;
                    case MCELIECE_6960119 -> CMCEParameterSpec.mceliece6960119;
                    case MCELIECE_6960119F -> CMCEParameterSpec.mceliece6960119f;
                    case MCELIECE_8192128 -> CMCEParameterSpec.mceliece8192128;
                    case MCELIECE_8192128F -> CMCEParameterSpec.mceliece8192128f;
                };
                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, CmceKeyGenSpec::mceliece8192128f);

        registerPublicKeyImporter(CmcePublicKeySpec.class, new PublicKeyImporter<>() {

            @Override
            public PublicKey importPublic(CmcePublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("CMCE", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        registerPrivateKeyImporter(CmcePrivateKeySpec.class, new PrivateKeyImporter<>() {

            @Override
            public PrivateKey importPrivate(CmcePrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("CMCE", providerName());
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
        Provider p = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (p == null) {
            throw new NoSuchProviderException("BC provider not registered");
        }
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        // MCELIECE_348864 and MCELIECE_348864F are excluded: removed in BC 1.86.
        return List.of(
            new ParameterSetDescriptor.Concrete<>("CMCE-460896",   "McEliece 460896",   SecurityLevel.classical(192), CmceKeyGenSpec.of(CmceKeyGenSpec.Variant.MCELIECE_460896)),
            new ParameterSetDescriptor.Concrete<>("CMCE-460896F",  "McEliece 460896f",  SecurityLevel.classical(192), CmceKeyGenSpec.of(CmceKeyGenSpec.Variant.MCELIECE_460896F)),
            new ParameterSetDescriptor.Concrete<>("CMCE-6688128",  "McEliece 6688128",  SecurityLevel.classical(256), CmceKeyGenSpec.of(CmceKeyGenSpec.Variant.MCELIECE_6688128)),
            new ParameterSetDescriptor.Concrete<>("CMCE-6688128F", "McEliece 6688128f", SecurityLevel.classical(256), CmceKeyGenSpec.of(CmceKeyGenSpec.Variant.MCELIECE_6688128F)),
            new ParameterSetDescriptor.Concrete<>("CMCE-6960119",  "McEliece 6960119",  SecurityLevel.classical(256), CmceKeyGenSpec.of(CmceKeyGenSpec.Variant.MCELIECE_6960119)),
            new ParameterSetDescriptor.Concrete<>("CMCE-6960119F", "McEliece 6960119f", SecurityLevel.classical(256), CmceKeyGenSpec.of(CmceKeyGenSpec.Variant.MCELIECE_6960119F)),
            new ParameterSetDescriptor.Concrete<>("CMCE-8192128",  "McEliece 8192128",  SecurityLevel.classical(256), CmceKeyGenSpec.of(CmceKeyGenSpec.Variant.MCELIECE_8192128)),
            new ParameterSetDescriptor.Concrete<>("CMCE-8192128F", "McEliece 8192128f", SecurityLevel.classical(256), CmceKeyGenSpec.of(CmceKeyGenSpec.Variant.MCELIECE_8192128F))
        );
    }

}
