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
package zeroecho.core.alg.saber;

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
 * Implements the SABER post-quantum key encapsulation mechanism for the crypto
 * catalog and wires it to the Bouncy Castle PQC provider.
 *
 * <h2>Capabilities</h2> This algorithm exposes two capability families:
 * <ul>
 * <li>KEM: encapsulation with a recipient {@code PublicKey} and decapsulation
 * with a {@code PrivateKey} using {@link KemContext}.</li>
 * <li>AGREEMENT: message-based agreement built on top of KEM via a
 * {@code KemMessageAgreementAdapter}, returning a
 * {@link MessageAgreementContext} for both initiator and responder flows.</li>
 * </ul>
 * The agreement capability simply adapts the underlying KEM operation into a
 * message-oriented interface suitable for one-pass key agreement.
 *
 * <h2>Key material import and generation</h2> The algorithm registers
 * operation-specific key implementations for:
 * <ul>
 * <li>{@code SaberKeyGenSpec}: generates SABER key pairs for the requested
 * parameter set using {@code KeyPairGenerator} from the provider.</li>
 * <li>{@code zeroecho.core.alg.saber.SaberPublicKeySpec}: imports an
 * X.509-encoded SABER public key.</li>
 * <li>{@code zeroecho.core.alg.saber.SaberPrivateKeySpec}: imports a
 * PKCS#8-encoded SABER private key.</li>
 * </ul>
 *
 * <p>
 * Instances of this class are lightweight and stateless after construction. All
 * provider lookups are performed on demand.
 *
 * <p>
 * <b>Example</b> <pre>{@code
 * CryptoAlgorithm saber = new SaberAlgorithm();
 *
 * // Generate a key pair for a specific SABER variant
 * KeyPair kp = saber.asymmetricKeyPairGenerator(SaberKeyGenSpec.class)
 *                    .generateKeyPair(SaberKeyGenSpec.saberkem256r3());
 *
 * // Encapsulation (initiator)
 * KemContext enc = saber.createContext(KeyUsage.ENCAPSULATE, kp.getPublic(), VoidSpec.INSTANCE);
 * KemResult out = enc.encapsulate();
 *
 * // Decapsulation (responder)
 * KemContext dec = saber.createContext(KeyUsage.DECAPSULATE, kp.getPrivate(), VoidSpec.INSTANCE);
 * SecretKey k = dec.decapsulate(out.ciphertext());
 * }</pre>
 */
public final class SaberAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Creates a SABER algorithm instance backed by the Bouncy Castle PQC provider
     * and registers KEM and AGREEMENT capabilities, along with key generation and
     * key import builders for SABER public and private keys.
     *
     * <p>
     * The constructor:
     * <ul>
     * <li>Registers KEM encapsulate and decapsulate capabilities bound to
     * {@link KemContext} and {@code SaberKemContext}.</li>
     * <li>Registers AGREEMENT capabilities that adapt KEM to
     * {@link MessageAgreementContext} for initiator and responder roles.</li>
     * <li>Registers asymmetric key builders for generating SABER key pairs via
     * {@code SaberKeyGenSpec} and importing X.509 and PKCS#8 encodings.</li>
     * </ul>
     *
     * <p>
     * <b>Example</b> <pre>{@code
     * SaberAlgorithm alg = new SaberAlgorithm();
     * }</pre>
     */
    public SaberAlgorithm() {
        super("SABER", "SABER", BouncyCastlePQCProvider.PROVIDER_NAME);

        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new SaberKemContext(this, k), () -> VoidSpec.INSTANCE);
        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new SaberKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new SaberKemContext(this, recipient)).asInitiator()
                            .build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new SaberKemContext(this, myPriv)).asResponder()
                            .build();
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(SaberKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            @Override
            public KeyPair generateKeyPair(SaberKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("SABER", providerName());
                org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec params = switch (spec.variant()) {
                    case LIGHTSABERKEM128R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.lightsaberkem128r3;
                    case SABERKEM128R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.saberkem128r3;
                    case FIRESABERKEM128R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.firesaberkem128r3;

                    case LIGHTSABERKEM192R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.lightsaberkem192r3;
                    case SABERKEM192R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.saberkem192r3;
                    case FIRESABERKEM192R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.firesaberkem192r3;

                    case LIGHTSABERKEM256R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.lightsaberkem256r3;
                    case SABERKEM256R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.saberkem256r3;
                    case FIRESABERKEM256R3 -> org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec.firesaberkem256r3;
                };

                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, SaberKeyGenSpec::saberkem256r3);

        registerPublicKeyImporter(SaberPublicKeySpec.class, new PublicKeyImporter<>() {

            @Override
            public PublicKey importPublic(SaberPublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("SABER", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        registerPrivateKeyImporter(SaberPrivateKeySpec.class, new PrivateKeyImporter<>() {

            @Override
            public PrivateKey importPrivate(SaberPrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("SABER", providerName());
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
     * {@link Security} providers registry.
     *
     * @throws NoSuchProviderException if the provider is not registered
     */
    private static void ensureProvider() throws NoSuchProviderException {
        Provider p = Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME);
        if (p == null) {
            throw new NoSuchProviderException("BCPQC provider not registered");
        }
    }
}
