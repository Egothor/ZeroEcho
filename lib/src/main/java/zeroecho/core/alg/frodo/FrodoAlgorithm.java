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
package zeroecho.core.alg.frodo;

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
import java.util.Arrays;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;

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
 * <h2>Frodo Key Encapsulation Mechanism (KEM)</h2>
 *
 * Implementation of the FrodoKEM post-quantum algorithm, registered as a
 * {@link zeroecho.core.CryptoAlgorithm} within ZeroEcho.
 *
 * <p>
 * FrodoKEM is a lattice-based key encapsulation mechanism designed to resist
 * quantum adversaries. It is based on the hardness of the Learning With Errors
 * (LWE) problem, avoiding reliance on structured lattices. This provides
 * conservative security at the cost of relatively large key sizes compared to
 * schemes such as Kyber.
 * </p>
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li>{@link zeroecho.core.AlgorithmFamily#KEM}:
 * <ul>
 * <li>{@link zeroecho.core.KeyUsage#ENCAPSULATE} with a
 * {@link java.security.PublicKey} to create a
 * {@link zeroecho.core.context.KemContext}.</li>
 * <li>{@link zeroecho.core.KeyUsage#DECAPSULATE} with a
 * {@link java.security.PrivateKey} to recover the shared secret.</li>
 * </ul>
 * </li>
 * <li>{@link zeroecho.core.AlgorithmFamily#AGREEMENT}:
 * <ul>
 * <li>As initiator (Alice) using a recipient {@link java.security.PublicKey},
 * the KEM encapsulation is adapted into a
 * {@link zeroecho.core.context.MessageAgreementContext}.</li>
 * <li>As responder (Bob) using his {@link java.security.PrivateKey}, the
 * decapsulation is similarly adapted into a
 * {@link zeroecho.core.context.MessageAgreementContext}.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Key Management</h2>
 * <ul>
 * <li>Key generation is parameterized by {@link FrodoKeyGenSpec}, which selects
 * a concrete variant such as {@code FRODO_640_AES} or
 * {@code FRODO_1344_SHAKE}.</li>
 * <li>Public keys may be imported from {@link FrodoPublicKeySpec} using an
 * X.509 encoding.</li>
 * <li>Private keys may be imported from {@link FrodoPrivateKeySpec} using a
 * PKCS#8 encoding.</li>
 * <li>Generation and public/private import are registered as independent exact
 * capabilities.</li>
 * </ul>
 *
 * <h2>Provider requirements</h2>
 * <p>
 * FrodoKEM operations are delegated to the BouncyCastle PQC provider
 * ({@code BCPQC}). The static method {@link #ensureProvider()} verifies that
 * the provider is installed; otherwise, a
 * {@link java.security.NoSuchProviderException} is thrown.
 * </p>
 *
 * <h2>Example usage</h2> <pre>{@code
 * // Generate a Frodo keypair
 * CryptoAlgorithm frodo = CryptoAlgorithms.require("Frodo");
 * KeyPair kp = frodo.asymmetricKeyPairGenerator(FrodoKeyGenSpec.class)
 *                   .generateKeyPair(FrodoKeyGenSpec.frodo1344aes());
 *
 * // Encapsulate using the recipient's public key
 * KemContext enc = frodo.createContext(KeyUsage.ENCAPSULATE, kp.getPublic(), VoidSpec.INSTANCE);
 * 
 * // Decapsulate using the recipient's private key
 * KemContext dec = frodo.createContext(KeyUsage.DECAPSULATE, kp.getPrivate(), VoidSpec.INSTANCE);
 * }</pre>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances of {@code FrodoAlgorithm} are immutable and may be shared safely
 * across threads. Contexts created via capabilities are not guaranteed to be
 * thread-safe.
 * </p>
 *
 * @since 1.0
 */
public final class FrodoAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Constructs and registers the Frodo post-quantum algorithm.
     *
     * <p>
     * The constructor wires all roles and key builders supported by FrodoKEM:
     * </p>
     * <ul>
     * <li>Binds {@link zeroecho.core.AlgorithmFamily#KEM} roles for
     * {@link zeroecho.core.KeyUsage#ENCAPSULATE} (public key) and
     * {@link zeroecho.core.KeyUsage#DECAPSULATE} (private key) to
     * {@link FrodoKemContext}.</li>
     * <li>Binds {@link zeroecho.core.AlgorithmFamily#AGREEMENT} roles for initiator
     * and responder, adapting the KEM context to a
     * {@link zeroecho.core.context.MessageAgreementContext} via
     * {@link zeroecho.core.alg.common.agreement.KemMessageAgreementAdapter}.</li>
     * <li>Registers asymmetric key builders for:
     * <ul>
     * <li>{@link FrodoKeyGenSpec} - key pair generation with a selectable Frodo
     * variant.</li>
     * <li>{@link FrodoPublicKeySpec} - importing X.509-encoded public keys.</li>
     * <li>{@link FrodoPrivateKeySpec} - importing PKCS#8-encoded private keys.</li>
     * </ul>
     * </li>
     * </ul>
     *
     * <p>
     * The default algorithm identifier is {@code "Frodo"} with display name
     * {@code "FrodoKEM"}, bound to the {@code BCPQC} provider.
     * </p>
     *
     * @throws java.lang.IllegalStateException if registration of capabilities or
     *                                         builders fails
     */
    public FrodoAlgorithm() {
        super("Frodo", "FrodoKEM", BouncyCastlePQCProvider.PROVIDER_NAME);

        capability(AlgorithmFamily.KEM, KeyUsage.ENCAPSULATE, KemContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> new FrodoKemContext(this, k), () -> VoidSpec.INSTANCE);
        capability(AlgorithmFamily.KEM, KeyUsage.DECAPSULATE, KemContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> new FrodoKemContext(this, k), () -> VoidSpec.INSTANCE);

        // AGREEMENT (initiator): Alice has Bob's public key → encapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← return your
                                                                                                 // existing KemContext
                PublicKey.class, // ← initiator uses recipient's public key
                VoidSpec.class, // ← must implement ContextSpec
                (PublicKey recipient, VoidSpec spec) -> {
                    // create a context bound to recipient public key for encapsulation
                    return KemMessageAgreementAdapter.builder().upon(new FrodoKemContext(this, recipient)).asInitiator()
                            .build();
                }, () -> VoidSpec.INSTANCE // default
        );

        // AGREEMENT (responder): Bob has his private key → decapsulate
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, // ← same KemContext
                                                                                                 // type
                PrivateKey.class, // ← responder uses their private key
                VoidSpec.class, (PrivateKey myPriv, VoidSpec spec) -> {
                    return KemMessageAgreementAdapter.builder().upon(new FrodoKemContext(this, myPriv)).asResponder()
                            .build();
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(FrodoKeyGenSpec.class, new AsymmetricKeyPairGenerator<>() {
            @Override
            public KeyPair generateKeyPair(FrodoKeyGenSpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Frodo", providerName());
                FrodoParameterSpec params = switch (spec.variant()) {
                    case FRODO_640_AES -> FrodoParameterSpec.frodokem640aes;
                    case FRODO_640_SHAKE -> FrodoParameterSpec.frodokem640shake;
                    case FRODO_976_AES -> FrodoParameterSpec.frodokem976aes;
                    case FRODO_976_SHAKE -> FrodoParameterSpec.frodokem976shake;
                    case FRODO_1344_AES -> FrodoParameterSpec.frodokem1344aes;
                    case FRODO_1344_SHAKE -> FrodoParameterSpec.frodokem1344shake;
                };
                kpg.initialize(params, new SecureRandom());
                return kpg.generateKeyPair();
            }
        }, FrodoKeyGenSpec::frodo1344aes);

        registerPublicKeyImporter(FrodoPublicKeySpec.class, new PublicKeyImporter<>() {

            @Override
            public PublicKey importPublic(FrodoPublicKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("Frodo", providerName());
                return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
            }
        });

        registerPrivateKeyImporter(FrodoPrivateKeySpec.class, new PrivateKeyImporter<>() {

            @Override
            public PrivateKey importPrivate(FrodoPrivateKeySpec spec) throws GeneralSecurityException {
                ensureProvider();
                KeyFactory kf = KeyFactory.getInstance("Frodo", providerName());
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
}
