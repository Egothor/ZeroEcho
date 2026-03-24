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
package zeroecho.core.alg.dh;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.alg.common.agreement.GenericJcaAgreementContext;
import zeroecho.core.alg.common.agreement.GenericJcaMessageAgreementContext;
import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * Diffie-Hellman algorithm registration for use in the pluggable cryptography
 * catalog.
 *
 * <p>
 * This class registers a Diffie-Hellman (DH) algorithm under the identifier
 * {@code "DH"} with sane defaults and JCA compatibility. It declares the
 * algorithm’s capabilities, default parameters, and key builders so that higher
 * layers can use DH for key agreement in a consistent and type-safe way.
 * </p>
 *
 * <h2>Features</h2>
 * <ul>
 * <li>Algorithm identifier and display name: {@code "DH"}.</li>
 * <li>Agreement capability producing {@link AgreementContext} instances backed
 * by the JCA algorithm name {@code "DiffieHellman"}.</li>
 * <li>Default parameter specification: {@link DhSpec#ffdhe2048()}.</li>
 * <li>Asymmetric key builder for {@link DhSpec}-based key pair generation via
 * {@link DhKeyGenBuilder}.</li>
 * <li>Support for importing keys from {@link DhPublicKeySpec} and
 * {@link DhPrivateKeySpec} using standard JCA key factories.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances of {@code DhAlgorithm} are immutable after
 * construction. They are typically created once at application startup and
 * safely reused across threads as shared registrations in a
 * {@link zeroecho.core.CryptoCatalog}.
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Create and register the algorithm
 * DhAlgorithm dh = new DhAlgorithm();
 * CryptoCatalog catalog = CryptoCatalog.load();
 *
 * // Create a DH spec (or rely on the default ffdhe2048)
 * DhSpec spec = DhSpec.ffdhe3072();
 *
 * // Generate a key pair using the registered builder
 * KeyPair kp = CryptoAlgorithms.keyPair("DH", spec);
 *
 * // Obtain an agreement context for DH key agreement
 * AgreementContext ctx = CryptoAlgorithms.create("DH", KeyUsage.AGREEMENT, kp.getPrivate(), spec);
 *
 * // Use the context with a peer public key to derive a shared secret
 * ctx.setPeerPublic(peerPublicKey);
 * byte[] secret = ctx.deriveSecret();
 * }</pre>
 *
 * @see AlgorithmFamily
 * @see KeyUsage
 * @see AgreementContext
 * @see DhSpec
 * @see DhKeyGenBuilder
 * @see AbstractCryptoAlgorithm
 * @since 1.0
 */
public final class DhAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Creates a Diffie-Hellman algorithm registration with standard defaults.
     *
     * <p>
     * This constructor:
     * </p>
     * <ul>
     * <li>Registers the algorithm under the identifier {@code "DH"} and display
     * name {@code "DH"}.</li>
     * <li>Declares an {@link AlgorithmFamily#AGREEMENT} capability for
     * {@link KeyUsage#AGREEMENT}, producing {@link GenericJcaAgreementContext}
     * instances bound to the JCA name {@code "DiffieHellman"}.</li>
     * <li>Sets {@link DhSpec#ffdhe2048()} as the default parameter
     * specification.</li>
     * <li>Registers {@link DhKeyGenBuilder} as the asymmetric key builder for
     * {@link DhSpec}.</li>
     * <li>Registers asymmetric key builders for importing keys via
     * {@link DhPublicKeySpec} and {@link DhPrivateKeySpec} using JCA
     * {@link java.security.KeyFactory}.</li>
     * </ul>
     */
    public DhAlgorithm() {
        super("DH", "DH");

        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, AgreementContext.class, PrivateKey.class,
                DhSpec.class,
                (PrivateKey k, DhSpec s) -> new GenericJcaAgreementContext(this, k, "DiffieHellman", null),
                DhSpec::ffdhe2048);
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, KeyPairKey.class,
                DhSpec.class, (KeyPairKey k, DhSpec s) -> new GenericJcaMessageAgreementContext(this, k,
                        "DiffieHellman", null, "DH", null),
                DhSpec::ffdhe2048);

        registerAsymmetricKeyBuilder(DhSpec.class, new DhKeyGenBuilder(), DhSpec::ffdhe2048);
        registerAsymmetricKeyBuilder(DhPublicKeySpec.class, new AsymmetricKeyBuilder<>() {

            @Override
            public KeyPair generateKeyPair(DhPublicKeySpec spec) throws GeneralSecurityException {
                throw new UnsupportedOperationException("Use DhKeyGenBuilder for keypair generation.");
            }

            @Override
            public PublicKey importPublic(DhPublicKeySpec spec) throws GeneralSecurityException {
                KeyFactory kf = KeyFactory.getInstance("DH");
                return kf.generatePublic(new X509EncodedKeySpec(spec.encoded()));
            }

            @Override
            public PrivateKey importPrivate(DhPublicKeySpec spec) throws GeneralSecurityException {
                throw new UnsupportedOperationException("Use DhPrivateKeySpec for private key import.");
            }
        }, null);
        registerAsymmetricKeyBuilder(DhPrivateKeySpec.class, new AsymmetricKeyBuilder<>() {

            @Override
            public KeyPair generateKeyPair(DhPrivateKeySpec spec) throws GeneralSecurityException {
                throw new UnsupportedOperationException("Use DhKeyGenBuilder for keypair generation.");
            }

            @Override
            public PublicKey importPublic(DhPrivateKeySpec spec) throws GeneralSecurityException {
                throw new UnsupportedOperationException("Use DhPrivateKeySpec for public key import.");
            }

            @Override
            public PrivateKey importPrivate(DhPrivateKeySpec spec) throws GeneralSecurityException {
                KeyFactory kf = KeyFactory.getInstance("DH");
                return kf.generatePrivate(new PKCS8EncodedKeySpec(spec.encoded()));
            }
        }, null);

    }
}
