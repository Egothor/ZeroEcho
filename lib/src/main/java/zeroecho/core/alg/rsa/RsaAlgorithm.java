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
package zeroecho.core.alg.rsa;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * RSA algorithm binding for encryption/decryption and signature/verification.
 *
 * <p>
 * This class wires RSA to the ZeroEcho algorithm registry by declaring its
 * capabilities, supported roles, and key builders. It supports both encryption
 * (typically RSA-OAEP) and digital signatures (typically RSA-PSS).
 * </p>
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li><b>Encryption/Decryption</b>: Uses {@link RsaEncSpec}, with OAEP
 * (SHA-256) as the default padding scheme.</li>
 * <li><b>Signing/Verification</b>: Uses {@link RsaSigSpec}, with PSS (SHA-256,
 * 32-byte salt) as the default signature scheme.</li>
 * </ul>
 *
 * <h2>Key builders</h2>
 * <ul>
 * <li>{@link RsaKeyGenSpec}: Generates RSA key pairs with configurable key size
 * and public exponent (default: 2048 bits, exponent 65537).</li>
 * <li>{@link RsaPublicKeySpec}: Imports an X.509-encoded public key.</li>
 * <li>{@link RsaPrivateKeySpec}: Imports a PKCS#8-encoded private key.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * RsaAlgorithm rsa = new RsaAlgorithm();
 *
 * // Generate a new RSA-2048 key pair
 * KeyPair kp = rsa.asymmetricKeyBuilder(RsaKeyGenSpec.class)
 *                 .generateKeyPair(RsaKeyGenSpec.rsa2048());
 *
 * // Encrypt with OAEP (SHA-256)
 * EncryptionContext enc = rsa.create(KeyUsage.ENCRYPT, kp.getPublic(), null);
 *
 * // Sign with PSS (SHA-256)
 * SignatureContext sig = rsa.create(KeyUsage.SIGN, kp.getPrivate(), null);
 * }</pre>
 *
 * <p>
 * <b>Security note:</b> This implementation defaults to OAEP with SHA-256 for
 * encryption and PSS with SHA-256 for signatures, which are considered secure
 * and modern choices. Legacy padding modes such as PKCS#1 v1.5 are deliberately
 * not exposed to avoid misuse.
 * </p>
 *
 * @since 1.0
 */
public final class RsaAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Constructs a new RSA algorithm definition and registers its roles and key
     * builders.
     *
     * <p>
     * The constructor wires the following:
     * </p>
     * <ul>
     * <li>{@link KeyUsage#ENCRYPT} / {@link KeyUsage#DECRYPT} using
     * {@link RsaEncSpec}, with OAEP (SHA-256) as the default scheme.</li>
     * <li>{@link KeyUsage#SIGN} / {@link KeyUsage#VERIFY} using {@link RsaSigSpec},
     * with PSS (SHA-256, 32-byte salt) as the default scheme.</li>
     * <li>{@link RsaKeyGenSpec}: RSA key pair generation (default: 2048-bit, public
     * exponent 65537).</li>
     * <li>{@link RsaPublicKeySpec}: Import of X.509-encoded public keys.</li>
     * <li>{@link RsaPrivateKeySpec}: Import of PKCS#8-encoded private keys.</li>
     * </ul>
     *
     * <p>
     * All roles are registered under the {@link AlgorithmFamily#ASYMMETRIC} family.
     * Default specs are chosen to be modern and secure, excluding legacy padding
     * modes such as PKCS#1 v1.5.
     * </p>
     *
     * @throws IllegalArgumentException if an RSA context cannot be initialized due
     *                                  to provider-level constraints (e.g.,
     *                                  unsupported parameters).
     */
    public RsaAlgorithm() {
        super("RSA", "RSA");

        // Encryption
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.ENCRYPT, EncryptionContext.class, PublicKey.class,
                RsaEncSpec.class, (PublicKey k, RsaEncSpec s) -> new RsaCipherContext(this, k, true, s),
                () -> RsaEncSpec.oaep(RsaEncSpec.Hash.SHA256));
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.DECRYPT, EncryptionContext.class, PrivateKey.class,
                RsaEncSpec.class, (PrivateKey k, RsaEncSpec s) -> new RsaCipherContext(this, k, false, s),
                () -> RsaEncSpec.oaep(RsaEncSpec.Hash.SHA256));

        // Signatures
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.SIGN, SignatureContext.class, PrivateKey.class,
                RsaSigSpec.class, (PrivateKey k, RsaSigSpec s) -> {
                    try {
                        return new RsaSignatureContext(this, k, s);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("RSA signer init", e);
                    }
                }, () -> RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32));
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class,
                RsaSigSpec.class, (PublicKey k, RsaSigSpec s) -> {
                    try {
                        return new RsaSignatureContext(this, k, s);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("RSA verifier init", e);
                    }
                }, () -> RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32));

        // Key builders
        registerAsymmetricKeyBuilder(RsaKeyGenSpec.class, new AsymmetricKeyBuilder<>() {
            @Override
            public KeyPair generateKeyPair(RsaKeyGenSpec spec) throws GeneralSecurityException {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                RSAKeyGenParameterSpec params = new RSAKeyGenParameterSpec(spec.keySize(),
                        BigInteger.valueOf(spec.publicExponent()));
                kpg.initialize(params);
                return kpg.generateKeyPair();
            }

            @Override
            public PublicKey importPublic(RsaKeyGenSpec spec) {
                throw new UnsupportedOperationException("Use RsaPublicKeySpec to import a public key.");
            }

            @Override
            public PrivateKey importPrivate(RsaKeyGenSpec spec) {
                throw new UnsupportedOperationException("Use RsaPrivateKeySpec to import a private key.");
            }
        }, RsaKeyGenSpec::rsa2048);

        registerAsymmetricKeyBuilder(RsaPublicKeySpec.class, new AsymmetricKeyBuilder<>() {
            @Override
            public KeyPair generateKeyPair(RsaPublicKeySpec spec) {
                throw new UnsupportedOperationException("Generation not supported for encoded spec.");
            }

            @Override
            public PublicKey importPublic(RsaPublicKeySpec spec) throws GeneralSecurityException {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePublic(new X509EncodedKeySpec(spec.encoded()));
            }

            @Override
            public PrivateKey importPrivate(RsaPublicKeySpec spec) {
                throw new UnsupportedOperationException("Use RsaPrivateKeySpec for private keys.");
            }
        }, null);

        registerAsymmetricKeyBuilder(RsaPrivateKeySpec.class, new AsymmetricKeyBuilder<>() {
            @Override
            public KeyPair generateKeyPair(RsaPrivateKeySpec spec) {
                throw new UnsupportedOperationException("Generation not supported for encoded spec.");
            }

            @Override
            public PublicKey importPublic(RsaPrivateKeySpec spec) {
                throw new UnsupportedOperationException("Use RsaPublicKeySpec for public keys.");
            }

            @Override
            public PrivateKey importPrivate(RsaPrivateKeySpec spec) throws GeneralSecurityException {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePrivate(new PKCS8EncodedKeySpec(spec.encoded()));
            }
        }, null);
    }
}
