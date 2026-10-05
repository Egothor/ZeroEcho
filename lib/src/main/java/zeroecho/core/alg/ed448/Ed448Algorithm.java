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
package zeroecho.core.alg.ed448;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.List;

import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.SecurityLevel;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.spec.VoidSpec;

/**
 * <h2>Ed448 Digital Signature Algorithm</h2>
 *
 * Implementation of the Edwards-curve Digital Signature Algorithm over the
 * Curve448 curve, commonly referred to as Ed448.
 *
 * <p>
 * Ed448 is a modern elliptic curve signature scheme standardized in
 * <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>. It provides
 * high security margins (224-bit classical strength) and is designed for
 * simplicity, determinism, and resilience against common implementation
 * pitfalls such as malleability.
 * </p>
 *
 * <h2>Roles</h2>
 * <ul>
 * <li>{@link KeyUsage#SIGN}: Contexts that sign messages using a private key,
 * producing fixed-length Ed448 signatures.</li>
 * <li>{@link KeyUsage#VERIFY}: Contexts that verify Ed448 signatures using the
 * corresponding public key.</li>
 * </ul>
 *
 * <h2>Key material</h2>
 * <ul>
 * <li>{@link Ed448KeyGenSpec}: Generation of new key pairs with defined
 * parameters.</li>
 * <li>{@link Ed448PublicKeySpec}: Encoded form of Ed448 public keys (X.509
 * format).</li>
 * <li>{@link Ed448PrivateKeySpec}: Encoded form of Ed448 private keys (PKCS#8
 * format).</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances of this class are immutable and safe to
 * reuse across threads. Context objects created through capabilities are not
 * necessarily thread-safe.
 *
 * <pre>{@code
 * // Example: generate a key pair and sign data
 * CryptoAlgorithm ed448 = new Ed448Algorithm();
 * KeyPair kp = ed448.asymmetricKeyPairGenerator(Ed448KeyGenSpec.class)
 *                    .generateKeyPair(Ed448KeyGenSpec.defaultSpec());
 *
 * SignatureContext signer = ed448.createContext(KeyUsage.SIGN, kp.getPrivate(), null);
 * byte[] sig = signer.sign(data);
 *
 * SignatureContext verifier = ed448.createContext(KeyUsage.VERIFY, kp.getPublic(), null);
 * boolean ok = verifier.verify(data, sig);
 * }</pre>
 *
 * @since 1.0
 */
public final class Ed448Algorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());
    /**
     * Constructs and wires the Ed448 algorithm definition.
     *
     * <p>
     * The constructor registers:
     * </p>
     * <ul>
     * <li><b>Roles</b>:
     * <ul>
     * <li>{@link KeyUsage#SIGN} using {@link SignatureContext} with a
     * {@link PrivateKey} and {@link VoidSpec} (no additional parameters).</li>
     * <li>{@link KeyUsage#VERIFY} using {@link SignatureContext} with a
     * {@link PublicKey} and {@link VoidSpec}.</li>
     * </ul>
     * </li>
     * <li><b>Asymmetric key builders</b>:
     * <ul>
     * <li>{@link Ed448KeyGenSpec} via {@link Ed448KeyGenBuilder}, defaulting to
     * {@link Ed448KeyGenSpec#defaultSpec()}.</li>
     * <li>{@link Ed448PublicKeySpec} via {@link Ed448PublicKeyBuilder}.</li>
     * <li>{@link Ed448PrivateKeySpec} via {@link Ed448PrivateKeyBuilder}.</li>
     * </ul>
     * </li>
     * </ul>
     *
     * <p>
     * No exceptions are thrown by this constructor. Any provider initialization
     * needed for signing or verification is deferred to the creation of
     * {@link SignatureContext} instances.
     * </p>
     *
     * <pre>{@code
     * // Example: instantiate and obtain a signer
     * CryptoAlgorithm ed448 = new Ed448Algorithm();
     * SignatureContext signer = ed448.createContext(KeyUsage.SIGN, privateKey, null);
     * }</pre>
     */
    public Ed448Algorithm() {
        super("Ed448", "Ed448");

        // SIGN (private key)
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.SIGN, SignatureContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> {
                    try {
                        return new Ed448SignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init Ed448 signer", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        // VERIFY (public key)
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> {
                    try {
                        return new Ed448SignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init Ed448 verifier", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        // Key builders
        registerAsymmetricKeyPairGenerator(Ed448KeyGenSpec.class, new Ed448KeyGenBuilder(),
                Ed448KeyGenSpec::defaultSpec);
        registerPublicKeyImporter(Ed448PublicKeySpec.class, new Ed448PublicKeyBuilder());
        registerPrivateKeyImporter(Ed448PrivateKeySpec.class, new Ed448PrivateKeyBuilder());
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>("Ed448", "Ed448 (224-bit)", SecurityLevel.classical(224), Ed448KeyGenSpec.defaultSpec())
        );
    }

}
