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
package zeroecho.core.alg.ecdsa;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoCatalog;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.context.SignatureContext;

/**
 * <h2>Elliptic Curve Digital Signature Algorithm (ECDSA)</h2>
 *
 * Implementation of the ECDSA digital signature scheme within the ZeroEcho
 * cryptographic framework. This algorithm supports signing and verification
 * using elliptic curve keys defined by {@link EcdsaCurveSpec}.
 *
 * <h2>Roles</h2>
 * <ul>
 * <li>{@link KeyUsage#SIGN} - Create digital signatures using a
 * {@link PrivateKey} on a selected curve.</li>
 * <li>{@link KeyUsage#VERIFY} - Verify digital signatures using a
 * {@link PublicKey} on the same curve.</li>
 * </ul>
 *
 * <h2>Key builders</h2>
 * <ul>
 * <li>{@link EcdsaCurveSpec} - Used to generate a new key pair for a chosen
 * curve.</li>
 * <li>{@link EcdsaPublicKeySpec} - Used to import an existing ECDSA public
 * key.</li>
 * <li>{@link EcdsaPrivateKeySpec} - Used to import an existing ECDSA private
 * key.</li>
 * </ul>
 *
 * <h2>Provider model</h2> This implementation leverages the Java Cryptography
 * Architecture (JCA) with algorithm identifiers supplied by
 * {@link EcdsaCurveSpec#jcaFactory()}. The {@link GenericJcaSignatureContext}
 * is used internally to provide streaming-friendly signing and verification
 * with strict enforcement of fixed-length signatures.
 *
 * <h2>Default configuration</h2> If no curve specification is explicitly
 * provided, the default is {@link EcdsaCurveSpec#P256}.
 *
 * <pre>{@code
 * // Example: Sign and verify with ECDSA/P-256
 * KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("ECDSA", EcdsaCurveSpec.P256);
 * SignatureContext signer = session.createContext("ECDSA", KeyUsage.SIGN, kp.getPrivate(), EcdsaCurveSpec.P256);
 * SignatureContext verifier = session.createContext("ECDSA", KeyUsage.VERIFY, kp.getPublic(), EcdsaCurveSpec.P256);
 * }</pre>
 *
 * @since 1.0
 */
public final class EcdsaAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Constructs a new ECDSA algorithm instance and registers its capabilities:
     * <ul>
     * <li>{@link KeyUsage#SIGN} with {@link PrivateKey} and
     * {@link EcdsaCurveSpec}</li>
     * <li>{@link KeyUsage#VERIFY} with {@link PublicKey} and
     * {@link EcdsaCurveSpec}</li>
     * <li>Asymmetric key builders for {@link EcdsaCurveSpec},
     * {@link EcdsaPublicKeySpec}, and {@link EcdsaPrivateKeySpec}</li>
     * </ul>
     *
     * <p>
     * On construction, the algorithm declares its supported roles and registers
     * builders with the {@link CryptoAlgorithm} infrastructure so they can be
     * discovered by the {@link CryptoCatalog} or invoked through the
     * session-bound {@link zeroecho.sdk.KeyBuilders} entry point.
     * </p>
     */
    public EcdsaAlgorithm() {
        super("ECDSA", "ECDSA");

        // SIGN
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.SIGN, SignatureContext.class, PrivateKey.class,
                EcdsaCurveSpec.class, (PrivateKey k, EcdsaCurveSpec s) -> {
                    try {
                        return new GenericJcaSignatureContext(this, k,
                                GenericJcaSignatureContext.jcaFactory(s.jcaFactory(), null),
                                GenericJcaSignatureContext.SignLengthResolver.fixed(s.signFixedLength()));
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init " + s.jcaFactory() + " signer", e);
                    }
                }, () -> EcdsaCurveSpec.P256);

        // VERIFY
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class,
                EcdsaCurveSpec.class, (PublicKey k, EcdsaCurveSpec s) -> {
                    try {
                        return new GenericJcaSignatureContext(this, k,
                                GenericJcaSignatureContext.jcaFactory(s.jcaFactory(), null),
                                GenericJcaSignatureContext.VerifyLengthResolver.fixed(s.signFixedLength()));
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init " + s.jcaFactory() + " verifier", e);
                    }
                }, () -> EcdsaCurveSpec.P256);

        registerAsymmetricKeyPairGenerator(EcdsaCurveSpec.class, new EcdsaKeyGenBuilder(),
                () -> EcdsaCurveSpec.P256);
        registerPublicKeyImporter(EcdsaPublicKeySpec.class, new EcdsaPublicKeyBuilder());
        registerPrivateKeyImporter(EcdsaPrivateKeySpec.class, new EcdsaPrivateKeyBuilder());
    }
}
