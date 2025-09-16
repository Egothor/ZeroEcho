/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.alg.sphincsplus;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.spec.VoidSpec;

/**
 * SPHINCS+ signature algorithm binding for the ZeroEcho framework.
 *
 * <p>
 * {@code SphincsPlusAlgorithm} integrates the SPHINCS+ stateless hash-based
 * signature scheme as defined in the NIST PQC standardization process. It
 * registers signing and verification roles, along with asymmetric key builders
 * for generation and import of SPHINCS+ key material.
 * </p>
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li>{@link KeyUsage#SIGN}: produces SPHINCS+ signatures using a
 * {@link java.security.PrivateKey}.</li>
 * <li>{@link KeyUsage#VERIFY}: verifies SPHINCS+ signatures using a
 * {@link java.security.PublicKey}.</li>
 * </ul>
 *
 * <p>
 * Each role is bound to a {@link zeroecho.core.context.SignatureContext}
 * created via {@link SphincsPlusSignatureContext}. Both roles are configured
 * with a {@link zeroecho.core.spec.VoidSpec}, as SPHINCS+ requires no runtime
 * context parameters.
 * </p>
 *
 * <h2>Key builders</h2>
 * <ul>
 * <li>{@link SphincsPlusKeyGenSpec}: generate new key pairs with parameter set
 * selection (e.g., SPHINCS+-SHAKE-256s, fast/robust variants).</li>
 * <li>{@link SphincsPlusPublicKeySpec}: import X.509-encoded public keys.</li>
 * <li>{@link SphincsPlusPrivateKeySpec}: import PKCS#8-encoded private
 * keys.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * CryptoAlgorithm alg = new SphincsPlusAlgorithm();
 * KeyPair kp = alg.asymmetricKeyBuilder(SphincsPlusKeyGenSpec.class)
 *                 .generateKeyPair(SphincsPlusKeyGenSpec.sphincsPlusSha256_128s());
 *
 * try (SignatureContext signer =
 *          alg.create(KeyUsage.SIGN, kp.getPrivate(), null)) {
 *     signer.update(message);
 *     byte[] sig = signer.sign();
 * }
 *
 * try (SignatureContext verifier =
 *          alg.create(KeyUsage.VERIFY, kp.getPublic(), null)) {
 *     verifier.update(message);
 *     boolean ok = verifier.verify(sig);
 * }
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances of this class are immutable and can be
 * shared across threads. The created {@link SignatureContext} objects are not
 * thread-safe.
 *
 * @since 1.0
 */
public final class SphincsPlusAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Creates a new SPHINCS+ algorithm instance and registers its capabilities.
     *
     * <p>
     * The constructor binds the algorithm identifier {@code "SPHINCS+"} (with
     * display name {@code "SPHINCSPLUS"}) to the following:
     * </p>
     * <ul>
     * <li>Capability for {@link KeyUsage#SIGN}, producing a
     * {@link zeroecho.core.context.SignatureContext} from a
     * {@link java.security.PrivateKey}.</li>
     * <li>Capability for {@link KeyUsage#VERIFY}, producing a
     * {@link zeroecho.core.context.SignatureContext} from a
     * {@link java.security.PublicKey}.</li>
     * <li>Asymmetric key builders for {@link SphincsPlusKeyGenSpec},
     * {@link SphincsPlusPublicKeySpec}, and {@link SphincsPlusPrivateKeySpec} to
     * support key pair generation and key import from standard encodings.</li>
     * </ul>
     *
     * <p>
     * Both signing and verifying contexts are configured with
     * {@link zeroecho.core.spec.VoidSpec}, since SPHINCS+ requires no runtime
     * parameters beyond the key material.
     * </p>
     *
     * @throws IllegalArgumentException if a signature context cannot be initialized
     *                                  due to provider errors
     */
    public SphincsPlusAlgorithm() {
        super("SPHINCS+", "SPHINCSPLUS");

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.SIGN, SignatureContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> {
                    try {
                        return new SphincsPlusSignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init SPHINCS+ signer", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> {
                    try {
                        return new SphincsPlusSignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init SPHINCS+ verifier", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyBuilder(SphincsPlusKeyGenSpec.class, new SphincsPlusKeyGenBuilder(),
                SphincsPlusKeyGenSpec::defaultSpec);
        registerAsymmetricKeyBuilder(SphincsPlusPublicKeySpec.class, new SphincsPlusPublicKeyBuilder(), null);
        registerAsymmetricKeyBuilder(SphincsPlusPrivateKeySpec.class, new SphincsPlusPrivateKeyBuilder(), null);
    }
}
