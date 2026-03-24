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
package zeroecho.core.alg.common.eddsa;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * <h2>Abstract EdDSA Key-Pair Builder</h2>
 *
 * Base class for key generation builders targeting Edwards-curve Digital
 * Signature Algorithm (EdDSA) variants such as Ed25519 and Ed448.
 *
 * <p>
 * This class integrates with the JCA {@link KeyPairGenerator} by exposing the
 * correct algorithm name (e.g., {@code "Ed25519"} or {@code "Ed448"}). Concrete
 * subclasses provide this algorithm identifier via {@link #jcaKeyPairAlg()}.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Expose a template method {@link #jcaKeyPairAlg()} to return the canonical
 * JCA algorithm identifier.</li>
 * <li>Generate key pairs using JCA without requiring extra parameters.</li>
 * <li>Intentionally reject public and private key imports, as those are
 * delegated to the corresponding {@code *KeySpec} builders.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Instances are stateless. Each call to
 * {@link #generateKeyPair(AlgorithmKeySpec)} acquires a new
 * {@link KeyPairGenerator}, so builders are safe for concurrent use.
 *
 * @param <S> the algorithm-specific {@link AlgorithmKeySpec} subtype
 *
 * @since 1.0
 */
public abstract class AbstractEdDSAKeyGenBuilder<S extends AlgorithmKeySpec> implements AsymmetricKeyBuilder<S> {
    /**
     * Returns the JCA algorithm name understood by {@link KeyPairGenerator}.
     *
     * <p>
     * Implementations must return the canonical algorithm string supported by the
     * JDK, e.g.:
     * </p>
     * <ul>
     * <li>{@code "Ed25519"}</li>
     * <li>{@code "Ed448"}</li>
     * </ul>
     *
     * @return the JCA algorithm identifier string
     */
    protected abstract String jcaKeyPairAlg(); // e.g., "Ed25519", "Ed448"

    /**
     * Generates a new EdDSA key pair using JCA defaults.
     *
     * <p>
     * The provided {@code spec} is not inspected in this base implementation, but
     * it satisfies the {@link AsymmetricKeyBuilder} contract. Subclasses may extend
     * this behavior to interpret spec parameters.
     * </p>
     *
     * @param spec algorithm-specific key specification (currently unused)
     * @return a fresh {@link KeyPair} for the chosen EdDSA variant
     * @throws GeneralSecurityException if the JCA provider does not support the
     *                                  specified EdDSA algorithm
     */
    @Override
    public KeyPair generateKeyPair(S spec) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(jcaKeyPairAlg());
        return kpg.generateKeyPair();
    }

    /**
     * Always throws, as this builder does not support public key import.
     *
     * <p>
     * Importing encoded EdDSA public keys must be done through the corresponding
     * {@code *PublicKeySpec} builder class.
     * </p>
     *
     * @param spec algorithm-specific key specification
     * @return never returns normally
     * @throws UnsupportedOperationException always thrown
     */
    @Override
    public PublicKey importPublic(S spec) {
        throw new UnsupportedOperationException("Use the corresponding PublicKeySpec to import a public key.");
    }

    /**
     * Always throws, as this builder does not support private key import.
     *
     * <p>
     * Importing encoded EdDSA private keys must be done through the corresponding
     * {@code *PrivateKeySpec} builder class.
     * </p>
     *
     * @param spec algorithm-specific key specification
     * @return never returns normally
     * @throws UnsupportedOperationException always thrown
     */
    @Override
    public PrivateKey importPrivate(S spec) {
        throw new UnsupportedOperationException("Use the corresponding PrivateKeySpec to import a private key.");
    }
}
