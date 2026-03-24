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
package zeroecho.core.spi;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Factory interface for constructing asymmetric key pairs and importing
 * public/private keys from specifications.
 *
 * <p>
 * Implementations encapsulate algorithm-specific details (for example RSA,
 * Ed25519, X25519) while exposing a uniform API for generation and import
 * operations. This allows higher-level code to work generically with
 * {@code AsymmetricKeyBuilder} without depending on algorithm internals.
 * </p>
 *
 * <h2>Operations</h2>
 * <ul>
 * <li>{@link #generateKeyPair(AlgorithmKeySpec)} - creates a fresh key pair
 * using the supplied algorithm spec (such as curve parameters or modulus
 * length).</li>
 * <li>{@link #importPublic(AlgorithmKeySpec)} - wraps externally supplied
 * public key material in a {@link PublicKey}, validating that it conforms to
 * the algorithm specification.</li>
 * <li>{@link #importPrivate(AlgorithmKeySpec)} - wraps externally supplied
 * private key material in a {@link PrivateKey}, validating that it conforms to
 * the algorithm specification.</li>
 * </ul>
 *
 * <h2>Usage guidelines</h2>
 * <ul>
 * <li>Always prefer {@link #generateKeyPair(AlgorithmKeySpec)} when creating
 * new credentials.</li>
 * <li>Use {@link #importPublic(AlgorithmKeySpec)} and
 * {@link #importPrivate(AlgorithmKeySpec)} for interoperability, loading from
 * key stores, or migration from existing material.</li>
 * <li>Implementations should reject malformed or weak keys and enforce
 * algorithm-specific constraints (for example, minimum modulus length for RSA
 * or disallowed small subgroup curves).</li>
 * </ul>
 *
 * <h2>Thread safety</h2> Implementations must be stateless or otherwise safe
 * for concurrent use across threads.
 *
 * @param <S> algorithm-specific key specification type
 *
 * @since 1.0
 */
public interface AsymmetricKeyBuilder<S extends AlgorithmKeySpec> {
    /**
     * Generates a new asymmetric key pair according to the given specification.
     *
     * @param spec algorithm parameters, such as modulus length or curve identifier
     * @return a new {@link KeyPair} containing a public and private key
     * @throws GeneralSecurityException if the algorithm or parameters are invalid
     *                                  or unsupported
     */
    KeyPair generateKeyPair(S spec) throws GeneralSecurityException;

    /**
     * Imports an externally supplied public key according to the given
     * specification.
     *
     * <p>
     * Implementations must validate that the provided material is properly
     * formatted, has acceptable length, and is consistent with the specified
     * algorithm.
     * </p>
     *
     * @param spec algorithm parameters and encoded public key material
     * @return a {@link PublicKey} validated and usable for cryptographic operations
     * @throws GeneralSecurityException if the key material is invalid or does not
     *                                  match the specification
     */
    PublicKey importPublic(S spec) throws GeneralSecurityException;

    /**
     * Imports an externally supplied private key according to the given
     * specification.
     *
     * <p>
     * Implementations must validate that the provided material is properly
     * formatted, has acceptable length, and is consistent with the specified
     * algorithm.
     * </p>
     *
     * @param spec algorithm parameters and encoded private key material
     * @return a {@link PrivateKey} validated and usable for cryptographic
     *         operations
     * @throws GeneralSecurityException if the key material is invalid or does not
     *                                  match the specification
     */
    PrivateKey importPrivate(S spec) throws GeneralSecurityException;
}
