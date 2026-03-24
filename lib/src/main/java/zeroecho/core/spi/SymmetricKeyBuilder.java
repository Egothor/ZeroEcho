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

import javax.crypto.SecretKey;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Factory interface for constructing symmetric keys from algorithm-specific
 * specifications.
 *
 * <p>
 * Implementations encapsulate the details of generating or importing
 * {@link SecretKey} instances for a particular symmetric algorithm (for example
 * AES, ChaCha20, or HMAC). This abstraction provides a uniform API for higher
 * layers, independent of provider-specific implementations.
 * </p>
 *
 * <h2>Operations</h2>
 * <ul>
 * <li>{@link #generateSecret(AlgorithmKeySpec)} - creates a fresh random key
 * using the parameters supplied by the algorithm specification.</li>
 * <li>{@link #importSecret(AlgorithmKeySpec)} - wraps externally supplied raw
 * key material in a {@link SecretKey}, validating that it conforms to the
 * specification.</li>
 * </ul>
 *
 * <h2>Usage guidelines</h2>
 * <ul>
 * <li>Prefer {@link #generateSecret(AlgorithmKeySpec)} for new credentials to
 * ensure strong, random keys.</li>
 * <li>Use {@link #importSecret(AlgorithmKeySpec)} only when loading existing
 * keys, migrating from another system, or interoperating with external storage
 * formats.</li>
 * <li>Implementations must enforce algorithm constraints, including required
 * key sizes and disallowing known-weak parameters.</li>
 * <li>Returned {@link SecretKey} instances should be immutable and, where
 * possible, wrapped in provider-specific classes that prevent serialization or
 * unintended exposure.</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Implementations must be stateless or otherwise safe to use concurrently
 * across multiple threads.
 * </p>
 *
 * @param <S> algorithm-specific key specification type
 *
 * @since 1.0
 */
public interface SymmetricKeyBuilder<S extends AlgorithmKeySpec> {
    /**
     * Generates a new symmetric key according to the given specification.
     *
     * @param spec algorithm parameters, such as required key size or algorithm
     *             variant
     * @return a freshly generated {@link SecretKey} containing random key material
     * @throws GeneralSecurityException if key generation fails or the parameters
     *                                  are invalid or unsupported
     */
    SecretKey generateSecret(S spec) throws GeneralSecurityException;

    /**
     * Imports an externally provided symmetric key according to the given
     * specification.
     *
     * <p>
     * Implementations must validate that the provided material matches the
     * algorithm’s requirements (for example, correct length and encoding). Weak or
     * truncated keys must be rejected.
     * </p>
     *
     * @param spec algorithm parameters and raw key material
     * @return a validated {@link SecretKey} suitable for cryptographic use
     * @throws GeneralSecurityException if the key material is invalid, corrupted,
     *                                  or inconsistent with the specification
     */
    SecretKey importSecret(S spec) throws GeneralSecurityException;
}
