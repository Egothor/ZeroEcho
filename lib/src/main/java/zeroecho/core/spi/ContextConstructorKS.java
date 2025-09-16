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
package zeroecho.core.spi;

import java.io.IOException;
import java.security.Key;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.spec.ContextSpec;

/**
 * Factory interface to construct a {@link CryptoContext} from a key and an
 * optional specification.
 *
 * <p>
 * Each cryptographic algorithm binds one or more roles (for example,
 * {@code ENCRYPT}, {@code SIGN}) to a corresponding context type. For each
 * binding, a {@code ContextConstructorKS} is registered as the factory that
 * creates the runtime context for the role. The role itself is implied by the
 * registration and does not need to be passed explicitly here.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Validate that the provided key is compatible with the expected key
 * type.</li>
 * <li>Interpret the {@link ContextSpec} parameters (such as IVs, padding modes,
 * or curve identifiers).</li>
 * <li>Construct and return a ready-to-use {@link CryptoContext} instance bound
 * to the given key and spec.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <p>
 * {@code ContextConstructorKS} is primarily used internally by
 * {@link CryptoAlgorithm} implementations when binding roles. Higher-level code
 * should not call it directly; instead use {@link CryptoAlgorithm#create} or
 * {@link zeroecho.core.CryptoAlgorithms#create}.
 * </p>
 *
 * <h2>Thread safety</h2> Implementations should be stateless and safe to invoke
 * concurrently from multiple threads.
 *
 * @param <C> context type produced
 * @param <K> key type accepted
 * @param <S> specification type accepted
 *
 * @since 1.0
 */
@FunctionalInterface
public interface ContextConstructorKS<C extends CryptoContext, K extends Key, S extends ContextSpec> {
    /**
     * Creates a new {@link CryptoContext} instance bound to the provided key and
     * specification.
     *
     * @param key  non-null cryptographic key suitable for the role
     * @param spec role-specific parameters; may be {@code null} if defaults are
     *             acceptable
     * @return a newly constructed context ready for cryptographic operations
     * @throws IOException if context creation fails due to I/O, provider issues, or
     *                     invalid parameters
     */
    C create(K key, S spec) throws IOException;
}
