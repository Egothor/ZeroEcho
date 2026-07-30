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

import java.security.Key;

import zeroecho.core.context.CryptoContext;
import zeroecho.core.spec.ContextSpec;

/**
 * Creates a cryptographic context from a key and a context specification.
 *
 * <p>
 * Implementations report provider and parameter failures with unchecked
 * exceptions; context construction is a pure in-memory operation and does not
 * expose an I/O failure contract. Factories must be stateless or otherwise safe
 * for concurrent invocation; returned contexts retain their own documented
 * thread-safety contracts.
 * </p>
 *
 * @param <C> context type produced
 * @param <K> key type accepted
 * @param <S> specification type accepted
 * @since 1.0
 */
@FunctionalInterface
public interface ContextFactoryKS<C extends CryptoContext, K extends Key, S extends ContextSpec> {
    /**
     * Creates a context bound to the supplied key and specification.
     *
     * @param key  non-null key
     * @param spec non-null resolved context specification
     * @return a newly created context
     */
    C createContext(K key, S spec);
}
