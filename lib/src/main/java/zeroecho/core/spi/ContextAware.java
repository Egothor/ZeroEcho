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

import conflux.CtxInterface;

/**
 * Optional service-provider interface for cryptographic primitives that need to
 * share or persist per-session parameters using a {@link CtxInterface}.
 *
 * <p>
 * Many cryptographic algorithms require auxiliary values in addition to the
 * key, such as initialization vectors (IVs), nonces, salts, or additional
 * authenticated data (AAD). Implementations that support external parameter
 * passing can expose this interface so higher layers can provide or retrieve
 * these values through a shared context.
 * </p>
 *
 * <h2>Typical parameters</h2>
 * <ul>
 * <li>Initialization vectors (IV) for block cipher modes such as CBC or
 * GCM.</li>
 * <li>Nonces for stream ciphers or AEAD schemes.</li>
 * <li>Salts for password-based key derivation functions.</li>
 * <li>Additional authenticated data (AAD) for AEAD constructions.</li>
 * </ul>
 *
 * <h2>Design guidelines</h2>
 * <ul>
 * <li>Implementations should fail fast if required parameters are missing in
 * the provided context.</li>
 * <li>Contexts may be reused across operations, but values should be scoped to
 * the session or algorithm instance.</li>
 * <li>Implementations should treat {@link CtxInterface} as a structured
 * key–value store and avoid ad-hoc parameter passing.</li>
 * </ul>
 *
 * <h2>Thread safety</h2> The thread-safety of this interface depends on the
 * provided {@link CtxInterface} implementation. Callers should not assume
 * concurrent mutation is safe unless explicitly documented.
 *
 * @since 1.0
 */
public interface ContextAware {
    /**
     * Attaches a context object that will be used to read and write per-session
     * parameters.
     *
     * <p>
     * Typical values include initialization vectors (IV), nonces, salts, or
     * additional authenticated data (AAD). Implementations may throw if the context
     * is missing required values or contains invalid entries.
     * </p>
     *
     * @param ctx non-null parameter context
     * @throws NullPointerException if {@code ctx} is {@code null}
     */
    void setContext(CtxInterface ctx);

    /**
     * Returns the context currently in use.
     *
     * <p>
     * This method must never return {@code null} after the first successful
     * invocation of {@link #setContext(CtxInterface)} or after a context has been
     * created internally by the implementation.
     * </p>
     *
     * @return the active parameter context
     */
    CtxInterface context();
}
