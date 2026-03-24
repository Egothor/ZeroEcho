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
package zeroecho.core.alg.chacha;

import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.spec.ContextSpec;

/**
 * <h2>ChaCha base specification marker</h2>
 *
 * Common sealed interface for all ChaCha-family specifications. Implemented by
 * {@link ChaChaSpec} (raw stream cipher) and {@link ChaCha20Poly1305Spec}
 * (AEAD).
 *
 * <p>
 * Extends {@link zeroecho.core.spec.ContextSpec} to allow binding
 * algorithm-specific parameters into a context.
 * </p>
 *
 * <h3>Header support</h3>
 * <ul>
 * <li>{@link #header()} may return a {@link SymmetricHeaderCodec} that encodes
 * parameters (e.g., nonce, AAD hash) into the ciphertext stream.</li>
 * <li>If {@code null}, no header is used and parameters must be managed via
 * {@code CtxInterface} or other out-of-band means.</li>
 * </ul>
 *
 * <h3>Example</h3> <pre>{@code
 * ChaChaBaseSpec spec = ChaCha20Poly1305Spec.withHeader(
 *     new ChaCha20Poly1305HeaderCodec()
 * );
 * SymmetricHeaderCodec codec = spec.header(); // non-null
 * }</pre>
 *
 * @since 1.0
 */
public sealed interface ChaChaBaseSpec extends ContextSpec permits ChaChaSpec, ChaCha20Poly1305Spec {
    /**
     * Returns the optional header codec used to serialize/deserialize stream
     * headers for this ChaCha mode.
     *
     * @return {@link SymmetricHeaderCodec} instance, or {@code null} if no header
     */
    SymmetricHeaderCodec header(); // may be null
}
