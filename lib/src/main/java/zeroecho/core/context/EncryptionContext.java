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
package zeroecho.core.context;

import java.io.IOException;
import java.io.InputStream;

/**
 * Context for performing encryption or decryption in streaming pipelines.
 *
 * <p>
 * An {@code EncryptionContext} transforms data on-the-fly as it is read from an
 * upstream source. It provides a passthrough {@link InputStream} that
 * transparently applies encryption or decryption according to the configured
 * algorithm, key, and parameters.
 * </p>
 *
 * <h2>Lifecycle</h2>
 * <ul>
 * <li>Create a context via {@code ZeroEchoSession#createContext(...)} for the
 * {@link zeroecho.core.KeyUsage#ENCRYPT} or
 * {@link zeroecho.core.KeyUsage#DECRYPT} role.</li>
 * <li>Call {@link #attach(InputStream)} to obtain a wrapped stream.</li>
 * <li>Read from the returned stream; data is encrypted or decrypted on demand
 * until end-of-file.</li>
 * <li>Call {@link #close()} to release underlying resources and finalize any
 * state (e.g., authentication tags in AEAD modes).</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>When using AEAD modes (e.g., AES-GCM), callers must preserve the
 * associated authentication tag and any nonces or IVs required for
 * decryption.</li>
 * <li>Reading the stream to completion is usually required for integrity checks
 * to succeed; truncation can result in verification failures.</li>
 * <li>Contexts are not guaranteed to be thread-safe; use one context per
 * pipeline.</li>
 * </ul>
 *
 * @since 1.0
 */
public non-sealed interface EncryptionContext extends CryptoContext {
    /**
     * Attaches this context to an upstream input stream.
     *
     * <p>
     * The returned stream applies encryption or decryption as bytes are read.
     * Implementations may buffer internally, and callers should always close the
     * stream (or the context) to ensure all data is flushed and state is finalized.
     * </p>
     *
     * @param upstream the source stream supplying plaintext (for encryption) or
     *                 ciphertext (for decryption)
     * @return a new input stream that transforms data according to the context
     * @throws IOException if the stream cannot be wrapped or the underlying cipher
     *                     initialization fails
     */
    InputStream attach(InputStream upstream) throws IOException;
}
