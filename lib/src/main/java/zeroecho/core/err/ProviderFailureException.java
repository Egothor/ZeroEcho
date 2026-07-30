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
package zeroecho.core.err;

/**
 * Exception signaling a failure in the underlying cryptographic provider during
 * algorithm initialization or operation.
 *
 * <p>
 * This runtime exception is used to wrap provider or JCA/JCE errors that occur
 * while creating or initializing cipher contexts (for example, inside AES-GCM
 * or ChaCha20-Poly1305 {@code attach(...)} flows). Typical root causes include
 * unavailable transformations, invalid provider state, or rejected parameters
 * that surface as {@code GeneralSecurityException} and are rethrown as
 * {@code ProviderFailureException}.
 * </p>
 *
 * <h2>Usage and semantics</h2>
 * <ul>
 * <li>Thrown from context setup or transformation wiring when
 * {@code Cipher.getInstance(...)} or {@code init(...)} fails in the
 * provider.</li>
 * <li>Represents provider-layer failure, distinct from unsupported role/spec
 * conditions (see {@link UnsupportedRoleException} and
 * {@link UnsupportedSpecException}).</li>
 * <li>May be translated to {@code IOException} at API boundaries that declare
 * I/O only, while preserving the original cause via {@link #getCause()}.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * try {
 *     Cipher c = Cipher.getInstance(jceName());   // provider resolution
 *     initCipher(c, nonce);                       // provider init
 *     return new Stream(upstream, c, jceName());  // streaming transform
 * } catch (GeneralSecurityException e) {
 *     throw new ProviderFailureException(jceName() + " attach/init failed", e);
 * }
 * }</pre>
 *
 * @since 1.0
 */
public class ProviderFailureException extends RuntimeException {
    private static final long serialVersionUID = 2610774892439787602L;

    /**
     * Creates a new exception wrapping a provider failure.
     *
     * @param m human-readable detail message describing the failed provider
     *          operation
     * @param t original cause from the provider layer (usually a
     *          {@code GeneralSecurityException})
     */
    public ProviderFailureException(String m, Throwable t) {
        super(m, t);
    }
}
