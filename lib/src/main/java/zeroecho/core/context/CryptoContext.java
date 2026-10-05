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

import java.io.Closeable;
import java.security.Key;

import zeroecho.core.CryptoAlgorithm;

/**
 * Common interface for all cryptographic operation contexts.
 *
 * <p>
 * A {@code CryptoContext} represents the active state of an algorithm bound to
 * a specific key and optional parameters. Contexts encapsulate resources such
 * as cipher instances, digest engines, or signature state machines. They are
 * created by a {@link zeroecho.core.CryptoAlgorithm} for a particular
 * {@link zeroecho.core.KeyUsage} role and remain valid until {@link #close()}
 * is called.
 * </p>
 *
 * <h2>Lifecycle</h2>
 * <ul>
 * <li>Contexts are created via {@code ZeroEchoSession#createContext(...)}.</li>
 * <li>They may wrap native or provider-managed resources that must be
 * released.</li>
 * <li>Callers must stop using a context after closing it. This is a caller
 * lifecycle obligation, not a guarantee that subsequent calls are rejected;
 * some implementations have no context-owned resources and close is a no-op.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Bound keys are borrowed from the caller and are never destroyed by
 * context closure.</li>
 * <li>Applications should call {@link #close()} promptly. Closing is not a
 * guarantee of erasing provider-managed key material or Java heap copies.</li>
 * <li>Contexts are not guaranteed to be thread-safe; concurrent use should be
 * avoided unless explicitly documented by the implementation.</li>
 * </ul>
 *
 * <h2>Subtypes</h2> Concrete context kinds are represented by specialized
 * subinterfaces:
 * <ul>
 * <li>{@link DigestContext} - unkeyed hash and XOF pipelines</li>
 * <li>{@link EncryptionContext} - symmetric/asymmetric encryption and
 * decryption streams</li>
 * <li>{@link MacContext} - message authentication codes</li>
 * <li>{@link SignatureContext} - digital signatures (sign/verify)</li>
 * <li>{@link AgreementContext} - key agreement protocols</li>
 * <li>{@link KemContext} - key encapsulation mechanisms (KEM)</li>
 * </ul>
 *
 * @since 1.0
 */
public sealed interface CryptoContext extends Closeable
        permits DigestContext, EncryptionContext, KemContext, MacContext, SignatureContext, AgreementContext {
    /**
     * Returns the algorithm that created this context.
     *
     * @return the algorithm definition that owns this context
     */
    CryptoAlgorithm algorithm();

    /**
     * Returns the key bound to this context.
     *
     * <p>
     * For unkeyed contexts such as digests, this may be
     * {@link zeroecho.core.NullKey#INSTANCE}.
     * </p>
     *
     * @return the cryptographic key or sentinel bound to this context
     */
    Key key();

    /**
     * Completes the context's implementation-specific cleanup.
     *
     * <p>
     * Implementations release resources they explicitly own; cleanup can be a
     * no-op for contexts holding only borrowed or garbage-collected state. The
     * bound key remains caller-owned: closing a context never destroys the key.
     * Callers that own a destroyable key must destroy it explicitly after all
     * contexts and other consumers have released it.
     * Streams returned by the context have independent lifecycles: callers must
     * complete and close those streams before closing the context. This method
     * does not promise to finalize stream output or verify authentication tags.
     * </p>
     *
     * @throws java.io.IOException if the underlying provider encounters an I/O
     *                             error during cleanup
     */
    @Override
    void close() throws java.io.IOException;
}
