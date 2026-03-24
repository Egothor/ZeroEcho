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
package zeroecho.sdk.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.function.Consumer;

import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;

/**
 * SignatureTrailerInputStream reads an upstream stream that has a trailing
 * signature tag and exposes only the original body while capturing the detached
 * signature.
 *
 * <h2>Overview</h2> This class is a specialized
 * {@code TailStrippingInputStream} that wraps a {@link SignatureContext}
 * produced stream. The wrapped context emits {@code [body][signature]}; this
 * stream transparently strips the trailing signature bytes from the output and
 * optionally delivers a defensive copy of the signature to a user-supplied
 * callback.
 *
 * <p>
 * The signature length is obtained from {@link SignatureContext#tagLength()}
 * and the upstream stream is obtained via
 * {@link SignatureContext#wrap(java.io.InputStream)}. Resource ownership is
 * explicit: {@link #close()} closes both the underlying stream chain and the
 * {@code SignatureContext}.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * SignatureContext sc = CryptoAlgorithms.create("Ed25519", KeyUsage.SIGN, privateKey, spec);
 * try (InputStream in = new SignatureTrailerInputStream(
 *         sc,
 *         originalContent.getStream(),
 *         8192,
 *         sig -> ctx.put(SIG_KEY, sig))) {
 *     // read 'in' to obtain only the body; signature is delivered to the callback
 *     in.transferTo(out);
 * }
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are not thread-safe. Use from a single
 * thread and do not share across readers.
 */
public final class SignatureTrailerInputStream extends TailStrippingInputStream {

    private final SignatureContext sc;
    private final Consumer<byte[]> onSignature;

    /**
     * Creates a new signature-stripping stream that passes through only the body
     * while capturing the trailing signature tag.
     *
     * <p>
     * This constructor immediately calls
     * {@link SignatureContext#wrap(java.io.InputStream)} to obtain the producing
     * stream and configures the tail length to
     * {@link SignatureContext#tagLength()}.
     * </p>
     *
     * @param sc          the signature context that wraps the upstream stream and
     *                    provides tag metadata; must not be null
     * @param upstream    the upstream stream that yields {@code [body][signature]};
     *                    must not be null
     * @param bufferSize  internal buffer size used by the tail stripper; must be
     *                    positive
     * @param onSignature optional callback invoked exactly once with a defensive
     *                    copy of the finalized signature bytes; may be null
     * @throws IOException          if initializing the underlying wrapped stream
     *                              fails
     * @throws NullPointerException if {@code sc} or {@code upstream} is null
     */
    public SignatureTrailerInputStream(SignatureContext sc, InputStream upstream, int bufferSize,
            Consumer<byte[]> onSignature) throws IOException {
        super(Objects.requireNonNull(sc, "sc").wrap(Objects.requireNonNull(upstream, "upstream")), sc.tagLength(),
                bufferSize);
        this.sc = sc;
        this.onSignature = onSignature;
    }

    /**
     * Receives the stripped tail bytes and forwards a defensive copy to the
     * registered callback.
     *
     * <p>
     * If no callback is set or the tail is {@code null}, this method returns
     * without action. Any runtime exception thrown by the callback is caught and
     * ignored so that stream semantics remain unaffected.
     * </p>
     *
     * @param tail the stripped signature bytes, or {@code null} if no tail was
     *             detected
     * @throws IOException never thrown by this implementation, preserved for the
     *                     template method contract
     */
    @Override
    protected void processTail(byte[] tail) throws IOException {
        if (tail == null || onSignature == null) {
            return;
        }
        try {
            onSignature.accept(tail.clone());
        } catch (RuntimeException ignored) { // NOPMD
            // user callback must not break stream semantics
        }
    }

    /**
     * Closes the stream and the associated {@link SignatureContext}.
     *
     * <p>
     * This method first closes the underlying stream chain (draining to EOF if
     * required by the base class), then closes the signature context. If closing
     * the underlying stream throws an {@link IOException}, that exception is
     * rethrown after attempting to close the context.
     * </p>
     *
     * @throws IOException if closing the underlying stream fails
     */
    @Override
    public void close() throws IOException {
        try (sc) {
            super.close(); // drains to EOF if needed and closes the wrapped stream
        }
    }
}
