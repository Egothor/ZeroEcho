/* *****************************************************************************
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
package zeroecho.sdk.builders;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.function.Supplier;

import conflux.CtxInterface;
import conflux.Key;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.TagEngineBuilder;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * Builder for {@link DataContent} pipelines that attach or verify an
 * authentication tag at end of stream.
 *
 * <p>
 * A {@code TagTrailerDataContentBuilder} composes with a {@link TagEngine} to
 * produce {@link DataContent} instances for two complementary flows:
 * </p>
 * <ul>
 * <li><b>Encrypt</b> (produce): the wrapped engine emits {@code [body][tag]}
 * when EOF is reached.</li>
 * <li><b>Decrypt</b> (verify): the trailer is stripped from input, supplied to
 * {@link TagEngine#setExpectedTag(byte[])}, and the body is streamed through
 * the engine for verification.</li>
 * </ul>
 *
 * <h2>Construction</h2>
 * <ul>
 * <li>Use the single-engine constructor if only one stream will be built from
 * this instance.</li>
 * <li>Prefer the factory constructor (for example, with
 * {@link TagEngineBuilder}) to obtain a fresh {@link TagEngine} per stream and
 * avoid state reuse.</li>
 * </ul>
 *
 * <h2>Verification behavior</h2>
 * <ul>
 * <li>{@link #throwOnMismatch()} - default; verification failures surface as
 * {@link java.io.IOException} from the returned stream when EOF finalizes
 * verification.</li>
 * <li>{@link #flagInContext(CtxInterface, Key)} - instead of throwing, the
 * engine records a {@code Boolean} under the provided {@link Key} in the
 * supplied {@link CtxInterface}.</li>
 * </ul>
 *
 * @param <T> the engine-specific verification type parameter used by
 *            {@link TagEngine}
 * @since 1.0
 */
public final class TagTrailerDataContentBuilder<T> implements DataContentBuilder<DataContent> {

    /**
     * Factory that creates a new {@link TagEngine} per use.
     */
    private final Supplier<? extends TagEngine<T>> engineFactory;

    /**
     * Buffer size for the tail-stripper (default 8192).
     */
    private int bufferSize = 8192;

    /**
     * Optional context and key for verification flagging.
     */
    private CtxInterface ctx;
    private Key<Boolean> verifyKey;

    /**
     * Creates a builder bound to a fixed engine instance.
     *
     * <p>
     * This form ties the builder to a single-use engine. Prefer
     * {@link #TagTrailerDataContentBuilder(Supplier)} when multiple streams are
     * expected.
     * </p>
     *
     * @param engine preconstructed engine instance; must not be {@code null}
     * @throws NullPointerException if {@code engine} is {@code null}
     */
    public TagTrailerDataContentBuilder(TagEngine<T> engine) {
        Objects.requireNonNull(engine, "engine");
        this.engineFactory = () -> engine;
    }

    /**
     * Creates a builder with an engine factory.
     *
     * <p>
     * A fresh engine is obtained for each built stream. See
     * {@link TagEngineBuilder} for standard factories.
     * </p>
     *
     * @param engineFactory supplier producing a new {@link TagEngine}; must not be
     *                      {@code null}
     * @throws NullPointerException if {@code engineFactory} is {@code null}
     */
    public TagTrailerDataContentBuilder(Supplier<? extends TagEngine<T>> engineFactory) {
        this.engineFactory = Objects.requireNonNull(engineFactory, "engineFactory");
    }

    /**
     * Sets the internal I/O buffer size used when stripping the trailer.
     *
     * @param bytes buffer size in bytes; must be at least 1
     * @return this builder for chaining
     * @throws IllegalArgumentException if {@code bytes < 1}
     */
    public TagTrailerDataContentBuilder<T> bufferSize(int bytes) {
        if (bytes < 1) { // NOPMD
            throw new IllegalArgumentException("bufferSize must be >= 1");
        }
        this.bufferSize = bytes;
        return this;
    }

    /**
     * Configures decryption to throw on verification mismatch.
     *
     * <p>
     * This is the default. The underlying engine is set up to raise
     * {@link java.io.IOException} at EOF when the computed tag does not equal the
     * expected tag.
     * </p>
     *
     * @return this builder for chaining
     */
    public TagTrailerDataContentBuilder<T> throwOnMismatch() {
        this.ctx = null;
        this.verifyKey = null;
        return this;
    }

    /**
     * Configures decryption to flag the verification outcome in the provided
     * context instead of throwing.
     *
     * <p>
     * On mismatch, {@code Boolean.FALSE} is stored under {@code verifyKey}; on
     * success, {@code Boolean.TRUE} is stored.
     * </p>
     *
     * @param ctx       context for recording the result; must not be {@code null}
     * @param verifyKey key under which to record the verification result; must not
     *                  be {@code null}
     * @return this builder for chaining
     * @throws NullPointerException if {@code ctx} or {@code verifyKey} is
     *                              {@code null}
     */
    public TagTrailerDataContentBuilder<T> flagInContext(CtxInterface ctx, Key<Boolean> verifyKey) {
        this.ctx = ctx;
        this.verifyKey = verifyKey;
        return this;
    }

    /**
     * Builds a {@link DataContent} pipeline for the selected direction.
     *
     * <ul>
     * <li><b>Encrypt</b>: the engine appends the tag trailer after body bytes.</li>
     * <li><b>Decrypt</b>: the trailer is stripped, supplied to the engine, and the
     * body is streamed and verified.</li>
     * </ul>
     *
     * @param encrypt {@code true} to build the encrypting path, {@code false} for
     *                the decrypting path
     * @return the configured {@link DataContent} pipeline
     */
    @Override
    public DataContent build(boolean encrypt) {
        return encrypt ? new Encrypting<>(engineFactory) : new Decrypting<>(engineFactory, bufferSize, ctx, verifyKey);
    }

    /**
     * Encryption pipeline stage that appends a tag trailer.
     *
     * <p>
     * The engine itself emits {@code [body][tag]} via
     * {@link TagEngine#wrap(InputStream)}.
     * </p>
     */
    private static final class Encrypting<T> implements PlainContent {
        private final Supplier<? extends TagEngine<T>> engineFactory;
        private DataContent input;

        private Encrypting(Supplier<? extends TagEngine<T>> engineFactory) {
            this.engineFactory = engineFactory;
        }

        /**
         * Sets the upstream content to be processed.
         *
         * @param input upstream data; must not be {@code null}
         * @throws NullPointerException if {@code input} is {@code null}
         */
        @Override
        public void setInput(DataContent input) {
            this.input = input;
        }

        /**
         * Returns a stream that forwards the body and appends the tag on EOF.
         *
         * @return a wrapped stream that emits {@code [body][tag]}
         * @throws IOException if no upstream is set or the engine fails to wrap
         */
        @Override
        public InputStream getStream() throws IOException {
            if (input == null) {
                throw new IOException("TagTrailer[encrypt] has no upstream input");
            }
            // Fresh engine per stream; engine must emit [body][tag] itself.
            TagEngine<T> engine = engineFactory.get();
            return engine.wrap(input.getStream());
        }
    }

    /**
     * Decryption pipeline stage that strips and verifies a trailing tag.
     *
     * <p>
     * The final {@code tagLength()} bytes are removed from the upstream, supplied
     * to {@link TagEngine#setExpectedTag(byte[])}, and the remaining body is
     * streamed through {@link TagEngine#wrap(InputStream)}. The engine performs
     * verification according to the configured strategy.
     * </p>
     */
    private static final class Decrypting<T> implements PlainContent {
        private final Supplier<? extends TagEngine<T>> engineFactory;
        private final int bufferSize;
        private final CtxInterface ctx;
        private final Key<Boolean> verifyKey;

        private DataContent input;

        private Decrypting(Supplier<? extends TagEngine<T>> engineFactory, int bufferSize, CtxInterface ctx,
                Key<Boolean> verifyKey) {
            this.engineFactory = engineFactory;
            this.bufferSize = bufferSize;
            this.ctx = ctx;
            this.verifyKey = verifyKey;
        }

        /**
         * Sets the upstream content to be processed.
         *
         * @param input upstream data; must not be {@code null}
         * @throws NullPointerException if {@code input} is {@code null}
         */
        @Override
        public void setInput(DataContent input) {
            this.input = input;
        }

        /**
         * Returns a stream that yields only the body while the tag is verified at EOF.
         *
         * @return a wrapped stream that verifies the detached trailer
         * @throws IOException if no upstream is set, the declared tag length is
         *                     invalid, or wrapping fails
         */
        @Override
        public InputStream getStream() throws IOException {
            if (input == null) {
                throw new IOException("TagTrailer[decrypt] has no upstream input");
            }

            // Fresh engine per stream
            TagEngine<T> engine = engineFactory.get();

            final int tagLen = engine.tagLength();
            if (tagLen <= 0) {
                throw new IOException("Invalid tagLength: " + tagLen);
            }

            if (ctx == null) {
                engine.setVerificationApproach(engine.getVerificationCore().getThrowOnMismatch());
            } else {
                engine.setVerificationApproach(engine.getVerificationCore().getFlagOkInCtx(ctx, verifyKey));
            }

            // Strip the final tag from the plaintext and pass it to the engine immediately.
            InputStream bodyOnly = new TailStrippingInputStream(input.getStream(), tagLen, bufferSize) {
                @Override
                protected void processTail(byte[] tail) throws IOException {
                    engine.setExpectedTag(tail); // engine may verify now or defer until EOF
                }
            };

            // Feed the engine only the body. The engine handles verification on its own.
            return engine.wrap(bodyOnly);
        }
    }
}
