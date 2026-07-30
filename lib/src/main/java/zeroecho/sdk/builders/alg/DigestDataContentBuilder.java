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
package zeroecho.sdk.builders.alg;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Consumer;

import conflux.CtxInterface;
import conflux.Key;
import zeroecho.core.KeyUsage;
import zeroecho.core.NullKey;
import zeroecho.core.alg.digest.DigestSpec;
import zeroecho.core.context.DigestContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * DigestDataContentBuilder constructs streaming pipelines that compute message
 * digests while reading an InputStream.
 *
 * <h2>Overview</h2> The builder creates {@link PlainContent} that either passes
 * the original bytes through and strips the trailing digest tag from the
 * underlying engine, or emits the finalized digest itself in raw, hexadecimal,
 * or Base64 form. Algorithm selection is performed via convenience methods such
 * as {@link #sha256()} or {@link #shake256(int)} which configure an internal
 * {@link DigestSpec}.
 *
 * <h2>Output modes</h2>
 * <ul>
 * <li><b>Pass-through</b>: the output stream is identical to the input stream
 * while the digest is computed under the hood. The trailing tag produced by the
 * engine is stripped off transparently.</li>
 * <li><b>Emit digest</b>: the output stream contains only the digest, encoded
 * as raw bytes, hex, or Base64.</li>
 * </ul>
 *
 * <h2>Context integration</h2> A runtime context can be supplied via
 * {@link #context(conflux.CtxInterface)}. When provided together with
 * {@link #storeInCtx(conflux.Key)}, the finalized digest bytes are stored in
 * the context. A callback may also be registered via
 * {@link #onDigest(java.util.function.Consumer)} to receive a defensive copy of
 * the digest.
 *
 * <h2>Examples</h2> <pre>{@code
 * // 1) Pass-through SHA-256 that stores the digest in a context:
 * PlainContent content = DigestDataContentBuilder.builder()
 *     .sha256()
 *     .context(ctx)
 *     .storeInCtx(digestKey)
 *     .passThrough()
 *     .build(true);
 *
 * // 2) Emit hex-encoded SHA3-512 digest:
 * PlainContent hexOut = DigestDataContentBuilder.builder()
 *     .sha3_512()
 *     .emitHexDigest()
 *     .build(true);
 *
 * // 3) Emit 32-byte SHAKE128 digest in Base64 and also receive it via a callback:
 * PlainContent b64Out = DigestDataContentBuilder.builder()
 *     .shake128(32)
 *     .onDigest(bytes -> System.out.println("len=" + bytes.length))
 *     .emitBase64Digest()
 *     .build(true);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are mutable and not thread-safe. Configure
 * and use each builder instance from a single thread.
 *
 * @see DigestSpec
 * @see DigestContext
 * @see zeroecho.sdk.builders.core.DataContentBuilder
 * @see zeroecho.sdk.content.api.PlainContent
 */
public final class DigestDataContentBuilder implements DataContentBuilder<PlainContent> {
    private final ZeroEchoSession session;

    /**
     * OutputMode selects how the digest-computing pipeline presents its result to
     * callers.
     *
     * <p>
     * A mode controls whether the produced stream passes the original bytes through
     * (while computing the digest transparently) or emits only the finalized digest
     * in a chosen encoding. Modes are set by the builder methods
     * {@link #passThrough()}, {@link #emitRawDigest()}, {@link #emitHexDigest()},
     * and {@link #emitBase64Digest()}.
     * </p>
     *
     * <p>
     * Context storage via {@link #storeInCtx(conflux.Key)} and callbacks registered
     * with {@link #onDigest(java.util.function.Consumer)} are honored in all modes
     * after the digest has been finalized.
     * </p>
     *
     * @since 1.0
     */
    private enum OutputMode {
        /**
         * Pass-through mode emits the original input bytes and strips the trailing tag.
         *
         * <p>
         * The underlying {@link DigestContext} appends a digest tag after the body. The
         * pipeline transparently removes that tag from the stream, leaving the body
         * unchanged. The finalized digest is still made available to the optional
         * context and callback.
         * </p>
         */
        PASSTHROUGH,
        /**
         * Emit-raw mode outputs only the finalized digest bytes.
         *
         * <p>
         * The upstream content is fully consumed to finalize the digest, then the
         * pipeline exposes a stream over the raw digest bytes with no additional
         * encoding. This is suitable when a binary digest is required by the caller.
         * </p>
         */
        EMIT_RAW,
        /**
         * Emit-hex mode outputs the finalized digest as lowercase hexadecimal text.
         *
         * <p>
         * The hex string is ASCII-encoded with no separators or prefixes. This mode is
         * convenient for logs, configuration files, and protocols that prefer textual
         * digests.
         * </p>
         */
        EMIT_HEX,
        /**
         * Emit-Base64 mode outputs the finalized digest as Base64 text without padding.
         *
         * <p>
         * The output is the RFC 4648 Base64 alphabet with padding omitted. This mode
         * provides a compact textual representation suitable for HTTP headers and JSON.
         * </p>
         */
        EMIT_BASE64
    }

    // ---- configuration ----
    private DigestSpec spec = DigestSpec.sha256();
    private OutputMode mode = OutputMode.PASSTHROUGH;

    private CtxInterface ctx; // optional
    private Key<byte[]> ctxStoreKey; // optional
    private Consumer<byte[]> callback; // optional
    private int bufferSize = 8192; // internal I/O buffer for tail-stripper

    private DigestDataContentBuilder(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Creates a new builder for constructing digest-computing {@link PlainContent}
     * pipelines.
     *
     * <h4>Example</h4> <pre>{@code
     * PlainContent pc = DigestDataContentBuilder.builder()
     *     .sha256()
     *     .emitRawDigest()
     *     .build(true);
     * }</pre>
     *
     * @return a new {@code DigestDataContentBuilder} instance
     */
    public static DigestDataContentBuilder builder(ZeroEchoSession session) {
        return new DigestDataContentBuilder(session);
    }

    /**
     * Selects SHA-256 as the digest algorithm.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder sha256() {
        this.spec = DigestSpec.sha256();
        return this;
    }

    /**
     * Selects SHA-384 as the digest algorithm.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder sha384() {
        this.spec = DigestSpec.sha384();
        return this;
    }

    /**
     * Selects SHA-512 as the digest algorithm.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder sha512() {
        this.spec = DigestSpec.sha512();
        return this;
    }

    /**
     * Selects SHA3-256 as the digest algorithm.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder sha3_256() {
        this.spec = DigestSpec.sha3_256();
        return this;
    }

    /**
     * Selects SHA3-512 as the digest algorithm.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder sha3_512() {
        this.spec = DigestSpec.sha3_512();
        return this;
    }

    /**
     * Selects SHAKE128 with a given output length.
     *
     * @param outLenBytes the desired digest length in bytes
     * @return {@code this} builder for chaining
     * @throws IllegalArgumentException if {@code outLenBytes} is invalid for the
     *                                  implementation
     */
    public DigestDataContentBuilder shake128(int outLenBytes) {
        this.spec = DigestSpec.shake128(outLenBytes);
        return this;
    }

    /**
     * Selects SHAKE256 with a given output length.
     *
     * @param outLenBytes the desired digest length in bytes
     * @return {@code this} builder for chaining
     * @throws IllegalArgumentException if {@code outLenBytes} is invalid for the
     *                                  implementation
     */
    public DigestDataContentBuilder shake256(int outLenBytes) {
        this.spec = DigestSpec.shake256(outLenBytes);
        return this;
    }

    /**
     * Configures the builder to pass the input through unchanged and strip the
     * trailing tag.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder passThrough() {
        this.mode = OutputMode.PASSTHROUGH;
        return this;
    }

    /**
     * Configures the builder to emit the finalized digest as raw bytes.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder emitRawDigest() {
        this.mode = OutputMode.EMIT_RAW;
        return this;
    }

    /**
     * Configures the builder to emit the finalized digest as lowercase hexadecimal
     * text.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder emitHexDigest() {
        this.mode = OutputMode.EMIT_HEX;
        return this;
    }

    /**
     * Configures the builder to emit the finalized digest as Base64 text without
     * padding.
     *
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder emitBase64Digest() {
        this.mode = OutputMode.EMIT_BASE64;
        return this;
    }

    /**
     * Sets the internal buffer size used by the tail-stripping wrapper.
     *
     * @param bytes buffer size in bytes; must be greater than or equal to 1
     * @return {@code this} builder for chaining
     * @throws IllegalArgumentException if {@code bytes < 1}
     */
    public DigestDataContentBuilder bufferSize(int bytes) {
        if (bytes < 1) { // NOPMD
            throw new IllegalArgumentException("bufferSize must be >= 1");
        }
        this.bufferSize = bytes;
        return this;
    }

    /**
     * Sets an optional runtime context used to store the finalized digest when
     * requested.
     *
     * @param ctx the context instance; may be null to disable context storage
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder context(CtxInterface ctx) {
        this.ctx = ctx;
        return this;
    }

    /**
     * Requests that the finalized digest be written into the context under the
     * provided key.
     *
     * <p>
     * This setting is only effective if a non-null context is provided via
     * {@link #context(CtxInterface)}.
     * </p>
     *
     * @param key the context key used to store the digest; may be null to clear
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder storeInCtx(Key<byte[]> key) {
        this.ctxStoreKey = key;
        return this;
    }

    /**
     * Registers a callback to receive a defensive copy of the finalized digest.
     *
     * @param cb the callback to invoke after the digest is computed; may be null to
     *           clear
     * @return {@code this} builder for chaining
     */
    public DigestDataContentBuilder onDigest(Consumer<byte[]> cb) {
        this.callback = cb;
        return this;
    }

    /**
     * Builds a digest-computing {@link PlainContent} according to the current
     * configuration.
     *
     * <p>
     * The boolean parameter is ignored and present only to satisfy the
     * {@link zeroecho.sdk.builders.core.DataContentBuilder} interface.
     * </p>
     *
     * <h4>Result</h4>
     * <ul>
     * <li>Pass-through mode returns content that outputs the original bytes while
     * computing the digest and stripping the trailing tag.</li>
     * <li>Emit modes return content whose output is only the digest in the
     * requested encoding.</li>
     * </ul>
     *
     * @param encryptFlagIgnored ignored parameter from the interface
     * @return a {@link PlainContent} pipeline that performs the selected digest
     *         behavior when its stream is consumed
     */
    @Override
    public PlainContent build(boolean encryptFlagIgnored) {
        return switch (mode) {
            case PASSTHROUGH -> new PassthroughDigestContent(spec, ctx, ctxStoreKey, callback, bufferSize);
            case EMIT_RAW, EMIT_HEX, EMIT_BASE64 ->
                new DigestBytesContent(spec, ctx, ctxStoreKey, callback, mode, bufferSize);
        };
    }

    /**
     * Pass-through: output == input; digest is computed by DigestContext and
     * captured from the produced trailer using
     * TailStrippingInputStream#processTail(...).
     */
    private final class PassthroughDigestContent implements PlainContent {
        private final DigestSpec spec;
        private final CtxInterface ctx;
        private final Key<byte[]> storeKey;
        private final Consumer<byte[]> callback;
        private final int bufferSize;

        private DataContent input;

        private PassthroughDigestContent(DigestSpec spec, CtxInterface ctx, Key<byte[]> storeKey,
                Consumer<byte[]> callback, int bufferSize) {
            this.spec = Objects.requireNonNull(spec, "spec");
            this.ctx = ctx;
            this.storeKey = storeKey;
            this.callback = callback;
            this.bufferSize = bufferSize;
        }

        @Override
        public void setInput(DataContent input) {
            this.input = Objects.requireNonNull(input, "input must not be null");
        }

        @Override
        public InputStream getStream() throws IOException {
            if (input == null) {
                throw new IllegalStateException("Upstream input is not set.");
            }

            // Create a DigestContext via registry (DIGEST / DIGEST / NullKey + spec).
            final DigestContext dctx = session.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE, // NOPMD
                    spec);

            // Engine emits [body][tag]; we strip the tag and capture it.
            final InputStream produced = dctx.wrap(input.getStream());
            final int tagLen = dctx.tagLength();

            return new TailStrippingInputStream(produced, tagLen, bufferSize) {
                @Override
                protected void processTail(byte[] tail) throws IOException {
                    if (tail == null) {
                        return;
                    }
                    byte[] copy = tail.clone();
                    if (ctx != null && storeKey != null) {
                        try {
                            ctx.put(storeKey, copy);
                        } catch (RuntimeException ignore) { // NOPMD
                        }
                    }
                    if (callback != null) {
                        try {
                            callback.accept(copy.clone());
                        } catch (RuntimeException ignore) { // NOPMD
                        }
                    }
                }
            };
        }
    }

    /**
     * Emit-only: consumes upstream so the engine appends the tag; we capture the
     * tag via TailStrippingInputStream and then return a stream over the encoded
     * tag.
     */
    private final class DigestBytesContent implements PlainContent {
        private final DigestSpec spec;
        private final CtxInterface ctx;
        private final Key<byte[]> storeKey;
        private final Consumer<byte[]> callback;
        private final OutputMode out;
        private final int bufferSize;

        private DataContent input;

        private DigestBytesContent(DigestSpec spec, CtxInterface ctx, Key<byte[]> storeKey, Consumer<byte[]> callback,
                OutputMode out, int bufferSize) {
            this.spec = Objects.requireNonNull(spec, "spec");
            this.ctx = ctx;
            this.storeKey = storeKey;
            this.callback = callback;
            this.out = Objects.requireNonNull(out, "out");
            if (out == OutputMode.PASSTHROUGH) {
                throw new IllegalArgumentException("DigestBytesContent must use an emit-* mode");
            }
            this.bufferSize = bufferSize;
        }

        @Override
        public void setInput(DataContent input) {
            this.input = Objects.requireNonNull(input, "input must not be null");
        }

        @Override
        public InputStream getStream() throws IOException {
            if (input == null) {
                throw new IllegalStateException("Upstream input is not set.");
            }

            // Create engine and its output (which appends [tag] after the body).
            final DigestContext dctx = session.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE, // NOPMD
                    spec);
            final InputStream produced = dctx.wrap(input.getStream());
            final int tagLen = dctx.tagLength();

            // Capture trailer while reading the produced stream to EOF.
            final byte[][] holder = new byte[1][];
            try (InputStream in = new TailStrippingInputStream(produced, tagLen, bufferSize) {
                @Override
                protected void processTail(byte[] tail) throws IOException {
                    holder[0] = (tail == null ? null : tail.clone());
                }
            }) {
                byte[] buf = new byte[8192];
                while (true) {
                    int n = in.read(buf);
                    if (n < 0) {
                        break; // discard body (we only need the digest)
                    }
                }
            }

            byte[] digest = holder[0];
            if (digest == null) {
                digest = new byte[0];
            }

            // Store / callback (raw bytes)
            byte[] toStore = digest.clone();
            if (ctx != null && storeKey != null) {
                try {
                    ctx.put(storeKey, toStore);
                } catch (RuntimeException ignore) { // NOPMD
                }
            }
            if (callback != null) {
                try {
                    callback.accept(toStore.clone());
                } catch (RuntimeException ignore) { // NOPMD
                }
            }

            // Encode as requested
            byte[] outBytes = switch (out) {
                case EMIT_RAW -> toStore;
                case EMIT_HEX -> java.util.HexFormat.of().formatHex(toStore).getBytes(StandardCharsets.UTF_8);
                case EMIT_BASE64 -> Base64.getEncoder().withoutPadding().encode(toStore);
                default -> throw new IllegalStateException("Unexpected output mode: " + out);
            };
            return new ByteArrayInputStream(outBytes);
        }
    }
}
