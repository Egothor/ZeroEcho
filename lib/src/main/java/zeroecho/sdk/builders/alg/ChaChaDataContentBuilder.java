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
package zeroecho.sdk.builders.alg;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Objects;

import javax.crypto.SecretKey;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.alg.chacha.ChaCha20Poly1305HeaderCodec;
import zeroecho.core.alg.chacha.ChaCha20Poly1305Spec;
import zeroecho.core.alg.chacha.ChaChaHeaderCodec;
import zeroecho.core.alg.chacha.ChaChaKeyGenSpec;
import zeroecho.core.alg.chacha.ChaChaKeyImportSpec;
import zeroecho.core.alg.chacha.ChaChaSpec;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spi.ContextAware;
import zeroecho.core.spi.SymmetricKeyBuilder;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.EncryptedContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * ChaChaDataContentBuilder builds streaming ChaCha20 and ChaCha20-Poly1305
 * pipelines that encrypt or decrypt as an {@link java.io.InputStream} is
 * consumed.
 *
 * <h2>Variants</h2> The builder selects between two cipher variants:
 * <ul>
 * <li>Stream (ChaCha20): chosen by default or when {@link #initialCounter(int)}
 * or {@link #withCounter(int)} is used.</li>
 * <li>AEAD (ChaCha20-Poly1305): chosen when {@link #withAad(byte[])} is
 * provided.</li>
 * </ul>
 * Supplying both AAD and counter options is a configuration error and results
 * in an {@link IllegalStateException}.
 *
 * <h2>Key material</h2> A secret key is resolved in the following order:
 * <ol>
 * <li>Explicit key via {@link #withKey(javax.crypto.SecretKey)}.</li>
 * <li>Key generation via {@link #generateKey()} with a default 256-bit
 * spec.</li>
 * <li>Key import via {@link #importKeyRaw(byte[])},
 * {@link #importKeyHex(String)}, or {@link #importKeyBase64(String)}.</li>
 * <li>Fallback to default 256-bit generation if none of the above is
 * provided.</li>
 * </ol>
 *
 * <h2>Context and headers</h2> A runtime {@link conflux.CtxInterface} can be
 * attached via {@link #context(conflux.CtxInterface)} to exchange parameters
 * such as nonce, AAD, or counter. When a context is present, the builder writes
 * values under algorithm-specific keys from {@code ConfluxKeys}. If a header is
 * requested with {@link #withHeader()} or a custom {@link SymmetricHeaderCodec}
 * is supplied via {@link #withHeaderCodec(SymmetricHeaderCodec)}, a context is
 * required; if none was provided, a temporary one is created internally. A
 * default header codec is chosen based on the variant when no custom codec is
 * set. The nonce is typically 12 bytes; if absent during encryption and a
 * context is available, an implementation-specific nonce may be generated and
 * stored in the context.
 *
 * <h2>Usage examples</h2> <pre>{@code
 * // 1) ChaCha20 stream encryption with generated key and header
 * DataContent enc = ChaChaDataContentBuilder.builder()
 *     .generateKey()
 *     .withHeader()
 *     .build(true);
 *
 * // 2) ChaCha20-Poly1305 decryption with supplied key, nonce, and AAD
 * DataContent dec = ChaChaDataContentBuilder.builder()
 *     .withKey(secretKey)
 *     .withNonce(nonce12)                  // 12 bytes
 *     .withAad("meta".getBytes(StandardCharsets.UTF_8))
 *     .build(false);
 *
 * // 3) ChaCha20 stream encryption with explicit counter propagated via context
 * DataContent enc2 = ChaChaDataContentBuilder.builder()
 *     .withKey(secretKey)
 *     .context(ctx)
 *     .withCounter(7)                      // overrides initialCounter in ctx
 *     .build(true);
 *
 * // 4) Import a key from hex and decrypt without headers
 * DataContent dec2 = ChaChaDataContentBuilder.builder()
 *     .importKeyHex(hexKey)
 *     .build(false);
 * }</pre>
 *
 * <h2>Behavior of {@link #build(boolean)}</h2> Calling {@code build(true)}
 * returns a pipeline that encrypts as the stream is read; {@code build(false)}
 * returns a pipeline that decrypts. In stream mode,
 * {@link #initialCounter(int)} sets the spec's initial counter (default is 1),
 * while {@link #withCounter(int)} stores an override in the context. In AEAD
 * mode, {@link #withAad(byte[])} supplies additional authenticated data.
 *
 * <h2>Thread-safety</h2> Instances are mutable and not thread-safe. Configure
 * and use each builder instance from a single thread.
 *
 * @see zeroecho.sdk.content.api.DataContent
 * @see zeroecho.sdk.builders.core.DataContentBuilder
 * @see zeroecho.core.CryptoAlgorithms
 * @see zeroecho.core.context.EncryptionContext
 * @see SymmetricHeaderCodec
 */
public final class ChaChaDataContentBuilder implements DataContentBuilder<DataContent> {

    private SecretKey secretKey;
    private ChaChaKeyGenSpec genSpec;
    private ChaChaKeyImportSpec importSpec;

    private CtxInterface ctx;
    private byte[] nonce;

    private int initialCounter = 1;
    private boolean initialCounterSet; // = false;
    private Integer counter; // = null;

    private byte[] aad; // = null;

    private SymmetricHeaderCodec headerCodec; // = null;
    private boolean headerRequested; // = false;

    /**
     * Returns a new builder instance for constructing ChaCha20 or ChaCha20-Poly1305
     * streaming pipelines.
     *
     * <h4>Examples</h4> <pre>{@code
     * DataContent enc = ChaChaDataContentBuilder.builder()
     *     .generateKey()
     *     .withHeader()
     *     .build(true);
     * }</pre>
     *
     * @return a new {@code ChaChaDataContentBuilder}
     */
    public static ChaChaDataContentBuilder builder() {
        return new ChaChaDataContentBuilder();
    }

    private ChaChaDataContentBuilder() {
    }

    /**
     * Sets an explicit secret key to use for encryption or decryption.
     *
     * <p>
     * Supplying a key clears any previously configured key generation or import
     * specification.
     * </p>
     *
     * @param k the secret key to use; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public ChaChaDataContentBuilder withKey(SecretKey k) {
        this.secretKey = Objects.requireNonNull(k);
        this.genSpec = null;
        this.importSpec = null;
        return this;
    }

    /**
     * Requests generation of a fresh ChaCha key using a default 256-bit
     * specification.
     *
     * <p>
     * Enabling key generation clears any previously configured explicit key or
     * import specification.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public ChaChaDataContentBuilder generateKey() {
        this.genSpec = ChaChaKeyGenSpec.chacha256();
        this.secretKey = null;
        this.importSpec = null;
        return this;
    }

    /**
     * Imports a secret key from raw key bytes appropriate for the selected ChaCha
     * variant.
     *
     * <p>
     * Supplying an import spec clears any previously configured explicit key or key
     * generation request.
     * </p>
     *
     * @param raw the raw key bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code raw} is null
     * @throws IllegalArgumentException if {@code raw} is not a valid key length
     */
    public ChaChaDataContentBuilder importKeyRaw(byte[] raw) {
        this.importSpec = ChaChaKeyImportSpec.fromRaw(raw);
        this.secretKey = null;
        this.genSpec = null;
        return this;
    }

    /**
     * Imports a secret key from a hexadecimal string.
     *
     * <p>
     * Supplying an import spec clears any previously configured explicit key or key
     * generation request.
     * </p>
     *
     * @param hex the hex-encoded key; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code hex} is null
     * @throws IllegalArgumentException if {@code hex} is not valid hexadecimal or
     *                                  not a valid key length
     */
    public ChaChaDataContentBuilder importKeyHex(String hex) {
        this.importSpec = ChaChaKeyImportSpec.fromHex(hex);
        this.secretKey = null;
        this.genSpec = null;
        return this;
    }

    /**
     * Imports a secret key from a Base64 string.
     *
     * <p>
     * Supplying an import spec clears any previously configured explicit key or key
     * generation request.
     * </p>
     *
     * @param b64 the Base64-encoded key; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code b64} is null
     * @throws IllegalArgumentException if {@code b64} is not valid Base64 or not a
     *                                  valid key length
     */
    public ChaChaDataContentBuilder importKeyBase64(String b64) {
        this.importSpec = ChaChaKeyImportSpec.fromBase64(b64);
        this.secretKey = null;
        this.genSpec = null;
        return this;
    }

    /**
     * Sets an optional runtime context used to read or write parameters such as
     * nonce, AAD, or counter.
     *
     * <p>
     * When a header is requested and no context is provided, a temporary context is
     * created internally.
     * </p>
     *
     * @param ctx the context instance to use; may be null
     * @return {@code this} builder for chaining
     */
    public ChaChaDataContentBuilder context(CtxInterface ctx) {
        this.ctx = ctx;
        return this;
    }

    /**
     * Sets an optional nonce value.
     *
     * <p>
     * For ChaCha20 and ChaCha20-Poly1305 this is typically 12 bytes. If absent
     * during encryption and a context is in use, an implementation-specific nonce
     * may be generated and placed into the context.
     * </p>
     *
     * @param nonce the nonce bytes; may be null
     * @return {@code this} builder for chaining
     */
    public ChaChaDataContentBuilder withNonce(byte[] nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets the initial counter for ChaCha20 stream mode.
     *
     * <p>
     * Calling this method selects stream mode unless AEAD is selected via
     * {@link #withAad(byte[])}. The default initial counter is 1.
     * </p>
     *
     * @param c the initial counter value
     * @return {@code this} builder for chaining
     */
    public ChaChaDataContentBuilder initialCounter(int c) {
        this.initialCounter = c;
        this.initialCounterSet = true;
        return this;
    }

    /**
     * Sets an explicit counter override to be propagated through the context.
     *
     * <p>
     * This value is stored under an algorithm-specific key in the provided context
     * and overrides {@link #initialCounter(int)} if present.
     * </p>
     *
     * @param c the counter value to use
     * @return {@code this} builder for chaining
     */
    public ChaChaDataContentBuilder withCounter(int c) {
        this.counter = c;
        return this;
    }

    /**
     * Sets additional authenticated data for ChaCha20-Poly1305.
     *
     * <p>
     * Providing AAD selects AEAD mode. Passing {@code null} or an empty array
     * leaves the decision to other configuration such as stream counters.
     * </p>
     *
     * @param aad the AAD bytes; may be null
     * @return {@code this} builder for chaining
     */
    public ChaChaDataContentBuilder withAad(byte[] aad) {
        this.aad = aad;
        return this;
    }

    /**
     * Sets a custom header codec to emit or parse algorithm headers.
     *
     * <p>
     * Supplying a codec clears the implicit header request flag. If no codec is
     * supplied but a header is requested via {@link #withHeader()}, a default is
     * chosen based on the selected variant.
     * </p>
     *
     * @param codec the header codec to use; may be null to clear
     * @return {@code this} builder for chaining
     */
    public ChaChaDataContentBuilder withHeaderCodec(SymmetricHeaderCodec codec) {
        this.headerCodec = codec;
        this.headerRequested = false;
        return this;
    }

    /**
     * Requests that a header be emitted (on encrypt) or parsed (on decrypt).
     *
     * <p>
     * If no custom codec is set, a default codec is chosen depending on whether
     * stream or AEAD mode is inferred.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public ChaChaDataContentBuilder withHeader() {
        this.headerRequested = true;
        return this;
    }

    /**
     * Builds a streaming encryption or decryption pipeline according to the current
     * configuration.
     *
     * <p>
     * AEAD mode is selected if AAD is provided via {@link #withAad(byte[])}, using
     * the algorithm id "CHACHA20-POLY1305". Otherwise stream mode is used, with the
     * algorithm id "CHACHA20".
     * </p>
     *
     * <p>
     * The key is resolved in this order: explicit key, key generation spec, key
     * import spec, default 256-bit generation.
     * </p>
     *
     * <p>
     * If a header is requested and no context is provided, a temporary context is
     * created. When encrypting with a context, if no nonce is supplied, the
     * implementation may generate one and store it into the context.
     * </p>
     *
     * <pre>{@code
     * DataContent enc = ChaChaDataContentBuilder.builder()
     *     .generateKey()
     *     .withHeader()
     *     .build(true);
     * }</pre>
     *
     * @param encrypt {@code true} to build an encrypting pipeline, {@code false}
     *                for a decrypting pipeline
     * @return a {@link zeroecho.sdk.content.api.DataContent} instance that performs
     *         the requested operation when its stream is consumed
     * @throws IllegalStateException if conflicting configuration is detected or key
     *                               construction fails
     */
    @Override
    public DataContent build(boolean encrypt) { // NOPMD
        final Variant v = inferVariant();
        final String algId = v == Variant.AEAD ? "CHACHA20-POLY1305" : "CHACHA20";

        final SecretKey key = resolveKey(algId);

        // header → ensure ctx exists
        if ((headerRequested || headerCodec != null) && ctx == null) {
            ctx = Ctx.INSTANCE
                    .getContext("chacha-" + (v == Variant.AEAD ? "aead" : "stream") + "-" + System.nanoTime());
        }
        // fill ctx with runtime params
        if (ctx != null) {
            if (nonce != null && nonce.length > 0) {
                ctx.put(ConfluxKeys.iv(algId), nonce);
            }
            if (v == Variant.AEAD) {
                if (aad != null) { // NOPMD
                    ctx.put(ConfluxKeys.aad(algId), aad);
                }
            } else {
                if (counter != null) {
                    ctx.put(ConfluxKeys.tagBits(algId), counter);
                }
            }
        }

        // pick default header now that variant is known (unless user supplied one)
        final SymmetricHeaderCodec hdr = (headerCodec != null) ? headerCodec
                : headerRequested ? (v == Variant.AEAD ? new ChaCha20Poly1305HeaderCodec() : new ChaChaHeaderCodec())
                        : null;

        if (v == Variant.AEAD) {
            final ChaCha20Poly1305Spec spec = ChaCha20Poly1305Spec.builder().header(hdr).build();
            return encrypt ? new EncryptContent<>(algId, key, spec, ctx) : new DecryptContent<>(algId, key, spec, ctx);
        } else {
            final ChaChaSpec spec = ChaChaSpec.builder().initialCounter(initialCounter).header(hdr).build();
            return encrypt ? new EncryptContent<>(algId, key, spec, ctx) : new DecryptContent<>(algId, key, spec, ctx);
        }
    }

    /**
     * Internal selector for the cipher variant inferred from the builder
     * configuration.
     *
     * <h2>Selection rules</h2>
     * <ul>
     * <li>{@code AEAD} is selected when non-empty AAD is supplied via
     * {@link #withAad(byte[])}.</li>
     * <li>{@code STREAM} is selected when a counter is configured via
     * {@link #initialCounter(int)} or {@link #withCounter(int)}, or when neither
     * AAD nor counter options are provided (default).</li>
     * <li>Supplying both AAD and counter options is invalid and results in
     * {@link IllegalStateException} at build time.</li>
     * </ul>
     *
     * <p>
     * The selected variant determines the algorithm id ({@code "CHACHA20"} vs
     * {@code "CHACHA20-POLY1305"}), the required parameters, and the finalization
     * behavior (AEAD verification at EOF).
     * </p>
     */
    private enum Variant {

        /**
         * ChaCha20 stream mode.
         *
         * <p>
         * Chosen by default or when a counter is configured. The initial counter
         * defaults to 1 unless overridden by {@link #initialCounter(int)}; an explicit
         * override can be propagated via {@link #withCounter(int)}.
         * </p>
         */
        STREAM,
        /**
         * ChaCha20-Poly1305 authenticated encryption mode.
         *
         * <p>
         * Selected when non-empty AAD is provided via {@link #withAad(byte[])}. The
         * pipeline produces and verifies an authentication tag; decryption failure must
         * be treated as fatal.
         * </p>
         */
        AEAD
    }

    private Variant inferVariant() {
        final boolean wantsAead = aad != null && aad.length > 0;
        final boolean wantsStream = initialCounterSet || counter != null;

        if (wantsAead && wantsStream) {
            throw new IllegalStateException(
                    "Conflicting ChaCha configuration: AAD was provided (AEAD) and counter options were set (STREAM). "
                            + "Remove either AAD or counter/initialCounter.");
        }
        // If neither explicitly set, default STREAM (matches common expectation)
        return wantsAead ? Variant.AEAD : Variant.STREAM;
    }

    private SecretKey resolveKey(String algId) {
        if (secretKey != null) {
            return secretKey;
        }
        try {
            CryptoAlgorithm algo = CryptoAlgorithms.require(algId);
            if (genSpec != null) {
                SymmetricKeyBuilder<ChaChaKeyGenSpec> b = algo.symmetricKeyBuilder(ChaChaKeyGenSpec.class);
                return b.generateSecret(genSpec);
            }
            if (importSpec != null) {
                SymmetricKeyBuilder<ChaChaKeyImportSpec> b = algo.symmetricKeyBuilder(ChaChaKeyImportSpec.class);
                return b.importSecret(importSpec);
            }
            SymmetricKeyBuilder<ChaChaKeyGenSpec> b = algo.symmetricKeyBuilder(ChaChaKeyGenSpec.class);
            return b.generateSecret(ChaChaKeyGenSpec.chacha256());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha key construction failed for " + algId, e);
        }
    }

    /**
     * Streaming encrypting content that pulls bytes from an upstream
     * {@link DataContent} and exposes the encrypted view as an
     * {@link java.io.InputStream}.
     *
     * <p>
     * An instance is configured with the algorithm id, key, spec, and optional
     * context. The upstream content is provided via {@link #setInput(DataContent)}
     * and the transformed stream is obtained from {@link #getStream()}.
     * </p>
     *
     * <p>
     * The actual cipher work is delegated to an
     * {@link zeroecho.core.context.EncryptionContext} created through
     * {@link zeroecho.core.CryptoAlgorithms#create(String, zeroecho.core.KeyUsage, java.security.Key, zeroecho.core.spec.ContextSpec)}.
     * If the created context implements {@code ContextAware}, the configured
     * context is injected before the stream is attached.
     * </p>
     */
    private static final class EncryptContent<S extends ContextSpec> implements EncryptedContent {
        private final String algId;
        private final SecretKey key;
        private final S spec;
        private final CtxInterface ctx;
        private DataContent upstream;

        private EncryptContent(String algId, SecretKey key, S spec, CtxInterface ctx) {
            this.algId = algId;
            this.key = key;
            this.spec = spec;
            this.ctx = ctx;
        }

        /**
         * Sets the upstream content that will be encrypted.
         *
         * @param input the source content whose bytes will be read and encrypted
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = input;
        }

        /**
         * Returns a stream that provides the encrypted view of the upstream content.
         *
         * <p>
         * The method creates an {@link zeroecho.core.context.EncryptionContext} for the
         * configured algorithm id and encryption role, injects the optional context if
         * applicable, and attaches the upstream stream to it. The returned stream
         * performs encryption on-the-fly as it is read.
         * </p>
         *
         * @return an input stream that yields encrypted bytes
         * @throws IOException          if the upstream stream cannot be obtained or if
         *                              context creation or attachment fails
         * @throws NullPointerException if no upstream content has been set via
         *                              {@link #setInput(DataContent)}
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "encrypt: missing input content");
            final EncryptionContext enc = CryptoAlgorithms.create(algId, KeyUsage.ENCRYPT, key, spec); // NOPMD
            if (enc instanceof ContextAware ca) {
                ca.setContext(ctx);
            }
            return enc.attach(upstream.getStream());
        }
    }

    /**
     * Streaming decrypting content that pulls bytes from an upstream
     * {@link DataContent} and exposes the decrypted view as an
     * {@link java.io.InputStream}.
     *
     * <p>
     * An instance is configured with the algorithm id, key, spec, and optional
     * context. The upstream content is provided via {@link #setInput(DataContent)}
     * and the transformed stream is obtained from {@link #getStream()}.
     * </p>
     *
     * <p>
     * The actual cipher work is delegated to an
     * {@link zeroecho.core.context.EncryptionContext} created through
     * {@link zeroecho.core.CryptoAlgorithms#create(String, zeroecho.core.KeyUsage, java.security.Key, zeroecho.core.spec.ContextSpec)}.
     * If the created context implements {@code ContextAware}, the configured
     * context is injected before the stream is attached.
     * </p>
     */
    private static final class DecryptContent<S extends ContextSpec> implements PlainContent {
        private final String algId;
        private final SecretKey key;
        private final S spec;
        private final CtxInterface ctx;
        private DataContent upstream;

        private DecryptContent(String algId, SecretKey key, S spec, CtxInterface ctx) {
            this.algId = algId;
            this.key = key;
            this.spec = spec;
            this.ctx = ctx;
        }

        /**
         * Sets the upstream content that will be decrypted.
         *
         * @param input the source content whose bytes will be read and decrypted
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = input;
        }

        /**
         * Returns a stream that provides the decrypted view of the upstream content.
         *
         * <p>
         * The method creates an {@link zeroecho.core.context.EncryptionContext} for the
         * configured algorithm id and decryption role, injects the optional context if
         * applicable, and attaches the upstream stream to it. The returned stream
         * performs decryption on-the-fly as it is read; in AEAD mode it will also
         * verify the authentication tag when the stream is fully consumed.
         * </p>
         *
         * @return an input stream that yields decrypted bytes
         * @throws IOException          if the upstream stream cannot be obtained or if
         *                              context creation or attachment fails
         * @throws NullPointerException if no upstream content has been set via
         *                              {@link #setInput(DataContent)}
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "decrypt: missing input content");
            final EncryptionContext dec = CryptoAlgorithms.create(algId, KeyUsage.DECRYPT, key, spec); // NOPMD
            if (dec instanceof ContextAware ca) {
                ca.setContext(ctx);
            }
            return dec.attach(upstream.getStream());
        }
    }
}
