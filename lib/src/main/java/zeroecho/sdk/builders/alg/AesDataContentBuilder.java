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
import java.util.Base64;
import java.util.Objects;

import javax.crypto.SecretKey;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.alg.aes.AesHeaderCodec;
import zeroecho.core.alg.aes.AesKeyGenSpec;
import zeroecho.core.alg.aes.AesKeyImportSpec;
import zeroecho.core.alg.aes.AesSpec;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spi.ContextAware;
import zeroecho.core.spi.SymmetricKeyBuilder;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.EncryptedContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * Fluent builder that exposes AES as a
 * {@link zeroecho.sdk.content.api.DataContent} in pull‑mode.
 * <p>
 * This is the simplest way to integrate AES into pipelines. Supply the key with
 * {@link #withKey(javax.crypto.SecretKey)}, choose a mode (e.g.,
 * {@link #modeGcm(int)}), optionally install a header codec via
 * {@link #withHeader()}, and call {@link #build(boolean)} for encryption
 * ({@code true}) or decryption ({@code false}). Connect your upstream source
 * with
 * {@link zeroecho.sdk.content.api.DataContent#setInput(zeroecho.sdk.content.api.DataContent)}
 * and consume the resulting {@link java.io.InputStream}.
 * </p>
 *
 * <h2>Examples</h2> <pre>{@code
 * // Encrypt (pull-mode)
 * DataContent enc = AesDataContentBuilder.builder()
 *     .withKey(secret)
 *     .modeGcm(128)
 *     .withHeader()
 *     .build(true);
 * enc.setInput(PlainFileBuilder.ofPath(inPath).build());
 * try (InputStream s = enc.getStream()) { s.transferTo(Files.newOutputStream(ctPath)); }
 *
 * // Decrypt (pull-mode)
 * DataContent dec = AesDataContentBuilder.builder()
 *     .withKey(secret)
 *     .modeGcm(128)
 *     .withHeader()
 *     .build(false);
 * dec.setInput(PlainFileBuilder.ofPath(ctPath).build());
 * try (InputStream s = dec.getStream()) { s.transferTo(Files.newOutputStream(ptPath)); }
 * }</pre>
 *
 * <h2>Runtime parameters</h2> Optional IV and AAD can be provided via
 * {@link #withIv(byte[])} and {@link #withAad(byte[])}. If a Conflux context is
 * present (set via {@link #context(conflux.CtxInterface)} or implied by a
 * header), a fresh IV is generated on encrypt when absent and stored back into
 * the context. For GCM, AAD defaults to empty.
 *
 * <h2>Thread‑safety</h2> The builder is not thread‑safe. Built
 * {@code DataContent} instances are independent.
 *
 * @since 1.0
 */
public final class AesDataContentBuilder implements DataContentBuilder<DataContent> {
    private SecretKey secretKey;
    private AesKeyGenSpec genSpec;
    private AesKeyImportSpec importSpec;

    private final AesSpec.Builder _spec = AesSpec.builder();

    private byte[] iv; // optional
    private byte[] aad; // optional

    private SymmetricHeaderCodec headerCodec; // optional; carried by AesSpec

    private CtxInterface ctx; // may be null (caller opts out of ctx features)

    private SecretKey generatedKey; // if we generate a key, it is stored here

    /**
     * Creates a new AES builder with default spec (GCM/128, no header) and no key
     * selected. Use {@link #withKey(SecretKey)} (recommended), or import/generate a
     * key, then select a mode.
     *
     * @return a new builder instance
     */
    public static AesDataContentBuilder builder() {
        return new AesDataContentBuilder();
    }

    private AesDataContentBuilder() {
    }

    /**
     * Sets the key to use. Overrides any previous generate/import choice.
     *
     * @param k the AES {@link SecretKey}; must be 128/192/256-bit
     * @return this builder
     * @throws NullPointerException if {@code k} is null
     */
    public AesDataContentBuilder withKey(SecretKey k) {
        this.secretKey = Objects.requireNonNull(k);
        this.genSpec = null;
        this.importSpec = null;
        return this;
    }

    /**
     * Requests generation of a fresh AES key of the given size.
     * <p>
     * <b>Note:</b> prefer {@link #withKey(SecretKey)} for pipelines that need
     * predictable key reuse across encrypt/decrypt runs.
     * </p>
     *
     * @param bits 128, 192, or 256
     * @return this builder
     * @throws IllegalArgumentException if size is invalid
     */
    public AesDataContentBuilder generateKey(int bits) {
        this.genSpec = new AesKeyGenSpec(bits);
        this.secretKey = null;
        this.importSpec = null;
        return this;
    }

    /**
     * Imports a raw AES key (16/24/32 bytes).
     *
     * @param raw key material; copied defensively
     * @return this builder
     * @throws IllegalArgumentException if length is not 16/24/32
     */
    public AesDataContentBuilder importKeyRaw(byte[] raw) {
        this.importSpec = AesKeyImportSpec.fromRaw(raw);
        this.secretKey = null;
        this.genSpec = null;
        return this;
    }

    /**
     * Imports a hex‑encoded AES key (32/48/64 hex chars).
     *
     * @param hex hex string; not null
     * @return this builder
     * @throws NullPointerException     if {@code hex} is null
     * @throws IllegalArgumentException if the decoded length is not 16/24/32
     */
    public AesDataContentBuilder importKeyHex(String hex) {
        return importKeyRaw(java.util.HexFormat.of().parseHex(hex));
    }

    /**
     * Imports a Base64‑encoded AES key (no padding required).
     *
     * @param b64 Base64 text; not null
     * @return this builder
     * @throws NullPointerException     if {@code b64} is null
     * @throws IllegalArgumentException if the decoded length is not 16/24/32
     */
    public AesDataContentBuilder importKeyBase64(String b64) {
        return importKeyRaw(Base64.getDecoder().decode(b64));
    }

    /**
     * Copies mode/padding/tagBits/header from a fully built {@link AesSpec}.
     *
     * @param s the spec to apply
     * @return this builder
     * @throws NullPointerException if {@code s} is null
     */
    public AesDataContentBuilder spec(AesSpec s) {
        this._spec.mode(s.mode()).padding(s.padding()).tagLenBits(s.tagLenBits()).header(s.header());
        return this;
    }

    /**
     * Selects GCM and sets the authentication tag length in bits.
     *
     * @param tagBits 96..128 (step 8)
     * @return this builder
     * @throws IllegalArgumentException if {@code tagBits} is out of range
     */
    public AesDataContentBuilder modeGcm(int tagBits) {
        this._spec.mode(AesSpec.Mode.GCM).tagLenBits(tagBits);
        return this;
    }

    /**
     * Selects CTR with NOPADDING. Pair with a MAC if integrity is required.
     *
     * @return this builder
     */
    public AesDataContentBuilder modeCtr() {
        this._spec.mode(AesSpec.Mode.CTR).padding(AesSpec.Padding.NOPADDING);
        return this;
    }

    /**
     * Selects CBC/PKCS5PADDING.
     *
     * @return this builder
     */
    public AesDataContentBuilder modeCbcPkcs5() {
        this._spec.mode(AesSpec.Mode.CBC).padding(AesSpec.Padding.PKCS5PADDING);
        return this;
    }

    /**
     * Selects CBC/NOPADDING. The plaintext length must be a multiple of the block
     * size.
     *
     * @return this builder
     */
    public AesDataContentBuilder modeCbcNoPadding() {
        this._spec.mode(AesSpec.Mode.CBC).padding(AesSpec.Padding.NOPADDING);
        return this;
    }

    /**
     * Supplies an explicit IV/nonce. If omitted during ENCRYPT and a context is
     * present, a fresh IV is generated and stored in the context.
     *
     * @param iv the IV (12 bytes for GCM, 16 bytes for CBC/CTR)
     * @return this builder
     * @throws IllegalArgumentException if the length does not match the mode
     */
    public AesDataContentBuilder withIv(byte[] iv) {
        this.iv = iv;
        return this;
    }

    /**
     * Supplies Additional Authenticated Data (GCM). AAD is not encrypted; it is
     * bound to the ciphertext. If a header is used, only a SHA‑256 hash of AAD is
     * written.
     *
     * @param aad AAD bytes (may be empty)
     * @return this builder
     */
    public AesDataContentBuilder withAad(byte[] aad) {
        this.aad = aad;
        return this;
    }

    /**
     * Installs a specific header codec into the spec so IV/tagBits/AAD hash can be
     * persisted in‑band.
     *
     * @param codec the codec to use (e.g., {@link AesHeaderCodec})
     * @return this builder
     */
    public AesDataContentBuilder withHeaderCodec(SymmetricHeaderCodec codec) {
        this.headerCodec = codec;
        return this;
    }

    /**
     * Convenience for {@link #withHeaderCodec(SymmetricHeaderCodec)} using
     * {@link AesHeaderCodec}.
     *
     * @return this builder
     */
    public AesDataContentBuilder withHeader() {
        return withHeaderCodec(new AesHeaderCodec());
    }

    /**
     * Provides a Conflux session context for exchanging IV/AAD/tagBits and enabling
     * header I/O. When null, no context features are used and no header is
     * written/read.
     *
     * @param ctx the context, or {@code null}
     * @return this builder
     */
    public AesDataContentBuilder context(CtxInterface ctx) {
        this.ctx = ctx;
        return this;
    }

    /**
     * Builds an encrypting or decrypting {@link DataContent}.
     * <ul>
     * <li>Resolves the key from {@link #withKey(SecretKey)} or the selected
     * generate/import spec.</li>
     * <li>Finalizes {@link AesSpec} (injecting the header if configured).</li>
     * <li>Propagates IV/AAD into the context if supplied.</li>
     * </ul>
     *
     * @param encrypt {@code true} for encryption; {@code false} for decryption
     * @return a {@link DataContent} that transforms its upstream stream
     * @throws IllegalStateException on key construction errors or provider
     *                               misconfiguration
     */
    @Override
    public DataContent build(boolean encrypt) {
        final SecretKey key = resolveKey();

        // finalize AesSpec from builder + header
        if (this.headerCodec != null) {
            if (ctx == null) {
                ctx = Ctx.INSTANCE.getContext("aes-ctx-" + System.nanoTime());
            }

            this._spec.header(this.headerCodec);
        }
        final AesSpec aesSpec = _spec.build();

        if (aad != null && aad.length > 0) {
            if (ctx == null) {
                ctx = Ctx.INSTANCE.getContext("aes-ctx-" + System.nanoTime());
            }
            ctx.put(ConfluxKeys.aad("AES"), aad);
        }
        if (iv != null && iv.length > 0) {
            if (ctx == null) {
                ctx = Ctx.INSTANCE.getContext("aes-ctx-" + System.nanoTime());
            }
            ctx.put(ConfluxKeys.iv("AES"), iv);
        }

        return encrypt ? new EncryptContent(key, aesSpec, ctx) : new DecryptContent(key, aesSpec, ctx);
    }

    /**
     * Returns the generated secret key associated with this instance.
     *
     * <p>
     * The value is typically produced during a key generation process and stored
     * internally for later retrieval. The returned reference is the actual
     * {@link SecretKey} object; callers should avoid modifying or exposing it
     * unnecessarily to preserve security.
     * </p>
     *
     * @return the generated {@link SecretKey}, or {@code null} if no key has been
     *         generated
     */
    public SecretKey generatedKey() {
        return generatedKey;
    }

    private SecretKey resolveKey() {
        if (secretKey != null) {
            return secretKey;
        }
        try {
            CryptoAlgorithm algo = CryptoAlgorithms.require("AES"); // registry lookup
            if (genSpec != null) {
                SymmetricKeyBuilder<AesKeyGenSpec> b = algo.symmetricKeyBuilder(AesKeyGenSpec.class);
                generatedKey = b.generateSecret(genSpec);
                return generatedKey;
            }
            if (importSpec != null) {
                SymmetricKeyBuilder<AesKeyImportSpec> b = algo.symmetricKeyBuilder(AesKeyImportSpec.class);
                return b.importSecret(importSpec);
            }
            SymmetricKeyBuilder<AesKeyGenSpec> b = algo.symmetricKeyBuilder(AesKeyGenSpec.class);
            generatedKey = b.generateSecret(AesKeyGenSpec.aes256());
            return generatedKey;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES key construction failed", e);
        }
    }

    /**
     * Streaming AES encryptor that adapts an upstream {@link DataContent} into a
     * ciphertext stream.
     *
     * <p>
     * An instance of {@code EncryptContent} produces an {@link java.io.InputStream}
     * that encrypts bytes on demand using the provided {@link SecretKey} and
     * {@link AesSpec}. The encryption is performed by an
     * {@link zeroecho.core.context.EncryptionContext} created via
     * {@link CryptoAlgorithms}. If the created context implements a context-aware
     * extension, the optional {@link CtxInterface} is forwarded to it to enable
     * header emission and parameter exchange (for example IV, tag bits, or AAD
     * digests).
     * </p>
     *
     * <h2>Lifetime semantics</h2>
     * <ul>
     * <li><b>Independence of the returned stream:</b> The {@link #getStream()}
     * method obtains an {@link zeroecho.core.context.EncryptionContext}, calls its
     * {@code attach(InputStream)} method, and returns the resulting stream. By
     * contract, the returned stream is usable even if the temporary encryption
     * context is closed immediately after {@code attach}. In other words, the
     * stream does not retain an operational dependency on the context object.</li>
     * <li><b>Caller responsibility:</b> Callers must close the stream returned by
     * {@link #getStream()} to ensure encryption finalization and resource
     * release.</li>
     * </ul>
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe. Each
     * {@code EncryptContent} should be configured once via
     * {@link #setInput(DataContent)} and then consumed by a single reader.
     *
     * <h2>Example</h2> <pre>{@code
     * EncryptContent enc = new EncryptContent(secretKey, aesSpec, ctx);
     * enc.setInput(plainContent);
     * try (InputStream cipher = enc.getStream()) {
     *     // consume ciphertext
     *     cipher.transferTo(out);
     * }
     * }</pre>
     */
    private static final class EncryptContent implements EncryptedContent {
        private final SecretKey key;
        private final AesSpec spec;
        private final CtxInterface ctx; // may be null
        private DataContent upstream;

        /**
         * Creates a new encrypting content adapter for AES.
         *
         * <p>
         * The supplied {@link SecretKey} and {@link AesSpec} determine the algorithm
         * parameters (mode, tag length, nonce semantics, etc.). If a
         * {@link CtxInterface} is provided, the underlying implementation may emit a
         * small header and/or exchange ephemeral parameters via the context. Passing
         * {@code null} disables such header-based coordination.
         * </p>
         *
         * @param key  symmetric AES key; must not be {@code null}
         * @param spec AES specification describing mode and parameters; must not be
         *             {@code null}
         * @param ctx  optional context used to exchange transient parameters; may be
         *             {@code null}
         * @throws NullPointerException if {@code key} or {@code spec} is {@code null}
         */
        private EncryptContent(SecretKey key, AesSpec spec, CtxInterface ctx) {
            this.key = key;
            this.spec = spec;
            this.ctx = ctx;
        }

        /**
         * Sets the upstream source of plaintext bytes to be encrypted.
         *
         * <p>
         * This method must be invoked exactly once before {@link #getStream()}. The
         * upstream stream supplied by {@code input} is not opened here; it is resolved
         * lazily when {@link #getStream()} is called.
         * </p>
         *
         * @param input upstream plaintext provider; must not be {@code null}
         * @throws NullPointerException if {@code input} is {@code null}
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = input;
        }

        /**
         * Returns a stream that yields the AES-encrypted form of the upstream content.
         *
         * <p>
         * This method creates an {@link zeroecho.core.context.EncryptionContext} for
         * AES in the {@link KeyUsage#ENCRYPT} role and attaches it to the upstream
         * stream. If the context is {@code ContextAware}, the optional
         * {@link CtxInterface} is passed to it; if not, an
         * {@link IllegalStateException} is thrown because header-based coordination
         * would be unavailable.
         * </p>
         *
         * <p>
         * The returned stream is independent of the temporary encryption context;
         * closing the context is not required for the stream to function. Callers must
         * close the returned stream to finalize encryption and release resources.
         * </p>
         *
         * @return an input stream that produces ciphertext derived from the upstream
         *         bytes
         * @throws IOException           if the AES context cannot be created or if
         *                               stream attachment fails
         * @throws NullPointerException  if no upstream content has been set via
         *                               {@link #setInput(DataContent)}
         * @throws IllegalStateException if the AES context does not implement
         *                               {@code ContextAware}
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "encrypt: missing input content");
            try (EncryptionContext enc = CryptoAlgorithms.create("AES", KeyUsage.ENCRYPT, key, spec)) {
                if (!(enc instanceof ContextAware)) {
                    throw new IllegalStateException("AES context is not ContextAware; cannot pass conflux Ctx");
                }
                ((ContextAware) enc).setContext(ctx); // ctx may be null → header disabled; IV generated only if ctx
                                                      // present
                return enc.attach(upstream.getStream());
            }
        }
    }

    /**
     * Streaming AES decryptor that adapts an upstream {@link DataContent} into a
     * plaintext stream.
     *
     * <p>
     * {@code DecryptContent} obtains an
     * {@link zeroecho.core.context.EncryptionContext} in the
     * {@link KeyUsage#DECRYPT} role and returns an {@link java.io.InputStream} that
     * decrypts bytes on demand using the provided {@link SecretKey} and
     * {@link AesSpec}. The implementation passes an optional {@link CtxInterface}
     * to the context when supported.
     * </p>
     *
     * <h2>Lifetime semantics</h2> The {@link #getStream()} method creates the
     * decryption context in a try-with-resources block and immediately returns the
     * stream produced by {@code attach}. By contract, the returned stream is
     * independent of the temporary context, so the context can be closed before the
     * caller consumes the stream. Callers are responsible for closing the returned
     * stream.
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe and are intended for
     * single-use pipelines.
     */
    private static final class DecryptContent implements PlainContent {
        private final SecretKey key;
        private final AesSpec spec;
        private final CtxInterface ctx; // may be null
        private DataContent upstream;

        /**
         * Creates a new decrypting content adapter for AES.
         *
         * <p>
         * The supplied {@link SecretKey} and {@link AesSpec} define algorithm
         * parameters. If a {@link CtxInterface} is provided and the underlying context
         * is {@code ContextAware}, runtime parameters (for example IV or tag length)
         * may be exchanged through the context. Passing {@code null} disables such
         * coordination.
         * </p>
         *
         * @param key  symmetric AES key; must not be {@code null}
         * @param spec AES specification describing mode and parameters; must not be
         *             {@code null}
         * @param ctx  optional context for exchanging ephemeral parameters; may be
         *             {@code null}
         * @throws NullPointerException if {@code key} or {@code spec} is {@code null}
         */
        private DecryptContent(SecretKey key, AesSpec spec, CtxInterface ctx) {
            this.key = key;
            this.spec = spec;
            this.ctx = ctx;
        }

        /**
         * Sets the upstream source of ciphertext bytes to be decrypted.
         *
         * <p>
         * This must be called exactly once before {@link #getStream()} is invoked. The
         * upstream stream is acquired lazily during {@link #getStream()}.
         * </p>
         *
         * @param input upstream ciphertext provider; must not be {@code null}
         * @throws NullPointerException if {@code input} is {@code null}
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = input;
        }

        /**
         * Returns a stream that yields the AES-decrypted form of the upstream content.
         *
         * <p>
         * The method creates a decryption
         * {@link zeroecho.core.context.EncryptionContext} via
         * {@link CryptoAlgorithms#create(String, KeyUsage, java.security.Key, zeroecho.core.spec.ContextSpec)},
         * forwards the optional {@link CtxInterface} when the context is
         * {@code ContextAware}, and returns the stream produced by {@code attach}. The
         * returned stream is independent of the temporary context and remains usable
         * after the context is closed by try-with-resources.
         * </p>
         *
         * @return an input stream that produces plaintext derived from the upstream
         *         bytes
         * @throws IOException           if the decryption context cannot be created or
         *                               if stream attachment fails
         * @throws NullPointerException  if no upstream content has been set via
         *                               {@link #setInput(DataContent)}
         * @throws IllegalStateException if the AES context does not implement
         *                               {@code ContextAware}
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "decrypt: missing input content");
            try (EncryptionContext dec = CryptoAlgorithms.create("AES", KeyUsage.DECRYPT, key, spec)) {
                if (!(dec instanceof ContextAware)) {
                    throw new IllegalStateException("AES context is not ContextAware; cannot pass conflux Ctx");
                }
                ((ContextAware) dec).setContext(ctx);
                return dec.attach(upstream.getStream());
            }
        }
    }
}
