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
package zeroecho.sdk.builders.alg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.KemContext.KemResult;
import zeroecho.core.io.Util;
import zeroecho.core.spec.VoidSpec;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.EncryptedContent;

/**
 * KEM-based envelope builder that first collects KEM parameters and only then
 * delegates to an explicit symmetric builder for the payload.
 *
 * <p>
 * This builder fixes the earlier unintuitive flow where each symmetric builder
 * duplicated KEM settings. With {@code KemDataContentBuilder} you configure the
 * KEM once (algorithm id, recipient key, KDF) and then select which payload
 * cipher to use by supplying an {@link AesDataContentBuilder} or a
 * {@link ChaChaDataContentBuilder}. The derived symmetric key is injected into
 * the provided symmetric builder prior to building the payload stage.
 * </p>
 *
 * <h2>Header format</h2> The produced envelope prepends the KEM encapsulation
 * ciphertext using the following simple framing: <pre>
 *   length L in Pack7 format
 *   L bytes of KEM ciphertext
 *   [payload stream produced by the symmetric builder]
 * </pre> The symmetric builder (AES or ChaCha) remains fully responsible for
 * its own optional header (IV, AAD tag, etc.) which follows immediately after
 * the KEM prefix.
 *
 * <h2>Usage</h2> <pre>{@code
 * // Encryption
 * DataContent content = DataContentChainBuilder.encrypt()
 *     .add(PlainStringBuilder.builder().value("hello"))
 *     .add(KemDataContentBuilder.builder()
 *            .kem("ML-KEM")
 *            .recipientPublic(recipientPub)
 *            .hkdfSha256("KEM-demo".getBytes(StandardCharsets.US_ASCII))
 *            .withAes(AesDataContentBuilder.builder().modeGcm(128).withHeader()))
 *     .build();
 *
 * // Decryption
 * DataContent plain = DataContentChainBuilder.decrypt()
 *     .add(PlainBytesBuilder.builder().bytes(cipherBytes))
 *     .add(KemDataContentBuilder.builder()
 *            .kem("ML-KEM")
 *            .recipientPrivate(recipientPriv)
 *            .hkdfSha256("KEM-demo".getBytes(StandardCharsets.US_ASCII))
 *            .withAes(AesDataContentBuilder.builder().modeGcm(128).withHeader()))
 *     .build();
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are not thread-safe. Create a new builder
 * per pipeline/use.
 *
 * @since 1.0
 */
public final class KemDataContentBuilder implements DataContentBuilder<DataContent> {
    private final ZeroEchoSession session;
    // ---------- KEM configuration ----------
    private String kemId;
    private PublicKey recipientPublic;
    private PrivateKey recipientPrivate;

    // Simple HKDF/SHA-256 or identity KDF. Default HKDF with info "ZeroEcho-KEM".
    private boolean useHkdf = true;
    private byte[] hkdfInfo = "ZeroEcho-KEM".getBytes(StandardCharsets.US_ASCII);

    // Maximum accepted KEM ciphertext length during decryption to avoid abuse.
    private int maxKemCiphertextLen = 1 << 16; // 64 KiB default

    // Derived key length in bytes for the symmetric payload. 32 = AES-256/ChaCha.
    private int derivedKeyBytes = 32;

    // ---------- Symmetric payload selection ----------
    private AesDataContentBuilder aesBuilder;
    private ChaChaDataContentBuilder chachaBuilder;

    private KemDataContentBuilder(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Returns a new {@code KemDataContentBuilder}.
     *
     * @param session active session used to create cryptographic contexts
     * @return fresh builder instance
     */
    public static KemDataContentBuilder builder(ZeroEchoSession session) {
        return new KemDataContentBuilder(session);
    }

    /**
     * Sets the canonical KEM algorithm identifier to use (e.g., "ML-KEM").
     *
     * @param id algorithm identifier resolved by the builder's
     *           {@link ZeroEchoSession}
     * @return this builder
     * @throws NullPointerException if {@code id} is null
     */
    public KemDataContentBuilder kem(String id) {
        this.kemId = Objects.requireNonNull(id, "kem id");
        return this;
    }

    /**
     * Sets the recipient public key for encapsulation (encryption path).
     *
     * @param k recipient public key
     * @return this builder
     * @throws NullPointerException if {@code k} is null
     */
    public KemDataContentBuilder recipientPublic(PublicKey k) {
        this.recipientPublic = Objects.requireNonNull(k, "recipientPublic");
        return this;
    }

    /**
     * Sets the recipient private key for decapsulation (decryption path).
     *
     * @param k recipient private key
     * @return this builder
     * @throws NullPointerException if {@code k} is null
     */
    public KemDataContentBuilder recipientPrivate(PrivateKey k) {
        this.recipientPrivate = Objects.requireNonNull(k, "recipientPrivate");
        return this;
    }

    /**
     * Configures HKDF-SHA256 as the key derivation function using the provided
     * {@code info} context string. If not set, a default constant is used.
     *
     * @param info application/context info; copied defensively; may be empty but
     *             must not be null
     * @return this builder
     * @throws NullPointerException if {@code info} is null
     */
    public KemDataContentBuilder hkdfSha256(byte[] info) {
        this.useHkdf = true;
        this.hkdfInfo = Objects.requireNonNull(info, "info").clone();
        return this;
    }

    /**
     * Disables HKDF and uses the shared secret directly (or truncated) for the
     * symmetric key. This is usually discouraged unless the KEM already outputs a
     * uniformly random key.
     *
     * @return this builder
     */
    public KemDataContentBuilder directSecret() {
        this.useHkdf = false;
        return this;
    }

    /**
     * Sets a safety limit for the KEM ciphertext length accepted in decryption.
     * Values up to the algorithm's maximum should be allowed.
     *
     * @param maxBytes maximum number of ciphertext bytes; must be positive
     * @return this builder
     * @throws IllegalArgumentException if {@code maxBytes} is not positive
     */
    public KemDataContentBuilder maxKemCiphertextLen(int maxBytes) {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxKemCiphertextLen must be > 0");
        }
        this.maxKemCiphertextLen = maxBytes;
        return this;
    }

    /**
     * Selects AES as the payload cipher and supplies a configured
     * {@link AesDataContentBuilder} that will receive the derived key.
     *
     * <p>
     * The builder instance will be mutated to inject the derived key. Supply a
     * fresh instance per pipeline to avoid cross-use.
     * </p>
     *
     * @param b AES payload builder to use
     * @return this builder
     * @throws NullPointerException if {@code b} is null
     * @see #derivedKeyBytes(int)
     */
    public KemDataContentBuilder withAes(AesDataContentBuilder b) {
        this.aesBuilder = Objects.requireNonNull(b, "aesBuilder");
        this.chachaBuilder = null;
        return this;
    }

    /**
     * Selects ChaCha20/ChaCha20-Poly1305 as the payload cipher and supplies a
     * configured {@link ChaChaDataContentBuilder} that will receive the derived
     * key.
     *
     * <p>
     * The builder instance will be mutated to inject the derived key. Supply a
     * fresh instance per pipeline to avoid cross-use.
     * </p>
     *
     * @param b ChaCha payload builder to use
     * @return this builder
     * @throws NullPointerException if {@code b} is null
     * @see #derivedKeyBytes(int)
     */
    public KemDataContentBuilder withChaCha(ChaChaDataContentBuilder b) {
        this.chachaBuilder = Objects.requireNonNull(b, "chachaBuilder");
        this.aesBuilder = null;
        return this;
    }

    /**
     * Sets the number of derived key bytes to feed into the selected symmetric
     * builder. Defaults to 32 (AES-256 or ChaCha20).
     *
     * @param bytes number of key bytes; typical values are 16, 24, or 32
     * @return this builder
     * @throws IllegalArgumentException if {@code bytes} is not positive
     */
    public KemDataContentBuilder derivedKeyBytes(int bytes) {
        if (bytes <= 0) {
            throw new IllegalArgumentException("derivedKeyBytes must be > 0");
        }
        this.derivedKeyBytes = bytes;
        return this;
    }

    /**
     * Builds the KEM envelope stage in either encryption or decryption mode.
     *
     * <p>
     * On encryption, the returned {@link DataContent} will:
     * <ol>
     * <li>encapsulate with the configured KEM and recipient public key,</li>
     * <li>derive a symmetric key via HKDF-SHA256 (or directly),</li>
     * <li>inject the key into the selected symmetric builder,</li>
     * <li>prepend the KEM encapsulation ciphertext, and</li>
     * <li>stream the symmetric payload output.</li>
     * </ol>
     * On decryption, it will:
     * <ol>
     * <li>read and decapsulate the KEM ciphertext using the recipient private
     * key,</li>
     * <li>derive the symmetric key,</li>
     * <li>inject it into the symmetric builder, and</li>
     * <li>stream-decrypt the remaining payload bytes.</li>
     * </ol>
     *
     * @param encrypt {@code true} to build the encryption stage, {@code false} for
     *                decryption
     * @return a {@link DataContent} representing the configured KEM envelope
     * @throws IllegalStateException if required parameters are missing or invalid
     */
    @Override
    public DataContent build(boolean encrypt) {
        validateConfiguration(encrypt);

        return encrypt
                ? new EncryptContent(kemId, recipientPublic, useHkdf, hkdfInfo.clone(), derivedKeyBytes,
                        maxKemCiphertextLen, aesBuilder, chachaBuilder)
                : new DecryptContent(kemId, recipientPrivate, useHkdf, hkdfInfo.clone(), derivedKeyBytes,
                        maxKemCiphertextLen, aesBuilder, chachaBuilder);

    }

    private void validateConfiguration(boolean encrypt) {
        if (kemId == null || kemId.isEmpty()) {
            throw new IllegalStateException("KEM algorithm id not set. Call kem(id).");
        }
        if (aesBuilder == null && chachaBuilder == null) {
            throw new IllegalStateException("No payload cipher selected. Call withAes(...) or withChaCha(...).");
        }
        if (encrypt && recipientPublic == null) {
            throw new IllegalStateException("Encryption requires recipientPublic(...)");
        }
        if (!encrypt && recipientPrivate == null) {
            throw new IllegalStateException("Decryption requires recipientPrivate(...)");
        }
    }

    // ======================================================================
    // Static final content implementations (no reference to outer builder)
    // ======================================================================

    /**
     * EncryptContent is a streaming envelope stage that performs KEM encapsulation,
     * derives a symmetric key, injects it into the selected payload builder, and
     * emits a concatenation of the KEM prefix and the payload stream.
     *
     * <p>
     * The produced stream has the following structure:
     * </p>
     * <pre>
     *   [Pack7 length][KEM ciphertext][payload bytes...]
     * </pre> The payload bytes are generated by the supplied
     * {@code AesDataContentBuilder} or {@code ChaChaDataContentBuilder} configured
     * with the derived key.
     *
     * <h2>Lifecycle</h2>
     * <ol>
     * <li>Encapsulate with {@link zeroecho.core.context.KemContext} using the
     * recipient public key.</li>
     * <li>Derive a symmetric key via HKDF-SHA256 (or use the shared secret
     * directly), sized by {@code derivedKeyBytes}.</li>
     * <li>Inject the key into the chosen symmetric builder and build the payload
     * stage in encrypt mode.</li>
     * <li>Prefix the KEM ciphertext using the builder's length framing and then
     * stream the payload.</li>
     * </ol>
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe. Each instance must be
     * configured and used from a single thread.
     */
    private final class EncryptContent implements EncryptedContent {
        private final String kemId;
        private final PublicKey recipientPublic;
        private final boolean useHkdf;
        private final byte[] hkdfInfo;
        private final int derivedKeyBytes;
        private final int maxKemCtLen; // used for sanity check on produced ct
        private final AesDataContentBuilder aesBuilder;
        private final ChaChaDataContentBuilder chachaBuilder;

        private DataContent upstream;

        private EncryptContent(String kemId, PublicKey recipientPublic, boolean useHkdf, byte[] hkdfInfo,
                int derivedKeyBytes, int maxKemCtLen, AesDataContentBuilder aesBuilder,
                ChaChaDataContentBuilder chachaBuilder) {
            this.kemId = kemId;
            this.recipientPublic = recipientPublic;
            this.useHkdf = useHkdf;
            this.hkdfInfo = hkdfInfo;
            this.derivedKeyBytes = derivedKeyBytes;
            this.maxKemCtLen = maxKemCtLen;
            this.aesBuilder = aesBuilder;
            this.chachaBuilder = chachaBuilder;
        }

        /**
         * Sets the upstream content that supplies the plaintext for the payload stage.
         *
         * @param input upstream content; must not be null
         * @throws NullPointerException if {@code input} is null
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input, "upstream");
        }

        /**
         * Returns a stream that emits the KEM length-prefixed ciphertext followed by
         * the symmetric payload ciphertext.
         *
         * <p>
         * This method constructs a {@link zeroecho.core.context.KemContext} for the
         * configured algorithm id and performs encapsulation; it then configures and
         * builds the selected symmetric builder in encrypt mode and concatenates the
         * KEM prefix with the payload stream.
         * </p>
         *
         * @return input stream producing the envelope bytes
         * @throws IOException           if KEM encapsulation, key derivation, or stream
         *                               setup fails
         * @throws IllegalStateException if no upstream content has been set
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "encrypt: missing input");
            byte[] shared = null;
            try (KemContext kem = session.createContext(kemId, KeyUsage.ENCAPSULATE, recipientPublic,
                    VoidSpec.INSTANCE)) {
                KemResult result = kem.encapsulate();
                byte[] ciphertext = Objects.requireNonNull(result.ciphertext(), "kem ciphertext");
                shared = Objects.requireNonNull(result.sharedSecret(), "kem sharedSecret");
                if (ciphertext.length <= 0 || ciphertext.length > maxKemCtLen) {
                    throw new IOException("KEM ciphertext length invalid: " + ciphertext.length);
                }

                DataContent symmetric = buildSymmetric(shared, true);
                symmetric.setInput(upstream);
                InputStream kemPrefix = writeLenPrefixedAsStream(ciphertext);
                InputStream payloadStream = symmetric.getStream();
                return new SequenceInputStream(kemPrefix, payloadStream);
            } finally {
                if (shared != null) {
                    Arrays.fill(shared, (byte) 0);
                }
            }
        }

        private DataContent buildSymmetric(byte[] shared, boolean encrypt) throws IOException {
            if (aesBuilder != null) {
                SecretKey payloadKey = deriveKey(shared, "AES", derivedKeyBytes, useHkdf, hkdfInfo);
                return aesBuilder.withKey(payloadKey).build(encrypt);
            }
            SecretKey payloadKey = deriveKey(shared, "ChaCha20", derivedKeyBytes, useHkdf, hkdfInfo);
            return chachaBuilder.withKey(payloadKey).build(encrypt);
        }
    }

    /**
     * DecryptContent is a streaming envelope stage that parses the KEM prefix,
     * derives a symmetric key via the configured KDF, and streams the remaining
     * bytes through the selected payload builder in decrypt mode.
     *
     * <p>
     * The input must have the structure:
     * </p>
     * <pre>
     *   [Pack7 length][KEM ciphertext][payload bytes...]
     * </pre> The KEM ciphertext is consumed to recover the shared secret and derive
     * the payload key; the payload bytes are then decrypted by the supplied
     * symmetric builder.
     * </p>
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe. Each instance must be
     * configured and used from a single thread.
     */
    private final class DecryptContent implements DataContent { // PlainContent would also be fine
        private final String kemId;
        private final PrivateKey recipientPrivate;
        private final boolean useHkdf;
        private final byte[] hkdfInfo;
        private final int derivedKeyBytes;
        private final int maxKemCtLen;
        private final AesDataContentBuilder aesBuilder;
        private final ChaChaDataContentBuilder chachaBuilder;

        private DataContent upstream;

        private DecryptContent(String kemId, PrivateKey recipientPrivate, boolean useHkdf, byte[] hkdfInfo,
                int derivedKeyBytes, int maxKemCtLen, AesDataContentBuilder aesBuilder,
                ChaChaDataContentBuilder chachaBuilder) {
            this.kemId = kemId;
            this.recipientPrivate = recipientPrivate;
            this.useHkdf = useHkdf;
            this.hkdfInfo = hkdfInfo;
            this.derivedKeyBytes = derivedKeyBytes;
            this.maxKemCtLen = maxKemCtLen;
            this.aesBuilder = aesBuilder;
            this.chachaBuilder = chachaBuilder;
        }

        /**
         * Sets the upstream content that supplies the envelope bytes to be decrypted.
         *
         * @param input upstream content; must not be null
         * @throws NullPointerException if {@code input} is null
         */
        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input, "upstream");
        }

        /**
         * Returns a stream that yields the plaintext produced by the symmetric payload
         * stage after KEM decapsulation and key derivation.
         *
         * <p>
         * This method reads and validates the length-prefixed KEM ciphertext, performs
         * decapsulation using a {@link zeroecho.core.context.KemContext}, derives the
         * symmetric key via HKDF-SHA256 (or directly), configures and builds the
         * selected symmetric builder in decrypt mode, and then streams the remainder of
         * the input through that payload stage.
         * </p>
         *
         * @return input stream producing plaintext bytes
         * @throws IOException           if the prefix is malformed, decapsulation
         *                               fails, key derivation fails, or the payload
         *                               stage cannot be created
         * @throws IllegalStateException if no upstream content has been set
         */
        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "decrypt: missing input");
            final InputStream in = upstream.getStream(); // NOPMD
            Throwable failure = null;
            boolean transferred = false;
            try {
                byte[] ciphertext = readLenPrefixed(in, maxKemCtLen);
                byte[] shared = null;
                DataContent symmetric;
                try (KemContext kem = session.createContext(kemId, KeyUsage.DECAPSULATE, recipientPrivate,
                        VoidSpec.INSTANCE)) {
                    shared = kem.decapsulate(ciphertext);
                    symmetric = buildSymmetric(shared);
                } finally {
                    if (shared != null) {
                        Arrays.fill(shared, (byte) 0);
                    }
                }

                symmetric.setInput(new BridgeDataContent(in));
                InputStream result = symmetric.getStream();
                transferred = true;
                return result;
            } catch (IOException | RuntimeException | Error exception) { // NOPMD - retain primary failure
                failure = exception;
                throw exception;
            } finally {
                if (!transferred) {
                    closeRejectedInput(in, failure);
                }
            }
        }

        private DataContent buildSymmetric(byte[] shared) throws IOException {
            if (aesBuilder != null) {
                SecretKey payloadKey = deriveKey(shared, "AES", derivedKeyBytes, useHkdf, hkdfInfo);
                return aesBuilder.withKey(payloadKey).build(false);
            }
            SecretKey payloadKey = deriveKey(shared, "ChaCha20", derivedKeyBytes, useHkdf, hkdfInfo);
            return chachaBuilder.withKey(payloadKey).build(false);
        }
    }

    /**
     * BridgeDataContent is a lightweight adapter that exposes an existing
     * {@link java.io.InputStream} as {@link zeroecho.sdk.content.api.DataContent}.
     *
     * <p>
     * This is used internally to hand the remaining bytes of an already-open input
     * stream to a downstream payload builder, without copying.
     * </p>
     *
     * <h2>Thread-safety</h2> Instances are not thread-safe and should be used by a
     * single consumer.
     */
    private final static class BridgeDataContent implements DataContent {
        private final InputStream stream;

        private BridgeDataContent(InputStream stream) {
            this.stream = stream;
        }

        /**
         * Returns the underlying stream without additional wrapping.
         *
         * @return the provided input stream
         * @throws IOException never thrown by this implementation
         */
        @Override
        public InputStream getStream() throws IOException {
            return stream;
        }

    }

    private static SecretKey deriveKey(byte[] shared, String algo, int keyBytes, boolean hkdf, byte[] info)
            throws IOException {
        byte[] material = null;
        try {
            if (hkdf) {
                try {
                    material = zeroecho.sdk.util.Kdf.hkdfSha256(shared, null, info, keyBytes);
                } catch (GeneralSecurityException exception) {
                    throw new IOException("HKDF-SHA256 failed", exception);
                }
            } else {
                if (shared.length < keyBytes) {
                    throw new IOException("Shared secret too short for direct use: " + shared.length);
                }
                material = Arrays.copyOf(shared, keyBytes);
            }
            return new SecretKeySpec(material, algo);
        } finally {
            if (material != null) {
                Arrays.fill(material, (byte) 0);
            }
        }
    }

    private static void closeRejectedInput(InputStream input, Throwable primary) throws IOException {
        try {
            input.close();
        } catch (IOException cleanupFailure) {
            if (primary != null) {
                primary.addSuppressed(cleanupFailure);
            } else {
                throw cleanupFailure;
            }
        }
    }

    private static InputStream writeLenPrefixedAsStream(byte[] ct) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(ct.length + 16);
        Util.write(baos, ct);
        return new ByteArrayInputStream(baos.toByteArray());
    }

    private static byte[] readLenPrefixed(InputStream in, int maxLen) throws IOException {
        return Util.read(in, maxLen);
    }
}
