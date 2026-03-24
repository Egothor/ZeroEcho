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
package zeroecho.sdk.guard;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;

/**
 * Builds a data content pipeline that supports multiple recipients and
 * delegates payload encryption to AES or ChaCha builders.
 *
 * <p>
 * This builder is responsible only for the multi-recipient envelope: generating
 * a content-encryption key (CEK), constructing recipient entries that can
 * recover the same CEK, and scanning those entries on decrypt to recover it.
 * Once the CEK is ready, the builder delegates the actual payload encryption or
 * decryption to an injected symmetric data-content builder (AES or ChaCha),
 * which is responsible for its own header and ciphertext framing.
 * </p>
 *
 * <p>
 * <b>Envelope layout.</b> The stream begins with a recipient table owned by
 * this builder:
 * <ul>
 * <li>pack7 recipientCount</li>
 * <li>for each recipient: UTF-8 entryId, then length-prefixed entryBlob</li>
 * <li>then follows the symmetric builder's header and payload stream</li>
 * </ul>
 * The symmetric stage parses its own header just as in the KEM-oriented
 * pipeline.
 */
public final class MultiRecipientDataSourceBuilder implements DataContentBuilder<DataContent> {
    // ---- symmetric selection (mirrors KemDataContentBuilder style) ----
    private AesDataContentBuilder aesBuilder;
    private ChaChaDataContentBuilder chachaBuilder;

    // ---- recipient scanning and construction ----
    private final List<Recipient> recipients = new ArrayList<>();
    private final List<RecipientOpener> openers = new ArrayList<>();
    private UnlockMaterial unlockMaterial;

    // ---- limits and CEK sizing ----
    private int payloadKeyBytes = 32; // e.g., 32 for AES-256 or ChaCha20
    private int maxRecipients = 64;
    private int maxEntryLen = 1 << 20; // up to 1 MiB per recipient entry

    /**
     * Creates a new builder for constructing a multi-recipient data source.
     *
     * <p>
     * The returned builder is initialized with safe defaults:
     * </p>
     * <ul>
     * <li>Payload key length: 32 bytes (suitable for AES-256).</li>
     * <li>Maximum recipients: 64.</li>
     * </ul>
     *
     * <p>
     * Callers can customize these parameters before building the final data source.
     * </p>
     *
     * @return a fresh {@code MultiRecipientDataSourceBuilder} instance with default
     *         settings
     */
    public static MultiRecipientDataSourceBuilder builder() {
        return new MultiRecipientDataSourceBuilder();
    }

    /**
     * Selects AES payload processing by installing an AES data content builder.
     *
     * <p>
     * The AES builder owns its parameters and header. This method clears any
     * previously installed ChaCha builder.
     * </p>
     *
     * @param builder configured AES data content builder
     * @return this builder
     * @throws NullPointerException if {@code builder} is {@code null}
     */
    public MultiRecipientDataSourceBuilder withAes(AesDataContentBuilder builder) {
        this.aesBuilder = Objects.requireNonNull(builder, "aesBuilder");
        this.chachaBuilder = null;
        return this;
    }

    /**
     * Randomly permutes the list of recipients using a default source of
     * randomness. All permutations occur with approximately equal likelihood.
     */
    public void shuffle() {
        Collections.shuffle(recipients);
    }

    /**
     * Selects ChaCha20-Poly1305 payload processing by installing a ChaCha data
     * content builder.
     *
     * <p>
     * The ChaCha builder owns its parameters and header. This method clears any
     * previously installed AES builder.
     * </p>
     *
     * @param builder configured ChaCha data content builder
     * @return this builder
     * @throws NullPointerException if {@code builder} is {@code null}
     */
    public MultiRecipientDataSourceBuilder withChaCha(ChaChaDataContentBuilder builder) {
        this.chachaBuilder = Objects.requireNonNull(builder, "chachaBuilder");
        this.aesBuilder = null;
        return this;
    }

    /**
     * Sets the CEK length in bytes that will be generated on encrypt and expected
     * on decrypt.
     *
     * <p>
     * Typical values: 16 or 32 for AES, 32 for ChaCha20-Poly1305.
     * </p>
     *
     * @param keyBytes CEK length in bytes
     * @return this builder
     * @throws IllegalArgumentException if {@code keyBytes} is not positive
     */
    public MultiRecipientDataSourceBuilder payloadKeyBytes(int keyBytes) {
        if (keyBytes <= 0) {
            throw new IllegalArgumentException("payloadKeyBytes must be > 0");
        }
        this.payloadKeyBytes = keyBytes;
        return this;
    }

    /**
     * Adds a password-based recipient that derives a KEK via PBKDF2(HMAC-SHA-256)
     * and AES-GCM-wraps the CEK.
     *
     * @param password   the password; the caller should clear the array after use
     * @param iterations PBKDF2 iteration count
     * @param saltLen    salt length in bytes
     * @param kekBytes   derived KEK length in bytes (for example, 16 or 32)
     * @return this builder
     * @throws NullPointerException if {@code password} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addPasswordRecipient(char[] password, int iterations, int saltLen,
            int kekBytes) {
        this.recipients.add(new PasswordRecipient(password, iterations, saltLen, kekBytes));
        return this;
    }

    /**
     * Adds a universal recipient backed by a caller-supplied {@link KemContext}.
     *
     * <p>
     * The context is used once to {@link KemContext#encapsulate()} and then closed.
     * The entry format and key wrapping are:
     * {@code kemCt || hkdfSalt || wrapIv || gcmWrappedCEK}. The entry id is
     * {@code "KEM:<kemAlgorithmId>:GCM-WRAP"} so that default openers still match.
     * </p>
     *
     * @param kem      configured context for
     *                 {@link zeroecho.core.KeyUsage#ENCAPSULATE}
     * @param kekBytes derived KEK length in bytes (e.g., 16 or 32)
     * @param saltLen  HKDF salt length in bytes
     * @return this builder
     * @throws NullPointerException if {@code kem} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addRecipient(KemContext kem, int kekBytes, int saltLen) {
        this.recipients.add(new KemCtxRecipient(Objects.requireNonNull(kem), kekBytes, saltLen));
        return this;
    }

    /**
     * Adds a universal recipient backed by a caller-supplied
     * {@link EncryptionContext}.
     *
     * <p>
     * The context must be configured for {@link zeroecho.core.KeyUsage#ENCRYPT}
     * with the appropriate asymmetric algorithm (e.g., RSA-OAEP, ElGamal, ECIES).
     * The CEK is encrypted by streaming it through
     * {@link EncryptionContext#attach(java.io.InputStream)}. The entry id is
     * {@code "ENC:" + ctx.algorithm().id()}.
     * </p>
     *
     * <p>
     * The context is consumed once and then closed by the builder.
     * </p>
     *
     * @param ctx the encryption context configured for ENCRYPT
     * @return this builder
     * @throws NullPointerException if {@code ctx} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addRecipient(EncryptionContext ctx) {
        this.recipients.add(new EncCtxRecipient(Objects.requireNonNull(ctx)));
        return this;
    }

    /**
     * Adds a password-based <b>decoy</b> recipient that derives a KEK via
     * PBKDF2(HMAC-SHA-256) and AES-GCM-wraps the CEK.
     *
     * @param password   the password; the caller should clear the array after use
     * @param iterations PBKDF2 iteration count
     * @param saltLen    salt length in bytes
     * @param kekBytes   derived KEK length in bytes (for example, 16 or 32)
     * @return this builder
     * @throws NullPointerException if {@code password} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addPasswordRecipientDecoy(char[] password, int iterations, int saltLen,
            int kekBytes) {
        this.recipients.add(new PasswordRecipient(password, iterations, saltLen, kekBytes, true));
        return this;
    }

    /**
     * Adds a universal <b>decoy</b> recipient backed by a caller-supplied
     * {@link KemContext}.
     *
     * <p>
     * The context is used once to {@link KemContext#encapsulate()} and then closed.
     * The entry format and key wrapping are:
     * {@code kemCt || hkdfSalt || wrapIv || gcmWrappedCEK}. The entry id is
     * {@code "KEM:<kemAlgorithmId>:GCM-WRAP"} so that default openers still match.
     * </p>
     *
     * @param kem      configured context for
     *                 {@link zeroecho.core.KeyUsage#ENCAPSULATE}
     * @param kekBytes derived KEK length in bytes (e.g., 16 or 32)
     * @param saltLen  HKDF salt length in bytes
     * @return this builder
     * @throws NullPointerException if {@code kem} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addRecipientDecoy(KemContext kem, int kekBytes, int saltLen) {
        this.recipients.add(new KemCtxRecipient(Objects.requireNonNull(kem), kekBytes, saltLen, true));
        return this;
    }

    /**
     * Adds a universal <b>decoy</b> recipient backed by a caller-supplied
     * {@link EncryptionContext}.
     *
     * <p>
     * The context must be configured for {@link zeroecho.core.KeyUsage#ENCRYPT}
     * with the appropriate asymmetric algorithm (e.g., RSA-OAEP, ElGamal, ECIES).
     * The CEK is encrypted by streaming it through
     * {@link EncryptionContext#attach(java.io.InputStream)}. The entry id is
     * {@code "ENC:" + ctx.algorithm().id()}.
     * </p>
     *
     * <p>
     * The context is consumed once and then closed by the builder.
     * </p>
     *
     * @param ctx the encryption context configured for ENCRYPT
     * @return this builder
     * @throws NullPointerException if {@code ctx} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addRecipientDecoy(EncryptionContext ctx) {
        this.recipients.add(new EncCtxRecipient(Objects.requireNonNull(ctx), true));
        return this;
    }

    /**
     * Supplies the unlocking material for decryption, either a private key or a
     * password.
     *
     * <p>
     * Only a single unlocking material is used. During decryption each opener
     * attempts to recover the CEK from the recipient entries using this material.
     * </p>
     *
     * @param material the unlocking material (private key or password)
     * @return this builder
     * @throws NullPointerException if {@code material} is {@code null}
     */
    public MultiRecipientDataSourceBuilder unlockWith(UnlockMaterial material) {
        this.unlockMaterial = Objects.requireNonNull(material);
        return this;
    }

    /**
     * Adds a custom recipient opener used during decryption when scanning recipient
     * entries.
     *
     * <p>
     * If no openers are added explicitly, the default set is installed during
     * {@link #build(boolean)} and covers KEM, RSA-OAEP, ElGamal, and PBKDF2
     * password recipients.
     * </p>
     *
     * @param opener the opener to add
     * @return this builder
     * @throws NullPointerException if {@code opener} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addOpener(RecipientOpener opener) {
        this.openers.add(Objects.requireNonNull(opener));
        return this;
    }

    /**
     * Adds a universal opener backed by a caller-supplied {@link KemContext}.
     *
     * <p>
     * The opener matches entries whose id starts with {@code "KEM:"} and whose
     * algorithm id equals {@code kem.algorithm().id()}. When a match is attempted,
     * the context is used to {@link KemContext#decapsulate(byte[])} and then
     * closed.
     * </p>
     *
     * @param kem context configured for {@link zeroecho.core.KeyUsage#DECAPSULATE}
     * @return this builder
     * @throws NullPointerException if {@code kem} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addOpener(KemContext kem) {
        this.openers.add(new KemCtxOpener(Objects.requireNonNull(kem)));
        return this;
    }

    /**
     * Adds a universal opener backed by a caller-supplied
     * {@link EncryptionContext}.
     *
     * <p>
     * The opener matches entries whose id equals
     * {@code "ENC:" + ctx.algorithm().id()}. When a match is attempted, the CEK
     * ciphertext blob is streamed through
     * {@link EncryptionContext#attach(java.io.InputStream)} to obtain the plaintext
     * CEK. The context is then closed.
     * </p>
     *
     * @param ctx context configured for {@link zeroecho.core.KeyUsage#DECRYPT}
     * @return this builder
     * @throws NullPointerException if {@code ctx} is {@code null}
     */
    public MultiRecipientDataSourceBuilder addOpener(EncryptionContext ctx) {
        this.openers.add(new EncCtxOpener(Objects.requireNonNull(ctx)));
        return this;
    }

    /**
     * Applies defensive limits for parsing the recipient table.
     *
     * <p>
     * All values are clamped to at least 1. These limits guard against resource
     * exhaustion from malformed input.
     * </p>
     *
     * @param maxRecipients maximum number of recipient entries allowed
     * @param maxEntryLen   maximum size in bytes for a single recipient entry blob
     * @return this builder
     */
    public MultiRecipientDataSourceBuilder headerLimits(int maxRecipients, int maxEntryLen) {
        this.maxRecipients = Math.max(1, maxRecipients);
        this.maxEntryLen = Math.max(1, maxEntryLen);
        return this;
    }

    /**
     * Builds either an encrypting or a decrypting content wrapper depending on the
     * {@code encrypt} flag.
     *
     * <p>
     * When {@code encrypt} is {@code true}, the wrapper emits the recipient table
     * followed by the symmetric builder's header and ciphertext. When
     * {@code encrypt} is {@code false}, the wrapper unlocks the CEK from the first
     * matching recipient entry and streams the symmetric plaintext.
     * </p>
     *
     * <p>
     * Default openers are installed automatically if none were added explicitly.
     * They support KEM, RSA-OAEP, ElGamal with PKCS1 padding, and PBKDF2 password
     * recipients.
     * </p>
     *
     * @param encrypt {@code true} to build an encrypting content source,
     *                {@code false} to build a decrypting one
     * @return an encrypting or decrypting {@link DataContent} wrapper
     * @throws IllegalStateException if no symmetric builder is selected, if
     *                               encryption is requested with no recipients, or
     *                               if decryption is requested without unlock
     *                               material
     */
    @Override
    public DataContent build(boolean encrypt) {
        if (aesBuilder == null && chachaBuilder == null) {
            throw new IllegalStateException("No symmetric builder selected. Call withAes(...) or withChaCha(...).");
        }
        if (encrypt && recipients.isEmpty()) {
            throw new IllegalStateException("No recipients configured for encryption");
        }
        if (!encrypt && unlockMaterial == null) {
            throw new IllegalStateException("Missing unlock material for decryption");
        }
        if (openers.isEmpty()) {
            openers.add(new EncCtxOpener());
            openers.add(new KemCtxOpener());
            openers.add(new PasswordOpener());
        }
        return encrypt
                ? new Encryptor(recipients, aesBuilder, chachaBuilder, payloadKeyBytes, maxRecipients, maxEntryLen)
                : new Decryptor(openers, unlockMaterial, aesBuilder, chachaBuilder, payloadKeyBytes, maxRecipients,
                        maxEntryLen);
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static Cipher cipherPreferJdk(String transformation) throws GeneralSecurityException {
        Provider jdk = Security.getProvider("SunJCE");
        if (jdk != null) {
            try {
                return Cipher.getInstance(transformation, jdk);
            } catch (GeneralSecurityException ignore) { // NOPMD
                /* fall through */
            }
        }
        return Cipher.getInstance(transformation);
    }

    /**
     * PBKDF2 with HMAC-SHA-256 key derivation.
     *
     * @param password   password characters
     * @param salt       salt bytes
     * @param iterations iteration count
     * @param outLen     output length in bytes
     * @return derived key material
     * @throws GeneralSecurityException if a provider cannot compute PBKDF2
     */
    /* default */ static byte[] pbkdf2HmacSha256(char[] password, byte[] salt, int iterations, int outLen)
            throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, outLen * 8);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    /**
     * AES-GCM key wrap that returns {@code ciphertext||tag}; IV and optional AAD
     * are provided as parameters.
     *
     * @param kek       key-encryption key
     * @param iv        12-byte IV
     * @param aad       optional additional authenticated data or null
     * @param plaintext CEK to wrap
     * @return wrapped bytes of CEK
     * @throws GeneralSecurityException if AES-GCM fails
     * @throws IOException              never in the current implementation
     */
    /* default */ static byte[] aesGcmWrap(byte[] kek, byte[] iv, byte[] aad, byte[] plaintext)
            throws GeneralSecurityException, IOException {
        Cipher c = cipherPreferJdk("AES/GCM/NOPADDING");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(128, iv));
        if (aad != null && aad.length > 0) {
            c.updateAAD(aad);
        }
        return c.doFinal(plaintext);
    }

    /**
     * AES-GCM key unwrap that authenticates and returns the plaintext CEK.
     *
     * @param kek        key-encryption key
     * @param iv         12-byte IV
     * @param aad        optional additional authenticated data or null
     * @param ciphertext wrapped bytes of CEK (ciphertext||tag)
     * @return unwrapped CEK
     * @throws GeneralSecurityException if AES-GCM authentication or decryption
     *                                  fails
     * @throws IOException              never in the current implementation
     */
    /* default */ static byte[] aesGcmUnwrap(byte[] kek, byte[] iv, byte[] aad, byte[] ciphertext)
            throws GeneralSecurityException, IOException {
        Cipher c = cipherPreferJdk("AES/GCM/NOPADDING");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(128, iv));
        if (aad != null && aad.length > 0) {
            c.updateAAD(aad);
        }
        return c.doFinal(ciphertext);
    }
}
