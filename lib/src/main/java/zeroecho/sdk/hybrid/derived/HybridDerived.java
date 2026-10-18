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
package zeroecho.sdk.hybrid.derived;

import java.util.Arrays;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.alg.hmac.HmacSpec;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;
import zeroecho.sdk.builders.alg.HmacDataContentBuilder;
import zeroecho.sdk.hybrid.kex.HybridKexExporter;

/**
 * Builder-style utility for deriving purpose-separated key material from a
 * hybrid KEX exporter and applying it to streaming algorithm builders.
 *
 * <p>
 * This class does not implement new cryptographic primitives. It derives keying
 * bytes via HKDF labels (using {@link HybridKexExporter}) and injects them into
 * existing builder instances.
 * </p>
 *
 * <h2>Labeling</h2>
 * <p>
 * Derivation uses a base label, plus fixed suffixes for individual fields:
 * </p>
 * <ul>
 * <li>{@code label + "/key"} for the secret key</li>
 * <li>{@code label + "/aad"} for AEAD AAD (optional, if derived)</li>
 * </ul>
 *
 * <p>
 * A caller-supplied transcript binding (public handshake context) may be
 * included and will be passed to the exporter as {@code info}. This improves
 * cross-protocol separation and reduces configuration mistakes.
 * </p>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Instances are mutable and not thread-safe.
 * </p>
 *
 * @since 1.0
 */
public final class HybridDerived {

    private final HybridKexExporter exporter;

    private String label;
    private byte[] transcript;

    private byte[] aadExplicit;
    private boolean aadDerive;
    private int aadDeriveLen;

    /**
     * Creates a new derived-material builder backed by an exporter.
     *
     * @param exporter exporter seeded from a hybrid KEX result (must not be null)
     * @return new derived-material builder
     * @throws NullPointerException if exporter is null
     * @since 1.0
     */
    public static HybridDerived from(HybridKexExporter exporter) {
        Objects.requireNonNull(exporter, "exporter");
        return new HybridDerived(exporter);
    }

    private HybridDerived(HybridKexExporter exporter) {
        this.exporter = exporter;
    }

    /**
     * Sets the base label used for purpose separation.
     *
     * <p>
     * The label should identify the protocol purpose of the derived material, for
     * example {@code "app/enc"} or {@code "handshake/confirm"}.
     * </p>
     *
     * @param label base label (must not be null or empty)
     * @return this builder
     * @throws NullPointerException     if label is null
     * @throws IllegalArgumentException if label is empty
     * @since 1.0
     */
    public HybridDerived label(String label) {
        Objects.requireNonNull(label, "label");
        if (label.isEmpty()) {
            throw new IllegalArgumentException("label must not be empty");
        }
        this.label = label;
        return this;
    }

    /**
     * Sets transcript binding bytes used as exporter {@code info}.
     *
     * <p>
     * The transcript should contain only public context (negotiated suite, public
     * keys/messages, channel binding, etc.). It must not contain secrets.
     * </p>
     *
     * @param transcript transcript bytes (may be null to clear)
     * @return this builder
     * @since 1.0
     */
    public HybridDerived transcript(byte[] transcript) {
        this.transcript = (transcript == null) ? null : transcript.clone();
        return this;
    }

    /**
     * Supplies explicit AAD bytes to be injected into AEAD builders.
     *
     * <p>
     * If set, no AAD derivation is performed.
     * </p>
     *
     * @param aad AAD bytes (may be null to clear)
     * @return this builder
     * @since 1.0
     */
    public HybridDerived aad(byte[] aad) {
        this.aadExplicit = (aad == null) ? null : aad.clone();
        this.aadDerive = false;
        this.aadDeriveLen = 0;
        return this;
    }

    /**
     * Requests deterministic derivation of AAD bytes from the exporter.
     *
     * <p>
     * This is optional. Many applications prefer to keep AAD as an
     * application-defined, already-available public context. If derived, the AAD is
     * separated using {@code label + "/aad"}.
     * </p>
     *
     * @param aadLen number of bytes to derive (must be &gt;= 1)
     * @return this builder
     * @throws IllegalArgumentException if aadLen &lt; 1
     * @since 1.0
     */
    public HybridDerived deriveAad(int aadLen) {
        if (aadLen < 1) { // NOPMD
            throw new IllegalArgumentException("aadLen must be >= 1");
        }
        this.aadDerive = true;
        this.aadDeriveLen = aadLen;
        this.aadExplicit = null;
        return this;
    }

    /**
     * Derives an AES key and applies it with optional AAD to the provided AES
     * builder.
     *
     * <p>
     * The returned value is the same builder instance to preserve fluent pipeline
     * construction.
     * </p>
     *
     * @param aes     AES builder to configure (must not be null)
     * @param keyBits AES key size in bits (128/192/256)
     * @return the provided builder instance
     * @throws NullPointerException     if aes is null
     * @throws IllegalArgumentException if keyBits is invalid
     * @since 1.0
     */
    public AesDataContentBuilder applyToAesGcm(AesDataContentBuilder aes, int keyBits) {
        Objects.requireNonNull(aes, "aes");
        validateBase();

        int keyLenBytes = bitsToBytesStrict(keyBits);
        byte[] keyRaw = exportBytes(label + "/key", keyLenBytes); // NOPMD
        try {
            SecretKey key = new SecretKeySpec(keyRaw, "AES");
            aes.withKey(key);
        } finally {
            Arrays.fill(keyRaw, (byte) 0);
        }

        byte[] aad = resolveAad();
        if (aad != null) {
            aes.withAad(aad);
        }

        return aes;
    }

    /**
     * Derives a ChaCha key and applies it with optional AAD to the provided ChaCha
     * builder.
     *
     * <p>
     * The returned value is the same builder instance to preserve fluent pipeline
     * construction.
     * </p>
     *
     * @param chacha  ChaCha builder to configure (must not be null)
     * @param keyBits key size in bits (typically 256)
     * @return the provided builder instance
     * @throws NullPointerException     if chacha is null
     * @throws IllegalArgumentException if keyBits is invalid
     * @since 1.0
     */
    public ChaChaDataContentBuilder applyToChaChaAead(ChaChaDataContentBuilder chacha, int keyBits) {
        Objects.requireNonNull(chacha, "chacha");
        validateBase();

        int keyLenBytes = bitsToBytesStrict(keyBits);
        byte[] keyRaw = exportBytes(label + "/key", keyLenBytes); // NOPMD
        try {
            SecretKey key = new SecretKeySpec(keyRaw, "ChaCha20");
            chacha.withKey(key);
        } finally {
            Arrays.fill(keyRaw, (byte) 0);
        }

        byte[] aad = resolveAad();
        if (aad != null) {
            chacha.withAad(aad);
        }

        return chacha;
    }

    /**
     * Derives a MAC key using the builder's recommended size and applies it to the
     * provided HMAC builder.
     *
     * <p>
     * This is the preferred integration method because it avoids duplicated
     * configuration: the HMAC variant is chosen by the builder
     * ({@link HmacDataContentBuilder#spec()}), and the key size recommendation is
     * provided by {@link HmacDataContentBuilder#recommendedKeyBits()}.
     * </p>
     *
     * <p>
     * The returned value is the same builder instance to preserve fluent pipeline
     * construction.
     * </p>
     *
     * @param hmac HMAC builder to configure (must not be null)
     * @return the provided builder instance
     * @throws NullPointerException  if {@code hmac} is null
     * @throws IllegalStateException if this {@code HybridDerived} instance is
     *                               missing required base configuration
     * @since 1.0
     */
    public HmacDataContentBuilder applyToHmac(HmacDataContentBuilder hmac) {
        Objects.requireNonNull(hmac, "hmac");
        validateBase();

        int keyBits = hmac.recommendedKeyBits();
        return applyToHmac(hmac, keyBits);
    }

    /**
     * Derives a MAC key of an explicit size (override) and applies it to the
     * provided HMAC builder.
     *
     * <p>
     * This overload exists for advanced use-cases where the application
     * intentionally chooses a key size different from
     * {@link HmacSpec#recommendedKeyBits()}, for example to align a policy across
     * different MAC functions or to satisfy interoperability constraints.
     * </p>
     *
     * <p>
     * Because HMAC accepts arbitrary key lengths, this method does not attempt to
     * validate semantic suitability of {@code keyBits}. Applications that require
     * stricter controls should enforce them via policy (for example minimum bit
     * strength) and use transcript-bound labels to guarantee key separation.
     * </p>
     *
     * <p>
     * The returned value is the same builder instance to preserve fluent pipeline
     * construction.
     * </p>
     *
     * @param hmac    HMAC builder to configure (must not be null)
     * @param keyBits key size in bits (must be a positive multiple of 8)
     * @return the provided builder instance
     * @throws NullPointerException     if {@code hmac} is null
     * @throws IllegalArgumentException if {@code keyBits} is invalid
     * @throws IllegalStateException    if this {@code HybridDerived} instance is
     *                                  missing required base configuration
     * @since 1.0
     */
    public HmacDataContentBuilder applyToHmac(HmacDataContentBuilder hmac, int keyBits) {
        Objects.requireNonNull(hmac, "hmac");
        validateBase();

        int keyLenBytes = bitsToBytesStrict(keyBits);
        byte[] keyRaw = exportBytes(label + "/key", keyLenBytes);
        try {
            // Prefer raw import to avoid duplicating MAC algorithm naming and to keep the
            // builder as the source of truth.
            return hmac.importKeyRaw(keyRaw);
        } finally {
            Arrays.fill(keyRaw, (byte) 0);
        }
    }

    private void validateBase() {
        if (label == null || label.isEmpty()) {
            throw new IllegalStateException("label must be set");
        }
    }

    private byte[] resolveAad() {
        if (aadExplicit != null) {
            return aadExplicit.clone();
        }
        if (aadDerive) {
            return exportBytes(label + "/aad", aadDeriveLen);
        }
        return null; // NOPMD
    }

    private byte[] exportBytes(String subLabel, int len) {
        byte[] info = transcript;
        return exporter.export(subLabel, info, len);
    }

    private static int bitsToBytesStrict(int bits) {
        if (bits < 8 || (bits % 8) != 0) {
            throw new IllegalArgumentException("bits must be a positive multiple of 8");
        }
        return bits / 8;
    }
}
