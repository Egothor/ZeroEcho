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
package zeroecho.core.alg.aes;

import java.util.Objects;

import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.ContextSpec;

/**
 * Static configuration for AES encryption and decryption.
 *
 * <p>
 * An {@code AesSpec} captures compile‑time choices for the AES transform: the
 * block mode, padding scheme (CBC only), and—when using GCM—the authentication
 * tag length in bits. It may optionally embed a
 * {@link zeroecho.core.SymmetricHeaderCodec} that governs how runtime
 * parameters (IV/nonce, tag bits, AAD hash) are written to and read from the
 * data stream. No IV/nonce or AAD bytes are stored in this type; those are
 * runtime values exchanged via a Conflux session context.
 * </p>
 *
 * <h2>Design</h2>
 * <ul>
 * <li><b>Immutability:</b> instances are immutable and thread‑safe.</li>
 * <li><b>Validation:</b> GCM requires {@code NOPADDING} and a tag length
 * between 96 and 128 bits (inclusive) in 8‑bit increments; non‑GCM modes must
 * not specify a tag length.</li>
 * <li><b>Header codec:</b> when present, the codec persists IV and GCM
 * parameters in‑band, and can bind AAD via a hash. The cipher context hydrates
 * the runtime context from this header during decryption, and writes it during
 * encryption.</li>
 * <li><b>Runtime parameters:</b> IV sizes are dictated by mode (12 bytes for
 * GCM; 16 for CBC/CTR) and are generated or required at runtime by the cipher
 * context, not by this spec.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class AesSpec implements ContextSpec, Describable {
    /**
     * AES block modes supported by this implementation.
     *
     * <p>
     * Mode selection determines IV length and security properties. GCM is an AEAD
     * mode; CBC and CTR provide confidentiality only and must be combined with a
     * MAC (Encrypt‑then‑MAC) when integrity/authenticity are required.
     * </p>
     */
    public enum Mode {
        /**
         * Cipher Block Chaining (CBC).
         *
         * <p>
         * Requires a 16‑byte IV. Supports {@link Padding#PKCS5PADDING} and
         * {@link Padding#NOPADDING}. Not an AEAD mode; pair with a MAC for integrity.
         * </p>
         */
        CBC,
        /**
         * Galois/Counter Mode (GCM), an authenticated encryption mode (AEAD).
         *
         * <p>
         * Requires a 12‑byte IV and {@link Padding#NOPADDING}. The tag length must be
         * 96–128 bits (multiple of 8). Supports Additional Authenticated Data (AAD).
         * Recommended default.
         * </p>
         */
        GCM,
        /**
         * Counter mode (CTR).
         *
         * <p>
         * Uses a 16‑byte nonce/IV and {@link Padding#NOPADDING}. Not an AEAD mode; pair
         * with a MAC for integrity.
         * </p>
         */
        CTR
    }

    /**
     * Padding schemes for CBC mode.
     *
     * <p>
     * GCM and CTR always use {@link #NOPADDING}.
     * </p>
     */
    public enum Padding {
        /**
         * No padding.
         *
         * <p>
         * Use only when the plaintext length is an exact multiple of the AES block size
         * (16 bytes). Applicable to CBC; mandatory for GCM/CTR.
         * </p>
         */
        NOPADDING,
        /**
         * PKCS#5 padding (recommended for CBC) available in the Standard JDK21+.
         */
        PKCS5PADDING
    } // CBC only

    private final Mode mode;
    private final Padding padding; // CBC: PKCS5 or NOPADDING; GCM/CTR: NOPADDING
    private final int tagLenBits; // GCM only (96..128 step 8). 0 for non-GCM.
    private final SymmetricHeaderCodec header;

    private AesSpec(Mode mode, Padding padding, int tagLenBits, SymmetricHeaderCodec header) {
        this.mode = Objects.requireNonNull(mode, "mode must not be null");
        this.padding = Objects.requireNonNull(padding, "padding must not be null");
        if (mode == Mode.GCM && padding != Padding.NOPADDING) {
            throw new IllegalArgumentException("GCM must use NOPADDING");
        }
        if (mode == Mode.GCM) {
            if (tagLenBits % 8 != 0 || tagLenBits < 96 || tagLenBits > 128) {
                throw new IllegalArgumentException("GCM tagLenBits must be 96..128 in steps of 8");
            }
        } else if (tagLenBits != 0) {
            throw new IllegalArgumentException("tagLenBits applies to GCM only");
        }
        this.tagLenBits = tagLenBits;
        this.header = header; // may be null
    }

    /**
     * Returns a new builder with safe defaults ({@link Mode#GCM},
     * {@link Padding#NOPADDING}, 128‑bit tag, no header).
     *
     * @return a fresh builder for {@link AesSpec}
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AesSpec}.
     *
     * <p>
     * Not thread‑safe. The resulting {@code AesSpec} is immutable.
     * </p>
     */
    public static final class Builder {
        private Mode mode = Mode.GCM;
        private Padding padding = Padding.NOPADDING;
        private int tagLenBits = 128; // only used for GCM
        private SymmetricHeaderCodec header;

        /**
         * Creates a builder initialized for AES-GCM with a 128-bit tag.
         */
        public Builder() {
            // Field initializers establish the documented defaults.
        }

        /**
         * Selects the AES mode.
         *
         * @param m the block mode ({@link Mode#CBC}, {@link Mode#GCM}, or
         *          {@link Mode#CTR})
         * @return this builder
         * @throws NullPointerException if {@code m} is {@code null}
         */
        public Builder mode(Mode m) {
            this.mode = Objects.requireNonNull(m);
            return this;
        }

        /**
         * Selects the padding scheme for CBC.
         *
         * <p>
         * Ignored for GCM and CTR, which always use {@link Padding#NOPADDING}.
         * </p>
         *
         * @param p the padding scheme
         * @return this builder
         * @throws NullPointerException if {@code p} is {@code null}
         */
        public Builder padding(Padding p) {
            this.padding = Objects.requireNonNull(p);
            return this;
        }

        /**
         * Sets the GCM authentication tag length in bits.
         *
         * <p>
         * Valid only when the mode is {@link Mode#GCM}. The value must be 96, 104, 112,
         * 120, or 128.
         * </p>
         *
         * @param t the tag length in bits
         * @return this builder
         */
        public Builder tagLenBits(int t) {
            this.tagLenBits = t;
            return this;
        }

        /**
         * Installs a header codec used by the cipher context to persist and recover
         * runtime parameters (e.g., IV, tag length, AAD hash).
         *
         * <p>
         * When {@code null}, no header is written or parsed.
         * </p>
         *
         * @param codec the codec to embed, or {@code null} to disable
         * @return this builder
         */
        public Builder header(SymmetricHeaderCodec codec) {
            this.header = codec;
            return this;
        }

        /**
         * Builds a validated {@link AesSpec}.
         *
         * <p>
         * Validation rules:
         * </p>
         * <ul>
         * <li>If mode is {@link Mode#GCM}, padding must be {@link Padding#NOPADDING}
         * and {@code tagLenBits} must be 96–128 in steps of 8.</li>
         * <li>If mode is not GCM, {@code tagLenBits} must be 0.</li>
         * </ul>
         *
         * @return an immutable specification
         * @throws IllegalArgumentException if parameters are inconsistent
         */
        public AesSpec build() {
            int t = (mode == Mode.GCM) ? tagLenBits : 0;
            return new AesSpec(mode, padding, t, header);
        }
    }

    /**
     * Creates a GCM specification with a 128‑bit authentication tag and the
     * provided header codec.
     *
     * @param header the header codec to embed, or {@code null} for none
     * @return a specification for {@code AES/GCM/NOPADDING} with a 128‑bit tag
     */
    public static AesSpec gcm128(SymmetricHeaderCodec header) {
        return builder().mode(Mode.GCM).tagLenBits(128).header(header).build();
    }

    /**
     * Creates a CBC specification using PKCS#7 padding and the provided header.
     *
     * @param header the header codec to embed, or {@code null} for none
     * @return a specification for {@code AES/CBC/PKCS7Padding}
     */
    public static AesSpec cbcPkcs7(SymmetricHeaderCodec header) {
        return builder().mode(Mode.CBC).padding(Padding.PKCS5PADDING).header(header).build();
    }

    /**
     * Creates a CTR specification with no padding and the provided header.
     *
     * @param header the header codec to embed, or {@code null} for none
     * @return a specification for {@code AES/CTR/NOPADDING}
     */
    public static AesSpec ctr(SymmetricHeaderCodec header) {
        return builder().mode(Mode.CTR).padding(Padding.NOPADDING).header(header).build();
    }

    /**
     * Returns the selected AES mode.
     *
     * <p>
     * This value determines IV length expectations and whether AAD and tag length
     * apply (GCM only).
     * </p>
     *
     * @return the block mode used by this specification
     */
    public Mode mode() {
        return mode;
    }

    /**
     * Returns the selected padding scheme.
     *
     * <p>
     * Relevant only for CBC; GCM and CTR always operate with no padding.
     * </p>
     *
     * @return the padding scheme (never {@code null})
     */
    public Padding padding() {
        return padding;
    }

    /**
     * Returns the authentication tag length in bits.
     *
     * <p>
     * For GCM, this is one of 96, 104, 112, 120, or 128. For non‑GCM modes, this
     * method returns {@code 0}.
     * </p>
     *
     * @return the GCM tag length in bits, or {@code 0} if not applicable
     */
    public int tagLenBits() {
        return tagLenBits;
    }

    /**
     * Returns the embedded header codec, if any.
     *
     * <p>
     * When non‑null, the cipher context writes the header during encryption (after
     * the IV is chosen) and reads it during decryption to hydrate the runtime
     * context.
     * </p>
     *
     * @return the header codec, or {@code null} if no header is used
     */
    public SymmetricHeaderCodec header() {
        return header;
    }

    /**
     * Produces a compact human‑readable description of this specification, such as
     * {@code "AES-GCM(tag=128)"} or {@code "AES-CBC/PKCS7Padding"}.
     *
     * @return a descriptive string for diagnostics and logs
     */
    @Override
    public String description() {
        return "AES-" + mode + (mode == Mode.CBC ? "/" + padding : "")
                + (mode == Mode.GCM ? "(tag=" + tagLenBits + ")" : "");
    }
}
