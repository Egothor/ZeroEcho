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
package zeroecho.core.alg.chacha;

import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.annotation.Describable;

/**
 * <h2>ChaCha20-Poly1305 algorithm specification</h2>
 *
 * Immutable parameters for configuring a ChaCha20-Poly1305 operation.
 * Optionally carries a {@link SymmetricHeaderCodec} to prepend/parse per-stream
 * headers (e.g., nonce and AAD hash) during encryption/decryption.
 *
 * <h3>Notes</h3>
 * <ul>
 * <li>If {@link #header()} is {@code null}, no header is written or read;
 * callers must exchange the nonce/AAD out-of-band via the context.</li>
 * <li>The effective authentication tag size is 128 bits.</li>
 * </ul>
 *
 * <h3>Example</h3> <pre>{@code
 * ChaCha20Poly1305Spec spec = ChaCha20Poly1305Spec.builder()
 *     .header(new ChaCha20Poly1305HeaderCodec())
 *     .build();
 * }</pre>
 *
 * @since 1.0
 */
public final class ChaCha20Poly1305Spec implements ChaChaBaseSpec, Describable {
    /**
     * Optional streaming header codec used to serialize/deserialize the per-stream
     * parameters (e.g., nonce and AAD hash). When {@code null}, no header is used.
     */
    private final SymmetricHeaderCodec header; // optional

    /**
     * Creates a specification instance.
     *
     * @param header optional {@link SymmetricHeaderCodec}; may be {@code null}
     */
    private ChaCha20Poly1305Spec(SymmetricHeaderCodec header) {
        this.header = header; // may be null
    }

    /**
     * Returns a new builder for {@link ChaCha20Poly1305Spec}.
     *
     * @return a fresh {@link Builder}
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for {@link ChaCha20Poly1305Spec}.
     */
    public static final class Builder {
        /**
         * Header codec to embed/parse per-stream parameters. May be {@code null}.
         */
        private SymmetricHeaderCodec header;

        /**
         * Creates a builder with stream-header encoding disabled.
         */
        public Builder() {
            // Null header is the documented default.
        }

        /**
         * Sets an optional streaming header codec.
         *
         * @param codec header codec to use, or {@code null} to disable headers
         * @return this builder
         */
        public Builder header(SymmetricHeaderCodec codec) {
            this.header = codec;
            return this;
        }

        /**
         * Builds an immutable {@link ChaCha20Poly1305Spec}.
         *
         * @return the constructed spec
         */
        public ChaCha20Poly1305Spec build() {
            return new ChaCha20Poly1305Spec(header);
        }
    }

    /**
     * Convenience factory that returns a spec with the provided header codec.
     *
     * @param header optional header codec; may be {@code null}
     * @return a new {@code ChaCha20Poly1305Spec} configured with {@code header}
     */
    public static ChaCha20Poly1305Spec withHeader(SymmetricHeaderCodec header) {
        return builder().header(header).build();
    }

    /**
     * Returns the optional header codec.
     *
     * @return header codec or {@code null} if none
     */
    @Override
    public SymmetricHeaderCodec header() {
        return header;
    }

    /**
     * Human-readable description of this spec.
     *
     * @return {@code "ChaCha20-Poly1305(tag=128)"}
     */
    @Override
    public String description() {
        return "ChaCha20-Poly1305(tag=128)";
    }
}
