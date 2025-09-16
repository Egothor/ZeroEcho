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
package zeroecho.core.alg.chacha;

import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.annotation.Describable;

/**
 * <h2>ChaCha20 stream cipher specification</h2>
 *
 * Immutable parameter set for configuring a {@code ChaCha20} context. Provides
 * an initial counter and an optional {@link SymmetricHeaderCodec}.
 *
 * <h3>Fields</h3>
 * <ul>
 * <li>{@link #initialCounter()} - the initial block counter used when no
 * counter is present in the context or header (must be non-negative). Default
 * is {@code 1}, matching common practice.</li>
 * <li>{@link #header()} - optional codec for encoding/decoding a stream header
 * that carries runtime parameters such as nonce and counter.</li>
 * </ul>
 *
 * <h3>Construction</h3> Use the fluent {@link Builder}: <pre>{@code
 * ChaChaSpec spec = ChaChaSpec.builder()
 *     .initialCounter(42)
 *     .header(new ChaChaHeaderCodec())
 *     .build();
 * }</pre>
 *
 * <h3>Convenience factory</h3>
 * <ul>
 * <li>{@link #chacha20(SymmetricHeaderCodec)} returns a spec with initial
 * counter {@code 1} and the provided header codec.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class ChaChaSpec implements ChaChaBaseSpec, Describable {
    private final int initialCounter; // used when counter not present in ctx/header
    private final SymmetricHeaderCodec header; // optional header codec

    /**
     * Creates a new ChaCha20 specification.
     *
     * @param initialCounter initial block counter (must be >= 0)
     * @param header         optional header codec (may be {@code null})
     * @throws IllegalArgumentException if {@code initialCounter < 0}
     */
    private ChaChaSpec(int initialCounter, SymmetricHeaderCodec header) {
        if (initialCounter < 0) {
            throw new IllegalArgumentException("initialCounter must be >= 0");
        }
        this.initialCounter = initialCounter;
        this.header = header; // may be null
    }

    /**
     * Returns a new builder for constructing a {@link ChaChaSpec}.
     *
     * @return fresh builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fluent builder for {@link ChaChaSpec}.
     */
    public static final class Builder {
        private int initialCounter = 1; // sane default per common practice
        private SymmetricHeaderCodec header; // = null;

        /**
         * Sets the initial counter value.
         *
         * @param c non-negative counter value
         * @return this builder
         */
        public Builder initialCounter(int c) {
            this.initialCounter = c;
            return this;
        }

        /**
         * Sets the optional header codec.
         *
         * @param codec header codec or {@code null}
         * @return this builder
         */
        public Builder header(SymmetricHeaderCodec codec) {
            this.header = codec;
            return this;
        }

        /**
         * Builds an immutable {@link ChaChaSpec}.
         *
         * @return constructed spec
         */
        public ChaChaSpec build() {
            return new ChaChaSpec(initialCounter, header);
        }
    }

    /**
     * Convenience factory for a ChaCha20 spec with counter = 1.
     *
     * @param header optional header codec
     * @return new spec instance
     */
    public static ChaChaSpec chacha20(SymmetricHeaderCodec header) {
        return builder().initialCounter(1).header(header).build();
    }

    /**
     * Returns the configured initial counter.
     *
     * @return non-negative counter value
     */
    public int initialCounter() {
        return initialCounter;
    }

    /**
     * Returns the optional header codec.
     *
     * @return codec instance or {@code null}
     */
    @Override
    public SymmetricHeaderCodec header() {
        return header;
    }

    /**
     * Human-readable description of this spec.
     *
     * @return string of the form {@code "ChaCha20(counter=N)"}
     */
    @Override
    public String description() {
        return "ChaCha20(counter=" + initialCounter + ")";
    }
}
