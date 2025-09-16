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
package zeroecho.sdk.builders.core;

import zeroecho.sdk.content.api.DataContent;

/**
 * A builder interface for constructing a chain of {@link DataContent}
 * components, where each content unit passes its output as the input to the
 * next one.
 *
 * <p>
 * This builder simplifies the composition of processing pipelines such as:
 * <ul>
 * <li>Encryption with multiple layers (e.g., compression → encryption →
 * signing)</li>
 * <li>Decryption chains (e.g., verification → decryption → decompression)</li>
 * </ul>
 *
 * <p>
 * The builder supports both encryption and decryption modes, which are applied
 * consistently across all {@link DataContentBuilder} instances in the chain.
 * </p>
 *
 * <p>
 * Usage example: <pre>{@code
 * DataContent chain = DataContentChainBuilder.encrypt()
 *     .add(PlainStringBuilder.builder().value("hello"))
 *     .add(DerivedAesParametersBuilder.builder().password("secret"))
 *     .build();
 * }</pre>
 */
public interface DataContentChainBuilder {
    /**
     * Adds a {@link DataContentBuilder} to the chain and links its output to the
     * input of the previously added {@code DataContent}, if any.
     *
     * <p>
     * The {@link DataContent} produced by this builder becomes the new tail of the
     * chain.
     * </p>
     *
     * @param builder the builder producing the next {@code DataContent}; must not
     *                be null
     * @return this chain builder instance, allowing for fluent chaining
     * @throws NullPointerException if {@code builder} is null
     */
    DataContentChainBuilder add(DataContentBuilder<? extends DataContent> builder);

    /**
     * Finalizes the chain and returns the tail {@link DataContent} instance.
     *
     * <p>
     * The returned content may internally reference earlier content via
     * {@link DataContent#setInput(DataContent)} chaining.
     * </p>
     *
     * @return the last {@code DataContent} in the chain, or {@code null} if no
     *         builders were added
     */
    DataContent build();

    /**
     * Creates a new {@code DataContentChainBuilder} configured for encryption mode.
     *
     * <p>
     * All added {@link DataContentBuilder} instances will receive {@code true} for
     * their {@code build(boolean encrypt)} method, indicating encryption behavior.
     * </p>
     *
     * @return a new chain builder in encryption mode
     */
    static DataContentChainBuilder encrypt() {
        return new DefaultDataContentChainBuilder(true);
    }

    /**
     * Creates a new {@code DataContentChainBuilder} configured for decryption mode.
     *
     * <p>
     * All added {@link DataContentBuilder} instances will receive {@code false} for
     * their {@code build(boolean encrypt)} method, indicating decryption behavior.
     * </p>
     *
     * @return a new chain builder in decryption mode
     */
    static DataContentChainBuilder decrypt() {
        return new DefaultDataContentChainBuilder(false);
    }

    /**
     * Default implementation of {@link DataContentChainBuilder}.
     *
     * <p>
     * Maintains a reference to the tail of the content chain. Each added builder is
     * built in the specified encryption/decryption mode and connected via
     * {@link DataContent#setInput(DataContent)} to the previously built content.
     * </p>
     */
    final class DefaultDataContentChainBuilder implements DataContentChainBuilder {
        private DataContent tail;
        private final boolean encrypt;

        private DefaultDataContentChainBuilder(final boolean encrypt) {
            this.encrypt = encrypt;
        }

        @Override
        public DataContentChainBuilder add(final DataContentBuilder<? extends DataContent> builder) {
            final DataContent previous = tail;

            tail = builder.build(encrypt);

            if (previous != null) {
                tail.setInput(previous);
            }

            return this;
        }

        @Override
        public DataContent build() {
            return tail;
        }
    }
}
