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

import java.util.Objects;

import zeroecho.sdk.content.api.PlainContent;
import zeroecho.sdk.content.builtin.PlainBytes;

/**
 * Builder interface for constructing {@link PlainBytes} instances that
 * encapsulate unencrypted byte array content.
 * <p>
 * This builder allows specifying a raw byte array to be wrapped as
 * {@code PlainContent}, which can be used as input for cryptographic operations
 * or as standalone plaintext data.
 * <p>
 * The {@link #build(boolean)} method accepts an {@code encrypt} flag for API
 * consistency, but the flag has no effect for plain byte content.
 *
 * <p>
 * <strong>Usage example:</strong>
 * 
 * <pre>{@code
 * PlainContent content = PlainBytesBuilder.builder()
 *     .bytes(new byte[] { 1, 2, 3, 4 })
 *     .build(false); // encrypt flag is ignored for PlainBytes
 * }</pre>
 *
 * @see PlainBytes
 */
public interface PlainBytesBuilder extends DataContentBuilder<PlainContent> {

    /**
     * Sets the byte array content to be wrapped by {@link PlainBytes}.
     *
     * @param bytes the byte array; must not be null
     * @return this builder instance for method chaining
     * @throws NullPointerException if {@code bytes} is null
     */
    PlainBytesBuilder bytes(byte[] bytes);

    /**
     * Creates a new instance of the default builder implementation.
     *
     * @return a new {@code PlainBytesBuilder}
     */
    static PlainBytesBuilder builder() {
        return new DefaultPlainBytesBuilder();
    }

    /**
     * Default implementation of the {@link PlainBytesBuilder} interface.
     * <p>
     * Builds a {@link PlainBytes} instance wrapping the specified byte array.
     * </p>
     */
    final class DefaultPlainBytesBuilder implements PlainBytesBuilder {
        private byte[] bytesField;

        private DefaultPlainBytesBuilder() {
        }

        @Override
        public PlainBytesBuilder bytes(final byte[] bytes) {
            this.bytesField = Objects.requireNonNull(bytes, "bytes must not be null");
            return this;
        }

        @Override
        public PlainContent build(final boolean encrypt) {
            if (bytesField == null) {
                throw new IllegalStateException("bytes must be set before building");
            }
            return new PlainBytes(bytesField);
        }
    }
}
