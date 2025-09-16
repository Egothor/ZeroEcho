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

import zeroecho.sdk.content.builtin.PlainString;

/**
 * Builder interface for constructing {@link PlainString} instances, which
 * represent unencrypted textual content.
 * <p>
 * This builder supports specifying a string value to be encapsulated and
 * optionally used in cryptographic processing pipelines, although the value
 * itself remains unencrypted.
 * <p>
 * The {@link #build(boolean)} method accepts an {@code encrypt} flag to comply
 * with the {@link DataContentBuilder} interface. However, this flag is ignored
 * because {@code PlainString} represents unencrypted data.
 * <p>
 * Usage example:
 * 
 * <pre>{@code
 * PlainString plainText = PlainStringBuilder.builder()
 *     .value("Hello, World!")
 *     .build(true); // encrypt flag is ignored for PlainString
 * }</pre>
 */
public interface PlainStringBuilder extends DataContentBuilder<PlainString> {

    /**
     * Creates a new instance of the default builder implementation.
     *
     * @return a new {@code PlainStringBuilder}
     */
    static PlainStringBuilder builder() {
        return new DefaultPlainStringBuilder();
    }

    /**
     * Sets the string value that the {@link PlainString} instance will contain.
     *
     * @param value the string value; may be {@code null} or empty depending on
     *              usage
     * @return this builder instance
     */
    PlainStringBuilder value(String value);

    /**
     * Default implementation of the {@link PlainStringBuilder} interface.
     * <p>
     * Builds a {@link PlainString} instance using the specified string value.
     */
    final class DefaultPlainStringBuilder implements PlainStringBuilder {
        private String valueField;

        private DefaultPlainStringBuilder() {
        }

        @Override
        public PlainStringBuilder value(final String value) {
            this.valueField = value;
            return this;
        }

        @Override
        public PlainString build(final boolean encrypt) {
            return new PlainString(valueField);
        }
    }
}
