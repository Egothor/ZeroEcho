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
package zeroecho.sdk.builders.core;

import zeroecho.sdk.content.api.DataContent;

/**
 * A builder interface for constructing instances of {@link DataContent}.
 * <p>
 * This interface enables a uniform and extensible way to create various
 * {@code DataContent} implementations in a fluent, builder-based style. It is
 * intended to be used with builder classes that encapsulate construction
 * parameters and logic specific to each {@code DataContent} subtype.
 * <p>
 * The {@link #build(boolean)} method configures the resulting
 * {@code DataContent} instance for either encryption or decryption mode. When
 * encryption is selected, additional metadata (such as headers) may be added to
 * the output stream; this metadata must be preserved and reused during
 * decryption.
 * <p>
 * Typical usage example:
 * 
 * <pre>{@code
 * DataContent content = SomeDataContentBuilder.builder()
 *     .parameterX(...)
 *     .parameterY(...)
 *     .build(true); // true for encryption mode
 * }</pre>
 *
 * @param <T> the type of {@link DataContent} produced by this builder
 * 
 * @author Leo Galambos
 */
@FunctionalInterface
public interface DataContentBuilder<T extends DataContent> {
    /**
     * Constructs and returns a new {@link DataContent} instance based on the
     * builder's current configuration.
     *
     * @param encrypt whether the resulting {@code DataContent} should be configured
     *                for encryption ({@code true}) or decryption ({@code false}).
     *                In encryption mode, additional headers or metadata may be
     *                inserted into the stream which must be retained for successful
     *                decryption.
     * @return the constructed {@code DataContent} instance
     */
    T build(boolean encrypt);
}
