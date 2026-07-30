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

import java.net.URL;
import java.util.Objects;

import zeroecho.sdk.content.api.PlainContent;
import zeroecho.sdk.content.builtin.PlainFile;

/**
 * Builder interface for constructing {@link PlainContent} instances that
 * represent unencrypted file-based content sourced from a {@link URL}.
 * <p>
 * This builder allows specifying the source URL of a file to be used as plain
 * (non-encrypted) content. It is typically used as input for cryptographic
 * operations or for representing raw file data.
 * <p>
 * The {@link #build(boolean)} method accepts an {@code encrypt} flag to comply
 * with the {@link DataContentBuilder} interface; however, this flag is ignored
 * for plain content types.
 * <p>
 * <strong>Usage example:</strong>
 * 
 * <pre>{@code
 * PlainContent plainFile = PlainFileBuilder.builder()
 *     .url(new URL("file:///path/to/file.txt"))
 *     .build(true); // encrypt flag is ignored for PlainFile
 * }</pre>
 *
 * @see PlainFile
 */
public interface PlainFileBuilder extends DataContentBuilder<PlainContent> {
    /**
     * Sets the URL of the file to be used as the plain content source.
     *
     * @param url the URL of the file; must not be {@code null}
     * @return this builder instance
     */
    PlainFileBuilder url(URL url);

    /**
     * Creates a new instance of the default builder implementation.
     *
     * @return a new {@code PlainFileBuilder}
     */
    static PlainFileBuilder builder() {
        return new DefaultPlainFileBuilder();
    }

    /**
     * Default implementation of the {@link PlainFileBuilder} interface.
     * <p>
     * Builds a {@link PlainFile} instance using the specified URL.
     */
    final class DefaultPlainFileBuilder implements PlainFileBuilder {
        private URL urlField;

        private DefaultPlainFileBuilder() {
        }

        @Override
        public PlainFileBuilder url(final URL url) {
            this.urlField = Objects.requireNonNull(url);
            return this;
        }

        @Override
        public PlainContent build(final boolean encrypt) {
            return new PlainFile(urlField);
        }
    }
}
