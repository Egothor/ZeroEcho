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
package zeroecho.sdk.content.api;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Represents a generic unit of data content. This may include plain, secret, or
 * encrypted forms of data.
 */
public interface DataContent { // NOPMD
    /**
     * Default maximum number of bytes that {@link #toBytes()} will read. This
     * prevents accidental memory overload when reading large content into RAM.
     */
    int DEFAULT_MAX_READ_SIZE = 32 * 1024 * 1024; // 32 MB

    /**
     * Returns an {@link InputStream} representing the content's data.
     * <p>
     * The stream may be raw or transformed depending on the content type.
     *
     * @return input stream of the content; never {@code null}
     * @throws IOException if an I/O error occurs opening the stream
     */
    InputStream getStream() throws IOException;

    /**
     * Returns the content's data as a byte array, with a size limit of 16MB by
     * default.
     * <p>
     * This method is intended for small to medium-sized content. If the content
     * exceeds {@link #DEFAULT_MAX_READ_SIZE}, a {@link IllegalStateException} is
     * thrown.
     *
     * @return the content data as {@code byte[]}
     * @throws RuntimeException      if reading from the stream fails
     * @throws IllegalStateException if content exceeds allowed memory limit
     */
    default byte[] toBytes() {
        try (InputStream in = getStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            in.transferTo(out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read content stream", e);
        }
    }

    /**
     * Returns the content's data as a UTF-8 encoded string.
     * <p>
     * The default implementation converts {@code toBytes()} using UTF-8.
     * <strong>Warning:</strong> This method is only safe if the content represents
     * valid UTF-8 text. For arbitrary binary data (e.g., encrypted content), this
     * may produce invalid or garbled output.
     *
     * @return the content data as {@code String}
     * @throws RuntimeException         if reading from the stream fails
     * @throws IllegalArgumentException if the bytes are not valid UTF-8 (optional)
     */
    default String toText() {
        return new String(toBytes(), StandardCharsets.UTF_8);
    }

    /**
     * Connects this content to the output of a previous stage in the pipeline.
     * <p>
     * This method is used to supply the input data that this content will process
     * (e.g., a {@code PlainContent} being encrypted, or an encrypted content being
     * decrypted).
     * </p>
     *
     * @param input the {@code DataContent} instance providing upstream data; may be
     *              {@code null} if this is the start of the pipeline
     * @throws UnsupportedOperationException if not overridden by a subclass
     * @throws IllegalArgumentException      if the input is not allowed by the
     *                                       implementation
     * 
     * @implSpec The default implementation of this method throws
     *           {@link UnsupportedOperationException}. Subclasses that support
     *           chaining must override this method.
     */
    default void setInput(DataContent input) {
        throw new UnsupportedOperationException("This content type does not accept input chaining.");
    }
}
