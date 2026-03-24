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
/**
 * Built-in plain content sources: bytes, strings, files, and passwords.
 *
 * <p>
 * This package provides simple {@link zeroecho.sdk.content.api.DataContent}
 * implementations that act as the first stage of a pipeline. They expose bytes
 * via {@link zeroecho.sdk.content.api.DataContent#getStream()} and deliberately
 * reject upstream input because they are sources, not transforms.
 * </p>
 *
 * <h2>Components</h2>
 * <ul>
 * <li>{@link PlainBytes} - wraps an in-memory byte array and exposes it as a
 * read-only stream. The provided array is defensively copied so later caller
 * mutations do not affect the content.</li>
 * <li>{@link PlainString} - wraps a UTF-8 string and exposes it as bytes on
 * demand.</li>
 * <li>{@link PlainFile} - reads content from a {@link java.net.URL} such as
 * {@code file:} or {@code https:}.</li>
 * <li>{@link SecretPassword} - specialization for secret phrases; extends
 * {@link PlainString} and publishes the password into a process context for
 * downstream consumers when constructed.</li>
 * </ul>
 *
 * <h2>Behavior</h2>
 * <ul>
 * <li>These classes start a data pipeline and therefore throw
 * {@link IllegalArgumentException} if
 * {@link zeroecho.sdk.content.api.DataContent#setInput(zeroecho.sdk.content.api.DataContent)}
 * is called with a non-null argument.</li>
 * <li>Callers must close the {@link java.io.InputStream} returned by
 * {@link zeroecho.sdk.content.api.DataContent#getStream()}.</li>
 * <li>{@link PlainBytes} returns a defensive copy from
 * {@link zeroecho.sdk.content.api.DataContent#toBytes()} and
 * {@link PlainString} encodes to UTF-8 when bytes are requested.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Wrap a byte[] as a DataContent source and stream it to an OutputStream.
 * zeroecho.sdk.content.api.DataContent src = new zeroecho.sdk.content.builtin.PlainBytes(data);
 * try (java.io.InputStream in = src.getStream()) {
 *     in.transferTo(out);
 * }
 *
 * // Read from a file URL.
 * java.net.URL url = java.nio.file.Path.of("input.bin").toUri().toURL();
 * zeroecho.sdk.content.api.DataContent fileSrc = new zeroecho.sdk.content.builtin.PlainFile(url);
 * try (java.io.InputStream in = fileSrc.getStream()) {
 *     in.transferTo(out);
 * }
 *
 * // Use a password source (also published to a shared context by the constructor).
 * zeroecho.sdk.content.api.DataContent secret = new zeroecho.sdk.content.builtin.SecretPassword(24);
 * }</pre>
 *
 * @since 1.0
 */
package zeroecho.sdk.content.builtin;
