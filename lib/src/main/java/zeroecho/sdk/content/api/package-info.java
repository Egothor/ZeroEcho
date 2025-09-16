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
/**
 * Content abstractions for streaming data in the SDK.
 *
 * <p>
 * This package defines the common {@link DataContent} contract used by SDK
 * pipelines, plus marker interfaces that classify content as plain or
 * encrypted, and an extended interface for exporting content in alternate
 * formats. Implementations expose data via {@link DataContent#getStream()} and
 * may participate in pipelines by accepting upstream input with
 * {@link DataContent#setInput(DataContent)}.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link DataContent} - base interface representing a unit of content with
 * stream access and convenience helpers for bytes and text.</li>
 * <li>{@link PlainContent} - marker for content representing cleartext or
 * decrypted data.</li>
 * <li>{@link EncryptedContent} - marker for content that is the result of
 * encryption and can be stored or transported in untrusted locations.</li>
 * <li>{@link SecretContent} - specialization of plain content intended to carry
 * secret phrases.</li>
 * <li>{@link ExportableDataContent} - extension that can render content in
 * different export modes via {@link ExportableDataContent.ExportMode} (for
 * example, RAW, BASH_SCRIPT, CMD_SCRIPT). {@link AbstractExportableDataContent}
 * provides a small base with input plumbing and mode management.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <p>
 * Content is consumed as a stream and must be closed by the caller. For small
 * payloads, helpers like {@link DataContent#toBytes()} and
 * {@link DataContent#toText()} can be convenient, but streaming should be
 * preferred for large data.
 * </p>
 * <pre>{@code
 * // Consume a DataContent instance and write it to an OutputStream.
 * zeroecho.sdk.content.api.DataContent content = ...obtained from a builder or pipeline ...;
 * try (java.io.InputStream in = content.getStream()) {
 *     in.transferTo(out);
 * }
 * }</pre>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>Implementations may or may not support
 * {@link DataContent#setInput(DataContent)}; the default method throws
 * {@link UnsupportedOperationException} to signal non-participation in
 * chaining.</li>
 * <li>Exportable content chooses its formatting according to
 * {@link ExportableDataContent#getExportMode()}.</li>
 * <li>Thread-safety is not guaranteed; consult concrete implementations.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.content.api;
