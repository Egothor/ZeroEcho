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
 * Export helpers and platform deployers for SDK content.
 *
 * <p>
 * This package provides streaming utilities and exportable content
 * implementations that render {@link zeroecho.sdk.content.api.DataContent} for
 * deployment to external platforms or for script-based transport. Exports can
 * be produced as raw bytes or as platform-specific scripts according to
 * {@link zeroecho.sdk.content.api.ExportableDataContent.ExportMode}.
 * </p>
 *
 * <h2>Scope</h2>
 * <ul>
 * <li>Streaming utilities that reformat content for export-friendly forms (for
 * example, Base64 with line control).</li>
 * <li>Exportable content that uploads directly to a remote service or generates
 * scripts for deferred execution.</li>
 * <li>Foundations for additional deployers, including steganographic carriers
 * and other public platforms beyond Piwigo.</li>
 * </ul>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link Base64Stream} - an {@link java.io.InputStream} that encodes a
 * binary stream to Base64 with optional per-line prefix/suffix and configurable
 * line length (useful for script emitters).</li>
 * <li><i>Piwigo uploader</i> - an exportable content implementation
 * (package-private) that can either upload an image directly to a Piwigo server
 * or generate Bash/CMD scripts that reconstruct and upload the image. It is
 * built on {@link zeroecho.sdk.content.api.AbstractExportableDataContent} and
 * honors
 * {@link zeroecho.sdk.content.api.ExportableDataContent.ExportMode}.</li>
 * </ul>
 *
 * <h2>Typical usage</h2>
 * <h3>Format a stream as Base64 command lines</h3> <pre>{@code
 * java.io.InputStream source = ... raw bytes ...;
 * java.io.InputStream encoded = new zeroecho.sdk.content.export.Base64Stream(
 *     source,
 *     "echo ".getBytes(java.nio.charset.StandardCharsets.UTF_8),
 *     76,
 *     "\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)
 * );
 * encoded.transferTo(System.out);
 * }</pre>
 *
 * <h3>Render an exportable content in a chosen mode</h3> <pre>{@code
 * zeroecho.sdk.content.api.ExportableDataContent content = ... some exportable content ...;
 * content.setExportMode(zeroecho.sdk.content.api.ExportableDataContent.ExportMode.BASH_SCRIPT);
 * try (java.io.InputStream script = content.getStream()) {
 *     script.transferTo(out);
 * }
 * }</pre>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>Prefer exporting {@link zeroecho.sdk.content.api.EncryptedContent} when
 * targeting untrusted destinations.</li>
 * <li>Avoid embedding secrets in scripts; pass credentials via environment
 * variables or secure stores when possible.</li>
 * <li>When adding steganographic exporters, document cover formats and
 * concealment limits clearly.</li>
 * </ul>
 *
 * <h2>Extensibility</h2>
 * <ul>
 * <li>New deployers should extend
 * {@link zeroecho.sdk.content.api.AbstractExportableDataContent} and select a
 * default {@link zeroecho.sdk.content.api.ExportableDataContent.ExportMode}
 * appropriate for the platform.</li>
 * <li>Utilities like {@link Base64Stream} can be reused to generate
 * platform-friendly payloads without buffering whole files.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.content.export;
