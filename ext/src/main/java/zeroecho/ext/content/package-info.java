/* *****************************************************************************
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
 * Content abstractions and streaming payloads for the SDK.
 *
 * <p>
 * This package defines the common content model used by the SDK and organizes
 * concrete sources and exporters under dedicated subpackages. Content objects
 * expose streaming access to bytes and can be chained into pipelines produced
 * by builder APIs.
 * </p>
 *
 * <h2>Subpackages</h2>
 * <ul>
 * <li>{@link zeroecho.ext.content.export} - export helpers and platform
 * deployers, such as {@link zeroecho.ext.content.export.Base64Stream} and
 * exportable content that targets external destinations (for example, gallery
 * platforms) or script-based transports.</li>
 * </ul>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Support exportable content that can render itself as raw bytes or
 * platform-specific scripts via
 * {@link zeroecho.sdk.content.api.ExportableDataContent}.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Stream a DataContent instance to an OutputStream.
 * zeroecho.sdk.content.api.DataContent content = ... obtained from a builder chain ...;
 * try (java.io.InputStream in = content.getStream()) {
 *     in.transferTo(out);
 * }
 *
 * // If exportable, render in an alternate mode (for example, a shell script).
 * if (content instanceof zeroecho.sdk.content.api.ExportableDataContent exportable) {
 *     exportable.setExportMode(
 *         zeroecho.sdk.content.api.ExportableDataContent.ExportMode.BASH_SCRIPT);
 *     try (java.io.InputStream script = exportable.getStream()) {
 *         script.transferTo(out);
 *     }
 * }
 * }</pre>
 *
 * <h2>Extensibility</h2>
 * <ul>
 * <li>New exporters should extend
 * {@link zeroecho.sdk.content.api.AbstractExportableDataContent} and honor the
 * selected
 * {@link zeroecho.sdk.content.api.ExportableDataContent.ExportMode}.</li>
 * <li>The export area is intended to host deployers for additional public
 * platforms and, where appropriate, steganographic carriers for concealed
 * delivery of encrypted streams.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.ext.content;
