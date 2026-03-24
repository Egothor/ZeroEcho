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

/**
 * An extension of {@link DataContent} that provides export capabilities in
 * different modes.
 * <p>
 * This interface is intended for data sources that support not only raw binary
 * streaming but also platform-specific script export, such as Bash or Windows
 * CMD. The export mode determines how the underlying content is transformed or
 * wrapped.
 *
 * <p>
 * Typical use cases include:
 * <ul>
 * <li>Uploading images or data directly to a remote server (RAW mode)</li>
 * <li>Generating self-contained Bash scripts that embed the encoded data
 * (BASH_SCRIPT mode)</li>
 * <li>Generating CMD scripts for use on Windows systems (CMD_SCRIPT mode)</li>
 * </ul>
 *
 * <p>
 * Implementations are responsible for adapting the content to the selected
 * {@code ExportMode}.
 *
 * @see ExportableDataContent.ExportMode
 * @see DataContent
 */
public interface ExportableDataContent extends DataContent {
    /**
     * Enumeration of supported export modes.
     */
    enum ExportMode {
        /**
         * Raw mode returns the content as a direct InputStream, without any
         * transformation or encoding.
         */
        RAW,
        /**
         * Bash script mode returns a shell script with embedded Base64-encoded content,
         * suitable for execution on Unix-like systems.
         */
        BASH_SCRIPT,
        /**
         * CMD script mode returns a Windows batch file containing encoded content that
         * can be decoded and used locally.
         */
        CMD_SCRIPT
    }

    /**
     * Returns the current export mode.
     *
     * @return the export mode that determines how the content will be formatted or
     *         transformed
     */
    ExportMode getExportMode();

    /**
     * Sets the desired export mode.
     *
     * @param mode the export mode to use; must not be {@code null}
     * @throws NullPointerException if the mode is {@code null}
     */
    void setExportMode(ExportMode mode);
}
