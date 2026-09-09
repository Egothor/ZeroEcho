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

import java.util.Objects;

/**
 * An abstract base class for exportable data content, providing default
 * implementations for managing input data and export mode.
 *
 * <p>
 * This class is intended to be extended by concrete implementations that
 * generate various forms of export output, such as raw binary streams, shell
 * scripts, or platform-specific wrappers.
 * </p>
 *
 * <p>
 * It manages:
 * <ul>
 * <li>The {@link DataContent} input that is to be exported</li>
 * <li>The {@link ExportMode} that controls how the export is formatted</li>
 * </ul>
 *
 * <p>
 * Implementing classes must override {@link ExportableDataContent#getStream()}
 * to provide the actual export logic based on the configured mode.
 * </p>
 */
public abstract class AbstractExportableDataContent implements ExportableDataContent {
    /**
     * The export mode (RAW, BASH_SCRIPT, CMD_SCRIPT, etc.). Defaults to RAW.
     */
    protected ExportMode mode = ExportMode.RAW;
    /**
     * The input data to be exported. Must be non-null before use.
     */
    protected DataContent input;

    /**
     * Creates an exporter with {@link ExportMode#RAW} selected and no input.
     */
    public AbstractExportableDataContent() {
        // Field initializers establish the initial state.
    }

    /**
     * Sets the input {@link DataContent} for export.
     *
     * @param input the input data to be exported
     * @throws NullPointerException if {@code input} is {@code null}
     */
    @Override
    public void setInput(DataContent input) {
        this.input = Objects.requireNonNull(input, "Input content cannot be null.");
    }

    /**
     * Returns the currently selected export mode.
     *
     * @return the {@link ExportMode} in use
     */
    @Override
    public ExportMode getExportMode() {
        return mode;
    }

    /**
     * Sets the export mode to control how the data is output.
     *
     * @param mode the desired {@link ExportMode}
     */
    @Override
    public void setExportMode(ExportMode mode) {
        this.mode = mode;
    }
}
