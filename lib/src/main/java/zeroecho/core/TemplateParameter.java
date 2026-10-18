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
package zeroecho.core;

import java.util.Objects;

/**
 * Describes a single user-supplied parameter accepted by a
 * {@link ParameterSetDescriptor.Template}.
 *
 * <p>
 * Each {@code TemplateParameter} carries presentation metadata and a Java type.
 * Machine-readable domain constraints, required flags and defaults are exposed
 * separately by {@link ParameterSetDescriptor.Template#constraints()}. Descriptions
 * explain purpose; clients must not parse them to discover validation rules.
 * </p>
 *
 * @param name        machine-readable parameter name used as the map key
 *                    (e.g., {@code "keySizeBits"})
 * @param displayName human-readable label for UIs and error messages
 * @param type        the Java type of the parameter value (e.g.,
 *                    {@code Integer.class})
 * @param description brief description of constraints and purpose
 * @since 1.0
 */
public record TemplateParameter(String name, String displayName, Class<?> type, String description) {

    /**
     * Validates the record fields on construction.
     *
     * @throws NullPointerException if any field is {@code null}
     * @throws IllegalArgumentException if the name, label or description is blank
     */
    public TemplateParameter {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(displayName, "displayName must not be null");
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(description, "description must not be null");
        if (name.isBlank() || displayName.isBlank() || description.isBlank()) {
            throw new IllegalArgumentException("Parameter name, label and description must not be blank");
        }
    }
}
