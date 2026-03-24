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
package zeroecho.pki.api.attr;

/**
 * Typed and governed attribute definition used across credential frameworks.
 *
 * <p>
 * The definition includes a stable identifier, type information, documentation
 * metadata, and governance hints. Frameworks map universal attributes into
 * framework-specific fields and extensions.
 * </p>
 *
 * @param id           stable attribute identifier
 * @param displayName  human-readable name
 * @param valueType    logical value type
 * @param multiValued  whether multiple values are allowed
 * @param sensitivity  sensitivity classification
 * @param stability    lifecycle maturity
 * @param accessPolicy governance hints
 * @param meta         structured documentation metadata
 */
public record AttributeDefinition(AttributeId id, String displayName, AttributeValueType valueType, boolean multiValued,
        AttributeSensitivity sensitivity, AttributeStability stability, AttributeAccessPolicy accessPolicy,
        AttributeMeta meta) {

    /**
     * Creates an attribute definition.
     *
     * @throws IllegalArgumentException if inputs are invalid
     */
    public AttributeDefinition {
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        if (displayName == null || displayName.isBlank()) {
            throw new IllegalArgumentException("displayName must not be null/blank");
        }
        if (valueType == null || sensitivity == null || stability == null || accessPolicy == null || meta == null) {
            throw new IllegalArgumentException("non-null fields must not be null");
        }
    }
}
