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
package zeroecho.pki.server.schema;

import java.util.List;

/** Immutable model for machine-readable operation parameter schemas. */
public final class OperationParameterSchema { // NOPMD MissingStaticMethodInNonInstantiatableClass - Namespace for public schema records; instances have no meaning.

    /** Wire types matching the codec's strict intake methods. */
    public enum FieldType {
        /** Plain string value. */ TEXT,
        /** Signed 64-bit integer. */ INTEGER,
        /** Boolean true/false. */ BOOLEAN,
        /** Set of plain strings. */ TEXT_SET,
        /** Single enum constant from a closed set. */ ENUM,
        /** Set of enum constants from a closed set. */ ENUM_SET,
        /** Base64-encoded binary. */ BASE64,
        /** Nested JSON object validated by the typed operation decoder. */ OBJECT
    }

    /**
     * Specification for one operation argument field.
     * @param name argument name
     * @param type JSON wire type
     * @param required whether omission is rejected
     * @param choices permitted enum constants, empty for other types
     */
    public record FieldSpec(String name, FieldType type, boolean required, List<String> choices) {
        /** Snapshots the choice list. */
        public FieldSpec {
            choices = List.copyOf(choices);
        }

        /** Defines a string argument.
         * @param name argument name
         * @param required whether omission is rejected
         * @return immutable string field
         */
        public static FieldSpec text(String name, boolean required) {
            return new FieldSpec(name, FieldType.TEXT, required, List.of());
        }

        /** Defines an integer argument; decoder-specific bounds still apply.
         * @param name argument name
         * @param required whether omission is rejected
         * @return immutable integer field
         */
        public static FieldSpec integer(String name, boolean required) {
            return new FieldSpec(name, FieldType.INTEGER, required, List.of());
        }

        /** Defines a boolean argument.
         * @param name argument name
         * @param required whether omission is rejected
         * @return immutable boolean field
         */
        public static FieldSpec bool(String name, boolean required) {
            return new FieldSpec(name, FieldType.BOOLEAN, required, List.of());
        }

        /** Defines a set of strings encoded as a JSON array.
         * @param name argument name
         * @param required whether omission is rejected
         * @return immutable string-set field
         */
        public static FieldSpec textSet(String name, boolean required) {
            return new FieldSpec(name, FieldType.TEXT_SET, required, List.of());
        }

        /** Defines standard Base64 binary data encoded as a JSON string.
         * @param name argument name
         * @param required whether omission is rejected
         * @return immutable binary field
         */
        public static FieldSpec base64(String name, boolean required) {
            return new FieldSpec(name, FieldType.BASE64, required, List.of());
        }

        /** Defines a nested JSON argument.
         * @param name argument name
         * @param required whether omission is rejected
         * @return immutable field definition
         */
        public static FieldSpec object(String name, boolean required) {
            return new FieldSpec(name, FieldType.OBJECT, required, List.of());
        }

        /** Defines one enum constant encoded as a JSON string.
         * @param name argument name
         * @param required whether omission is rejected
         * @param choices permitted constants
         * @return immutable enum field
         */
        public static FieldSpec enum_(String name, boolean required, List<String> choices) {
            return new FieldSpec(name, FieldType.ENUM, required, choices);
        }

        /** Defines enum constants encoded as a JSON array.
         * @param name argument name
         * @param required whether omission is rejected
         * @param choices permitted constants
         * @return immutable enum-set field
         */
        public static FieldSpec enumSet(String name, boolean required, List<String> choices) {
            return new FieldSpec(name, FieldType.ENUM_SET, required, choices);
        }
    }

    /**
     * Specification for one operation: identity, required permission, and fields.
     * @param operationId canonical operation identity
     * @param permissionAction permission action constant
     * @param permissionResourceType permission resource-type constant
     * @param fields ordered argument definitions
     */
    public record OperationSpec(String operationId, String permissionAction, String permissionResourceType,
            List<FieldSpec> fields) {
        /** Snapshots the field list. */
        public OperationSpec {
            fields = List.copyOf(fields);
        }
    }

    private OperationParameterSchema() {
    }
}
