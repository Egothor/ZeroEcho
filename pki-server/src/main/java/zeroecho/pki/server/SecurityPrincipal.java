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
package zeroecho.pki.server;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Transport-independent authenticated-identity target used by authorization.
 * Authentication credentials and secrets are deliberately excluded.
 *
 * @param principalId canonical stable principal identity
 * @param type closed principal type
 * @param displayName safe administrative display label
 * @param organization optional canonical owner/organization relationship
 * @param attributes finite safe relationship attributes
 * @param enabled whether authorization assignments may be considered
 */
public record SecurityPrincipal(String principalId, Type type, String displayName,
        Optional<String> organization, Map<String, String> attributes, boolean enabled) {
    /** Closed principal types. */
    public enum Type {
        /** Human administrative or requesting identity. */ USER(1),
        /** Non-human authenticated service identity. */ SERVICE(2),
        /** Protocol-specific account identity. */ ACCOUNT(3),
        /** Unauthenticated public identity. */ PUBLIC(4);

        private final int code;

        Type(int code) {
            this.code = code;
        }

        /**
         * Returns the stable persistence code.
         *
         * @return encoded principal-type code
         */
        public int code() {
            return code;
        }

        /**
         * Resolves one stable persistence code.
         *
         * @param code encoded principal-type code
         * @return corresponding principal type
         * @throws IllegalArgumentException if {@code code} is unknown
         */
        public static Type fromCode(int code) {
            return switch (code) {
                case 1 -> USER;
                case 2 -> SERVICE;
                case 3 -> ACCOUNT;
                case 4 -> PUBLIC;
                default -> throw new IllegalArgumentException("Unknown principal type code");
            };
        }
    }

    /** Validates and snapshots finite safe principal metadata. */
    public SecurityPrincipal {
        requireId(principalId);
        Objects.requireNonNull(type, "type");
        if (displayName == null || displayName.isBlank() || displayName.length() > 256) {
            throw new IllegalArgumentException("Principal display name is invalid");
        }
        organization = Objects.requireNonNull(organization, "organization").map(SecurityPrincipal::requireText);
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
        if (attributes.size() > 32 || attributes.entrySet().stream()
                .anyMatch(entry -> entry.getKey().isBlank() || entry.getKey().length() > 64
                        || entry.getValue().isBlank() || entry.getValue().length() > 256)) {
            throw new IllegalArgumentException("Principal attributes are not finite canonical metadata");
        }
        if (type == Type.PUBLIC && (!"public".equals(principalId) || organization.isPresent())) {
            throw new IllegalArgumentException("Public principal identity is fixed and unowned");
        }
    }

    private static void requireId(String value) {
        if (value == null || !value.matches("[a-zA-Z0-9][a-zA-Z0-9._:@-]{0,255}")) {
            throw new IllegalArgumentException("Principal identity is not canonical");
        }
    }

    private static String requireText(String value) {
        if (value == null || value.isBlank() || value.length() > 256) {
            throw new IllegalArgumentException("Principal relationship value is invalid");
        }
        return value;
    }
}
