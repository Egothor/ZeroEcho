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

import java.util.Objects;
import java.util.Set;

import zeroecho.pki.api.PkiId;

/**
 * Immutable process policy controlling which logical authorities one realm
 * context may expose.
 *
 * @param mode exposure mode
 * @param authorityIds exact exposed authorities for explicit mode
 * @param authorityCreationPermitted whether realm-scoped authority creation is permitted
 */
public record AuthorityExposurePolicy(Mode mode, Set<PkiId> authorityIds,
        boolean authorityCreationPermitted) {
    /** Closed authority-exposure modes. */
    public enum Mode {
        /** Every authority in the realm session is eligible for scoped exposure. */
        ALL_REALM_AUTHORITIES(1),
        /** Only the exact configured authority identities are eligible. */
        EXPLICIT_AUTHORITIES(2);

        private final int code;

        Mode(int code) {
            this.code = code;
        }

        /**
         * Returns the stable persistence code.
         *
         * @return encoded exposure-mode code
         */
        public int code() {
            return code;
        }

        /**
         * Resolves one stable persistence code.
         *
         * @param code encoded exposure-mode code
         * @return corresponding exposure mode
         * @throws IllegalArgumentException if {@code code} is unknown
         */
        public static Mode fromCode(int code) {
            return switch (code) {
                case 1 -> ALL_REALM_AUTHORITIES;
                case 2 -> EXPLICIT_AUTHORITIES;
                default -> throw new IllegalArgumentException("Unknown authority exposure code");
            };
        }
    }

    /** Validates and defensively snapshots the exposure policy. */
    public AuthorityExposurePolicy {
        Objects.requireNonNull(mode, "mode");
        authorityIds = Set.copyOf(Objects.requireNonNull(authorityIds, "authorityIds"));
        if (mode == Mode.ALL_REALM_AUTHORITIES && !authorityIds.isEmpty()) {
            throw new IllegalArgumentException("All-authority mode cannot carry an explicit set");
        }
        if (mode == Mode.EXPLICIT_AUTHORITIES && authorityIds.isEmpty()) {
            throw new IllegalArgumentException("Explicit authority mode requires at least one authority");
        }
    }

    /**
     * Tests process exposure for one canonical authority.
     *
     * @param authorityId authority to test
     * @return whether the process may expose it
     */
    public boolean allows(PkiId authorityId) {
        Objects.requireNonNull(authorityId, "authorityId");
        return mode == Mode.ALL_REALM_AUTHORITIES || authorityIds.contains(authorityId);
    }
}
