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
package zeroecho.pki.api.ca;

import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.KeyRef;

/**
 * Explicit outgoing CA role changes, independent of the parent signing roles.
 * Missing roles or members retain their exact immutable issuer binding values.
 * This immutable value neither generates keys nor authorizes their use.
 * @param version selector version, exactly one
 * @param primary optional primary role changes
 * @param alternative optional alternative role changes; cannot add a missing role
 */
public record CaRotationSelection(int version, Optional<RoleChange> primary,
        Optional<RoleChange> alternative) {
    /** Rejects empty or unsupported selectors; all optional containers are required. */
    public CaRotationSelection {
        Objects.requireNonNull(primary, "primary");
        Objects.requireNonNull(alternative, "alternative");
        if (version != 1 || primary.isEmpty() && alternative.isEmpty()) {
            throw new IllegalArgumentException("An explicit CA rotation role is required");
        }
    }

    /**
     * Constructs the existing primary-key-only request without changing its algorithm.
     * @param key explicit managed replacement key
     * @return version-one primary selection
     */
    public static CaRotationSelection primaryKey(KeyRef key) {
        return new CaRotationSelection(1, Optional.of(new RoleChange(Optional.of(key), Optional.empty())), Optional.empty());
    }

    /**
     * Freezes all outgoing role members from one retained generation.
     * Algorithm/provider compatibility must subsequently be checked by the domain.
     * @param retained exact selected immutable issuer binding
     * @return complete primary and, when present, alternative selection
     * @throws IllegalArgumentException if an alternative change targets a single-key issuer
     */
    public CaRotationSelection effective(IssuerCryptographicBinding retained) {
        Objects.requireNonNull(retained, "retained");
        if (alternative.isPresent() && retained.alternative().isEmpty()) {
            throw new IllegalArgumentException("Rotation cannot add an alternative role");
        }
        return new CaRotationSelection(1, Optional.of(complete(primary, retained.primary())),
                retained.alternative().map(value -> complete(alternative, value)));
    }

    private static RoleChange complete(Optional<RoleChange> change, IssuerKeyBinding retained) {
        return new RoleChange(Optional.of(change.flatMap(RoleChange::keyRef).orElse(retained.keyRef())),
                Optional.of(change.flatMap(RoleChange::signatureAlgorithmId)
                        .orElse(retained.signatureAlgorithm().canonicalForm())));
    }

    /**
     * One explicit role override. Missing members retain their authoritative values.
     * @param keyRef optional managed key reference; never a private-key payload
     * @param signatureAlgorithmId optional exact canonical signature identity
     */
    public record RoleChange(Optional<KeyRef> keyRef, Optional<String> signatureAlgorithmId) {
        /** Rejects an empty override or unbounded/non-exact algorithm text. */
        public RoleChange {
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(signatureAlgorithmId, "signatureAlgorithmId");
            if (keyRef.isEmpty() && signatureAlgorithmId.isEmpty()) {
                throw new IllegalArgumentException("An explicit role member is required");
            }
            keyRef.ifPresent(CaCommandInputs::key);
            signatureAlgorithmId.ifPresent(value -> {
                if (value.isBlank() || value.length() > 8192 || value.indexOf('\0') >= 0
                        || !value.equals(value.strip())) {
                    throw new IllegalArgumentException("Invalid exact signature identity");
                }
            });
        }
    }
}
