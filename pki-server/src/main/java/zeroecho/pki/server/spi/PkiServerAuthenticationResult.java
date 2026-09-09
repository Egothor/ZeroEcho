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
package zeroecho.pki.server.spi;

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.server.AdministrativeAuthenticationMode;

/** Safe closed mutual-TLS authentication result. */
public sealed interface PkiServerAuthenticationResult permits PkiServerAuthenticationResult.Authenticated,
        PkiServerAuthenticationResult.Rejected {
    /**
     * Successfully resolved persisted principal identity.
     *
     * @param mode administrative authentication topology
     * @param transportPrincipalId trusted proxy principal in proxy mode
     * @param endClientPrincipalId authenticated end-client principal
     */
    record Authenticated(AdministrativeAuthenticationMode mode, Optional<String> transportPrincipalId,
            String endClientPrincipalId) implements PkiServerAuthenticationResult {
        /** Validates the finite principal identity. */
        public Authenticated {
            Objects.requireNonNull(mode, "mode");
            transportPrincipalId = Objects.requireNonNull(transportPrincipalId, "transportPrincipalId");
            transportPrincipalId.ifPresent(Authenticated::requirePrincipal);
            requirePrincipal(endClientPrincipalId);
            if (mode == AdministrativeAuthenticationMode.DIRECT_MTLS && transportPrincipalId.isPresent()
                    || mode == AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY
                    && transportPrincipalId.isEmpty()) {
                throw new IllegalArgumentException("Authentication principal separation is invalid");
            }
        }

        /**
         * Creates a direct-mTLS result for an existing certificate mapper.
         *
         * @param principalId authenticated end-client principal
         */
        public Authenticated(String principalId) {
            this(AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(), principalId);
        }

        private static void requirePrincipal(String principalId) {
            if (principalId == null || !principalId.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
                throw new IllegalArgumentException("Principal identity is invalid");
            }
        }
    }

    /**
     * Authentication rejection containing only a stable safe code.
     *
     * @param mode administrative authentication topology
     * @param transportPrincipalId trusted proxy principal when resolved
     * @param endClientPrincipalId end-client principal when safely resolved
     * @param code stable non-disclosing rejection code
     */
    record Rejected(AdministrativeAuthenticationMode mode, Optional<String> transportPrincipalId,
            Optional<String> endClientPrincipalId, Code code) implements PkiServerAuthenticationResult {
        /** Validates the rejection. */
        public Rejected {
            Objects.requireNonNull(mode, "mode");
            transportPrincipalId = Objects.requireNonNull(transportPrincipalId, "transportPrincipalId");
            endClientPrincipalId = Objects.requireNonNull(endClientPrincipalId, "endClientPrincipalId");
            transportPrincipalId.ifPresent(Authenticated::requirePrincipal);
            endClientPrincipalId.ifPresent(Authenticated::requirePrincipal);
            Objects.requireNonNull(code, "code");
        }

        /**
         * Creates a direct-mode rejection without resolved identity metadata.
         *
         * @param code stable non-disclosing rejection code
         */
        public Rejected(Code code) {
            this(AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(), Optional.empty(), code);
        }
    }

    /** Safe non-disclosing rejection codes. */
    enum Code {
        /** Presented certificate is invalid. */ CERTIFICATE_INVALID,
        /** No exact principal mapping exists. */ MAPPING_UNAVAILABLE,
        /** More than one principal mapping matches. */ MAPPING_AMBIGUOUS,
        /** Resolved principal is disabled. */ PRINCIPAL_DISABLED,
        /** Forwarded identity is forbidden in the active topology. */ FORWARDED_IDENTITY_FORBIDDEN,
        /** Transport proxy is not trusted. */ PROXY_NOT_TRUSTED,
        /** Proxy may not forward client identities. */ FORWARDING_NOT_AUTHORIZED,
        /** Required forwarded client identity is absent. */ FORWARDED_IDENTITY_MISSING,
        /** Forwarded client identity is malformed or untrusted. */ FORWARDED_IDENTITY_INVALID,
        /** Client certificate trust validation failed. */ CLIENT_TRUST_REJECTED,
        /** Client certificate usage constraints reject authentication. */ CLIENT_USAGE_REJECTED,
        /** Transport and end-client identities collide. */ IDENTITY_COLLISION,
        /** Authentication failed internally without a safe detailed classification. */ INTERNAL_FAILURE
    }

    /**
     * Returns the resolved end-client principal when authentication succeeded.
     *
     * @return principal identity when authenticated, otherwise empty
     */
    default Optional<String> resolvedPrincipalId() {
        return this instanceof Authenticated authenticated
                ? Optional.of(authenticated.endClientPrincipalId()) : Optional.empty();
    }
}
