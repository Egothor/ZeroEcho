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

/** Safe closed mutual-TLS authentication result. */
public sealed interface PkiServerAuthenticationResult permits PkiServerAuthenticationResult.Authenticated,
        PkiServerAuthenticationResult.Rejected {
    /** Successfully resolved persisted principal identity. */
    record Authenticated(String principalId) implements PkiServerAuthenticationResult {
        /** Validates the finite principal identity. */
        public Authenticated {
            if (principalId == null || !principalId.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) {
                throw new IllegalArgumentException("Principal identity is invalid");
            }
        }
    }

    /** Authentication rejection containing only a stable safe code. */
    record Rejected(Code code) implements PkiServerAuthenticationResult {
        /** Validates the rejection. */ public Rejected { Objects.requireNonNull(code, "code"); }
    }

    /** Safe non-disclosing rejection codes. */
    enum Code {
        CERTIFICATE_INVALID, MAPPING_UNAVAILABLE, MAPPING_AMBIGUOUS, PRINCIPAL_DISABLED, INTERNAL_FAILURE
    }

    /** @return principal identity when authentication succeeded */
    default Optional<String> resolvedPrincipalId() {
        return this instanceof Authenticated authenticated
                ? Optional.of(authenticated.principalId()) : Optional.empty();
    }
}
