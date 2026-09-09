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
package zeroecho.pki.spi.confirmation;

import java.security.PublicKey;
import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;

/**
 * Request-local authoritative credential input for key-possession proof validation.
 *
 * <p>The PKI orchestration layer constructs this value only after resolving and
 * strictly parsing the authoritative certificate on each request. Facade callers
 * cannot supply the key. The referenced JCA key is request-local trusted input rather than a
 * promise that every arbitrary {@link PublicKey} implementation is formally
 * immutable. Providers must not retain the value or its key after a call.</p>
 *
 * <p>This value carries no encoded certificate, store access, mutation authority,
 * requester, owner, actor, response, or verification result.</p>
 *
 * @param proofSuiteBinding exact configured proof-suite binding
 * @param credentialId exact authoritative credential identity
 * @param publicKey request-local public key extracted by PKI orchestration
 */
public record KeyPossessionProofCredential(ConfirmationProofSuiteBinding proofSuiteBinding,
        PkiId credentialId, PublicKey publicKey) {

    /**
     * Validates the exact binding, credential identity, and extracted key reference.
     *
     * @throws NullPointerException if a reference component is {@code null}
     * @throws IllegalArgumentException if {@code credentialId} is not canonical
     */
    public KeyPossessionProofCredential {
        Objects.requireNonNull(proofSuiteBinding, "proofSuiteBinding");
        credentialId = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
        Objects.requireNonNull(publicKey, "publicKey");
    }

    /** Returns a structural description without public-key encoding or implementation details. */
    @Override
    public String toString() {
        return "KeyPossessionProofCredential[proofSuiteBinding=" + proofSuiteBinding
                + ", credentialId=" + credentialId + ", publicKey=<redacted>]";
    }
}
