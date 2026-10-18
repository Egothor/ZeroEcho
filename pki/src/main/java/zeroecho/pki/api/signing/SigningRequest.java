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

package zeroecho.pki.api.signing;

import java.util.Objects;

import zeroecho.core.spec.AlgorithmIdentity;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.orch.SigningSubmissionId;

/**
 * Immutable privileged input for one sign-only operation.
 *
 * @param submissionId caller-reserved operation identity
 * @param accessContext trusted authorization and audit context
 * @param keyRef authorized provider key reference
 * @param fairnessAuthorityId durable scheduling authority identity
 * @param signatureAlgorithm exact signature identity; the service enforces its security floor and provider support before staging
 * @param candidateEncoding encoding of staged candidate bytes
 * @param signatureEncoding requested signature encoding; currently BINARY
 */
public record SigningRequest(SigningSubmissionId submissionId,
        AccessContext accessContext, KeyRef keyRef, PkiId fairnessAuthorityId,
        AlgorithmIdentity signatureAlgorithm, Encoding candidateEncoding, Encoding signatureEncoding) {
    /**
     * Validates required components and the signature identity's semantic kind.
     * Provider support and the PKI security floor are checked by preparation.
     * @throws NullPointerException if a component is null
     * @throws IllegalArgumentException if the identity is not a signature or the signature encoding is not BINARY
     */
    public SigningRequest {
        Objects.requireNonNull(submissionId, "submissionId");
        Objects.requireNonNull(accessContext, "accessContext");
        Objects.requireNonNull(keyRef, "keyRef");
        Objects.requireNonNull(fairnessAuthorityId, "fairnessAuthorityId");
        Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        if (signatureAlgorithm.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw new IllegalArgumentException("signatureAlgorithm must identify a signature");
        }
        Objects.requireNonNull(candidateEncoding, "candidateEncoding");
        Objects.requireNonNull(signatureEncoding, "signatureEncoding");
        if (signatureEncoding != Encoding.BINARY) {
            throw new IllegalArgumentException("Only BINARY signatures are supported");
        }
    }

    /** Returns a representation that omits privileged request metadata. */
    @Override public String toString() { return "SigningRequest[redacted]"; }
}
