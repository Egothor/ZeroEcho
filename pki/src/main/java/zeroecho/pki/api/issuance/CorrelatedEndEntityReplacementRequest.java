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

package zeroecho.pki.api.issuance;

import java.util.Objects;
import zeroecho.pki.api.PkiId;

/**
 * Immutable correlated replacement input. The exact predecessor digest, typed
 * original request and frozen profile, issuer and path bind one durable operation.
 * Construction grants no authority and does not validate proof or current status.
 *
 * @param issuerCaId expected logical issuing authority
 * @param request predecessor and exact replacement request
 * @param predecessorSha256 canonical lowercase SHA-256 of predecessor DER
 * @param intent frozen orchestration identity and selection
 */
public record CorrelatedEndEntityReplacementRequest(PkiId issuerCaId, EndEntityReplacementRequest request,
        String predecessorSha256, IssuanceIntent intent) {
    /**
     * Validates bounded coordinates without accessing persistent state.
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if a digest or coordinate is invalid
     */
    public CorrelatedEndEntityReplacementRequest {
        Objects.requireNonNull(issuerCaId, "issuerCaId");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(intent, "intent");
        Objects.requireNonNull(predecessorSha256, "predecessorSha256");
        if (!predecessorSha256.matches("[0-9a-f]{64}")
                || !request.profileId().equals(intent.expectedProfile().profileId())) {
            throw new IllegalArgumentException("Replacement binding is invalid");
        }
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(issuerCaId.value());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(request.existingCredentialId().value());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(intent.expectedProfile().profileId());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(intent.expectedIssuerId().value());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(intent.expectedChainPathId().value());
    }

    /** @return a redacted diagnostic description */
    @Override public String toString() { return "CorrelatedEndEntityReplacementRequest[redacted]"; }
}

