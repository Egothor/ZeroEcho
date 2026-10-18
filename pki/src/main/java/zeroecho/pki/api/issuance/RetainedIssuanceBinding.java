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
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Immutable CSR-free coordinates for exact lookup of retained issuance semantics.
 * This value carries no authorization, credential, runtime state or operation handle.
 * Callers must authenticate and authorize lookup and the returned persisted scope.
 * Construction validates bounded identifiers and commitments without consulting a store.
 *
 * @param authorityId exact issuing authority
 * @param issuanceId stable external issuance identity
 * @param expectedProfile frozen profile identity, version and digest
 * @param expectedIssuerId frozen issuer generation
 * @param expectedChainPathId frozen issuance chain path
 * @param expectedChainPathCommitment lowercase SHA-256 chain-path commitment
 * @param effectiveCommitment lowercase SHA-256 effective issuance commitment, including CSR and validity
 */
public record RetainedIssuanceBinding(PkiId authorityId, String issuanceId, CertificateProfileRef expectedProfile,
        PkiId expectedIssuerId, PkiId expectedChainPathId, String expectedChainPathCommitment,
        String effectiveCommitment) {
    /**
     * Validates the same frozen coordinate bounds as correlated issuance requests.
     * Identifier validation takes linear time and constant auxiliary memory.
     * @throws NullPointerException if a required identifier or profile is null
     * @throws IllegalArgumentException if an identity or digest is invalid, or an identifier
     *         exceeds 4,096 UTF-8 bytes or contains an unpaired surrogate
     */
    public RetainedIssuanceBinding {
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(expectedProfile, "expectedProfile");
        Objects.requireNonNull(expectedIssuerId, "expectedIssuerId");
        Objects.requireNonNull(expectedChainPathId, "expectedChainPathId");
        IssuanceIntent.requireIssuanceId(issuanceId);
        IssuanceIntent.requireDigest(expectedChainPathCommitment);
        IssuanceIntent.requireDigest(effectiveCommitment);
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(authorityId.value());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(expectedProfile.profileId());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(expectedIssuerId.value());
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(expectedChainPathId.value());
    }

    /** Returns a representation without privileged correlation or issuance coordinates. */
    @Override public String toString() { return "RetainedIssuanceBinding[redacted]"; }
}
