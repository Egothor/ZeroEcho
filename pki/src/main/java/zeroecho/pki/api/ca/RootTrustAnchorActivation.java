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

import java.time.Instant;
import java.util.Objects;
import zeroecho.pki.api.PkiId;

/** Immutable successful activation receipt; external distribution is operator-attested, never inferred.
 * @param version record version, one
 * @param transitionId exact candidate transition
 * @param transitionCommitment exact completed transition SHA-256
 * @param expectedHead approved original head fence
 * @param candidateIssuerId selected candidate generation
 * @param candidatePathId selected candidate path
 * @param newEpoch expected epoch plus one
 * @param activationRequestId immutable activation request identity
 * @param actorId authenticated approving/executing actor identity
 * @param approvalPolicyCommitment exact approval policy commitment
 * @param approvedTargetCommitment exact approved activation target commitment
 * @param acceptedAt authoritative accepted time
 * @param distributionAcknowledged explicit external-distribution acknowledgment, required true */
public record RootTrustAnchorActivation(int version, PkiId transitionId, String transitionCommitment,
        CaHeadSnapshot expectedHead, PkiId candidateIssuerId, PkiId candidatePathId, long newEpoch,
        PkiId activationRequestId, String actorId, String approvalPolicyCommitment, String approvedTargetCommitment,
        Instant acceptedAt, boolean distributionAcknowledged) {
    /**
     * Creates a complete acknowledged activation receipt.
     * @param version record version, one
     * @param transitionId exact candidate transition
     * @param transitionCommitment exact completed transition SHA-256
     * @param expectedHead approved original head fence
     * @param candidateIssuerId selected candidate generation
     * @param candidatePathId selected candidate path
     * @param newEpoch expected epoch plus one
     * @param activationRequestId immutable activation request identity
     * @param actorId authenticated approving/executing actor identity
     * @param approvalPolicyCommitment exact approval policy commitment
     * @param approvedTargetCommitment exact approved activation target commitment
     * @param acceptedAt authoritative accepted time
     * @param distributionAcknowledged explicit external-distribution acknowledgment, required true
     * @throws NullPointerException if transitionId, expectedHead, candidateIssuerId, candidatePathId,
     *     activationRequestId, acceptedAt is null
     * @throws IllegalArgumentException if version is not one, distribution is unacknowledged, the new epoch is
     *     not the nonoverflowing successor, actor identity is blank or oversized, or a commitment is invalid
     */
    public RootTrustAnchorActivation {
        Objects.requireNonNull(transitionId, "transitionId"); Objects.requireNonNull(expectedHead, "expectedHead");
        Objects.requireNonNull(candidateIssuerId, "candidateIssuerId"); Objects.requireNonNull(candidatePathId, "candidatePathId");
        Objects.requireNonNull(activationRequestId, "activationRequestId"); Objects.requireNonNull(acceptedAt, "acceptedAt");
        if (version != 1 || !distributionAcknowledged || expectedHead.epoch() == Long.MAX_VALUE || newEpoch != expectedHead.epoch() + 1
                || actorId == null || actorId.isBlank() || actorId.length() > 4096) {
            throw new IllegalArgumentException("Invalid root trust-anchor activation");
        }
        digest(transitionCommitment); digest(approvalPolicyCommitment); digest(approvedTargetCommitment);
    }
    private static void digest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) { throw new IllegalArgumentException("Invalid activation commitment"); }
    }
}
