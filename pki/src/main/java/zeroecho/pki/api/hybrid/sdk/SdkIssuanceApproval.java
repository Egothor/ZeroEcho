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
package zeroecho.pki.api.hybrid.sdk;

import java.time.Instant;
import java.util.Objects;

/**
 * Retained SDK approval input. Domain preparation independently verifies both
 * proofs at durable acceptance time and revalidates the frozen policy coordinates.
 * @param preview frozen effective public issuance coordinates
 * @param primaryFrame exact accepted F1 frame, whose target hash binds preview
 * @param targetFrame exact retained F7 target bound by the subject proofs
 * @param primaryProof accepted primary subject proof, defensively copied
 * @param alternativeProof accepted alternative subject proof, defensively copied
 * @param expectedF3 exact retained SHA-512 proof commitment
 * @param proofAcceptedAt trusted durable proof acceptance instant
 */
public record SdkIssuanceApproval(SdkIssuancePreview preview, HybridSdkFrame primaryFrame, HybridSdkFrame targetFrame,
        byte[] primaryProof, byte[] alternativeProof, String expectedF3, Instant proofAcceptedAt) {
    /** Snapshots proof bytes without establishing their validity or authorizing issuance. */
    public SdkIssuanceApproval {
        Objects.requireNonNull(preview); Objects.requireNonNull(primaryFrame); Objects.requireNonNull(targetFrame);
        Objects.requireNonNull(primaryProof); Objects.requireNonNull(alternativeProof);
        if (primaryFrame.kind() != 1 || targetFrame.kind() != 7 || primaryProof.length < 1 || primaryProof.length > 104
                || alternativeProof.length != 4627 || expectedF3 == null || !expectedF3.matches("sha512:[0-9a-f]{128}")) {
            throw new IllegalArgumentException("Invalid retained SDK proof coordinates");
        }
        primaryProof = primaryProof.clone(); alternativeProof = alternativeProof.clone();
        Objects.requireNonNull(proofAcceptedAt);
    }
    /** @return independent copy of the accepted primary signature */
    @Override public byte[] primaryProof() { return primaryProof.clone(); }
    /** @return independent copy of the accepted alternative signature */
    @Override public byte[] alternativeProof() { return alternativeProof.clone(); }
}
