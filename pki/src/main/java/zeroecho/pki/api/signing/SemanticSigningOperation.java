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

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;

/**
 * Immutable authoritative semantic observation. The outer state is read before
 * the signature state, so a concurrently advancing signature can appear with an
 * older pending outer state. Only {@link SemanticSigningState#COMPLETED} exposes
 * a domain result; raw signature bytes are never exposed here.
 *
 * @param submissionId retained operation identity
 * @param scope persisted coordinates requiring caller authorization
 * @param signingState current signature lifecycle, without internal RETIRED
 * @param state outer domain lifecycle
 * @param signingRevision observed signature revision
 * @param revision observed outer revision
 * @param createdAt authoritative creation time
 * @param deadline authoritative signing deadline
 * @param detailCode optional safe outer terminal detail
 * @param result completed domain result, never a raw signature
 */
public record SemanticSigningOperation(SigningSubmissionId submissionId,
        SemanticSigningScope scope, SigningOperationState signingState,
        SemanticSigningState state, long signingRevision, long revision,
        Instant createdAt, Instant deadline, Optional<String> detailCode,
        Optional<EncodedObject> result) {
    /** Validates and defensively snapshots the observed domain result. */
    public SemanticSigningOperation {
        Objects.requireNonNull(submissionId, "submissionId");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(signingState, "signingState");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(deadline, "deadline");
        detailCode = Objects.requireNonNull(detailCode, "detailCode");
        result = Objects.requireNonNull(result, "result")
                .map(value -> new EncodedObject(value.encoding(), value.bytes()));
        if (signingRevision < 0 || revision < 0 || deadline.isBefore(createdAt)
                || state == SemanticSigningState.COMPLETED != result.isPresent()
                || detailCode.filter(String::isBlank).isPresent()) {
            throw new IllegalArgumentException("Semantic signing observation is inconsistent");
        }
    }

    /**
     * Derives the publisher's exact credential identity from a completed CA or issuance DER result.
     * No certificate parsing, repository lookup or authorization is performed. Other
     * kinds, pending/failed operations and non-DER results return empty. Hashing takes
     * O(D) time and O(D) transient memory for the existing defensive DER snapshot;
     * no identity or payload is cached in this observation.
     * @return the exact {@code x509:} SHA-256 identity, when applicable
     */
    public Optional<PkiId> completedCredentialId() {
        if ((scope.kind() != SemanticSigningKind.CA && scope.kind() != SemanticSigningKind.ISSUANCE)
                || state != SemanticSigningState.COMPLETED
                || result.isEmpty() || result.orElseThrow().encoding() != Encoding.DER) {
            return Optional.empty();
        }
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(result.orElseThrow().bytes());
            return Optional.of(new PkiId("x509:" + java.util.HexFormat.of().formatHex(digest)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    /** Returns a representation that omits privileged operation data. */
    @Override public String toString() { return "SemanticSigningOperation[redacted]"; }
}
