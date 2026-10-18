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
import zeroecho.pki.api.orch.SigningSubmissionId;

/**
 * Immutable authoritative signing-operation snapshot.
 *
 * @param submissionId durable operation identity
 * @param state projected lifecycle state; internal RETIRED never leaks
 * @param revision monotonic durable revision
 * @param createdAt store-bound creation time
 * @param deadline authoritative deadline
 * @param providerUpdatedAt optional trusted provider observation time
 * @param detailCode optional finite non-sensitive detail
 * @param signature BINARY signature only for successful state
 */
public record SigningOperation(SigningSubmissionId submissionId,
        SigningOperationState state, long revision, Instant createdAt,
        Instant deadline, Optional<Instant> providerUpdatedAt,
        Optional<String> detailCode, Optional<EncodedObject> signature) {
    /** Validates and snapshots one public operation. */
    public SigningOperation {
        Objects.requireNonNull(submissionId, "submissionId");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(deadline, "deadline");
        providerUpdatedAt = Objects.requireNonNull(providerUpdatedAt, "providerUpdatedAt");
        detailCode = Objects.requireNonNull(detailCode, "detailCode");
        signature = Objects.requireNonNull(signature, "signature").map(value ->
                new EncodedObject(value.encoding(), value.bytes()));
        if (revision < 0L || deadline.isBefore(createdAt)
                || state == SigningOperationState.SUCCEEDED != signature.isPresent()
                || signature.filter(value -> value.encoding() != Encoding.BINARY).isPresent()
                || detailCode.filter(String::isBlank).isPresent()) {
            throw new IllegalArgumentException("Signing operation snapshot is inconsistent");
        }
    }

    /** Returns a deliberately redacted representation. */
    @Override public String toString() { return "SigningOperation[redacted]"; }
}
