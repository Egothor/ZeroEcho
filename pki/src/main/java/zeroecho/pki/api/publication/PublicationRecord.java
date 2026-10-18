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
package zeroecho.pki.api.publication;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;

/**
 * Persisted current state of one publication operation.
 *
 * <p>
 * Publication records support operational troubleshooting, auditability, and
 * re-publication workflows.
 * </p>
 *
 * @param publicationId publication id
 * @param sourceType authoritative source-object type
 * @param sourceId authoritative source-object identity
 * @param content exact immutable source content
 * @param target configured destination identity
 * @param status durable lifecycle state
 * @param attemptNumber non-negative monotonic attempt number
 * @param attemptToken stable token for the current attempt, when one exists
 * @param createdAt registration time
 * @param updatedAt last durable state-change time
 * @param failure safe failure classification
 * @param evidence safe outcome-evidence classification
 */
public record PublicationRecord(PkiId publicationId, PublicationSourceType sourceType, PkiId sourceId,
        DurableContentReference content, PublicationTarget target, PublicationStatus status,
        long attemptNumber, Optional<String> attemptToken, Instant createdAt, Instant updatedAt,
        Optional<PublicationFailure> failure, Optional<PublicationEvidence> evidence) {

    /**
     * Creates a publication record.
     *
     * @throws IllegalArgumentException if inputs are invalid
     */
    public PublicationRecord {
        Objects.requireNonNull(publicationId, "publicationId");
        Objects.requireNonNull(sourceType, "sourceType");
        Objects.requireNonNull(sourceId, "sourceId");
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(attemptToken, "attemptToken");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        Objects.requireNonNull(failure, "failure");
        Objects.requireNonNull(evidence, "evidence");
        if (attemptNumber < 0L || updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("Publication revision or time is invalid");
        }
        attemptToken.ifPresent(PublicationRecord::requireAttemptToken);
        validateState(status, attemptNumber, attemptToken, failure, evidence);
    }

    /**
     * Tests whether another record describes the same immutable operation.
     *
     * @param other candidate record
     * @return {@code true} when all immutable fields match exactly
     */
    public boolean hasSameOperation(PublicationRecord other) {
        return other != null && publicationId.equals(other.publicationId)
                && sourceType == other.sourceType && sourceId.equals(other.sourceId)
                && sameContent(content, other.content) && target.equals(other.target)
                && createdAt.equals(other.createdAt);
    }

    private static boolean sameContent(DurableContentReference first, DurableContentReference second) {
        return first.storeId().equals(second.storeId()) && first.contentId().equals(second.contentId())
                && first.encoding() == second.encoding() && first.length() == second.length()
                && first.sha256().equals(second.sha256()) && first.lifecycle() == second.lifecycle();
    }

    private static void requireAttemptToken(String token) {
        if (!token.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Publication attempt token is not canonical");
        }
    }

    private static void validateState(PublicationStatus status, long attemptNumber, Optional<String> token,
            Optional<PublicationFailure> failure, Optional<PublicationEvidence> evidence) {
        boolean hasAttempt = attemptNumber > 0L && token.isPresent();
        switch (status) {
            case PENDING -> requireState(token.isEmpty() && failure.isEmpty() && evidence.isEmpty());
            case DISPATCH_PREPARED -> requireState(hasAttempt && failure.isEmpty() && evidence.isEmpty());
            case SUCCEEDED -> requireState(hasAttempt && failure.isEmpty() && evidence.isPresent());
            case RETRYABLE_FAILURE -> requireState(hasAttempt
                    && failure.filter(value -> value == PublicationFailure.EXTERNAL_RETRYABLE).isPresent()
                    && evidence.isPresent());
            case TERMINAL_FAILURE -> requireState(hasAttempt && failure.isPresent());
            case OUTCOME_UNKNOWN -> requireState(hasAttempt && failure.isPresent() && evidence.isEmpty());
        }
    }

    private static void requireState(boolean valid) {
        if (!valid) {
            throw new IllegalArgumentException("Publication record state is inconsistent");
        }
    }
}
