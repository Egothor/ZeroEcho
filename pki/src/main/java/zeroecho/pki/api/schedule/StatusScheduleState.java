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
package zeroecho.pki.api.schedule;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.PkiId;

/**
 * Immutable durable scheduling progress, separate from configuration revision.
 * @param configuration latest operator configuration
 * @param nextDue next unclaimed due instant
 * @param workerRevision monotonic progress fence
 * @param execution latest claimed execution, retained until replaced by a later claim
 */
public record StatusScheduleState(StatusSchedule configuration, Instant nextDue,
        long workerRevision, Optional<Execution> execution) {
    /** Validates the progress snapshot. */
    public StatusScheduleState {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(nextDue, "nextDue");
        execution = Objects.requireNonNull(execution, "execution");
        if (configuration.revision() < 1 || workerRevision < 0) { throw new IllegalArgumentException("Invalid schedule revision"); }
    }

    /** Durable execution stages. */
    public enum Phase {
        /** Authorization captured; signing may not yet have been accepted. */ CLAIMED,
        /** Canonical status object and execution result committed atomically. */ EFFECT_COMMITTED,
        /** Next due instant committed; no regeneration is permitted. */ SCHEDULE_ADVANCED,
        /** Accepted execution failed and requires configuration or operator intervention. */ FAILED
    }

    /**
     * Immutable claim and its current durable outcome.
     * @param executionId deterministic identity of the scheduled occurrence
     * @param configuration configuration captured when claimed
     * @param due claimed due instant
     * @param fence worker revision which authorized this claim
     * @param phase durable phase
     * @param signingOperationId accepted signing identity, absent before acceptance
     * @param acceptanceCommitment exact acceptance commitment, empty before acceptance
     * @param statusObjectId committed canonical effect identity
     * @param detailCode stable failure code, empty except on failure
     */
    public record Execution(String executionId, StatusSchedule configuration, Instant due, long fence,
            Phase phase, Optional<PkiId> signingOperationId, String acceptanceCommitment,
            Optional<PkiId> statusObjectId, String detailCode) {
        /** Validates finite identity and stage invariants. */
        public Execution {
            Objects.requireNonNull(configuration, "configuration"); Objects.requireNonNull(due, "due");
            Objects.requireNonNull(phase, "phase"); Objects.requireNonNull(signingOperationId, "signingOperationId");
            Objects.requireNonNull(statusObjectId, "statusObjectId"); Objects.requireNonNull(acceptanceCommitment, "acceptanceCommitment");
            Objects.requireNonNull(detailCode, "detailCode");
            if (executionId == null || !executionId.matches("[0-9a-f]{64}") || fence < 1
                    || configuration.revision() < 1 || acceptanceCommitment.length() > 8192
                    || !configuration.enabled() || phase != Phase.CLAIMED && signingOperationId.isEmpty()
                    || signingOperationId.isEmpty() != acceptanceCommitment.isEmpty()
                    || (phase == Phase.EFFECT_COMMITTED || phase == Phase.SCHEDULE_ADVANCED) != statusObjectId.isPresent()
                    || phase == Phase.FAILED != !detailCode.isEmpty()
                    || !detailCode.matches("[A-Z0-9_]{0,128}")) {
                throw new IllegalArgumentException("Invalid scheduled execution");
            }
        }
    }
}
