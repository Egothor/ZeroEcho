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
package zeroecho.pki.testkit;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Test-only sampler retaining the first durable signing state observed at an
 * explicit test-controlled boundary, while also reporting sampled absence
 * before that state becomes visible.
 *
 * <p>
 * The recorder deliberately reads the store only when {@link #sample} is called,
 * using the stable, read-only snapshot contract of
 * {@link SignWorkflowStore#listSignWorkflows()}. It is not a store decorator and
 * retains no workflow record, payload, error, or secret material. Concurrent-map
 * bookkeeping has expected {@code O(1)} cost and the recorder retains
 * {@code O(S)} entries for {@code S} sampled submission IDs. Obtaining and
 * searching the snapshot has the store implementation's cost; for the current
 * store it is typically {@code O(W)} time and {@code O(W)} temporary memory for
 * {@code W} retained workflow records.
 * </p>
 *
 * <p>This class is thread-safe.</p>
 */
public final class SigningTransitionRecorder {
    private final ConcurrentMap<PkiId, Observation> firstObservations = new ConcurrentHashMap<>();

    /**
     * Samples one submission at the caller-selected boundary. An earlier absence
     * may upgrade exactly once to the first observed durable state; a retained
     * durable state is never replaced.
     *
     * @param store authoritative signing store to sample
     * @param submissionId exact submission identifier
     * @return the first retained observation for the identifier
     */
    public Observation sample(SignWorkflowStore store, PkiId submissionId) {
        SignWorkflowStore exactStore = Objects.requireNonNull(store, "store");
        PkiId exactId = Objects.requireNonNull(submissionId, "submissionId");
        Observation sampled = new Observation(stateFromStableSnapshot(exactStore, exactId));
        return firstObservations.compute(exactId, (ignored, current) -> {
            if (current == null
                    || (current.state().isEmpty() && sampled.state().isPresent())) {
                return sampled;
            }
            return current;
        });
    }

    private static Optional<SignWorkflowStore.State> stateFromStableSnapshot(
            SignWorkflowStore store, PkiId submissionId) {
        for (SignWorkflowStore.Workflow record : store.listSignWorkflows()) {
            if (submissionId.equals(record.submissionId())) {
                return Optional.of(record.state());
            }
        }
        return Optional.empty();
    }

    /**
     * Returns the first observation retained for an identifier.
     *
     * @param submissionId exact submission identifier
     * @return retained observation, or empty when the identifier was never sampled
     */
    public Optional<Observation> firstObservation(PkiId submissionId) {
        return Optional.ofNullable(firstObservations.get(
                Objects.requireNonNull(submissionId, "submissionId")));
    }

    /**
     * One durable-state observation. An empty state means that no durable signing
     * intent existed at the latest sampled boundary before the first state became
     * visible.
     *
     * @param state first observed durable state, or empty for absence
     */
    public record Observation(Optional<SignWorkflowStore.State> state) {
        /** Validates the immutable observation. */
        public Observation {
            state = Objects.requireNonNull(state, "state");
        }
    }
}
