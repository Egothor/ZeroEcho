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
package zeroecho.pki.impl.core.signing;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProvider.OperationObservation;
import zeroecho.pki.spi.crypto.SigningProvider.ObservationState;
import zeroecho.pki.spi.crypto.SigningProviderExecutor;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.SignWorkflowStore.Workflow;

/**
 * Executes one durable signing step on the calling thread without scheduling work.
 *
 * <p>The executor borrows its store, provider, and outer continuation driver. It
 * owns no threads, queues, locks, or workflow registry. Claiming, cancellation,
 * and progress notification are supplied for each invocation and are not retained.
 * All provider calls, durable checkpoints, and outer continuations run inline.</p>
 *
 * <p>Instances may be shared when the borrowed dependencies support concurrent
 * calls. The caller must supply the store's fenced claim operation; an unsuccessful
 * claim performs no provider call. Executor bookkeeping takes constant time and
 * auxiliary memory, excluding the existing store, provider, and continuation costs.</p>
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CommentRequired" })
public final class SigningStepExecutor {
    private static final String PROVIDER_ID_MISMATCH = "PROVIDER_ID_MISMATCH";
    private static final String CONTENT_INTEGRITY_FAILURE = "CONTENT_INTEGRITY_FAILURE";
    private static final String EXPIRED = "EXPIRED";

    private final PkiStore store;
    private final SigningProvider provider;
    private final OuterTerminalDriver outerDriver;
    private final SigningProviderExecutor executor;

    /** Idempotently verifies a claimed CA proof or advances terminal outer publication. */
    @FunctionalInterface
    public interface OuterTerminalDriver {
        /**
         * Advances a claimed CA-proof verification or an authoritative terminal workflow.
         *
         * @param workflow claimed proof-verification or terminal signing workflow
         */
        void advance(Workflow workflow);
    }

    /**
     * Creates an inline executor borrowing all execution dependencies.
     *
     * @param store authoritative durable store
     * @param provider configured signing provider
     * @param providerCallTimeout positive timeout no greater than one day
     * @param outerDriver idempotent CA-proof and terminal-publication continuation
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if the timeout is not positive or exceeds one day
     */
    public SigningStepExecutor(PkiStore store, SigningProvider provider,
            Duration providerCallTimeout, OuterTerminalDriver outerDriver) {
        this.store = Objects.requireNonNull(store, "store");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.outerDriver = Objects.requireNonNull(outerDriver, "outerDriver");
        this.executor = new SigningProviderExecutor(store, provider, providerCallTimeout);
    }

    /**
     * Advances the observed workflow through one claim and its eligible action.
     *
     * <p>Terminal observations advance their outer continuation without a new claim.
     * Nonterminal observations use the caller's fenced claim and retain the observed
     * preclaim state to distinguish initial dispatch from recovery reconciliation.
     * Cancellation preserves mandatory bounded-attempt checkpoints. Retry eligibility,
     * lease fencing, and durable state remain authoritative in the store.</p>
     *
     * @param source authoritative observation, including its preclaim state
     * @param claim call-scoped fenced claim; empty means no step is eligible
     * @param cancellation call-scoped provider cancellation and shutdown signal
     * @param progress call-scoped notification after durable progress
     * @return whether the caller should rescan after releasing this identifier;
     *         this is a scheduling hint, not a completion result
     * @throws NullPointerException if any argument is null
     */
    public boolean advance(Workflow source, Function<Workflow, Optional<Workflow>> claim,
            CancellationSignal cancellation, Runnable progress) {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(claim, "claim");
        Objects.requireNonNull(cancellation, "cancellation");
        Objects.requireNonNull(progress, "progress");
        if (terminal(source.state())) {
            advanceTerminal(source, cancellation, progress);
            return false;
        }
        Optional<Workflow> claimed = claim.apply(source);
        if (claimed.isEmpty()) {
            return false;
        }
        Workflow exact = claimed.orElseThrow();
        advanceClaimed(source, exact, cancellation, progress);
        return exact.mode() == SignWorkflowStore.Mode.BOUNDED_OBSERVATION
                || exact.stage() != SignWorkflowStore.Stage.SINGLE;
    }

    private void verifyCaProof(Workflow workflow, CancellationSignal cancellation, Runnable progress) {
        try {
            outerDriver.advance(workflow);
            progress.run();
        } catch (RuntimeException infrastructureFailure) {
            defer(workflow, SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE, cancellation, progress);
        }
    }

    private void dispatch(Workflow workflow, CancellationSignal cancellation, Runnable progress) {
        if (!initialCallBeforeDeadline(workflow, progress)) {
            return;
        }
        RepeatableContent content;
        try {
            content = store.stagedContent().openContent(workflow.stage() == SignWorkflowStore.Stage.CA_PROOF
                    ? workflow.envelope().proofStep().orElseThrow().challenge() : workflow.envelope().candidate());
        } catch (IOException | RuntimeException failure) {
            transitionFailure(workflow, CONTENT_INTEGRITY_FAILURE, cancellation, progress);
            return;
        }
        try (content) {
            if (!initialCallBeforeDeadline(workflow, progress)) {
                return;
            }
            apply(workflow, executor.dispatch(workflow, content, cancellation), Action.DISPATCH, cancellation, progress);
        } catch (IOException | RuntimeException failure) {
            defer(workflow, SignWorkflowStore.ReconciliationFailureClass.SUBMISSION_UNCERTAIN, cancellation, progress);
        }
    }

    private void reconcile(Workflow workflow, boolean cancelWhenPending,
            CancellationSignal cancellation, Runnable progress) {
        if (!cancelWhenPending && !initialCallBeforeDeadline(workflow, progress)) {
            return;
        }
        try {
            OperationObservation observation = executor.reconcile(workflow, cancellation);
            if (cancelWhenPending && observation.state() == ObservationState.PENDING) {
                cancelProvider(workflow, cancellation, progress);
            } else {
                apply(workflow, observation, Action.RECONCILE, cancellation, progress);
            }
        } catch (RuntimeException failure) {
            defer(workflow, SignWorkflowStore.ReconciliationFailureClass.STATUS_UNAVAILABLE, cancellation, progress);
        }
    }

    private boolean initialCallBeforeDeadline(Workflow workflow, Runnable progress) {
        if (workflow.mode() != SignWorkflowStore.Mode.BOUNDED_OBSERVATION
                && workflow.stage() == SignWorkflowStore.Stage.SINGLE
                || workflow.deadline().isAfter(store.signingNow())) {
            return true;
        }
        // The authoritative lookup performs the existing expiry transition and cleanup.
        store.getSignWorkflow(workflow.operationId());
        progress.run();
        return false;
    }

    private void cancelProvider(Workflow workflow, CancellationSignal cancellation, Runnable progress) {
        try {
            apply(workflow, executor.cancel(workflow,
                    SigningProvider.CancellationReason.CALLER_REQUESTED, cancellation), Action.CANCEL, cancellation, progress);
        } catch (RuntimeException failure) {
            defer(workflow, SignWorkflowStore.ReconciliationFailureClass.CANCELLATION_UNCERTAIN, cancellation, progress);
        }
    }

    private void apply(Workflow workflow, OperationObservation observation, Action action,
            CancellationSignal cancellation, Runnable progress) {
        switch (observation.state()) {
            case PENDING -> {
                if (workflow.mode() == SignWorkflowStore.Mode.BOUNDED_OBSERVATION) {
                    Optional<Workflow> checkpoint = action == Action.DISPATCH
                            ? store.checkpointPendingSignDispatch(workflow.operationId(), workflow.revision(), workflow.fence())
                            : action == Action.RECONCILE
                                    && workflow.initialAttemptPhase() == SignWorkflowStore.InitialAttemptPhase.OBSERVATION_CONSUMED
                                    && workflow.state() == SignWorkflowStore.State.DISPATCHED
                                            ? store.completeSignObservation(workflow.operationId(), workflow.revision(), workflow.fence())
                                            : Optional.empty();
                    checkpoint.ifPresent(ignored -> progress.run());
                }
            }
            case RETRYABLE_UNKNOWN -> defer(workflow, switch (action) {
                case DISPATCH -> SignWorkflowStore.ReconciliationFailureClass.SUBMISSION_UNCERTAIN;
                case RECONCILE -> SignWorkflowStore.ReconciliationFailureClass.STATUS_UNAVAILABLE;
                case CANCEL -> SignWorkflowStore.ReconciliationFailureClass.CANCELLATION_UNCERTAIN;
            }, cancellation, progress);
            case SUCCEEDED, FAILED, CANCELLED, UNRECOVERABLE -> acceptTerminal(workflow, observation, cancellation, progress);
        }
    }

    private void acceptTerminal(Workflow workflow, OperationObservation observation,
            CancellationSignal cancellation, Runnable progress) {
        if (workflow.stage() == SignWorkflowStore.Stage.CA_PROOF) {
            store.checkpointCaProof(workflow.operationId(), workflow.revision(), workflow.fence(),
                    new SignWorkflowStore.CaSubjectProofOutcome(observation.state(), observation.detailCode(),
                            Optional.of(observation.updatedAt())), observation.signature()).ifPresent(changed -> {
                        progress.run();
                        if (terminal(changed.state())) {
                            advanceTerminal(changed, cancellation, progress);
                        }
                    });
            return;
        }
        Workflow source = workflow;
        if (observation.state() == ObservationState.CANCELLED
                && workflow.state() == SignWorkflowStore.State.DISPATCHED) {
            Optional<Workflow> cancelling = store.requestSignCancellation(workflow.operationId(),
                    workflow.revision(), workflow.fence());
            if (cancelling.isEmpty()) {
                return;
            }
            source = cancelling.orElseThrow();
        }
        if ((observation.state() == ObservationState.SUCCEEDED
                || observation.state() == ObservationState.CANCELLED)
                && !observation.updatedAt().isBefore(workflow.deadline())) {
            transition(source, SignWorkflowStore.State.EXPIRED, Optional.of(EXPIRED),
                    Optional.empty(), Optional.empty(), cancellation, progress);
            return;
        }
        SignWorkflowStore.State target = observation.state() == ObservationState.SUCCEEDED
                ? SignWorkflowStore.State.SUCCEEDED
                : observation.state() == ObservationState.CANCELLED
                        ? SignWorkflowStore.State.CANCELLED : SignWorkflowStore.State.FAILED;
        transition(source, target, Optional.of(observation.detailCode().name()),
                observation.signature(), Optional.of(observation.updatedAt()), cancellation, progress);
    }

    private void transitionFailure(Workflow workflow, String detail,
            CancellationSignal cancellation, Runnable progress) {
        transition(workflow, SignWorkflowStore.State.FAILED, Optional.of(detail),
                Optional.empty(), Optional.empty(), cancellation, progress);
    }

    private void transition(Workflow workflow, SignWorkflowStore.State target,
            Optional<String> detail, Optional<zeroecho.pki.api.EncodedObject> result,
            Optional<Instant> providerUpdatedAt, CancellationSignal cancellation, Runnable progress) {
        store.transitionSign(workflow.operationId(), workflow.revision(), workflow.fence(),
                target, detail, result, providerUpdatedAt).ifPresent(terminal -> {
                    progress.run();
                    advanceTerminal(terminal, cancellation, progress);
                });
    }

    private void defer(Workflow workflow,
            SignWorkflowStore.ReconciliationFailureClass failureClass,
            CancellationSignal cancellation, Runnable progress) {
        boolean unfinishedBoundedAttempt = workflow.mode() == SignWorkflowStore.Mode.BOUNDED_OBSERVATION
                && !workflow.initialAttemptPhase().finished();
        if (!cancellation.isCancelled() || unfinishedBoundedAttempt) {
            store.deferSignReconciliation(workflow.operationId(), workflow.revision(),
                    workflow.fence(), failureClass).ifPresent(ignored -> progress.run());
        }
    }

    private void advanceTerminal(Workflow workflow, CancellationSignal cancellation, Runnable progress) {
        if (workflow.envelope().outer().isPresent()) {
            try {
                outerDriver.advance(workflow);
            } catch (RuntimeException infrastructureFailure) {
                deferOuterContinuation(workflow.operationId(), cancellation);
            }
        } else if (workflow.state() != SignWorkflowStore.State.RETIRED) {
            store.retireSign(workflow.operationId(), workflow.revision(), workflow.fence())
                    .ifPresent(ignored -> progress.run());
        }
    }

    private void deferOuterContinuation(PkiId operationId, CancellationSignal cancellation) {
        if (cancellation.isCancelled()) {
            return;
        }
        Optional<Workflow> loaded = store.getSignWorkflow(operationId);
        if (loaded.isEmpty()) {
            return;
        }
        Workflow fresh = loaded.orElseThrow();
        if (fresh.state() == SignWorkflowStore.State.SUCCEEDED) {
            store.deferSignReconciliation(operationId, fresh.revision(), fresh.fence(),
                    SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE);
        }
    }

    private boolean providerMatches(Workflow workflow) {
        return workflow.namespace().equals(store.signingNamespace() + "." + provider.id())
                && provider.configurationCommitment().matches(workflow.configurationCommitment());
    }

    private static boolean terminal(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.SUCCEEDED
                || state == SignWorkflowStore.State.FAILED
                || state == SignWorkflowStore.State.CANCELLED
                || state == SignWorkflowStore.State.EXPIRED
                || state == SignWorkflowStore.State.RETIRED;
    }

    private enum Action { DISPATCH, RECONCILE, CANCEL }

    private void advanceClaimed(Workflow source, Workflow exact, CancellationSignal cancellation, Runnable progress) {
        if (!providerMatches(exact)) {
            transitionFailure(exact, PROVIDER_ID_MISMATCH, cancellation, progress);
            return;
        }
        if (exact.stage() == SignWorkflowStore.Stage.CA_PROOF_VERIFYING) {
            verifyCaProof(exact, cancellation, progress);
        } else if (source.state() == SignWorkflowStore.State.INTENT
                || source.stage() == SignWorkflowStore.Stage.CA_CERTIFICATE_READY) {
            dispatch(exact, cancellation, progress);
        } else if (source.state() == SignWorkflowStore.State.DISPATCHED) {
            if (exact.mode() == SignWorkflowStore.Mode.BOUNDED_OBSERVATION
                    && exact.initialAttemptPhase().finished()) {
                store.requestSignCancellation(exact.operationId(), exact.revision(), exact.fence())
                        .ifPresent(ignored -> progress.run());
            } else {
                reconcile(exact, false, cancellation, progress);
            }
        } else if (source.state() == SignWorkflowStore.State.CANCELLING) {
            reconcile(exact, true, cancellation, progress);
        }
    }
}
