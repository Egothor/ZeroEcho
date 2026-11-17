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

import java.util.ArrayList;

import java.util.Objects;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.signing.PreparedSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningRequest;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Module-private implementation of the externally opaque prepared carrier.
 */
public final class DefaultPreparedSigningRequest implements PreparedSigningRequest {
    private final SigningRequest request;
    private final DurableContentReference candidate;
    private final SigningAcceptanceReceipt receipt;
    private final Object owner;
    private final Optional<SignWorkflowStore.OuterCommand> outer;
    private final SignWorkflowStore.Mode mode;
    private final Optional<SignWorkflowStore.CaSubjectProofStep> proofStep;
    private final Optional<SignWorkflowStore.CaSubjectProofStep> alternativeProofStep;
    private int discardedCandidates;
    private boolean destructiveDiscardStarted;
    private final AtomicReference<Custody> custody =
            new AtomicReference<>(Custody.PREPARED);

    /**
     * Creates an opaque prepared request retaining candidate references and exclusive custody state.
     *
     * @param request frozen signing request; must not be null
     * @param candidate staged primary content reference; must not be null
     * @param receipt preallocated acceptance receipt; must not be null
     * @param owner identity token of the preparing service; must not be null
     * @param outer optional durable domain command; must not be null
     * @param mode workflow execution mode; must not be null
     * @param proofStep optional primary subject-key proof step; must not be null
     * @throws NullPointerException if a required value or optional container is null
     */
    /* default */ DefaultPreparedSigningRequest(SigningRequest request,
            DurableContentReference candidate, SigningAcceptanceReceipt receipt,
            Object owner, Optional<SignWorkflowStore.OuterCommand> outer, SignWorkflowStore.Mode mode,
            Optional<SignWorkflowStore.CaSubjectProofStep> proofStep) {
        this(request, candidate, receipt, owner, outer, mode, proofStep, Optional.empty());
    }

    /**
     * Creates an opaque prepared request retaining candidate references and exclusive custody state.
     *
     * @param request frozen signing request; must not be null
     * @param candidate staged primary content reference; must not be null
     * @param receipt preallocated acceptance receipt; must not be null
     * @param owner identity token of the preparing service; must not be null
     * @param outer optional durable domain command; must not be null
     * @param mode workflow execution mode; must not be null
     * @param proofStep optional primary subject-key proof step; must not be null
     * @param alternativeProofStep optional alternative proof step; must not be null
     * @throws NullPointerException if a required value or optional container is null
     */
    /* default */ DefaultPreparedSigningRequest(SigningRequest request, DurableContentReference candidate,
            SigningAcceptanceReceipt receipt, Object owner, Optional<SignWorkflowStore.OuterCommand> outer,
            SignWorkflowStore.Mode mode, Optional<SignWorkflowStore.CaSubjectProofStep> proofStep,
            Optional<SignWorkflowStore.CaSubjectProofStep> alternativeProofStep) {
        this.request = Objects.requireNonNull(request, "request");
        this.candidate = Objects.requireNonNull(candidate, "candidate");
        this.receipt = Objects.requireNonNull(receipt, "receipt");
        this.owner = Objects.requireNonNull(owner, "owner");
        this.outer = Objects.requireNonNull(outer, "outer");
        this.mode = Objects.requireNonNull(mode, "mode");
        this.proofStep = Objects.requireNonNull(proofStep, "proofStep");
        this.alternativeProofStep = Objects.requireNonNull(alternativeProofStep, "alternativeProofStep");
    }

    /**
     * {@inheritDoc}
     */
    @Override public SigningRequest request() { return request; }
    /**
     * {@inheritDoc}
     */
    @Override public DurableContentReference candidate() { return candidate; }
    /**
     * {@inheritDoc}
     */
    @Override public SigningAcceptanceReceipt receipt() { return receipt; }

    /**
     * Returns the frozen domain continuation command.
     *
     * @return optional domain command retained without execution
     */
    /* default */ Optional<SignWorkflowStore.OuterCommand> outer() { return outer; }
    /**
     * Returns the selected durable workflow mode.
     *
     * @return workflow mode captured at preparation
     */
    /* default */ SignWorkflowStore.Mode mode() { return mode; }
    /**
     * Returns the primary subject-key proof step.
     *
     * @return optional frozen primary proof step
     */
    /* default */ Optional<SignWorkflowStore.CaSubjectProofStep> proofStep() { return proofStep; }
    /**
     * Returns the alternative subject-key proof step.
     *
     * @return optional frozen alternative proof step
     */
    /* default */ Optional<SignWorkflowStore.CaSubjectProofStep> alternativeProofStep() { return alternativeProofStep; }
    /**
     * Lists staged content references in discard-index order.
     *
     * @return immutable list containing primary content followed by present proof challenges
     */
    /* default */ List<DurableContentReference> candidates() {
        List<DurableContentReference> candidates = new ArrayList<>(); candidates.add(candidate);
        proofStep.ifPresent(step -> candidates.add(step.challenge()));
        alternativeProofStep.ifPresent(step -> candidates.add(step.challenge()));
        return List.copyOf(candidates);
    }
    /**
     * Reports whether destructive cleanup has yet to begin.
     *
     * @return true before the first destructive discard action
     */
    /* default */ boolean needsDiscardValidation() { return !destructiveDiscardStarted; }
    /**
     * Tests the cleanup progress bit for one candidate index.
     *
     * @param index position in the candidates list, within the tracked bit mask
     * @return true if that candidate was already successfully discarded
     */
    /* default */ boolean discarded(int index) { return (discardedCandidates & (1 << index)) != 0; }
    /**
     * Marks that destructive cleanup began, so a retry cannot restore accept custody.
     */
    /* default */ void startDestructiveDiscard() { destructiveDiscardStarted = true; }
    /**
     * Records successful cleanup of one staged candidate.
     *
     * @param index position in the candidates list, within the tracked bit mask
     */
    /* default */ void markDiscarded(int index) { discardedCandidates |= 1 << index; }

    /**
     * Tests ownership using identity rather than value equality.
     *
     * @param expectedOwner preparing-service token to compare with the retained token
     * @return true only for the identical owner object
     */
    /* default */
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    boolean ownedBy(Object expectedOwner) { return owner == expectedOwner; }

    /**
     * Requires exclusive prepared custody before an operation may begin.
     *
     * @throws IllegalStateException if acceptance or discard already consumed the request
     */
    /* default */ void requireUnused() {
        if (custody.get() != Custody.PREPARED) {
            throw new IllegalStateException("Prepared signing request was already consumed");
        }
    }

    /**
     * Atomically transfers prepared custody to acceptance exactly once.
     *
     * @throws IllegalStateException if the request is no longer exclusively prepared
     */
    /* default */ void consumeForAccept() {
        if (!custody.compareAndSet(Custody.PREPARED, Custody.CONSUMED)) {
            throw new IllegalStateException("Prepared signing request was already consumed");
        }
    }

    /**
     * Atomically acquires discard custody for initial cleanup or a cleanup retry.
     *
     * @throws IllegalStateException if another action consumed or currently owns the request
     */
    /* default */ void beginDiscard() {
        Custody current = custody.get();
        if ((current != Custody.PREPARED && current != Custody.DISCARD_RETRY)
                || !custody.compareAndSet(current, Custody.DISCARDING)) {
            throw new IllegalStateException("Prepared signing request was already consumed");
        }
    }

    /**
     * Permanently consumes the request after successful destructive cleanup.
     *
     * @throws IllegalStateException if the request is not currently being discarded
     */
    /* default */ void completeDiscard() {
        if (!custody.compareAndSet(Custody.DISCARDING, Custody.CONSUMED)) {
            throw new IllegalStateException("Prepared signing discard state is inconsistent");
        }
    }

    /**
     * Releases a failed discard attempt while retaining destructive-cleanup progress.
     *
     * <p>Before destructive work begins, restores the accept-or-discard choice. Afterward,
     * only discard retries may acquire custody.</p>
     *
     * @throws IllegalStateException if the request is not currently being discarded
     */
    /* default */ void retryDiscard() {
        if (!custody.compareAndSet(Custody.DISCARDING,
                destructiveDiscardStarted ? Custody.DISCARD_RETRY : Custody.PREPARED)) {
            throw new IllegalStateException("Prepared signing discard state is inconsistent");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override public String toString() { return "PreparedSigningRequest[redacted]"; }

    /**
     * Exclusive custody state for the opaque prepared value.
     */
    private enum Custody {
        /**
         * Caller retains the exclusive accept-or-discard choice.
         */
        PREPARED,
        /**
         * One discard attempt exclusively owns cleanup.
         */
        DISCARDING,
        /**
         * Destructive cleanup began; only unfinished-reference cleanup may resume.
         */
        DISCARD_RETRY,
        /**
         * Custody transferred or cleanup completed permanently.
         */
        CONSUMED
    }
}
