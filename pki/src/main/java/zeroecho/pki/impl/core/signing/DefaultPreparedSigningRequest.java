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

package zeroecho.pki.impl.core.signing;

import java.util.Objects;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.signing.PreparedSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningRequest;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Module-private implementation of the externally opaque prepared carrier. */
public final class DefaultPreparedSigningRequest implements PreparedSigningRequest {
    private final SigningRequest request;
    private final DurableContentReference candidate;
    private final SigningAcceptanceReceipt receipt;
    private final Object owner;
    private final Optional<SignWorkflowStore.OuterCommand> outer;
    private final SignWorkflowStore.Mode mode;
    private final Optional<SignWorkflowStore.CaSubjectProofStep> proofStep;
    private int discardedCandidates;
    private boolean destructiveDiscardStarted;
    private final AtomicReference<Custody> custody =
            new AtomicReference<>(Custody.PREPARED);

    /* default */ DefaultPreparedSigningRequest(SigningRequest request,
            DurableContentReference candidate, SigningAcceptanceReceipt receipt,
            Object owner, Optional<SignWorkflowStore.OuterCommand> outer, SignWorkflowStore.Mode mode,
            Optional<SignWorkflowStore.CaSubjectProofStep> proofStep) {
        this.request = Objects.requireNonNull(request, "request");
        this.candidate = Objects.requireNonNull(candidate, "candidate");
        this.receipt = Objects.requireNonNull(receipt, "receipt");
        this.owner = Objects.requireNonNull(owner, "owner");
        this.outer = Objects.requireNonNull(outer, "outer");
        this.mode = Objects.requireNonNull(mode, "mode");
        this.proofStep = Objects.requireNonNull(proofStep, "proofStep");
    }

    @Override public SigningRequest request() { return request; }
    @Override public DurableContentReference candidate() { return candidate; }
    @Override public SigningAcceptanceReceipt receipt() { return receipt; }

    /* default */ Optional<SignWorkflowStore.OuterCommand> outer() { return outer; }
    /* default */ SignWorkflowStore.Mode mode() { return mode; }
    /* default */ Optional<SignWorkflowStore.CaSubjectProofStep> proofStep() { return proofStep; }
    /* default */ List<DurableContentReference> candidates() {
        return proofStep.isEmpty() ? List.of(candidate) : List.of(candidate, proofStep.orElseThrow().challenge());
    }
    /* default */ boolean needsDiscardValidation() { return !destructiveDiscardStarted; }
    /* default */ boolean discarded(int index) { return (discardedCandidates & (1 << index)) != 0; }
    /* default */ void startDestructiveDiscard() { destructiveDiscardStarted = true; }
    /* default */ void markDiscarded(int index) { discardedCandidates |= 1 << index; }

    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    /* default */ boolean ownedBy(Object expectedOwner) { return owner == expectedOwner; }

    /* default */ void requireUnused() {
        if (custody.get() != Custody.PREPARED) {
            throw new IllegalStateException("Prepared signing request was already consumed");
        }
    }

    /* default */ void consumeForAccept() {
        if (!custody.compareAndSet(Custody.PREPARED, Custody.CONSUMED)) {
            throw new IllegalStateException("Prepared signing request was already consumed");
        }
    }

    /* default */ void beginDiscard() {
        Custody current = custody.get();
        if ((current != Custody.PREPARED && current != Custody.DISCARD_RETRY)
                || !custody.compareAndSet(current, Custody.DISCARDING)) {
            throw new IllegalStateException("Prepared signing request was already consumed");
        }
    }

    /* default */ void completeDiscard() {
        if (!custody.compareAndSet(Custody.DISCARDING, Custody.CONSUMED)) {
            throw new IllegalStateException("Prepared signing discard state is inconsistent");
        }
    }

    /* default */ void retryDiscard() {
        if (!custody.compareAndSet(Custody.DISCARDING,
                destructiveDiscardStarted ? Custody.DISCARD_RETRY : Custody.PREPARED)) {
            throw new IllegalStateException("Prepared signing discard state is inconsistent");
        }
    }

    @Override public String toString() { return "PreparedSigningRequest[redacted]"; }

    /** Exclusive custody state for the opaque prepared value. */
    private enum Custody {
        /** Caller retains the exclusive accept-or-discard choice. */
        PREPARED,
        /** One discard attempt exclusively owns cleanup. */
        DISCARDING,
        /** Destructive cleanup began; only unfinished-reference cleanup may resume. */
        DISCARD_RETRY,
        /** Custody transferred or cleanup completed permanently. */
        CONSUMED
    }
}
