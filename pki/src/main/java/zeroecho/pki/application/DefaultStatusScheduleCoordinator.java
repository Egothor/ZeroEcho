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
package zeroecho.pki.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationRequest;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.schedule.StatusScheduleCoordinator;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.api.schedule.StatusScheduleState.Execution;
import zeroecho.pki.api.schedule.StatusScheduleState.Phase;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;

/** Session-owned orchestration; persistent store fences all acceptance and effect races. */
final class DefaultStatusScheduleCoordinator implements StatusScheduleCoordinator {
    private static final AccessContext ACCESS = new AccessContext(new Principal("SYSTEM", "status-schedule"),
            new Purpose("STATUS_GENERATE"), Optional.empty(), Optional.empty());
    private final PkiStore store;
    private final DefaultSemanticSigningService signing;
    private final Optional<LocalSigningExecutor> local;
    // Borrowed session-owned service; this coordinator never closes it.
    private final Optional<PublicationService> publications;
    private final Runnable requireOpen;

    /* default */ DefaultStatusScheduleCoordinator(PkiStore store, DefaultSemanticSigningService signing,
            Optional<LocalSigningExecutor> local, Optional<PublicationService> publications, Runnable requireOpen) {
        this.store = store; this.signing = signing; this.local = local;
        this.publications = publications; this.requireOpen = requireOpen;
    }

    @Override public List<StatusScheduleState> listWork(Optional<String> after, int limit, CancellationSignal cancellation) {
        requireOpen.run();
        return store.listStatusScheduleWork(after, limit, cancellation);
    }

    @Override public StatusScheduleState reconcile(StatusScheduleState observed, CancellationSignal cancellation) {
        requireOpen.run();
        StatusScheduleState current = refresh(observed.configuration());
        for (int step = 0; step < 2; step++) {
            checkCancellation(cancellation);
            current = reconcileOne(current, cancellation);
            if (current.execution().filter(value -> value.phase() == Phase.SCHEDULE_ADVANCED).isEmpty()
                    || !current.configuration().enabled() || current.nextDue().isAfter(store.signingNow())) { return current; }
        }
        return current;
    }

    private StatusScheduleState reconcileOne(StatusScheduleState observed, CancellationSignal cancellation) {
        StatusScheduleState current = observed;
        if (current.execution().isEmpty() || current.execution().orElseThrow().phase() == Phase.SCHEDULE_ADVANCED) {
            if (store.claimStatusSchedule(current).isEmpty()) { return refresh(current.configuration()); }
            current = refresh(current.configuration());
        }
        Execution execution = current.execution().orElseThrow();
        if (execution.phase() == Phase.FAILED) { return current; }
        if (execution.phase() == Phase.CLAIMED) {
            ClaimProgress progress = reconcileClaimed(current, cancellation);
            current = progress.state();
            if (!progress.continueEffect()) { return current; }
            execution = current.execution().orElseThrow();
        }
        if (execution.phase() != Phase.EFFECT_COMMITTED) { return current; }
        Optional<PublicationRecord> publication = processPublication(execution, cancellation);
        boolean advanced = store.advanceStatusSchedule(execution);
        if (advanced && publication.filter(value -> value.status() != PublicationStatus.SUCCEEDED).isPresent()) {
            throw new IllegalStateException("Scheduled publication requires explicit follow-up");
        }
        return refresh(current.configuration());
    }

    /** Preserves the original pass boundary when a claim requires another reconciliation. */
    private record ClaimProgress(StatusScheduleState state, boolean continueEffect) { }

    private ClaimProgress reconcileClaimed(StatusScheduleState observed, CancellationSignal cancellation) {
        StatusScheduleState current = observed;
        Execution execution = current.execution().orElseThrow();
        if (execution.signingOperationId().isEmpty()) { accept(execution, cancellation); }
        current = refresh(current.configuration());
        execution = current.execution().orElseThrow();
        if (execution.signingOperationId().isEmpty()) { return new ClaimProgress(current, false); }
        PkiId operationId = execution.signingOperationId().orElseThrow();
        Optional<LocalSigningResult.Failed> localFailure = Optional.empty();
        if (local.isPresent()) {
            LocalSigningResult result = local.orElseThrow().complete(operationId, cancellation);
            if (result instanceof LocalSigningResult.Failed failed) { localFailure = Optional.of(failed); }
        }
        current = refresh(current.configuration());
        execution = current.execution().orElseThrow();
        if (execution.phase() == Phase.CLAIMED) {
            DomainContinuationStore.Record domain = store.getDomainContinuation(operationId).orElseThrow();
            if (domain.state() == DomainContinuationStore.State.FAILED || domain.state() == DomainContinuationStore.State.EXPIRED) {
                store.failStatusSchedule(execution, domain.state() == DomainContinuationStore.State.EXPIRED ? "SIGNING_EXPIRED" : "SIGNING_FAILED");
            } else if (localFailure.filter(value -> !"SIGNING_NOT_READY".equals(value.failure().code())).isPresent()) {
                throw new IllegalStateException("Scheduled signing reconciliation failed");
            }
            return new ClaimProgress(refresh(current.configuration()), false);
        }
        return new ClaimProgress(current, true);
    }

    private Optional<PublicationRecord> processPublication(Execution execution, CancellationSignal cancellation) {
        Optional<PublicationRecord> publication = register(execution);
        if (publication.filter(value -> value.status() == PublicationStatus.PENDING).isPresent()) {
            checkCancellation(cancellation);
            PublicationService service = publications.orElseThrow(); // NOPMD CloseResource - Borrowed from the owning session, which controls its lifetime.
            PkiId publicationId = publication.orElseThrow().publicationId();
            try {
                service.process(publicationId);
            } catch (RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Resolve the persisted outcome after uncertain publication dispatch.
                // Before dispatch preparation, retain pending work. Unknown persistence must
                // be recovered before deciding whether a first attempt is still permitted.
                PublicationRecord persisted = service.find(publicationId).orElseThrow();
                if (persisted.status() == PublicationStatus.PENDING) { throw failure; }
            }
            publication = Optional.of(service.find(publicationId).orElseThrow());
            if (publication.orElseThrow().status() == PublicationStatus.PENDING) {
                throw new IllegalStateException("Scheduled publication has not started");
            }
        }
        return publication;
    }


    private void accept(Execution execution, CancellationSignal cancellation) {
        StatusSchedule configuration = execution.configuration();
        if (!"x509".equals(configuration.formatId().value()) || configuration.statusType() == StatusObjectType.OCSP) {
            throw new UnsupportedOperationException("Scheduled status family is unavailable");
        }
        PkiId issuer = store.getCa(configuration.caId()).orElseThrow().currentIssuanceIssuerId();
        PreparedSemanticSigningRequest prepared = configuration.statusType() == StatusObjectType.CRL
                ? signing.prepareFullCrl(ACCESS, new FullCrlRequest(issuer, configuration.interval()), cancellation)
                : signing.prepareDeltaCrl(ACCESS, new DeltaCrlRequest(issuer, configuration.interval()), cancellation);
        SigningAcceptanceResult accepted;
        try { accepted = signing.acceptScheduled(prepared, execution); }
        catch (RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Failed acceptance must discard the prepared request and rethrow.
            try { signing.discard(prepared); }
            catch (RuntimeException cleanup) { // NOPMD AvoidCatchingGenericException - Preserve the original acceptance failure during cleanup.
                if (cleanup != failure) { failure.addSuppressed(cleanup); } // NOPMD CompareObjectsWithEquals - Throwable self-suppression requires identity comparison.
            }
            throw failure;
        }
        if (accepted.disposition() == SigningAcceptanceDisposition.CAPACITY_REJECTED
                || accepted.disposition() == SigningAcceptanceDisposition.CONFLICT) {
            throw new IllegalStateException("Scheduled signing acceptance deferred");
        }
    }

    private Optional<PublicationRecord> register(Execution execution) {
        return execution.configuration().publicationTarget().map(target -> publications.orElseThrow(
                () -> new IllegalStateException("Publication service unavailable")).register(new PublicationRequest(
                        publicationId(execution, target), PublicationSourceType.STATUS_OBJECT,
                        execution.statusObjectId().orElseThrow(), target)));
    }

    private static PkiId publicationId(Execution execution, PublicationTarget target) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(("status-schedule-publication:v1:" + execution.executionId() + ":" + target.type().name() + ":")
                    .getBytes(StandardCharsets.US_ASCII));
            // Encode exact UTF-16 code units, avoiding replacement collisions for target identifiers.
            for (int index = 0; index < target.targetId().length(); index++) {
                char value = target.targetId().charAt(index);
                digest.update((byte) (value >>> 8)); digest.update((byte) value);
            }
            return new PkiId("schedule-publication:" + HexFormat.of().formatHex(digest.digest()));
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }

    private StatusScheduleState refresh(StatusSchedule configuration) {
        return store.getStatusScheduleState(configuration.caId(), configuration.statusType()).orElseThrow();
    }

    private static void checkCancellation(CancellationSignal cancellation) {
        if (cancellation.isCancelled()) { throw new java.util.concurrent.CancellationException("Schedule reconciliation cancelled"); }
    }
}
