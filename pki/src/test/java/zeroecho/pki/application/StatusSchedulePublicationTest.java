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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.publication.PublicationEvidence;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationRequest;
import zeroecho.pki.api.publication.PublicationResult;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.spi.store.PkiStore;

class StatusSchedulePublicationTest {
    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");

    @ParameterizedTest @ValueSource(strings = {"cancel", "before-dispatch", "prepared", "delivered"})
    void disabledAcceptedScheduleRecoversPublicationCutsWithoutAnotherSignature(String cut, @TempDir Path root) throws Exception {
        LocalPkiSessionTest.Fixture fixture = new LocalPkiSessionTest.Fixture(root);
        fixture.time(NOW);
        AtomicBoolean fault = new AtomicBoolean(true);
        AtomicBoolean cancellation = new AtomicBoolean();
        AtomicInteger attempts = new AtomicInteger();
        PkiId ca;
        PkiId publicationId;
        try (PkiSession session = fixture.open("publication-cut")) {
            session.localSigning().orElseThrow().execute(LocalPkiSessionTest.rootCommand(), CancellationSignal.NONE);
            ca = fixture.store.listCas().getFirst().caId();
            fixture.store.putStatusSchedule(new StatusSchedule(ca, StatusObjectType.CRL, new FormatId("x509"),
                    Duration.ofMinutes(10), 30, true, Optional.of(new PublicationTarget(PublicationTargetType.HTTP, "mirror")),
                    NOW, NOW, 0));
            // No publisher is configured in this session: generation commits its effect,
            // while deterministic publication registration remains recoverable work.
            assertThrows(IllegalStateException.class, () -> session.statusSchedules().orElseThrow().reconcile(
                    fixture.store.getStatusScheduleState(ca, StatusObjectType.CRL).orElseThrow(), CancellationSignal.NONE));
            StatusSchedule config = fixture.store.getStatusSchedule(ca, StatusObjectType.CRL).orElseThrow();
            fixture.store.putStatusSchedule(new StatusSchedule(ca, config.statusType(), config.formatId(), config.interval(),
                    config.graceSeconds(), false, config.publicationTarget(), NOW, NOW, config.revision()));
            DefaultStatusScheduleCoordinator coordinator = coordinator(fixture, cut, fault, cancellation, attempts);
            Class<? extends Throwable> expected = cut.equals("cancel") ? CancellationException.class
                    : cut.equals("before-dispatch") ? IllegalStateException.class : SimulatedCrash.class;
            assertThrows(expected, () -> coordinator.reconcile(
                    fixture.store.getStatusScheduleState(ca, StatusObjectType.CRL).orElseThrow(), cancellation::get));
            assertEquals(StatusScheduleState.Phase.EFFECT_COMMITTED,
                    fixture.store.getStatusScheduleState(ca, StatusObjectType.CRL).orElseThrow().execution().orElseThrow().phase());
            publicationId = fixture.store.listPublicationsPage(Optional.empty(), 10, value -> true, CancellationSignal.NONE)
                    .getFirst().publicationId();
            assertEquals(2, fixture.dispatches.get());
        }
        cancellation.set(false);
        fault.set(false);
        try (PkiSession session = fixture.open("publication-recovery")) {
            DefaultStatusScheduleCoordinator coordinator = coordinator(fixture, cut, fault, cancellation, attempts);
            StatusScheduleState pending = coordinator.listWork(Optional.empty(), 10, CancellationSignal.NONE).getFirst();
            if (cut.equals("prepared")) {
                assertThrows(IllegalStateException.class, () -> coordinator.reconcile(pending, CancellationSignal.NONE));
                assertEquals(PublicationStatus.OUTCOME_UNKNOWN, fixture.store.getPublicationRecord(publicationId).orElseThrow().status());
            } else {
                coordinator.reconcile(pending, CancellationSignal.NONE);
                assertEquals(PublicationStatus.SUCCEEDED, fixture.store.getPublicationRecord(publicationId).orElseThrow().status());
            }
            assertEquals(StatusScheduleState.Phase.SCHEDULE_ADVANCED,
                    fixture.store.getStatusScheduleState(ca, StatusObjectType.CRL).orElseThrow().execution().orElseThrow().phase());
            assertEquals(1, attempts.get());
            assertEquals(2, fixture.dispatches.get());
            assertEquals(1, fixture.store.listStatusObjects(ca).size());
            assertEquals(1, fixture.store.listPublicationsPage(Optional.empty(), 10, value -> true, CancellationSignal.NONE).size());
        }
    }

    private static DefaultStatusScheduleCoordinator coordinator(LocalPkiSessionTest.Fixture fixture, String cut,
            AtomicBoolean fault, AtomicBoolean cancellation, AtomicInteger attempts) {
        PublicationService publications = (PublicationService) Proxy.newProxyInstance(PublicationService.class.getClassLoader(),
                new Class<?>[]{PublicationService.class}, (proxy, method, args) -> {
                    PkiStore store = fixture.store;
                    if (method.getName().equals("register")) {
                        PublicationRequest request = (PublicationRequest) args[0];
                        Optional<PublicationRecord> existing = store.getPublicationRecord(request.publicationId());
                        if (existing.isPresent()) return existing.orElseThrow();
                        PublicationRecord record = store.createPublicationRecord(new PublicationRecord(request.publicationId(),
                                request.sourceType(), request.sourceId(), store.getStatusObject(request.sourceId()).orElseThrow().content(),
                                request.target(), PublicationStatus.PENDING, 0, Optional.empty(), NOW, NOW, Optional.empty(), Optional.empty()));
                        if (cut.equals("cancel") && fault.getAndSet(false)) cancellation.set(true);
                        return record;
                    }
                    if (method.getName().equals("find")) return store.getPublicationRecord((PkiId) args[0]);
                    if (method.getName().equals("process")) {
                        if (cut.equals("before-dispatch") && fault.getAndSet(false)) throw new IllegalStateException("before dispatch preparation");
                        PublicationRecord pending = store.getPublicationRecord((PkiId) args[0]).orElseThrow();
                        PublicationRecord prepared = transition(pending, PublicationStatus.DISPATCH_PREPARED);
                        assertEquals(true, store.replacePublicationRecord(pending, prepared));
                        attempts.incrementAndGet();
                        if (cut.equals("prepared") && fault.getAndSet(false)) throw new SimulatedCrash();
                        assertEquals(true, store.replacePublicationRecord(prepared, transition(prepared, PublicationStatus.SUCCEEDED)));
                        return new PublicationResult(pending.publicationId(), PublicationStatus.SUCCEEDED, 1);
                    }
                    throw new AssertionError("Unexpected publication call: " + method.getName());
                });
        PkiStore store = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[]{PkiStore.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("advanceStatusSchedule") && cut.equals("delivered") && fault.getAndSet(false)) throw new SimulatedCrash();
                    try { return method.invoke(fixture.store, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
        return new DefaultStatusScheduleCoordinator(store, null, Optional.empty(), Optional.of(publications), () -> { });
    }

    private static PublicationRecord transition(PublicationRecord previous, PublicationStatus status) {
        return new PublicationRecord(previous.publicationId(), previous.sourceType(), previous.sourceId(), previous.content(),
                previous.target(), status, 1, Optional.of("a".repeat(64)), NOW, NOW, Optional.empty(),
                status == PublicationStatus.SUCCEEDED ? Optional.of(PublicationEvidence.DIRECT_RESPONSE) : Optional.empty());
    }

    private static final class SimulatedCrash extends Error { private static final long serialVersionUID = 1L; }
}
