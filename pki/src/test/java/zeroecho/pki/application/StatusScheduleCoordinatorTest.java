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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.schedule.StatusScheduleCoordinator;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;

class StatusScheduleCoordinatorTest {
    @ParameterizedTest @ValueSource(strings = {"2026-10-05T12:00:00Z", "2026-10-05T12:00:00.750Z"})
    void localSessionSignsOncePerDueOccurrenceWithConfiguredCadenceAcrossRestart(String instant, @TempDir Path root) throws Exception {
        Instant now = Instant.parse(instant);
        LocalPkiSessionTest.Fixture fixture = new LocalPkiSessionTest.Fixture(root);
        fixture.time(now.truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
        PkiId ca;
        try (PkiSession session = fixture.open("scheduler-test")) {
            assertInstanceOf(LocalSigningResult.Completed.class, session.localSigning().orElseThrow()
                    .execute(LocalPkiSessionTest.rootCommand(), CancellationSignal.NONE));
            ca = fixture.store.listCas().getFirst().caId();
            fixture.time(now);
            StatusScheduleCoordinator coordinator = session.statusSchedules().orElseThrow();
            for (StatusObjectType type : new StatusObjectType[]{StatusObjectType.CRL, StatusObjectType.DELTA_CRL}) {
                fixture.store.putStatusSchedule(new StatusSchedule(ca, type, new FormatId("x509"), Duration.ofMinutes(10),
                        30, true, Optional.empty(), now, now, 0));
                StatusScheduleState state = coordinator.reconcile(fixture.store.getStatusScheduleState(ca, type).orElseThrow(), CancellationSignal.NONE);
                assertEquals(StatusScheduleState.Phase.SCHEDULE_ADVANCED, state.execution().orElseThrow().phase());
                StatusObject status = fixture.store.getStatusObject(state.execution().orElseThrow().statusObjectId().orElseThrow()).orElseThrow();
                assertEquals(Duration.ofMinutes(10), Duration.between(status.thisUpdate(), status.nextUpdate().orElseThrow()));
                assertEquals(now.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).plusSeconds(570), state.nextDue());
                coordinator.reconcile(state, CancellationSignal.NONE);
            }
            assertEquals(3, fixture.dispatches.get());
        }
        fixture.time(now.plusSeconds(3600));
        try (PkiSession session = fixture.open("scheduler-recovery")) {
            StatusScheduleState old = fixture.store.getStatusScheduleState(ca, StatusObjectType.CRL).orElseThrow();
            StatusScheduleState current = session.statusSchedules().orElseThrow().reconcile(old, CancellationSignal.NONE);
            assertEquals(StatusScheduleState.Phase.SCHEDULE_ADVANCED, current.execution().orElseThrow().phase());
            assertEquals(4, fixture.dispatches.get(), "Overdue hours coalesce into one new signature");
            assertEquals(3, fixture.store.listStatusObjects(ca).size());
            assertTrue(current.nextDue().isAfter(now.plusSeconds(3600)));
            StatusSchedule disabled = new StatusSchedule(ca, StatusObjectType.CRL, new FormatId("x509"), Duration.ofMinutes(10),
                    30, false, Optional.empty(), now, now, 0);
            fixture.store.putStatusSchedule(disabled);
            fixture.time(now.plusSeconds(7200));
            session.statusSchedules().orElseThrow().reconcile(current, CancellationSignal.NONE);
            assertEquals(4, fixture.dispatches.get());
        }
    }
}
