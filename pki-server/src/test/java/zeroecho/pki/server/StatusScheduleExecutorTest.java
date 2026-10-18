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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.schedule.StatusScheduleCoordinator;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.spi.store.PkiStore;

class StatusScheduleExecutorTest {
    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test void traversesAllPagesAndDisabledUnfinishedWorkDespiteOneFailure() {
        List<StatusScheduleState> rows = new ArrayList<>();
        for (int index = 0; index < 205; index++) rows.add(state(index, index != 204));
        AtomicInteger visits = new AtomicInteger();
        List<String> failures = new ArrayList<>();
        StatusScheduleCoordinator service = new StatusScheduleCoordinator() {
            @Override public List<StatusScheduleState> listWork(Optional<String> after, int limit, CancellationSignal cancellation) {
                assertEquals(200, limit);
                if (after.isEmpty()) return rows.subList(0, 200);
                assertEquals(PkiStore.statusScheduleCursor(rows.get(199).configuration()), after.orElseThrow());
                return rows.subList(200, rows.size());
            }
            @Override public StatusScheduleState reconcile(StatusScheduleState observed, CancellationSignal cancellation) {
                if (visits.getAndIncrement() == 0) throw new IllegalStateException("secret must not escape");
                return observed;
            }
        };
        StatusScheduleWorker.PassHints hints = new StatusScheduleExecutor(Optional.of(service), CLOCK, failures::add)
                .execute(CancellationSignal.NONE);
        assertEquals(205, visits.get());
        assertEquals(List.of("STATUS_SCHEDULE_EXECUTION_FAILED"), failures);
        assertFalse(hints.immediate());
        assertEquals(Optional.of(NOW.plusSeconds(60)), hints.nextEligible());
    }

    @Test void reportsFailedTransitionOnceButDoesNotCountRepeatedObservationAsFailure() {
        StatusScheduleState observed = state(1, true);
        StatusScheduleState.Execution execution = new StatusScheduleState.Execution("a".repeat(64),
                observed.configuration(), NOW, 1, StatusScheduleState.Phase.FAILED,
                Optional.of(new PkiId("sign:1")), "commitment", Optional.empty(), "SIGNING_FAILED");
        StatusScheduleState failed = new StatusScheduleState(observed.configuration(), NOW, 1, Optional.of(execution));
        AtomicInteger passes = new AtomicInteger();
        List<String> failures = new ArrayList<>();
        StatusScheduleCoordinator service = new StatusScheduleCoordinator() {
            @Override public List<StatusScheduleState> listWork(Optional<String> after, int limit, CancellationSignal cancellation) {
                return List.of(passes.getAndIncrement() == 0 ? observed : failed);
            }
            @Override public StatusScheduleState reconcile(StatusScheduleState state, CancellationSignal cancellation) { return failed; }
        };
        StatusScheduleExecutor executor = new StatusScheduleExecutor(Optional.of(service), CLOCK, failures::add);
        for (int pass = 0; pass < 3; pass++) assertFalse(executor.execute(CancellationSignal.NONE).immediate());
        assertEquals(List.of("STATUS_SCHEDULE_FAILED"), failures);
    }

    @Test void cancellationDoesNotBecomeAnExecutionFailure() {
        List<String> failures = new ArrayList<>();
        StatusScheduleCoordinator service = new StatusScheduleCoordinator() {
            @Override public List<StatusScheduleState> listWork(Optional<String> after, int limit, CancellationSignal cancellation) {
                return List.of(state(0, true));
            }
            @Override public StatusScheduleState reconcile(StatusScheduleState state, CancellationSignal cancellation) {
                throw new CancellationException();
            }
        };
        StatusScheduleExecutor executor = new StatusScheduleExecutor(Optional.of(service), CLOCK, failures::add);
        assertThrows(CancellationException.class, () -> executor.execute(CancellationSignal.NONE));
        assertEquals(List.of(), failures);
        assertEquals(StatusScheduleWorker.PassHints.idle(), executor.execute(() -> true));
    }

    private static StatusScheduleState state(int index, boolean enabled) {
        StatusSchedule config = new StatusSchedule(new PkiId("ca:" + index), StatusObjectType.CRL,
                new FormatId("x509"), Duration.ofMinutes(10), 30, enabled, Optional.empty(), NOW, NOW, 1);
        return new StatusScheduleState(config, NOW.plusSeconds(60), 0, Optional.empty());
    }
}
