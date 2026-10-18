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

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.function.Consumer;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.schedule.StatusScheduleCoordinator;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.spi.store.PkiStore;

/** Bounded-page traversal of durable schedule work, including disabled unfinished executions. */
final class StatusScheduleExecutor implements StatusScheduleWorker.ScheduleGateway {
    private static final int PAGE_SIZE = 200;
    private final Optional<StatusScheduleCoordinator> coordinator;
    private final Clock clock;
    private final Consumer<String> failure;

    /* default */ StatusScheduleExecutor(Optional<StatusScheduleCoordinator> coordinator, Clock clock, Consumer<String> failure) {
        this.coordinator = Objects.requireNonNull(coordinator, "coordinator");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.failure = Objects.requireNonNull(failure, "failure");
    }

    @Override public StatusScheduleWorker.PassHints execute(CancellationSignal cancellation) {
        if (coordinator.isEmpty()) { return StatusScheduleWorker.PassHints.idle(); }
        StatusScheduleCoordinator service = coordinator.orElseThrow();
        Optional<String> after = Optional.empty();
        Optional<Instant> earliest = Optional.empty();
        boolean immediate = false;
        for (;;) {
            if (cancellation.isCancelled()) { return StatusScheduleWorker.PassHints.idle(); }
            List<StatusScheduleState> page = service.listWork(after, PAGE_SIZE, cancellation);
            for (StatusScheduleState observed : page) {
                if (cancellation.isCancelled()) { return StatusScheduleWorker.PassHints.idle(); }
                try {
                    StatusScheduleState current = service.reconcile(observed, cancellation);
                    if (eligible(current, observed)) {
                        if (current.nextDue().isAfter(clock.instant())) {
                            earliest = earlier(earliest, current.nextDue());
                        } else {
                            immediate = true;
                        }
                    }
                } catch (CancellationException cancelled) {
                    throw cancelled;
                } catch (RuntimeException failed) { // NOPMD AvoidCatchingGenericException - Isolate one schedule failure; cancellation is handled separately and only a fixed code is reported.
                    if (cancellation.isCancelled()) { return StatusScheduleWorker.PassHints.idle(); }
                    failure.accept("STATUS_SCHEDULE_EXECUTION_FAILED");
                }
            }
            if (page.size() < PAGE_SIZE) { break; }
            after = Optional.of(PkiStore.statusScheduleCursor(page.getLast().configuration()));
        }
        return new StatusScheduleWorker.PassHints(immediate, earliest);
    }

    private static Optional<Instant> earlier(Optional<Instant> previous, Instant candidate) {
        return previous.isEmpty() || candidate.isBefore(previous.orElseThrow()) ? Optional.of(candidate) : previous;
    }

    private boolean eligible(StatusScheduleState current, StatusScheduleState observed) {
        if (current.execution().filter(value -> value.phase() == StatusScheduleState.Phase.FAILED).isPresent()) {
            if (!current.execution().equals(observed.execution())) { failure.accept("STATUS_SCHEDULE_FAILED"); }
            return false;
        }
        return current.configuration().enabled() && current.execution().filter(
                value -> value.phase() != StatusScheduleState.Phase.SCHEDULE_ADVANCED).isEmpty();
    }
}
