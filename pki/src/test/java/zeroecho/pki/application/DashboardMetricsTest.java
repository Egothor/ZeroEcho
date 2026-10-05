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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.spi.ProviderConfig;

class DashboardMetricsTest {
    @Test void preservesMeasuredZeroAndSeparatesUnavailableFromCollectionFailure(@TempDir Path root) throws Exception {
        DashboardLiveSource source = new DashboardLiveSource() {
            @Override public long approvalPendingTotal() { return 0; }
            @Override public long auditProjectionFailureTotal() { throw new IllegalStateException("sensitive detail"); }
            @Override public long jvmHeapUsedBytes() { return 123; }
            @Override public long adminRequestsTotal() { return 7; }
        };
        try (PkiSession session = PkiSession.open(configuration(root),
                PkiSessionRuntimeDependencies.none().withDashboardLiveSource(source),
                Clock.fixed(Instant.parse("2026-10-05T12:00:00Z"), ZoneOffset.UTC))) {
            PkiOperationResult result = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    session.operations().execute(new PkiOperation.QueryServerMetrics(), CancellationSignal.NONE)).result();
            assertEquals(new PkiOperationValue.IntegerValue(0), result.fields().get("approvalPendingTotal"));
            assertEquals(new PkiOperationValue.IntegerValue(123), result.fields().get("jvmHeapUsedBytes"));
            assertFalse(result.fields().containsKey("auditProjectionFailureTotal"));
            assertFalse(result.fields().containsKey("statusScheduleWorkerRunning"));
            Map<String, PkiOperationValue> states = assertInstanceOf(PkiOperationValue.ObjectValue.class,
                    result.fields().get("metricStates")).fields();
            assertState(states.get("approvalPendingTotal"), "AVAILABLE", Optional.empty());
            assertState(states.get("auditProjectionFailureTotal"), "FAILED", Optional.of("COLLECTION_FAILED"));
            assertState(states.get("statusScheduleWorkerRunning"), "UNAVAILABLE", Optional.of("NOT_CONFIGURED"));
            assertFalse(result.toString().contains("sensitive"));
        }
    }

    @Test void absentSourceDoesNotFabricateZerosAndCancellationSurvives() {
        DashboardLiveSource.NONE.snapshot().values().forEach(metric -> {
            assertEquals(DashboardLiveSource.State.UNAVAILABLE, metric.state());
            assertFalse(metric.value().isPresent());
        });
        assertThrows(CancellationException.class, () -> DashboardLiveSource.collect(() -> { throw new CancellationException(); }));
        assertEquals(DashboardLiveSource.State.FAILED, DashboardLiveSource.collect(() -> -1).state());
        assertThrows(IllegalArgumentException.class,
                () -> DashboardLiveSource.Metric.unavailable("secret exception: detail"));
    }

    private static void assertState(PkiOperationValue value, String state, Optional<String> reason) {
        Map<String, PkiOperationValue> fields = assertInstanceOf(PkiOperationValue.ObjectValue.class, value).fields();
        assertEquals(new PkiOperationValue.Text(state), fields.get("state"));
        assertEquals(reason.map(PkiOperationValue.Text::new).orElse(null), fields.get("reason"));
    }

    private static PkiSessionConfiguration configuration(Path root) {
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", root.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of());
    }
}
