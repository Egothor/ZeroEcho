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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.concurrent.CancellationException;
import java.util.function.LongSupplier;

/**
 * Server-layer live counters injected into dashboard metric computation.
 *
 * <p>The default {@link #NONE} reports unavailable measurements in its snapshot and retains
 * zero-returning legacy getters for compatibility. The {@code pki-server} layer provides a
 * concrete implementation wired to the running process.</p>
 */
public interface DashboardLiveSource {

    /** {@return unexpired approvals currently in PENDING state across all CAs} */
    long approvalPendingTotal();

    /** {@return sum of consecutive failure counts across all active audit projection workers} */
    long auditProjectionFailureTotal();

    /** {@return JVM heap currently used in bytes} */
    long jvmHeapUsedBytes();

    /** {@return monotonic total admin API requests counted since server start} */
    long adminRequestsTotal();

    /** Availability of one independently collected measurement. */
    enum State {
        /** A real measurement, including zero. */ AVAILABLE,
        /** No source is configured for this measurement. */ UNAVAILABLE,
        /** The configured source could not collect this measurement. */ FAILED
    }

    /**
     * Immutable measurement without exception or provider details.
     * @param state collection state
     * @param value nonnegative value, present exactly when available
     * @param reason stable safe reason code, empty when available
     */
    record Metric(State state, OptionalLong value, String reason) {
        /** Validates the value and disclosure invariants. */
        public Metric {
            Objects.requireNonNull(state, "state"); Objects.requireNonNull(value, "value"); Objects.requireNonNull(reason, "reason");
            if (state == State.AVAILABLE != value.isPresent() || value.isPresent() && value.orElseThrow() < 0
                    || state == State.AVAILABLE != reason.isEmpty() || !reason.matches("[A-Z0-9_]{0,64}")) {
                throw new IllegalArgumentException("Invalid dashboard measurement");
            }
        }
        /**
         * Creates a measurement from a real observation, including zero.
         * @param value nonnegative measured value
         * @return available measurement
         */
        public static Metric available(long value) { return new Metric(State.AVAILABLE, OptionalLong.of(value), ""); }
        /**
         * Creates an explicit unavailable measurement without a numeric value.
         * @param reason safe unavailable reason
         * @return unavailable measurement
         */
        public static Metric unavailable(String reason) { return new Metric(State.UNAVAILABLE, OptionalLong.empty(), reason); }
    }

    /**
     * Collects each legacy getter independently; custom four-getter sources remain compatible.
     * @return immutable measurements, preserving unavailable and failed states
     */
    default Map<String, Metric> snapshot() {
        Map<String, Metric> result = new LinkedHashMap<>();
        result.put("approvalPendingTotal", collect(this::approvalPendingTotal));
        result.put("auditProjectionFailureTotal", collect(this::auditProjectionFailureTotal));
        result.put("jvmHeapUsedBytes", collect(this::jvmHeapUsedBytes));
        result.put("adminRequestsTotal", collect(this::adminRequestsTotal));
        result.put("statusScheduleFailureTotal", Metric.unavailable("NOT_CONFIGURED"));
        result.put("statusScheduleWorkerRunning", Metric.unavailable("NOT_CONFIGURED"));
        return Map.copyOf(result);
    }

    /**
     * Safely collects one nonnegative metric while preserving cancellation.
     * @param supplier configured source
     * @return measured value or a safe collection-failed state
     */
    static Metric collect(LongSupplier supplier) {
        try { return Metric.available(supplier.getAsLong()); }
        catch (CancellationException cancelled) { throw cancelled; }
        catch (RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
            if (Thread.currentThread().isInterrupted()) { throw new CancellationException("Metric collection interrupted"); } // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
            return new Metric(State.FAILED, OptionalLong.empty(), "COLLECTION_FAILED");
        }
    }

    /** Unavailable source; legacy getters still return {@code 0}. */
    DashboardLiveSource NONE = new DashboardLiveSource() {
        @Override public long approvalPendingTotal() { return 0L; }
        @Override public long auditProjectionFailureTotal() { return 0L; }
        @Override public long jvmHeapUsedBytes() { return 0L; }
        @Override public long adminRequestsTotal() { return 0L; }
        @Override public Map<String, Metric> snapshot() {
            Map<String, Metric> result = new LinkedHashMap<>();
            for (String name : new String[]{"approvalPendingTotal", "auditProjectionFailureTotal", "jvmHeapUsedBytes",
                    "adminRequestsTotal", "statusScheduleFailureTotal", "statusScheduleWorkerRunning"}) {
                result.put(name, Metric.unavailable("NOT_CONFIGURED"));
            }
            return Map.copyOf(result);
        }
    };
}
