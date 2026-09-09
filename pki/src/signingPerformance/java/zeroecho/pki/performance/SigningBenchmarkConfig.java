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
package zeroecho.pki.performance;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Immutable command-line configuration for one signing macrobenchmark process. */
@SuppressWarnings({ "PMD.CommentDefaultAccessModifier", "PMD.UseVarargs", "PMD.CommentRequired",
        "PMD.UnnecessaryConstructor" })
record SigningBenchmarkConfig(String profile, TargetMode targetMode, String cellId, CellMode cellMode,
        int retainedPopulation, int activePopulation, int groupSize, long residentIndexBudgetBytes,
        long compactionTransientBudgetBytes,
        int warmupSeconds, int durationSeconds, int rate, int lanes, int queueCapacity,
        int providerMeanMillis, int providerJitterMillis, int payloadBytes,
        int sampleCapacity, int drainSeconds, long seed, boolean diagnosticEnvironmentOverride, Path output,
        Path workRoot) {

    private static final int MINIMUM_PAYLOAD_BYTES = 1;
    private static final int MAXIMUM_PAYLOAD_BYTES = 1_048_576;
    private static final int MAXIMUM_SAMPLE_CAPACITY = 10_000_000;
    private static final int MAXIMUM_RETAINED_POPULATION = 1_000_000;
    private static final int MAXIMUM_ACTIVE_POPULATION = 100_000;
    static final long DEFAULT_RESIDENT_INDEX_BUDGET_BYTES = 512L * 1024L * 1024L;
    static final long DEFAULT_COMPACTION_TRANSIENT_BUDGET_BYTES = 512L * 1024L * 1024L;

    SigningBenchmarkConfig {
        if (profile == null || profile.isBlank()) {
            throw new IllegalArgumentException("profile must not be blank");
        }
        Objects.requireNonNull(targetMode, "targetMode");
        if (cellId == null || !cellId.matches("[a-z0-9][a-z0-9-]{0,95}")) {
            throw new IllegalArgumentException("benchmark cellId is invalid");
        }
        Objects.requireNonNull(cellMode, "cellMode");
        if (retainedPopulation <= 0 || retainedPopulation > MAXIMUM_RETAINED_POPULATION
                || activePopulation <= 0 || activePopulation > MAXIMUM_ACTIVE_POPULATION
                || groupSize != 1 && groupSize != 8 && groupSize != 32 && groupSize != 64) {
            throw new IllegalArgumentException("benchmark population/group configuration is unsupported");
        }
        if (residentIndexBudgetBytes <= 0L) {
            throw new IllegalArgumentException("residentIndexBudgetBytes must be positive");
        }
        if (compactionTransientBudgetBytes <= 0L) {
            throw new IllegalArgumentException("compactionTransientBudgetBytes must be positive");
        }
        try {
            Math.addExact(residentIndexBudgetBytes, compactionTransientBudgetBytes);
        } catch (ArithmeticException overflow) {
            throw new IllegalArgumentException("combined index budget exceeds the supported range", overflow);
        }
        if (warmupSeconds < 0 || durationSeconds <= 0 || rate <= 0 || lanes <= 0 || queueCapacity < 0
                || providerMeanMillis < 0 || providerJitterMillis < 0
                || providerJitterMillis > providerMeanMillis || payloadBytes < MINIMUM_PAYLOAD_BYTES
                || payloadBytes > MAXIMUM_PAYLOAD_BYTES || sampleCapacity <= 0
                || sampleCapacity > MAXIMUM_SAMPLE_CAPACITY || drainSeconds <= 0) {
            throw new IllegalArgumentException("benchmark configuration is outside its supported range");
        }
        output = Objects.requireNonNull(output, "output").toAbsolutePath().normalize();
        workRoot = Objects.requireNonNull(workRoot, "workRoot").toAbsolutePath().normalize();
        long measurementArrivals = Math.multiplyExact((long) durationSeconds, rate);
        if (measurementArrivals > Integer.MAX_VALUE * 16L) {
            throw new IllegalArgumentException("measurement arrival count is too large");
        }
    }

    static SigningBenchmarkConfig parse(String[] arguments) {
        Map<String, String> values = parseArguments(arguments);
        String profile = values.getOrDefault("profile", "diagnostic");
        Preset preset = switch (profile) {
            case "acceptance" -> new Preset(TargetMode.NATIVE_SHARED_LEDGER, SigningBenchmarkGrid.ANCHOR_ID,
                    CellMode.GRID, 1_000_000, 100_000, 32,
                    30, 300, 1_100, 16, 64, 0, 0, 1_024, 1_000_000, 120);
            case "diagnostic" -> new Preset(TargetMode.LEGACY_FILESYSTEM_DIAGNOSTIC, "controlled-diagnostic",
                    CellMode.CONTROLLED_DIAGNOSTIC, 1_000, 10, 1,
                    5, 15, 100, 16, 64, 10, 2, 1_024, 100_000, 60);
            case "native-diagnostic" -> new Preset(TargetMode.NATIVE_SHARED_LEDGER,
                    "native-diagnostic-m1000-w10-l16-g32", CellMode.NATIVE_DIAGNOSTIC,
                    1_000, 10, 32, 5, 15, 100, 16, 64, 0, 0, 1_024, 100_000, 60);
            case "smoke" -> new Preset(TargetMode.NATIVE_SHARED_LEDGER, "native-smoke", CellMode.SMOKE,
                    3, 3, 1, 0, 1, 3, 1, 1, 0, 0, 1_024, 128, 30);
            default -> throw new IllegalArgumentException("unknown benchmark profile: " + profile);
        };
        rejectUnknown(values);
        return new SigningBenchmarkConfig(profile,
                TargetMode.parse(values.getOrDefault("target", preset.targetMode().commandValue())),
                values.getOrDefault("cellId", preset.cellId()),
                CellMode.parse(values.getOrDefault("cellMode", preset.cellMode().commandValue())),
                integer(values, "retainedPopulation", preset.retainedPopulation()),
                integer(values, "activePopulation", preset.activePopulation()),
                integer(values, "groupSize", preset.groupSize()),
                longValue(values, "residentIndexBudgetBytes", DEFAULT_RESIDENT_INDEX_BUDGET_BYTES),
                longValue(values, "compactionTransientBudgetBytes", DEFAULT_COMPACTION_TRANSIENT_BUDGET_BYTES),
                integer(values, "warmupSeconds", preset.warmupSeconds()),
                integer(values, "durationSeconds", preset.durationSeconds()),
                integer(values, "rate", preset.rate()), integer(values, "lanes", preset.lanes()),
                integer(values, "queueCapacity", preset.queueCapacity()),
                integer(values, "providerMeanMillis", preset.providerMeanMillis()),
                integer(values, "providerJitterMillis", preset.providerJitterMillis()),
                integer(values, "payloadBytes", preset.payloadBytes()),
                integer(values, "sampleCapacity", preset.sampleCapacity()),
                integer(values, "drainSeconds", preset.drainSeconds()),
                longValue(values, "seed", 0x5eed_2026L),
                booleanValue(values, "diagnosticEnvironmentOverride", false),
                Path.of(values.getOrDefault("output", "build/reports/signing-performance/result.json")),
                Path.of(values.getOrDefault("workRoot", "build/signing-performance/work")));
    }

    long measurementArrivals() {
        return Math.multiplyExact((long) durationSeconds, rate);
    }

    long warmupArrivals() {
        return Math.multiplyExact((long) warmupSeconds, rate);
    }

    String argumentsFingerprint() {
        String canonical = "profile=" + profile + "|target=" + targetMode.commandValue()
                + "|cellId=" + cellId + "|cellMode=" + cellMode.commandValue()
                + "|retainedPopulation=" + retainedPopulation
                + "|activePopulation=" + activePopulation + "|groupSize=" + groupSize
                + "|residentIndexBudgetBytes=" + residentIndexBudgetBytes
                + "|compactionTransientBudgetBytes=" + compactionTransientBudgetBytes
                + "|warmupSeconds=" + warmupSeconds + "|durationSeconds=" + durationSeconds
                + "|rate=" + rate + "|lanes=" + lanes + "|queueCapacity=" + queueCapacity
                + "|providerMeanMillis=" + providerMeanMillis
                + "|providerJitterMillis=" + providerJitterMillis
                + "|payloadBytes=" + payloadBytes + "|sampleCapacity=" + sampleCapacity
                + "|drainSeconds=" + drainSeconds + "|seed=" + seed
                + "|diagnosticEnvironmentOverride=" + diagnosticEnvironmentOverride
                + "|output=" + output + "|workRoot=" + workRoot;
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                    canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static Map<String, String> parseArguments(String[] arguments) {
        Objects.requireNonNull(arguments, "arguments");
        Map<String, String> values = new LinkedHashMap<>();
        for (String argument : arguments) {
            if (argument == null || !argument.startsWith("--") || argument.indexOf('=') < 3) {
                throw new IllegalArgumentException("benchmark arguments must use --name=value");
            }
            int separator = argument.indexOf('=');
            String name = argument.substring(2, separator);
            String value = argument.substring(separator + 1);
            if (value.isBlank() || values.putIfAbsent(name, value) != null) {
                throw new IllegalArgumentException("benchmark argument is blank or duplicated: " + name);
            }
        }
        return values;
    }

    private static void rejectUnknown(Map<String, String> values) {
        for (String name : values.keySet()) {
            if (!SetHolder.ALLOWED.containsKey(name)) {
                throw new IllegalArgumentException("unknown benchmark argument: " + name);
            }
        }
    }

    private static int integer(Map<String, String> values, String name, int fallback) {
        try {
            return values.containsKey(name) ? Integer.parseInt(values.get(name)) : fallback;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("benchmark argument must be an integer: " + name, invalid);
        }
    }

    private static long longValue(Map<String, String> values, String name, long fallback) {
        try {
            return values.containsKey(name) ? Long.parseLong(values.get(name)) : fallback;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("benchmark argument must be a long: " + name, invalid);
        }
    }

    private static boolean booleanValue(Map<String, String> values, String name, boolean fallback) {
        if (!values.containsKey(name)) {
            return fallback;
        }
        return switch (values.get(name)) {
            case "true" -> true;
            case "false" -> false;
            default -> throw new IllegalArgumentException("benchmark argument must be true or false: " + name);
        };
    }

    enum TargetMode {
        LEGACY_FILESYSTEM_DIAGNOSTIC("legacy-filesystem-diagnostic", "outer-bounded-executor"),
        NATIVE_SHARED_LEDGER("native-shared-ledger", "production-local-shared-ledger-step-scheduler");

        private final String commandValue;
        private final String admissionTopology;

        TargetMode(String commandValue, String admissionTopology) {
            this.commandValue = commandValue;
            this.admissionTopology = admissionTopology;
        }

        String commandValue() {
            return commandValue;
        }

        String admissionTopology() {
            return admissionTopology;
        }

        private static TargetMode parse(String value) {
            for (TargetMode mode : values()) {
                if (mode.commandValue.equals(value)) {
                    return mode;
                }
            }
            throw new IllegalArgumentException("unknown benchmark target: " + value);
        }
    }

    enum CellMode {
        GRID("grid"),
        CONTROLLED_DIAGNOSTIC("controlled-diagnostic"),
        NATIVE_DIAGNOSTIC("native-diagnostic"),
        SMOKE("smoke");

        private final String commandValue;

        CellMode(String commandValue) {
            this.commandValue = commandValue;
        }

        String commandValue() {
            return commandValue;
        }

        private static CellMode parse(String value) {
            for (CellMode mode : values()) {
                if (mode.commandValue.equals(value)) {
                    return mode;
                }
            }
            throw new IllegalArgumentException("unknown benchmark cell mode: " + value);
        }
    }

    private record Preset(TargetMode targetMode, String cellId, CellMode cellMode,
            int retainedPopulation, int activePopulation, int groupSize,
            int warmupSeconds, int durationSeconds, int rate, int lanes, int queueCapacity,
            int providerMeanMillis, int providerJitterMillis, int payloadBytes, int sampleCapacity,
            int drainSeconds) {
    }

    private static final class SetHolder {
        private static final Map<String, Boolean> ALLOWED = Map.ofEntries(
                Map.entry("profile", Boolean.TRUE), Map.entry("target", Boolean.TRUE),
                Map.entry("cellId", Boolean.TRUE), Map.entry("cellMode", Boolean.TRUE),
                Map.entry("retainedPopulation", Boolean.TRUE), Map.entry("activePopulation", Boolean.TRUE),
                Map.entry("groupSize", Boolean.TRUE),
                Map.entry("residentIndexBudgetBytes", Boolean.TRUE),
                Map.entry("compactionTransientBudgetBytes", Boolean.TRUE),
                Map.entry("warmupSeconds", Boolean.TRUE),
                Map.entry("durationSeconds", Boolean.TRUE), Map.entry("rate", Boolean.TRUE),
                Map.entry("lanes", Boolean.TRUE), Map.entry("queueCapacity", Boolean.TRUE),
                Map.entry("providerMeanMillis", Boolean.TRUE), Map.entry("providerJitterMillis", Boolean.TRUE),
                Map.entry("payloadBytes", Boolean.TRUE), Map.entry("sampleCapacity", Boolean.TRUE),
                Map.entry("drainSeconds", Boolean.TRUE), Map.entry("seed", Boolean.TRUE),
                Map.entry("diagnosticEnvironmentOverride", Boolean.TRUE),
                Map.entry("output", Boolean.TRUE), Map.entry("workRoot", Boolean.TRUE));

        private SetHolder() {
        }
    }
}
