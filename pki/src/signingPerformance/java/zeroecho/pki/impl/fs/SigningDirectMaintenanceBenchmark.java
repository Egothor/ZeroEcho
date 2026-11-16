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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.function.LongSupplier;
import zeroecho.pki.spi.store.MetadataKey;

/**
 * Opt-in direct maintenance characterization over real segmented-ledger primitives.
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CommentRequired",
        "PMD.SystemPrintln", "PMD.UseObjectForClearerAPI" })
public final class SigningDirectMaintenanceBenchmark {
    /**
     * Stable schema identifier emitted in this benchmark's JSON reports.
     */
    static final String SCHEMA = "zeroecho-signing-direct-maintenance-v1";
    private static final String NAMESPACE = "io.zeroecho.pki.benchmark-maintenance";

    private SigningDirectMaintenanceBenchmark() {
        // entry point
    }

    /**
     * Builds one fresh fixture, directly compacts once, and writes a diagnostic sidecar.
     *
     * @param arguments closed --name=value options selecting the benchmark scenario and report paths
     * @throws Exception if fixture preparation, measurement, filesystem access, or evidence validation fails
     */
    public static void main(String[] arguments) throws Exception {
        Configuration configuration = Configuration.parse(arguments);
        Result result = run(configuration);
        String json = result.toJson(configuration);
        writeReport(configuration.output(), json);
        System.out.println(json);
    }

    /**
     * Writes a complete JSON report without following a symbolic link at its destination.
     *
     * @param output JSON report destination outside the benchmark work image
     * @param json complete serialized JSON report to persist
     * @throws IOException if benchmark setup, filesystem access, measurement, or evidence validation fails
     * @throws NullPointerException if any of {@code output}, {@code json} is null
     */
    /* default */ static void writeReport(Path output, String json) throws IOException {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(json, "json");
        Path parent = output.getParent();
        if (parent == null) {
            throw new BenchmarkException("CONFIGURATION_INVALID");
        }
        try {
            Files.createDirectories(parent);
            if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)
                    && !Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)) {
                throw new BenchmarkException("REPORT_OUTPUT_INVALID");
            }
            Files.writeString(output, json + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    LinkOption.NOFOLLOW_LINKS);
        } catch (BenchmarkException failure) {
            throw failure;
        } catch (IOException failure) {
            throw new BenchmarkException("REPORT_OUTPUT_UNAVAILABLE", failure);
        }
    }

    /**
     * Builds a fresh production fixture and measures direct rotation, checkpoint, and reclamation.
     *
     * @param configuration validated benchmark scenario, limits, paths, and output metadata
     * @return measured result and production evidence; this method does not write the report
     * @throws IOException if benchmark setup, filesystem access, measurement, or evidence validation fails
     */
    /* default */ static Result run(Configuration configuration) throws IOException {
        return run(configuration, System::nanoTime);
    }

    /**
     * Builds a fresh production fixture and measures direct rotation, checkpoint, and reclamation.
     *
     * @param configuration validated benchmark scenario, limits, paths, and output metadata
     * @param nanoClock monotonic nanosecond source injected for deterministic timing checks
     * @return measured result and production evidence; this method does not write the report
     * @throws IOException if benchmark setup, filesystem access, measurement, or evidence validation fails
     * @throws NullPointerException if any of {@code configuration}, {@code nanoClock} is null
     */
    /* default */ static Result run(Configuration configuration, LongSupplier nanoClock)
            throws IOException {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(nanoClock, "nanoClock");
        prepareFreshWorkRoot(configuration.workRoot());
        try (Fixture fixture = Fixture.create(configuration)) {
            SigningManifestCodec.Manifest beforeManifest = fixture.maintenance().manifest();
            ManifestEvidence before = ManifestEvidence.from(beforeManifest);
            long preSealedBytes = sealedBytes(beforeManifest);
            JvmSample jvmBefore = JvmSample.capture();
            long started = nanoClock.getAsLong();
            long[] boundary = { Long.MIN_VALUE };
            int[] callbacks = { 0 };
            SigningLedgerMaintenance.Compaction compaction = fixture.maintenance().compact(
                    configuration.checkpointIdentity(), configuration.nextActiveIdentity(), () -> {
                        callbacks[0] = Math.incrementExact(callbacks[0]);
                        boundary[0] = nanoClock.getAsLong();
                    }, fixture);
            long returned = nanoClock.getAsLong();
            JvmSample jvmAfter = JvmSample.capture();
            Timings timings = Timings.checked(started, boundary[0], returned, callbacks[0]);

            SigningManifestCodec.Manifest afterManifest = fixture.maintenance().manifest();
            ManifestEvidence after = ManifestEvidence.from(afterManifest);
            long postSealedBytes = sealedBytes(afterManifest);
            fixture.trackMeasuredRotation(compaction.rotation());
            int artifactsBeforeReclaim = fixture.existingOldArtifacts();
            int reclaimedActions = fixture.maintenance().reclaim(configuration.sourceGenerations());
            int reclaimedArtifacts = Math.subtractExact(artifactsBeforeReclaim,
                    fixture.existingOldArtifacts());

            Evidence evidence = new Evidence(before, after, preSealedBytes, postSealedBytes,
                    compaction.checkpoint().length(), compaction.liveRecords(),
                    fixture.maintenance().sourceChannelsOpened(), reclaimedArtifacts,
                    reclaimedActions);
            verifyEvidence(configuration, evidence);
            return new Result(timings, evidence, JvmDelta.between(jvmBefore, jvmAfter));
        }
    }

    private static void verifyEvidence(Configuration configuration, Evidence evidence)
            throws BenchmarkException {
        int expectedSources = Math.addExact(configuration.sealedSegments(), 1);
        int expectedArtifacts = Math.multiplyExact(expectedSources, 2);
        if (evidence.beforeManifest().sealedCount() != configuration.sealedSegments()
                || evidence.afterManifest().sealedCount() != 0
                || evidence.afterManifest().checkpointName().isEmpty()
                || evidence.checkpointLiveRecords() != configuration.liveRecords()
                || evidence.sourceChannelsOpened() != expectedSources
                || evidence.reclaimedActions() != expectedSources
                || evidence.reclaimedArtifacts() != expectedArtifacts
                || evidence.checkpointBytes() <= 0L || evidence.preSealedBytes() <= 0L
                || evidence.postSealedBytes() != 0L) {
            throw new BenchmarkException("EVIDENCE_MISMATCH");
        }
    }

    private static long sealedBytes(SigningManifestCodec.Manifest manifest) {
        long bytes = 0L;
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            bytes = Math.addExact(bytes, segment.length());
        }
        return bytes;
    }

    private static void prepareFreshWorkRoot(Path workRoot) throws BenchmarkException {
        if (Files.exists(workRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new BenchmarkException("WORK_ROOT_NOT_FRESH");
        }
        Path parent = workRoot.getParent();
        if (parent == null) {
            throw new BenchmarkException("CONFIGURATION_INVALID");
        }
        try {
            Files.createDirectories(parent);
        } catch (IOException failure) {
            throw new BenchmarkException("FIXTURE_UNAVAILABLE_OR_INVALID", failure);
        }
        try {
            Files.createDirectory(workRoot);
        } catch (FileAlreadyExistsException failure) {
            throw new BenchmarkException("WORK_ROOT_NOT_FRESH", failure);
        } catch (IOException failure) {
            throw new BenchmarkException("FIXTURE_UNAVAILABLE_OR_INVALID", failure);
        }
    }

    /**
     * Explicit scenario configuration retained with the benchmark report.
     *
     * @param liveRecords retained live metadata records used by the maintenance fixture
     * @param sourceGenerations maximum source-generation count selected for direct compaction
     * @param sealedSegments sealed WAL segment count in the controlled image
     * @param firstGenerationIdentity first generation identity assigned to fixture WAL artifacts
     * @param checkpointIdentity fresh generation identity selected for the new checkpoint
     * @param nextActiveIdentity fresh generation identity selected for the post-maintenance active WAL
     * @param output JSON report destination outside the benchmark work image
     * @param workRoot benchmark-owned work directory; freshness requirements are enforced by the selected runner
     */
    /* default */ record Configuration(int liveRecords, int sourceGenerations,
            int sealedSegments, long firstGenerationIdentity, long checkpointIdentity,
            long nextActiveIdentity, Path output, Path workRoot) {
        private static final int MAXIMUM_LIVE_RECORDS = 1_000_000;
        private static final int MAXIMUM_SOURCE_GENERATIONS = 64;
        private static final int MAXIMUM_SEALED_SEGMENTS = 63;

        /**
         * Validates scenario bounds and normalizes the benchmark input/output paths.
         *
         * @param liveRecords retained live metadata records used by the maintenance fixture
         * @param sourceGenerations maximum source-generation count selected for direct compaction
         * @param sealedSegments sealed WAL segment count in the controlled image
         * @param firstGenerationIdentity first generation identity assigned to fixture WAL artifacts
         * @param checkpointIdentity fresh generation identity selected for the new checkpoint
         * @param nextActiveIdentity fresh generation identity selected for the post-maintenance active WAL
         * @param output JSON report destination outside the benchmark work image
         * @param workRoot benchmark-owned work directory; freshness requirements are enforced by the selected runner
         * @throws ContractException if populations, topology, identities, timing bounds, or path relationships violate this scenario
         * @throws NullPointerException if any of {@code output}, {@code workRoot} is null
         */
        Configuration {
            int actualSources;
            long highestFixtureIdentity;
            try {
                actualSources = Math.addExact(sealedSegments, 1);
                highestFixtureIdentity = Math.addExact(firstGenerationIdentity, sealedSegments);
            } catch (ArithmeticException failure) {
                throw new ContractException("CONFIGURATION_INVALID", failure);
            }
            if (liveRecords <= 0 || liveRecords > MAXIMUM_LIVE_RECORDS
                    || sourceGenerations <= 0
                    || sourceGenerations > MAXIMUM_SOURCE_GENERATIONS
                    || sealedSegments <= 0 || sealedSegments > MAXIMUM_SEALED_SEGMENTS
                    || actualSources > sourceGenerations || liveRecords < actualSources
                    || firstGenerationIdentity <= 0L || checkpointIdentity <= 0L
                    || nextActiveIdentity <= 0L || checkpointIdentity == nextActiveIdentity
                    || checkpointIdentity >= firstGenerationIdentity
                            && checkpointIdentity <= highestFixtureIdentity
                    || nextActiveIdentity >= firstGenerationIdentity
                            && nextActiveIdentity <= highestFixtureIdentity) {
                throw new ContractException("CONFIGURATION_INVALID");
            }
            output = Objects.requireNonNull(output, "output").toAbsolutePath().normalize();
            workRoot = Objects.requireNonNull(workRoot, "workRoot").toAbsolutePath().normalize();
            if (output.equals(workRoot) || output.startsWith(workRoot)) {
                throw new ContractException("CONFIGURATION_INVALID");
            }
        }

        /**
         * Parses the closed benchmark option set and enforces the scenario's bounded configuration.
         *
         * @param arguments closed --name=value benchmark options; duplicate or unknown options are rejected
         * @return validated normalized configuration
         * @throws ContractException if option syntax, names, numeric values, or scenario bounds are invalid
         */
        /* default */ static Configuration parse(String[] arguments) {
            Map<String, String> values = parseArguments(arguments);
            try {
                return new Configuration(integer(values, "liveRecords", 100_000),
                        integer(values, "sourceGenerations", 64),
                        integer(values, "sealedSegments", 8),
                        longValue(values, "firstGenerationIdentity", 1L),
                        longValue(values, "checkpointIdentity", 1_000_000L),
                        longValue(values, "nextActiveIdentity", 1_000_001L),
                        Path.of(values.getOrDefault("output",
                                "build/reports/signing-performance/direct-maintenance.json")),
                        Path.of(values.getOrDefault("workRoot",
                                "build/signing-performance/direct-maintenance")));
            } catch (NumberFormatException failure) {
                throw new ContractException("CONFIGURATION_INVALID", failure);
            }
        }

        /**
         * Computes the SHA-256 commitment of the canonical measurement-shaping configuration.
         *
         * @return lowercase hexadecimal configuration fingerprint; report/work paths are not measurement axes
         */
        /* default */ String fingerprint() {
            String canonical = "schema=" + SCHEMA + "|liveRecords=" + liveRecords
                    + "|sourceGenerations=" + sourceGenerations
                    + "|sealedSegments=" + sealedSegments
                    + "|firstGenerationIdentity=" + firstGenerationIdentity
                    + "|checkpointIdentity=" + checkpointIdentity
                    + "|nextActiveIdentity=" + nextActiveIdentity;
            return HexFormat.of().formatHex(SigningFormatSupport.sha256().digest(
                    canonical.getBytes(StandardCharsets.US_ASCII)));
        }

        private static Map<String, String> parseArguments(String[] arguments) {
            Objects.requireNonNull(arguments, "arguments");
            List<String> supported = List.of("liveRecords", "sourceGenerations",
                    "sealedSegments", "firstGenerationIdentity", "checkpointIdentity",
                    "nextActiveIdentity", "output", "workRoot");
            Map<String, String> values = new LinkedHashMap<>();
            for (String argument : arguments) {
                int separator = argument.indexOf('=');
                if (!argument.startsWith("--") || separator <= 2
                        || separator == argument.length() - 1) {
                    throw new ContractException("CONFIGURATION_INVALID");
                }
                String name = argument.substring(2, separator);
                if (!supported.contains(name)
                        || values.putIfAbsent(name, argument.substring(separator + 1)) != null) {
                    throw new ContractException("CONFIGURATION_INVALID");
                }
            }
            return values;
        }

        private static int integer(Map<String, String> values, String name, int fallback) {
            return Integer.parseInt(values.getOrDefault(name, Integer.toString(fallback)));
        }

        private static long longValue(Map<String, String> values, String name, long fallback) {
            return Long.parseLong(values.getOrDefault(name, Long.toString(fallback)));
        }
    }

    /**
     * Validated decomposition of direct-maintenance time around its rotation boundary.
     *
     * @param rotationToBoundaryNanos elapsed time from compaction start to its rotation boundary, in nanoseconds
     * @param checkpointAfterBoundaryNanos elapsed time from the boundary to compaction return, in nanoseconds
     * @param totalCompactionNanos total measured compaction duration, in nanoseconds
     */
    /* default */ record Timings(long rotationToBoundaryNanos,
            long checkpointAfterBoundaryNanos, long totalCompactionNanos) {
        /**
         * Validates one rotation boundary and computes nonnegative phase durations.
         *
         * @param started monotonic nanosecond timestamp before compaction
         * @param boundary monotonic nanosecond timestamp observed at the rotation boundary
         * @param returned monotonic nanosecond timestamp after compaction returned
         * @param callbacks number of boundary observations; exactly one is required
         * @return timings whose rotation and checkpoint components sum to the total
         * @throws BenchmarkException if benchmark setup, filesystem access, measurement, or evidence validation fails
         */
        /* default */ static Timings checked(long started, long boundary, long returned, int callbacks)
                throws BenchmarkException {
            try {
                long rotation = Math.subtractExact(boundary, started);
                long checkpoint = Math.subtractExact(returned, boundary);
                long total = Math.subtractExact(returned, started);
                if (callbacks != 1 || rotation < 0L || checkpoint < 0L || total < 0L
                        || Math.addExact(rotation, checkpoint) != total) {
                    throw new BenchmarkException("EVIDENCE_MISMATCH");
                }
                return new Timings(rotation, checkpoint, total);
            } catch (ArithmeticException failure) {
                throw new BenchmarkException("EVIDENCE_MISMATCH", failure);
            }
        }
    }

    /**
     * Immutable identity and commitment observations of one authoritative manifest.
     *
     * @param committedRevision authoritative manifest committed metadata revision
     * @param committedSequence authoritative manifest committed record sequence
     * @param sealedCount sealed WAL descriptor count in the manifest
     * @param activeIdentity active WAL generation identity
     * @param activeName store-local active WAL artifact name
     * @param checkpointName optional store-local checkpoint artifact name
     * @param fingerprint lowercase SHA-256 commitment of the encoded manifest or scenario configuration
     */
    /* default */ record ManifestEvidence(long committedRevision, long committedSequence,
            int sealedCount, long activeIdentity, String activeName,
            Optional<String> checkpointName, String fingerprint) {
        /**
         * Retains the benchmark evidence after checking its required components.
         *
         * @param committedRevision authoritative manifest committed metadata revision
         * @param committedSequence authoritative manifest committed record sequence
         * @param sealedCount sealed WAL descriptor count in the manifest
         * @param activeIdentity active WAL generation identity
         * @param activeName store-local active WAL artifact name
         * @param checkpointName optional store-local checkpoint artifact name
         * @param fingerprint lowercase SHA-256 commitment of the encoded manifest or scenario configuration
         * @throws NullPointerException if any of {@code activeName}, {@code checkpointName}, {@code fingerprint} is null
         */
        ManifestEvidence {
            Objects.requireNonNull(activeName, "activeName");
            checkpointName = Objects.requireNonNull(checkpointName, "checkpointName");
            Objects.requireNonNull(fingerprint, "fingerprint");
        }

        private static ManifestEvidence from(SigningManifestCodec.Manifest manifest) {
            byte[] encoded = SigningManifestCodec.encode(manifest);
            return new ManifestEvidence(manifest.committedRevision(), manifest.committedSequence(),
                    manifest.sealedSegments().size(), manifest.activeWal().identity(),
                    manifest.activeWal().name(), manifest.checkpoint().map(
                            SigningManifestCodec.Checkpoint::name),
                    HexFormat.of().formatHex(SigningFormatSupport.sha256().digest(encoded)));
        }
    }

    /**
     * Before/after artifact and reclamation evidence from direct maintenance.
     *
     * @param beforeManifest authoritative manifest evidence captured before maintenance
     * @param afterManifest authoritative manifest evidence captured after maintenance
     * @param preSealedBytes total sealed-artifact bytes before maintenance
     * @param postSealedBytes total sealed-artifact bytes after maintenance
     * @param checkpointBytes encoded checkpoint size, in bytes
     * @param checkpointLiveRecords live metadata record count emitted into the checkpoint
     * @param sourceChannelsOpened number of source artifact channels opened by direct maintenance
     * @param reclaimedArtifacts number of physical artifacts reclaimed
     * @param reclaimedActions number of classified reclamation actions completed
     */
    /* default */ record Evidence(ManifestEvidence beforeManifest,
            ManifestEvidence afterManifest, long preSealedBytes, long postSealedBytes,
            long checkpointBytes, int checkpointLiveRecords, long sourceChannelsOpened,
            int reclaimedArtifacts, int reclaimedActions) {
        /**
         * Retains the benchmark evidence after checking its required components.
         *
         * @param beforeManifest authoritative manifest evidence captured before maintenance
         * @param afterManifest authoritative manifest evidence captured after maintenance
         * @param preSealedBytes total sealed-artifact bytes before maintenance
         * @param postSealedBytes total sealed-artifact bytes after maintenance
         * @param checkpointBytes encoded checkpoint size, in bytes
         * @param checkpointLiveRecords live metadata record count emitted into the checkpoint
         * @param sourceChannelsOpened number of source artifact channels opened by direct maintenance
         * @param reclaimedArtifacts number of physical artifacts reclaimed
         * @param reclaimedActions number of classified reclamation actions completed
         * @throws NullPointerException if any of {@code beforeManifest}, {@code afterManifest} is null
         */
        Evidence {
            Objects.requireNonNull(beforeManifest, "beforeManifest");
            Objects.requireNonNull(afterManifest, "afterManifest");
        }
    }

    /**
     * JVM telemetry differences sampled around the measured operation.
     *
     * @param usedHeapDeltaBytes signed change in observed used heap, in bytes
     * @param gcCollections observed garbage-collection count delta
     * @param gcMillis observed garbage-collection time delta, in milliseconds
     * @param liveThreadAllocatedBytesEstimate estimated allocation delta, in bytes, or a negative unavailable sentinel
     */
    /* default */ record JvmDelta(long usedHeapDeltaBytes, long gcCollections,
            long gcMillis, long liveThreadAllocatedBytesEstimate) {
        private static JvmDelta between(JvmSample before, JvmSample after) {
            long allocated = before.allocatedBytes() < 0L
                    || after.allocatedBytes() < before.allocatedBytes()
                            ? -1L : after.allocatedBytes() - before.allocatedBytes();
            return new JvmDelta(after.usedHeapBytes() - before.usedHeapBytes(),
                    after.gcCollections() - before.gcCollections(),
                    after.gcMillis() - before.gcMillis(), allocated);
        }
    }

    private record JvmSample(long usedHeapBytes, long gcCollections,
            long gcMillis, long allocatedBytes) {
        private static JvmSample capture() {
            Runtime runtime = Runtime.getRuntime();
            long used = runtime.totalMemory() - runtime.freeMemory();
            long collections = 0L;
            long millis = 0L;
            for (GarbageCollectorMXBean collector :
                    ManagementFactory.getGarbageCollectorMXBeans()) {
                collections = Math.addExact(collections,
                        Math.max(0L, collector.getCollectionCount()));
                millis = Math.addExact(millis, Math.max(0L, collector.getCollectionTime()));
            }
            return new JvmSample(used, collections, millis, currentThreadAllocatedBytes());
        }

        private static long currentThreadAllocatedBytes() {
            java.lang.management.ThreadMXBean bean = ManagementFactory.getThreadMXBean();
            if (!(bean instanceof com.sun.management.ThreadMXBean allocation)
                    || !allocation.isThreadAllocatedMemorySupported()) {
                return -1L;
            }
            if (!allocation.isThreadAllocatedMemoryEnabled()) {
                allocation.setThreadAllocatedMemoryEnabled(true);
            }
            return allocation.getThreadAllocatedBytes(Thread.currentThread().threadId());
        }
    }

    /**
     * Measured timing and validated evidence returned by this benchmark run.
     *
     * @param timings validated direct-maintenance phase timings
     * @param evidence before/after manifest and artifact evidence
     * @param jvm JVM counter observations captured around the measurement
     */
    /* default */ record Result(Timings timings, Evidence evidence, JvmDelta jvm) {
        /**
         * Retains the benchmark evidence after checking its required components.
         *
         * @param timings validated direct-maintenance phase timings
         * @param evidence before/after manifest and artifact evidence
         * @param jvm JVM counter observations captured around the measurement
         * @throws NullPointerException if any of {@code timings}, {@code evidence}, {@code jvm} is null
         */
        Result {
            Objects.requireNonNull(timings, "timings");
            Objects.requireNonNull(evidence, "evidence");
            Objects.requireNonNull(jvm, "jvm");
        }

        /**
         * Serializes the measured result and its exact scenario/evidence coordinates as JSON.
         *
         * @param configuration validated benchmark scenario, limits, paths, and output metadata
         * @return complete JSON report without an acceptance verdict
         */
        /* default */ String toJson(Configuration configuration) {
            StringBuilder json = new StringBuilder(2_048).append('{');
            field(json, "schema", SCHEMA).append(',');
            field(json, "configurationFingerprint", configuration.fingerprint()).append(',');
            json.append("\"configuration\":{");
            number(json, "liveRecords", configuration.liveRecords()).append(',');
            number(json, "sourceGenerations", configuration.sourceGenerations()).append(',');
            number(json, "sealedSegments", configuration.sealedSegments()).append(',');
            number(json, "firstGenerationIdentity",
                    configuration.firstGenerationIdentity()).append(',');
            number(json, "checkpointIdentity", configuration.checkpointIdentity()).append(',');
            number(json, "nextActiveIdentity", configuration.nextActiveIdentity()).append(',');
            field(json, "output", configuration.output().toString()).append(',');
            field(json, "workRoot", configuration.workRoot().toString()).append("},");
            json.append("\"timing\":{");
            number(json, "rotationToBoundaryNanos",
                    timings.rotationToBoundaryNanos()).append(',');
            number(json, "checkpointAfterBoundaryNanos",
                    timings.checkpointAfterBoundaryNanos()).append(',');
            number(json, "totalCompactionNanos", timings.totalCompactionNanos()).append("},");
            json.append("\"evidence\":{");
            manifest(json, "manifestBefore", evidence.beforeManifest()).append(',');
            manifest(json, "manifestAfter", evidence.afterManifest()).append(',');
            number(json, "preSealedCount", evidence.beforeManifest().sealedCount()).append(',');
            number(json, "postSealedCount", evidence.afterManifest().sealedCount()).append(',');
            number(json, "preSealedBytes", evidence.preSealedBytes()).append(',');
            number(json, "postSealedBytes", evidence.postSealedBytes()).append(',');
            number(json, "checkpointBytes", evidence.checkpointBytes()).append(',');
            number(json, "checkpointLiveRecords", evidence.checkpointLiveRecords()).append(',');
            number(json, "sourceChannelsOpened", evidence.sourceChannelsOpened()).append(',');
            field(json, "rotationPublicationMode", "HARD_LINK").append(',');
            field(json, "zeroCopyEvidence", "STATIC_CODE_PATH").append(',');
            number(json, "reclaimedArtifacts", evidence.reclaimedArtifacts()).append(',');
            number(json, "reclaimedActions", evidence.reclaimedActions()).append("},");
            json.append("\"jvm\":{");
            number(json, "usedHeapDeltaBytes", jvm.usedHeapDeltaBytes()).append(',');
            number(json, "gcCollections", jvm.gcCollections()).append(',');
            number(json, "gcMillis", jvm.gcMillis()).append(',');
            if (jvm.liveThreadAllocatedBytesEstimate() < 0L) {
                json.append("\"liveThreadAllocatedBytesEstimate\":null,");
            } else {
                number(json, "liveThreadAllocatedBytesEstimate",
                        jvm.liveThreadAllocatedBytesEstimate()).append(',');
            }
            json.append("\"usedHeapIsRetainedHeapMeasurement\":false," )
                    .append("\"allocationScope\":\"LIVE_CALLER_THREAD_ESTIMATE\"},");
            json.append("\"contract\":{")
                    .append("\"directMaintenanceCharacterization\":true,")
                    .append("\"automaticEngineAdmissionContentionMeasured\":false,");
            field(json, "timeComplexity",
                    "O(L + B_live + S)").append(',');
            field(json, "auxiliaryMemory",
                    "O(L + B_batch + S), B_batch<=67108864 bytes, S<=64").append(',');
            json.append("\"diagnosticOnly\":true}");
            return json.append('}').toString();
        }

        private static StringBuilder manifest(StringBuilder json, String name,
                ManifestEvidence value) {
            quote(json, name).append(":{");
            number(json, "committedRevision", value.committedRevision()).append(',');
            number(json, "committedSequence", value.committedSequence()).append(',');
            number(json, "sealedCount", value.sealedCount()).append(',');
            number(json, "activeIdentity", value.activeIdentity()).append(',');
            field(json, "activeName", value.activeName()).append(',');
            if (value.checkpointName().isPresent()) {
                field(json, "checkpointName", value.checkpointName().orElseThrow()).append(',');
            } else {
                json.append("\"checkpointName\":null,");
            }
            return field(json, "fingerprint", value.fingerprint()).append('}');
        }

        private static StringBuilder field(StringBuilder json, String name, String value) {
            quote(json, name).append(':');
            return quote(json, value);
        }

        private static StringBuilder number(StringBuilder json, String name, long value) {
            quote(json, name).append(':').append(value);
            return json;
        }

        private static StringBuilder quote(StringBuilder json, String value) {
            json.append('"');
            for (int index = 0; index < value.length(); index++) {
                char current = value.charAt(index);
                switch (current) {
                    case '"', '\\' -> json.append('\\').append(current);
                    case '\b' -> json.append("\\b");
                    case '\f' -> json.append("\\f");
                    case '\n' -> json.append("\\n");
                    case '\r' -> json.append("\\r");
                    case '\t' -> json.append("\\t");
                    default -> {
                        if (current < 0x20) {
                            json.append(String.format(Locale.ROOT, "\\u%04x", (int) current));
                        } else {
                            json.append(current);
                        }
                    }
                }
            }
            return json.append('"');
        }
    }

    private static final class Fixture implements AutoCloseable {
        private final Configuration configuration;
        private final SigningGenerationRegistry generations;
        private final SigningMvccIndex index;
        private final SigningLedgerMaintenance maintenance;
        private final List<Path> oldArtifacts = new ArrayList<>();
        private long operationOrdinal;

        private Fixture(Configuration configuration, SigningGenerationRegistry generations,
                SigningMvccIndex index, SigningLedgerMaintenance maintenance) {
            this.configuration = configuration;
            this.generations = generations;
            this.index = index;
            this.maintenance = maintenance;
        }

        private static Fixture create(Configuration configuration) throws IOException {
            SigningGenerationRegistry generations = null;
            SigningMvccIndex index = null;
            SigningActiveWal active = null;
            SigningLedgerMaintenance maintenance = null;
            try {
                SigningLedgerRecovery.initializeFormat(configuration.workRoot());
                SigningActiveWal.Configuration activeConfiguration =
                        SigningActiveWal.Configuration.defaults(1);
                SigningActiveWal.Descriptor descriptor = new SigningActiveWal.Descriptor(
                        configuration.firstGenerationIdentity(), 0L, 0L);
                active = SigningActiveWal.open(configuration.workRoot().resolve(
                        SigningManifestCodec.activeName(descriptor.identity())),
                        descriptor, activeConfiguration);
                generations = new SigningGenerationRegistry();
                generations.create(descriptor.identity());
                generations.publish(descriptor.identity());
                SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(
                        FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
                SigningIndexCapacityBudget transientCapacity = new SigningIndexCapacityBudget(
                        FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
                long revisionSpan = Math.addExact(configuration.liveRecords(),
                        Math.addExact(configuration.sealedSegments(), 2L));
                index = new SigningMvccIndex(new SigningMvccIndex.Configuration(
                        configuration.liveRecords(), 4, revisionSpan, 0L),
                        generations, capacity, transientCapacity);
                SigningArtifactCatalog artifacts = new SigningArtifactCatalog();
                SigningManifestCodec.ActiveWal manifestActive = activeDescriptor(descriptor);
                artifacts.register(new SigningArtifactCatalog.Artifact(descriptor.identity(),
                        manifestActive.name(), SigningArtifactCatalog.Kind.ACTIVE_WAL));

                append(active, index, configuration, 0L, 0);
                SigningManifestCodec.Manifest manifest = new SigningManifestCodec.Manifest(
                        0L, 0L, Optional.empty(), List.of(), manifestActive);
                publishManifest(configuration.workRoot(), manifest);
                maintenance = new SigningLedgerMaintenance(configuration.workRoot(), manifest,
                        active, activeConfiguration, generations, index, artifacts,
                        new SigningLedgerMaintenance.Configuration(
                                256L * 1024L * 1024L, configuration.sourceGenerations()),
                        stage -> { });
                Fixture fixture = new Fixture(configuration, generations, index, maintenance);
                fixture.operationOrdinal = 1L;
                fixture.finishPopulation();
                return fixture;
            } catch (IOException | RuntimeException failure) {
                closeAfterFailure(maintenance != null ? maintenance : active, failure);
                closeAfterFailure(index, failure);
                closeAfterFailure(generations, failure);
                if (failure instanceof SigningLedgerMaintenance.MaintenanceException maintenanceFailure) {
                    throw maintenanceFailure;
                }
                if (failure instanceof IOException ioFailure) {
                    throw new BenchmarkException("FIXTURE_UNAVAILABLE_OR_INVALID", ioFailure);
                }
                throw new BenchmarkException("FIXTURE_UNAVAILABLE_OR_INVALID", failure);
            }
        }

        private void finishPopulation() throws IOException {
            for (int segment = 0; segment < configuration.sealedSegments(); segment++) {
                if (segment != 0) {
                    append(maintenance.activeWal(), index, configuration,
                            operationOrdinal++, segment);
                }
                SigningManifestCodec.ActiveWal prior = maintenance.manifest().activeWal();
                long nextIdentity = Math.addExact(configuration.firstGenerationIdentity(),
                        segment + 1L);
                SigningLedgerMaintenance.Rotation rotation = maintenance.rotate(nextIdentity);
                oldArtifacts.add(configuration.workRoot().resolve(prior.name()));
                oldArtifacts.add(configuration.workRoot().resolve(rotation.sealed().name()));
            }
            for (int record = configuration.sealedSegments();
                    record < configuration.liveRecords(); record++) {
                append(maintenance.activeWal(), index, configuration,
                        operationOrdinal++, record);
            }
        }

        private static void append(SigningActiveWal active, SigningMvccIndex index,
                Configuration configuration, long ordinal, int record) throws IOException {
            SigningActiveWal.CommitResult committed = await(active.submit(
                    SigningWalFrameCodec.RecordType.MUTATION,
                    new UUID(configuration.firstGenerationIdentity(), ordinal + 1L),
                    new byte[] { (byte) record }));
            SigningMvccIndex.RecordPointer pointer = new SigningMvccIndex.RecordPointer(
                    committed.generationIdentity(), committed.offset(), committed.frameLength(),
                    committed.sequence(), committed.revision(),
                    SigningWalFrameCodec.RecordType.MUTATION);
            MetadataKey key = new MetadataKey(NAMESPACE,
                    String.format(Locale.ROOT, "record-%08d", record));
            index.apply(committed.revision(), committed.sequence(),
                    List.of(SigningMvccIndex.Mutation.upsert(key, pointer)));
        }

        private void trackMeasuredRotation(SigningLedgerMaintenance.Rotation rotation) {
            oldArtifacts.add(configuration.workRoot().resolve(
                    SigningManifestCodec.activeName(rotation.sealed().generationIdentity())));
            oldArtifacts.add(configuration.workRoot().resolve(rotation.sealed().name()));
        }

        private int existingOldArtifacts() {
            int existing = 0;
            for (Path artifact : oldArtifacts) {
                if (Files.exists(artifact, LinkOption.NOFOLLOW_LINKS)) {
                    existing++;
                }
            }
            return existing;
        }

        private SigningLedgerMaintenance maintenance() {
            return maintenance;
        }

        @Override
        public void close() throws IOException {
            try {
                maintenance.close();
            } finally {
                try {
                    index.close();
                } finally {
                    generations.close();
                }
            }
        }

        private static void closeAfterFailure(AutoCloseable resource, Throwable failure) {
            if (resource == null) {
                return;
            }
            try {
                resource.close();
            } catch (Exception closeFailure) {
                failure.addSuppressed(closeFailure);
            }
        }

        private static SigningActiveWal.CommitResult await(
                SigningActiveWal.Acknowledgement acknowledgement) throws IOException {
            try {
                return acknowledgement.await();
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while preparing maintenance fixture", failure);
            } catch (ExecutionException failure) {
                throw new IOException("maintenance fixture WAL commit failed", failure.getCause());
            }
        }

        private static SigningManifestCodec.ActiveWal activeDescriptor(
                SigningActiveWal.Descriptor descriptor) {
            byte[] header = SigningWalContainerCodec.encode(new SigningWalContainerCodec.Header(
                    descriptor.identity(), descriptor.firstSequence(),
                    descriptor.baselineRevision()));
            return new SigningManifestCodec.ActiveWal(descriptor.identity(),
                    descriptor.firstSequence(), descriptor.baselineRevision(), header.length,
                    SigningFormatSupport.sha256().digest(header),
                    SigningManifestCodec.activeName(descriptor.identity()));
        }

        private static void publishManifest(Path root, SigningManifestCodec.Manifest manifest)
                throws IOException {
            byte[] encoded = SigningManifestCodec.encode(manifest);
            SigningFilePublisher.publishManifest(root.resolve(SigningLedgerRecovery.MANIFEST_FILE),
                    channel -> SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(encoded)));
        }
    }

    /**
     * Stable configuration-rejection exception for the benchmark command.
     */
    /* default */ static final class ContractException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        private final String reasonCode;

        private ContractException(String reasonCode) {
            super("signing direct-maintenance benchmark rejected: code=" + reasonCode);
            this.reasonCode = reasonCode;
        }

        private ContractException(String reasonCode, Throwable cause) {
            super("signing direct-maintenance benchmark rejected: code=" + reasonCode, cause);
            this.reasonCode = reasonCode;
        }

        /**
         * Returns the stable classification retained by this benchmark failure.
         *
         * @return caller-selected reason code without exception-graph rendering
         */
        /* default */ String reasonCode() {
            return reasonCode;
        }
    }

    /**
     * Stable fail-closed exception for benchmark execution or evidence mismatches.
     */
    /* default */ static final class BenchmarkException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String reasonCode;

        private BenchmarkException(String reasonCode) {
            super("signing direct-maintenance benchmark failed: code=" + reasonCode);
            this.reasonCode = reasonCode;
        }

        private BenchmarkException(String reasonCode, Throwable cause) {
            super("signing direct-maintenance benchmark failed: code=" + reasonCode, cause);
            this.reasonCode = reasonCode;
        }

        /**
         * Returns the stable classification retained by this benchmark failure.
         *
         * @return caller-selected reason code without exception-graph rendering
         */
        /* default */ String reasonCode() {
            return reasonCode;
        }
    }
}
