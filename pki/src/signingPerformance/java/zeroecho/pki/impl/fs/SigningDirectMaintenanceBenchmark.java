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

/** Opt-in direct maintenance characterization over real segmented-ledger primitives. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CommentRequired",
        "PMD.SystemPrintln", "PMD.UseObjectForClearerAPI" })
public final class SigningDirectMaintenanceBenchmark {
    static final String SCHEMA = "zeroecho-signing-direct-maintenance-v1";
    private static final String NAMESPACE = "io.zeroecho.pki.benchmark-maintenance";

    private SigningDirectMaintenanceBenchmark() {
        // entry point
    }

    /** Builds one fresh fixture, directly compacts once, and writes a diagnostic sidecar. */
    public static void main(String[] arguments) throws Exception {
        Configuration configuration = Configuration.parse(arguments);
        Result result = run(configuration);
        String json = result.toJson(configuration);
        writeReport(configuration.output(), json);
        System.out.println(json);
    }

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

    /* default */ static Result run(Configuration configuration) throws IOException {
        return run(configuration, System::nanoTime);
    }

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

    /* default */ record Configuration(int liveRecords, int sourceGenerations,
            int sealedSegments, long firstGenerationIdentity, long checkpointIdentity,
            long nextActiveIdentity, Path output, Path workRoot) {
        private static final int MAXIMUM_LIVE_RECORDS = 1_000_000;
        private static final int MAXIMUM_SOURCE_GENERATIONS = 64;
        private static final int MAXIMUM_SEALED_SEGMENTS = 63;

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

    /* default */ record Timings(long rotationToBoundaryNanos,
            long checkpointAfterBoundaryNanos, long totalCompactionNanos) {
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

    /* default */ record ManifestEvidence(long committedRevision, long committedSequence,
            int sealedCount, long activeIdentity, String activeName,
            Optional<String> checkpointName, String fingerprint) {
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

    /* default */ record Evidence(ManifestEvidence beforeManifest,
            ManifestEvidence afterManifest, long preSealedBytes, long postSealedBytes,
            long checkpointBytes, int checkpointLiveRecords, long sourceChannelsOpened,
            int reclaimedArtifacts, int reclaimedActions) {
        Evidence {
            Objects.requireNonNull(beforeManifest, "beforeManifest");
            Objects.requireNonNull(afterManifest, "afterManifest");
        }
    }

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

    /* default */ record Result(Timings timings, Evidence evidence, JvmDelta jvm) {
        Result {
            Objects.requireNonNull(timings, "timings");
            Objects.requireNonNull(evidence, "evidence");
            Objects.requireNonNull(jvm, "jvm");
        }

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

        /* default */ String reasonCode() {
            return reasonCode;
        }
    }

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

        /* default */ String reasonCode() {
            return reasonCode;
        }
    }
}
