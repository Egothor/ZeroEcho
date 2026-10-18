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
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongSupplier;

import zeroecho.pki.spi.store.MetadataStoreId;

/** Opt-in prepare/recover characterization over one controlled production ledger image. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CommentRequired",
        "PMD.SystemPrintln", "PMD.UseObjectForClearerAPI" })
public final class SigningRecoveryBenchmark {
    static final String SCHEMA = "zeroecho-signing-production-recovery-v1";

    private SigningRecoveryBenchmark() {
    }

    /** Prepares or recovers exactly one configured production-ledger image. */
    public static void main(String[] arguments) throws Exception {
        Configuration configuration = Configuration.parse(arguments);
        if (configuration.mode() == Mode.PREPARE_ONLY) {
            SigningControlledRecoveryImage.Descriptor descriptor =
                    SigningControlledRecoveryImage.prepare(configuration.workRoot(),
                            configuration.retainedPopulation(), configuration.activePopulation(),
                            configuration.sealedSegments(), configuration.suffixFrames(),
                            configuration.createdAt());
            System.out.println(descriptorJson(descriptor));
            return;
        }
        Result result = recover(configuration, System::nanoTime);
        String json = result.toJson(configuration);
        SigningDirectMaintenanceBenchmark.writeReport(configuration.output(), json);
        System.out.println(json);
    }

    static Result recover(Configuration configuration, LongSupplier nanoClock) throws IOException {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(nanoClock, "nanoClock");
        SigningControlledRecoveryImage.Descriptor descriptor =
                SigningControlledRecoveryImage.validate(configuration.workRoot(),
                        configuration.retainedPopulation(), configuration.activePopulation(),
                        configuration.sealedSegments(), configuration.suffixFrames());
        FsPaths paths = new FsPaths(configuration.workRoot().resolve("store"));
        Path metadataRoot = paths.transactionalMetadataRoot();
        String signingNamespace = Files.readString(paths.signingNamespaceFile()).trim();
        JvmSample before = JvmSample.capture();
        long started = nanoClock.getAsLong();
        SegmentedTransactionalMetadataStore store = SegmentedTransactionalMetadataStore.open(
                metadataRoot, new MetadataStoreId(signingNamespace),
                SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                SigningActiveWal.Configuration.defaults(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES,
                FilesystemStagedContentStore.readOnlyResolver(
                        paths.stagedContentRoot(), signingNamespace));
        long returned = nanoClock.getAsLong();
        JvmSample after = JvmSample.capture();
        SigningLedgerStoreEngine.CapacityObservation capacity;
        SigningLedgerStoreEngine.RecoveryProjectionStatistics projectionRecovery;
        SigningActiveWal.Snapshot writer;
        SigningLedgerRecovery.Statistics recovery;
        try (store) {
            capacity = store.capacityObservation();
            projectionRecovery = store.recoveryProjectionStatistics();
            writer = store.writerSnapshot();
            recovery = store.recoveryStatistics();
        }
        long elapsed;
        try {
            elapsed = Math.subtractExact(returned, started);
        } catch (ArithmeticException failure) {
            throw new BenchmarkException("EVIDENCE_MISMATCH", failure);
        }
        if (elapsed < 0L) {
            throw new BenchmarkException("EVIDENCE_MISMATCH");
        }
        ArtifactEvidence artifacts = ArtifactEvidence.capture(metadataRoot,
                SigningControlledRecoveryImage.readManifest(metadataRoot));
        Result result = new Result(elapsed, descriptor, capacity, projectionRecovery,
                recovery, artifacts, JvmDelta.between(before, after));
        verify(configuration, result, writer);
        return result;
    }

    private static void verify(Configuration configuration, Result result,
            SigningActiveWal.Snapshot writer) throws IOException {
        SigningLedgerStoreEngine.CapacityObservation capacity = result.capacity();
        SigningLedgerStoreEngine.RecoveryProjectionStatistics projection =
                result.projectionRecovery();
        SigningLedgerRecovery.Statistics recovery = result.recovery();
        ArtifactEvidence artifacts = result.artifacts();
        int expectedGenerations = Math.addExact(configuration.sealedSegments(), 2);
        int expectedRootEntries = Math.addExact(configuration.sealedSegments(), 4);
        long expectedReferences;
        try {
            expectedReferences = Math.addExact(configuration.retainedPopulation(),
                    configuration.activePopulation());
        } catch (ArithmeticException failure) {
            throw new BenchmarkException("EVIDENCE_MISMATCH", failure);
        }
        if (capacity.currentKeys() != configuration.retainedPopulation()
                || capacity.dueWork() != configuration.activePopulation()
                || capacity.ownerWork() != 0
                || capacity.projectedIdentities() != configuration.activePopulation()
                || capacity.retentionRecords() != 0
                || capacity.generationCurrentReferences() != expectedReferences
                || capacity.generationSnapshotPins() != 0L
                || capacity.registeredGenerations() != expectedGenerations
                || capacity.publishedGenerations() != expectedGenerations
                || projection.envelopesVisited() != configuration.activePopulation()
                || projection.statesVisited() != configuration.activePopulation()
                || projection.bindingsVisited() != configuration.activePopulation()
                || projection.outerRecordsVisited() != 0L
                || projection.activeEntriesBuilt() != configuration.activePopulation()
                || projection.statePointersRetained() != configuration.activePopulation()
                || (configuration.activePopulation() > 0L
                        && projection.peakTrackedEnvelopeWorkspaceBytes() <= 0L)
                || projection.currentTrackedEnvelopeWorkspaceBytes() != 0L
                || recovery.rootEntries() != expectedRootEntries
                || recovery.checkpointEntries() != configuration.retainedPopulation()
                || recovery.sealedSegments() != configuration.sealedSegments()
                || recovery.sealedFrames() != configuration.suffixFrames()
                || recovery.activeFrames() != 0L || recovery.truncatedBytes() != 0L
                || recovery.staleTemporaryFiles() != 0L
                || recovery.unreferencedArtifacts() != 0L
                || artifacts.checkpointEntries() != configuration.retainedPopulation()
                || artifacts.sealedSegments() != configuration.sealedSegments()
                || artifacts.suffixFrames() != configuration.suffixFrames()
                || artifacts.activeBytes() != SigningWalContainerCodec.HEADER_BYTES
                || writer.requestsCommitted() != 0L || writer.outstandingRequests() != 0
                || writer.queueDepth() != 0) {
            throw new BenchmarkException("EVIDENCE_MISMATCH");
        }
    }

    private static String descriptorJson(SigningControlledRecoveryImage.Descriptor descriptor) {
        return new StringBuilder(256).append('{')
                .append("\"schema\":\"")
                .append(SigningControlledRecoveryImage.DESCRIPTOR_SCHEMA).append("\",")
                .append("\"retainedPopulation\":").append(descriptor.retainedPopulation())
                .append(",\"activePopulation\":").append(descriptor.activePopulation())
                .append(",\"sealedSegments\":").append(descriptor.sealedSegments())
                .append(",\"suffixFrames\":").append(descriptor.suffixFrames())
                .append(",\"synthetic\":false,\"descriptorFingerprint\":\"")
                .append(descriptor.descriptorFingerprint()).append("\"}").toString();
    }

    enum Mode {
        PREPARE_ONLY,
        RECOVER_ONLY
    }

    record Configuration(Mode mode, long retainedPopulation, long activePopulation,
            int sealedSegments, long suffixFrames, Instant createdAt, Path output, Path workRoot) {
        Configuration {
            Objects.requireNonNull(mode, "mode");
            Objects.requireNonNull(createdAt, "createdAt");
            if (retainedPopulation <= 0L || retainedPopulation > 1_000_000L
                    || activePopulation < 0L || activePopulation > 1_000_000L
                    || sealedSegments < 1 || sealedSegments > 4096
                    || suffixFrames < sealedSegments || suffixFrames > 1_000_000L) {
                throw new ContractException("CONFIGURATION_INVALID");
            }
            try {
                if (Math.addExact(Math.multiplyExact(2L, activePopulation), 1L)
                        >= retainedPopulation) {
                    throw new ContractException("CONFIGURATION_INVALID");
                }
            } catch (ArithmeticException failure) {
                throw new ContractException("CONFIGURATION_INVALID", failure);
            }
            output = Objects.requireNonNull(output, "output").toAbsolutePath().normalize();
            workRoot = Objects.requireNonNull(workRoot, "workRoot").toAbsolutePath().normalize();
            if (output.equals(workRoot) || output.startsWith(workRoot)) {
                throw new ContractException("CONFIGURATION_INVALID");
            }
        }

        static Configuration parse(String[] arguments) {
            Map<String, String> values = parseArguments(arguments);
            try {
                int segments = integer(values, "sealedSegments", 4096);
                return new Configuration(mode(values.get("mode")),
                        longValue(values, "retainedPopulation", 1_000_000L),
                        longValue(values, "activePopulation", 100_000L), segments,
                        longValue(values, "suffixFrames", segments),
                        Instant.ofEpochMilli(longValue(values, "createdAtEpochMilli",
                                1_800_000_000_000L)),
                        Path.of(values.getOrDefault("output",
                                "build/reports/signing-performance/recovery.json")),
                        Path.of(values.getOrDefault("workRoot",
                                "build/signing-performance/recovery")));
            } catch (NumberFormatException | java.time.DateTimeException failure) {
                throw new ContractException("CONFIGURATION_INVALID", failure);
            }
        }

        private static Map<String, String> parseArguments(String[] arguments) {
            Objects.requireNonNull(arguments, "arguments");
            Map<String, String> values = new LinkedHashMap<>();
            for (String argument : arguments) {
                int separator = argument.indexOf('=');
                if (!argument.startsWith("--") || separator <= 2
                        || separator == argument.length() - 1) {
                    throw new ContractException("CONFIGURATION_INVALID");
                }
                String name = argument.substring(2, separator);
                if (!List.of("mode", "retainedPopulation", "activePopulation",
                        "sealedSegments", "suffixFrames", "createdAtEpochMilli", "output",
                        "workRoot").contains(name)
                        || values.putIfAbsent(name, argument.substring(separator + 1)) != null) {
                    throw new ContractException("CONFIGURATION_INVALID");
                }
            }
            return values;
        }

        private static Mode mode(String value) {
            if ("prepare-only".equals(value)) {
                return Mode.PREPARE_ONLY;
            }
            if ("recover-only".equals(value)) {
                return Mode.RECOVER_ONLY;
            }
            throw new ContractException("CONFIGURATION_INVALID");
        }

        private static int integer(Map<String, String> values, String name, int fallback) {
            return Integer.parseInt(values.getOrDefault(name, Integer.toString(fallback)));
        }

        private static long longValue(Map<String, String> values, String name, long fallback) {
            return Long.parseLong(values.getOrDefault(name, Long.toString(fallback)));
        }

        /* default */ String fingerprint() {
            String canonical = "schema=" + SCHEMA + "|mode=" + mode
                    + "|retainedPopulation=" + retainedPopulation
                    + "|activePopulation=" + activePopulation
                    + "|sealedSegments=" + sealedSegments
                    + "|suffixFrames=" + suffixFrames;
            return HexFormat.of().formatHex(SigningFormatSupport.sha256().digest(
                    canonical.getBytes(StandardCharsets.US_ASCII)));
        }
    }

    record ArtifactEvidence(long manifestBytes, long checkpointBytes, int checkpointEntries,
            int sealedSegments, long sealedBytes, long suffixFrames, long activeBytes) {
        private static ArtifactEvidence capture(Path root,
                SigningManifestCodec.Manifest manifest) throws IOException {
            SigningManifestCodec.Checkpoint checkpoint = manifest.checkpoint().orElseThrow(
                    () -> new BenchmarkException("EVIDENCE_MISMATCH"));
            Path checkpointPath = root.resolve(checkpoint.name());
            int entries;
            try (FileChannel channel = FileChannel.open(checkpointPath, StandardOpenOption.READ,
                    LinkOption.NOFOLLOW_LINKS)) {
                entries = SigningCheckpointCodec.reader(channel).header().entryCount();
            }
            long sealedBytes = 0L;
            long suffixFrames = 0L;
            for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
                long actual = Files.size(root.resolve(segment.name()));
                if (actual != segment.length()) {
                    throw new BenchmarkException("EVIDENCE_MISMATCH");
                }
                sealedBytes = Math.addExact(sealedBytes, actual);
                suffixFrames = Math.addExact(suffixFrames, segment.sequenceCount());
            }
            long checkpointBytes = Files.size(checkpointPath);
            long activeBytes = Files.size(root.resolve(manifest.activeWal().name()));
            if (checkpointBytes != checkpoint.length()
                    || activeBytes != manifest.activeWal().length()) {
                throw new BenchmarkException("EVIDENCE_MISMATCH");
            }
            return new ArtifactEvidence(
                    Files.size(root.resolve(SigningLedgerRecovery.MANIFEST_FILE)),
                    checkpointBytes, entries, manifest.sealedSegments().size(), sealedBytes,
                    suffixFrames, activeBytes);
        }
    }

    record Result(long openNanos, SigningControlledRecoveryImage.Descriptor descriptor,
            SigningLedgerStoreEngine.CapacityObservation capacity,
            SigningLedgerStoreEngine.RecoveryProjectionStatistics projectionRecovery,
            SigningLedgerRecovery.Statistics recovery, ArtifactEvidence artifacts, JvmDelta jvm) {
        String toJson(Configuration configuration) {
            StringBuilder json = new StringBuilder(2048).append('{');
            field(json, "schema", SCHEMA).append(',');
            field(json, "mode", "RECOVER_ONLY").append(',');
            field(json, "configurationFingerprint", configuration.fingerprint()).append(',');
            json.append("\"configuration\":{");
            number(json, "retainedPopulation", configuration.retainedPopulation()).append(',');
            number(json, "activePopulation", configuration.activePopulation()).append(',');
            number(json, "sealedSegments", configuration.sealedSegments()).append(',');
            number(json, "suffixFrames", configuration.suffixFrames()).append("},");
            number(json, "segmentedStoreOpenNanos", openNanos).append(',');
            json.append("\"provenance\":{");
            json.append("\"synthetic\":false,");
            field(json, "descriptorFingerprint", descriptor.descriptorFingerprint()).append("},");
            json.append("\"capacity\":{");
            number(json, "currentKeys", capacity.currentKeys()).append(',');
            number(json, "dueWork", capacity.dueWork()).append(',');
            number(json, "ownerWork", capacity.ownerWork()).append(',');
            number(json, "projectedIdentities", capacity.projectedIdentities()).append(',');
            number(json, "retentionRecords", capacity.retentionRecords()).append(',');
            number(json, "generationCurrentReferences",
                    capacity.generationCurrentReferences()).append(',');
            number(json, "generationSnapshotPins", capacity.generationSnapshotPins()).append(',');
            number(json, "steadyReservedBytes", capacity.steadyReservedBytes()).append(',');
            number(json, "steadyHighWaterReservedBytes",
                    capacity.steadyHighWaterReservedBytes()).append(',');
            number(json, "steadyMaximumBytes", capacity.steadyMaximumBytes()).append(',');
            number(json, "transientReservedBytes", capacity.transientReservedBytes()).append(',');
            number(json, "transientHighWaterReservedBytes",
                    capacity.transientHighWaterBytes()).append(',');
            number(json, "transientMaximumBytes", capacity.transientMaximumBytes()).append(',');
            number(json, "combinedReservedBytes", capacity.combinedReservedBytes()).append(',');
            number(json, "combinedHighWaterReservedBytes",
                    capacity.combinedHighWaterBytes()).append(',');
            number(json, "combinedMaximumBytes", capacity.combinedMaximumBytes()).append("},");
            json.append("\"projectionRecovery\":{");
            number(json, "envelopesVisited", projectionRecovery.envelopesVisited()).append(',');
            number(json, "statesVisited", projectionRecovery.statesVisited()).append(',');
            number(json, "bindingsVisited", projectionRecovery.bindingsVisited()).append(',');
            number(json, "outerRecordsVisited", projectionRecovery.outerRecordsVisited()).append(',');
            number(json, "activeEntriesBuilt", projectionRecovery.activeEntriesBuilt()).append(',');
            number(json, "statePointersRetained", projectionRecovery.statePointersRetained())
                    .append(',');
            number(json, "peakTrackedEnvelopeWorkspaceBytes",
                    projectionRecovery.peakTrackedEnvelopeWorkspaceBytes()).append(',');
            number(json, "currentTrackedEnvelopeWorkspaceBytes",
                    projectionRecovery.currentTrackedEnvelopeWorkspaceBytes())
                    .append("},");
            json.append("\"expectedReferenceAccounting\":{");
            number(json, "primaryMvccReferences", configuration.retainedPopulation()).append(',');
            number(json, "dueReferences", configuration.activePopulation()).append(',');
            number(json, "ownerReferences", 0L).append(',');
            number(json, "expectedRegistryTotal", expectedRegistryReferences(configuration))
                    .append("},");
            json.append("\"recovery\":{");
            number(json, "rootEntries", recovery.rootEntries()).append(',');
            number(json, "checkpointEntries", recovery.checkpointEntries()).append(',');
            number(json, "sealedSegments", recovery.sealedSegments()).append(',');
            number(json, "sealedFrames", recovery.sealedFrames()).append(',');
            number(json, "activeFrames", recovery.activeFrames()).append("},");
            json.append("\"artifacts\":{");
            number(json, "manifestBytes", artifacts.manifestBytes()).append(',');
            number(json, "checkpointBytes", artifacts.checkpointBytes()).append(',');
            number(json, "sealedBytes", artifacts.sealedBytes()).append(',');
            number(json, "activeBytes", artifacts.activeBytes()).append("},");
            json.append("\"jvm\":{");
            number(json, "usedHeapDeltaBytes", jvm.usedHeapDeltaBytes()).append(',');
            nullable(json, "liveThreadAllocatedBytesEstimate",
                    jvm.liveThreadAllocatedBytesEstimate()).append(',');
            number(json, "gcCollections", jvm.gcCollections()).append(',');
            number(json, "gcMillis", jvm.gcMillis()).append(',');
            json.append("\"usedHeapDeltaIsRetainedAttribution\":false,");
            field(json, "allocationScope", "CALLER_THREAD_ONLY").append(',');
            json.append("\"allocationExcludesOtherThreads\":true,");
            field(json, "gcScope", "PROCESS_GLOBAL").append("},");
            json.append("\"contract\":{");
            field(json, "timedOperation", "SegmentedTransactionalMetadataStore.open").append(',');
            field(json, "timeComplexity", "O(W + H + Z + F + S)").append(',');
            field(json, "installedState", "O(M + W)").append(',');
            field(json, "auxiliaryMemory", "O(M + W + S + B)").append(',');
            json.append("\"fullFilesystemPkiStoreReopenMeasured\":false,")
                    .append("\"diagnosticOnly\":true}");
            return json.append('}').toString();
        }

        private static long expectedRegistryReferences(Configuration configuration) {
            try {
                return Math.addExact(configuration.retainedPopulation(),
                        configuration.activePopulation());
            } catch (ArithmeticException failure) {
                throw new ContractException("CONFIGURATION_INVALID", failure);
            }
        }
    }

    record JvmDelta(long usedHeapDeltaBytes, long liveThreadAllocatedBytesEstimate,
            long gcCollections, long gcMillis) {
        private static JvmDelta between(JvmSample before, JvmSample after) {
            long allocated = before.allocatedBytes() < 0L
                    || after.allocatedBytes() < before.allocatedBytes()
                            ? -1L : after.allocatedBytes() - before.allocatedBytes();
            return new JvmDelta(after.usedHeapBytes() - before.usedHeapBytes(), allocated,
                    after.gcCollections() - before.gcCollections(),
                    after.gcMillis() - before.gcMillis());
        }
    }

    private record JvmSample(long usedHeapBytes, long allocatedBytes,
            long gcCollections, long gcMillis) {
        private static JvmSample capture() {
            Runtime runtime = Runtime.getRuntime();
            long collections = 0L;
            long millis = 0L;
            for (GarbageCollectorMXBean collector :
                    ManagementFactory.getGarbageCollectorMXBeans()) {
                collections = Math.addExact(collections,
                        Math.max(0L, collector.getCollectionCount()));
                millis = Math.addExact(millis, Math.max(0L, collector.getCollectionTime()));
            }
            return new JvmSample(runtime.totalMemory() - runtime.freeMemory(),
                    currentThreadAllocatedBytes(),
                    collections, millis);
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

    static final class ContractException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        private final String reasonCode;

        ContractException(String reasonCode) {
            super("signing recovery benchmark rejected: code=" + reasonCode);
            this.reasonCode = reasonCode;
        }

        ContractException(String reasonCode, Throwable cause) {
            super("signing recovery benchmark rejected: code=" + reasonCode, cause);
            this.reasonCode = reasonCode;
        }

        String reasonCode() {
            return reasonCode;
        }
    }

    static final class BenchmarkException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String reasonCode;

        BenchmarkException(String reasonCode) {
            super("signing recovery benchmark failed: code=" + reasonCode);
            this.reasonCode = reasonCode;
        }

        BenchmarkException(String reasonCode, Throwable cause) {
            super("signing recovery benchmark failed: code=" + reasonCode, cause);
            this.reasonCode = reasonCode;
        }

        String reasonCode() {
            return reasonCode;
        }
    }

    private static StringBuilder field(StringBuilder json, String name, String value) {
        quote(json, name).append(':');
        return quote(json, value);
    }

    private static StringBuilder number(StringBuilder json, String name, long value) {
        return quote(json, name).append(':').append(value);
    }

    private static StringBuilder nullable(StringBuilder json, String name, long value) {
        quote(json, name).append(':');
        return value < 0L ? json.append("null") : json.append(value);
    }

    private static StringBuilder quote(StringBuilder json, String value) {
        json.append('"');
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current == '"' || current == '\\') {
                json.append('\\');
            }
            json.append(current);
        }
        return json.append('"');
    }
}
