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
import java.io.OutputStream;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Benchmark-source real-ledger population fixture; absent from production artifacts. */
@SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.AvoidLiteralsInIfCondition",
        "PMD.CommentRequired" })
public final class SigningPopulationFixture {
    private static final int COHORT_SIZE = 31;
    private static final String GENERIC_NAMESPACE = "io.zeroecho.pki.benchmark-retained";
    private static final String WATERMARK_NAMESPACE = "io.zeroecho.pki.ledger-state";
    private static final String WATERMARK_KEY = "signing-time-watermark";
    private static final String PRELOAD_PROVIDER = "capacity-preload";
    private static final Principal OWNER = new Principal("SERVICE", "signing-population-fixture");
    private static final AccessContext ACCESS = new AccessContext(OWNER,
            new Purpose("SIGNING_PERFORMANCE_PRELOAD"), Optional.empty(), Optional.empty());
    private static final KeyRef KEY_REF = new KeyRef("benchmark:capacity-preload");
    private static final String ALGORITHM = "urn:zeroecho:algorithm:signature:rsa-pkcs1-sha256";
    private static final SigningProvider.ConfigurationCommitment CONFIGURATION =
            new SigningProvider.ConfigurationCommitment(new byte[32]);

    private SigningPopulationFixture() {
    }

    /** Populates, closes, and production-recovers one bounded benchmark image. */
    public static Artifact populate(Path storeRoot, FsPkiStoreOptions options, Instant createdAt,
            long genericRecords, long activeRecords) throws IOException {
        return populate(storeRoot, options, createdAt, genericRecords, activeRecords,
                QuiescentJvmCapture.unavailable(), PopulationProgress.none());
    }

    /** Populates and captures one constant-space quiescent capacity artifact. */
    public static Artifact populate(Path storeRoot, FsPkiStoreOptions options, Instant createdAt,
            long genericRecords, long activeRecords, QuiescentJvmCapture jvmCapture) throws IOException {
        return populate(storeRoot, options, createdAt, genericRecords, activeRecords,
                jvmCapture, PopulationProgress.none());
    }

    /** Populates and reports bounded count-based progress for the two population stages. */
    public static Artifact populate(Path storeRoot, FsPkiStoreOptions options, Instant createdAt,
            long genericRecords, long activeRecords, QuiescentJvmCapture jvmCapture,
            PopulationProgress progress) throws IOException {
        Objects.requireNonNull(storeRoot, "storeRoot");
        Objects.requireNonNull(options, "options");
        Objects.requireNonNull(jvmCapture, "jvmCapture");
        Objects.requireNonNull(progress, "progress");
        Instant exactCreatedAt = Instant.ofEpochMilli(
                Objects.requireNonNull(createdAt, "createdAt").toEpochMilli());
        requireCount(genericRecords, "genericRecords");
        requireCount(activeRecords, "activeRecords");
        Clock clock = Clock.fixed(exactCreatedAt, java.time.ZoneOffset.UTC);
        String signingNamespace;
        try (FilesystemPkiStore initialized = new FilesystemPkiStore(storeRoot, options, clock)) {
            // Establishes the complete production store layout before direct ledger population.
            signingNamespace = initialized.signingNamespace();
        }
        FsPaths paths = new FsPaths(storeRoot);
        Path metadataRoot = paths.transactionalMetadataRoot();
        MetadataStoreId storeId = new MetadataStoreId(signingNamespace);
        try (SegmentedTransactionalMetadataStore metadata =
                SegmentedTransactionalMetadataStore.open(metadataRoot,
                        storeId,
                        SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                        SigningActiveWal.Configuration.defaults(options.signingMaximumGroupSize()),
                        options.signingResidentIndexBudgetBytes(),
                        options.signingCompactionTransientBudgetBytes())) {
            metadata.observeWatermark(exactCreatedAt.toEpochMilli());
            populateGeneric(metadata, genericRecords, progress);
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, options, clock)) {
            if (activeRecords != 0L) {
                populateActive(store, exactCreatedAt, activeRecords, progress);
            } else {
                progress.started("active", 0L);
                progress.completed("active", 0L);
            }
        }
        CountingRecovery recovery = new CountingRecovery();
        SigningLedgerRecovery.Configuration configuration = new SigningLedgerRecovery.Configuration(
                8192, SigningManifestCodec.MAX_FILE_BYTES, SigningCheckpointCodec.MAX_ENTRIES,
                SigningActiveWal.Configuration.defaults(options.signingMaximumGroupSize()));
        // Closing the validated production recovery handle leaves the image ready for normal reopen.
        SigningLedgerRecovery.recover(metadataRoot, configuration, recovery).close();
        Observation observation = recovery.observation();
        long expectedCurrent = Math.addExact(Math.addExact(genericRecords,
                Math.multiplyExact(activeRecords, 3L)), 1L);
        Observation expected = new Observation(genericRecords, Math.multiplyExact(activeRecords, 2L), activeRecords,
                1L, expectedCurrent, activeRecords, activeRecords);
        if (!expected.equals(observation)) {
            throw new IOException("Signing benchmark population observation is inconsistent");
        }
        try (SegmentedTransactionalMetadataStore reopened =
                SegmentedTransactionalMetadataStore.open(metadataRoot,
                        storeId,
                        SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                        SigningActiveWal.Configuration.defaults(options.signingMaximumGroupSize()),
                        options.signingResidentIndexBudgetBytes(),
                        options.signingCompactionTransientBudgetBytes(),
                        FilesystemStagedContentStore.readOnlyResolver(
                                paths.stagedContentRoot(), signingNamespace))) {
            RecoveryShape recoveryShape = RecoveryShape.from(
                    reopened.recoveryProjectionStatistics());
            RecoveryShape expectedShape = new RecoveryShape(activeRecords, activeRecords,
                    activeRecords, 0L, activeRecords, activeRecords,
                    recoveryShape.peakTrackedEnvelopeWorkspaceBytes(), 0L);
            if (!expectedShape.equals(recoveryShape)
                    || (activeRecords > 0L
                            && recoveryShape.peakTrackedEnvelopeWorkspaceBytes() <= 0L)) {
                throw new IOException("Signing benchmark recovery shape is inconsistent");
            }
            return new Artifact(observation, recoveryShape,
                    CapacityEvidence.from(reopened.capacityObservation()), jvmCapture.capture());
        }
    }

    private static void populateGeneric(SegmentedTransactionalMetadataStore metadata, long records,
            PopulationProgress progress)
            throws IOException {
        progress.started("generic", records);
        ProgressMilestones milestones = new ProgressMilestones(records);
        long sequence = 0L;
        while (sequence < records) {
            int count = (int) Math.min(COHORT_SIZE, records - sequence);
            List<List<SigningTransactionPayloadCodec.Mutation>> cohort = new ArrayList<>(count);
            for (int index = 0; index < count; index++) {
                MetadataKey key = new MetadataKey(GENERIC_NAMESPACE, genericKey(sequence + index));
                cohort.add(List.of(new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L,
                        new byte[] { 1 })));
            }
            for (MetadataCommitResult result : metadata.directCommitCohort(cohort)) {
                if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                    throw new IOException("Signing benchmark generic population was not committed");
                }
            }
            sequence += count;
            milestones.report(progress, "generic", sequence);
        }
        progress.completed("generic", records);
    }

    private static void populateActive(FilesystemPkiStore store, Instant createdAt,
            long records, PopulationProgress progress) throws IOException {
        progress.started("active", records);
        ProgressMilestones milestones = new ProgressMilestones(records);
        String namespace = store.signingNamespace() + '.' + PRELOAD_PROVIDER;
        Instant deadline = createdAt.plus(Duration.ofDays(1));
        for (long sequence = 0L; sequence < records; sequence++) {
            PkiId submissionId = submissionId(namespace, createdAt, sequence);
            DurableContentReference reference = sharedReference(store);
            SignWorkflowStore.AcceptanceCommand command = new SignWorkflowStore.AcceptanceCommand(
                    submissionId, namespace, CONFIGURATION, ACCESS, KEY_REF, submissionId,
                    ALGORITHM, Encoding.BINARY, createdAt, deadline, reference, Optional.empty(),
                    SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
            if (store.acceptSign(command) != SignWorkflowStore.AcceptanceResult.ACCEPTED) {
                throw new IOException("Signing benchmark active population conflicted");
            }
            milestones.report(progress, "active", sequence + 1L);
        }
        progress.completed("active", records);
    }

    private static DurableContentReference sharedReference(FilesystemPkiStore store) throws IOException {
        try (ContentSink sink = store.stagedContent().beginContent(
                    Encoding.BINARY, DurableContentReference.Lifecycle.OPERATION);
                OutputStream output = sink.outputStream()) {
            output.write(new byte[] { 0x53, 0x50, 0x46 });
            return sink.complete();
        }
    }

    private static PkiId submissionId(String namespace, Instant createdAt, long sequence) {
        byte[] nonce = new byte[16];
        for (int index = Long.BYTES - 1; index >= 0; index--) {
            nonce[nonce.length - Long.BYTES + index] = (byte) (sequence + 1L >>> (Long.BYTES - 1 - index) * 8);
        }
        return SigningSubmissionId.parse(new PkiId("zsign:v1:" + namespace + ':'
                + createdAt.toEpochMilli() + ':' + HexFormat.of().formatHex(nonce))).id();
    }

    private static String genericKey(long sequence) {
        String value = Long.toString(sequence);
        return "g" + "0000000".substring(value.length()) + value;
    }

    private static void requireCount(long value, String name) {
        if (value < 0L || value > 1_000_000L) {
            throw new IllegalArgumentException(name + " is outside the fixture bound");
        }
    }

    /** Immutable constant-space observation produced by production recovery replay. */
    public record Observation(long genericRecords, long signRecords, long ownerRecords,
            long watermarkRecords, long currentRecords, long dueRecords, long sharedContentOwners) {
    }

    /** Exact constant-space counters for the split signing recovery shape. */
    public record RecoveryShape(long envelopesVisited, long statesVisited,
            long bindingsVisited, long outerRecordsVisited, long activeEntriesBuilt,
            long statePointersRetained, long peakTrackedEnvelopeWorkspaceBytes,
            long currentTrackedEnvelopeWorkspaceBytes) {
        private static RecoveryShape from(
                SigningLedgerStoreEngine.RecoveryProjectionStatistics statistics) {
            return new RecoveryShape(statistics.envelopesVisited(), statistics.statesVisited(),
                    statistics.bindingsVisited(), statistics.outerRecordsVisited(),
                    statistics.activeEntriesBuilt(), statistics.statePointersRetained(),
                    statistics.peakTrackedEnvelopeWorkspaceBytes(),
                    statistics.currentTrackedEnvelopeWorkspaceBytes());
        }
    }

    /** Complete constant-space population and quiescent-capacity artifact. */
    public record Artifact(Observation population, RecoveryShape recoveryShape,
            CapacityEvidence capacity, QuiescentJvm jvm) {
        public Artifact {
            Objects.requireNonNull(population, "population");
            Objects.requireNonNull(recoveryShape, "recoveryShape");
            Objects.requireNonNull(capacity, "capacity");
            Objects.requireNonNull(jvm, "jvm");
        }
    }

    /** Immutable scalar capacity observation copied from the reopened production ledger. */
    public record CapacityEvidence(int currentKeys, int mvccLiveSnapshots, long canonicalKeyBytes,
            long mvccEstimatedResidentBytes, long mvccReservedBytes,
            int dueWork, long dueCanonicalIdBytes, long dueEstimatedResidentBytes,
            long dueReservedBytes, int retentionRecords, long retentionReservedBytes,
            int ownerWork, long ownerCanonicalIdBytes, long ownerEstimatedResidentBytes,
            long ownerReservedBytes, int projectedIdentities, long projectionReservedBytes,
            int registeredGenerations, int publishedGenerations, int supersededGenerations,
            int reclaimingGenerations, int reclaimableGenerations,
            long generationCurrentReferences, long generationSnapshotPins,
            long steadyReservedBytes, long steadyHighWaterReservedBytes,
            long steadyMaximumBytes, long transientReservedBytes,
            long transientHighWaterReservedBytes, long transientMaximumBytes,
            long combinedReservedBytes, long combinedHighWaterReservedBytes,
            long combinedMaximumBytes) {

        private static CapacityEvidence from(SigningLedgerStoreEngine.CapacityObservation value) {
            return new CapacityEvidence(value.currentKeys(), value.mvccLiveSnapshots(),
                    value.canonicalKeyBytes(),
                    value.mvccEstimatedResidentBytes(), value.mvccReservedBytes(),
                    value.dueWork(), value.dueCanonicalIdBytes(),
                    value.dueEstimatedResidentBytes(), value.dueReservedBytes(),
                    value.retentionRecords(), value.retentionReservedBytes(),
                    value.ownerWork(), value.ownerCanonicalIdBytes(),
                    value.ownerEstimatedResidentBytes(), value.ownerReservedBytes(),
                    value.projectedIdentities(), value.projectionReservedBytes(),
                    value.registeredGenerations(), value.publishedGenerations(),
                    value.supersededGenerations(), value.reclaimingGenerations(),
                    value.reclaimableGenerations(), value.generationCurrentReferences(),
                    value.generationSnapshotPins(), value.steadyReservedBytes(),
                    value.steadyHighWaterReservedBytes(), value.steadyMaximumBytes(),
                    value.transientReservedBytes(), value.transientHighWaterBytes(),
                    value.transientMaximumBytes(), value.combinedReservedBytes(),
                    value.combinedHighWaterBytes(), value.combinedMaximumBytes());
        }
    }

    /** Existing bounded JVM counters sampled while the reopened ledger remains live. */
    public record QuiescentJvm(long usedHeapBytes, long allocatedBytes,
            long gcCollections, long gcMillis) {
        private static QuiescentJvm unavailable() {
            return new QuiescentJvm(-1L, -1L, -1L, -1L);
        }
    }

    /** Benchmark-owned callback that samples existing JVM counters at quiescence. */
    @FunctionalInterface
    public interface QuiescentJvmCapture {
        QuiescentJvm capture();

        private static QuiescentJvmCapture unavailable() {
            return QuiescentJvm::unavailable;
        }
    }

    /** Bounded population progress callback; implementations must not retain per-record state. */
    public interface PopulationProgress {
        /** Reports the start of one named stage. */
        void started(String stage, long total);

        /** Reports one of at most nine count-derived intermediate milestones. */
        void milestone(String stage, long completed, long total);

        /** Reports completion of one named stage. */
        void completed(String stage, long total);

        private static PopulationProgress none() {
            return NoOpPopulationProgress.INSTANCE;
        }
    }

    private enum NoOpPopulationProgress implements PopulationProgress {
        INSTANCE;

        @Override public void started(String stage, long total) {
            // Intentionally empty.
        }

        @Override public void milestone(String stage, long completed, long total) {
            // Intentionally empty.
        }

        @Override public void completed(String stage, long total) {
            // Intentionally empty.
        }
    }

    private static final class ProgressMilestones {
        private final long total;
        private int nextTenth = 1;

        private ProgressMilestones(long total) {
            this.total = total;
        }

        private void report(PopulationProgress progress, String stage, long completed) {
            while (nextTenth < 10 && completed * 10L >= total * nextTenth) {
                progress.milestone(stage, completed, total);
                nextTenth++;
            }
        }
    }

    private static final class CountingRecovery implements SigningLedgerRecovery.RecoverySink {
        private Observation observation;

        @Override public Session begin(SigningManifestCodec.Manifest manifest) {
            Objects.requireNonNull(manifest, "manifest");
            return new CountingSession(this);
        }

        private Observation observation() {
            if (observation == null) {
                throw new IllegalStateException("Signing benchmark recovery was not published");
            }
            return observation;
        }

    }

    private static final class CountingSession implements SigningLedgerRecovery.RecoverySink.Session {
        private final CountingRecovery owner;
        private long generic;
        private long records;
        private long owners;
        private long watermark;
        private long due;
        private long sharedOwners;

        private CountingSession(CountingRecovery owner) {
            this.owner = owner;
        }

        @Override public void acceptCheckpoint(SigningCheckpointCodec.Header header,
                SigningCheckpointCodec.EntryDescriptor entry, SigningWalFrameCodec.Frame frame)
                throws IOException {
            Objects.requireNonNull(header, "header");
            MetadataKey key = MetadataKey.parse(entry.key());
            classifyCurrent(key, currentContent(key, frame));
        }

        @Override public void acceptCheckpointBoundary(SigningCheckpointCodec.Header header) {
            Objects.requireNonNull(header, "header");
        }

        @Override public void acceptWalGroup(List<SigningWalFrameCodec.ScannedFrame> frames,
                long committedRevision) throws IOException {
            for (SigningWalFrameCodec.ScannedFrame scanned : frames) {
                SigningTransactionPayloadCodec.Payload payload =
                        SigningTransactionPayloadCodec.decode(scanned.frame().payload());
                if (payload.kind() == SigningTransactionPayloadCodec.Kind.WATERMARK) {
                    watermark = 1L;
                } else if (payload.kind() == SigningTransactionPayloadCodec.Kind.COMMIT
                        || payload.kind() == SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT) {
                    if (payload.watermark() >= 0L) {
                        watermark = 1L;
                    }
                    for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
                        if (mutation.kind() != SigningTransactionPayloadCodec.MutationKind.CREATE) {
                            throw new IOException("Signing benchmark preload contains a non-create mutation");
                        }
                        classifyCurrent(mutation.key(), mutation.contentInternal());
                    }
                }
            }
        }

        private void classifyCurrent(MetadataKey key, byte[] content) throws IOException {
            switch (key.namespace()) {
                case GENERIC_NAMESPACE -> generic++;
                case "io.zeroecho.pki.signing-envelope" -> {
                    Objects.requireNonNull(content, "content");
                    records++;
                }
                case SigningWorkProjection.STATE_NAMESPACE -> {
                    SignWorkflowStore.MutableState state = FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE,
                            Objects.requireNonNull(content, "content"));
                    if (state.state() != SignWorkflowStore.State.INTENT) {
                        throw new IOException("Signing benchmark preload record is not active");
                    }
                    records++;
                    due++;
                }
                case "io.zeroecho.pki.signing-candidate-binding" -> {
                    FsCodec.decode(FsCodec.SIGN_CANDIDATE_BINDING,
                            Objects.requireNonNull(content, "content"));
                    owners++;
                    sharedOwners++;
                }
                case "io.zeroecho.pki.domain-continuation" -> {
                    Objects.requireNonNull(content, "content");
                }
                case WATERMARK_NAMESPACE -> {
                    if (!WATERMARK_KEY.equals(key.key())) {
                        throw new IOException("Signing benchmark watermark identity is invalid");
                    }
                    watermark = 1L;
                }
                default -> {
                    // Other production-store namespaces are outside the signing-ledger population count.
                }
            }
        }

        private static byte[] currentContent(MetadataKey key, SigningWalFrameCodec.Frame frame)
                throws IOException {
            SigningTransactionPayloadCodec.Payload payload =
                    SigningTransactionPayloadCodec.decode(frame.payload());
            for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
                if (key.equals(mutation.key()) && mutation.contentInternal() != null) {
                    return mutation.contentInternal();
                }
            }
            if (WATERMARK_NAMESPACE.equals(key.namespace()) && WATERMARK_KEY.equals(key.key())) {
                return new byte[0];
            }
            throw new IOException("Signing benchmark checkpoint content is missing");
        }

        @Override public SigningLedgerRecovery.RecoverySink.Prepared prepare() {
            Observation candidate = new Observation(generic, records, owners, watermark,
                    generic + records + owners + watermark, due, sharedOwners);
            return new SigningLedgerRecovery.RecoverySink.Prepared() {
                @Override public void publish() {
                    owner.observation = candidate;
                }

                @Override public void close() {
                    // Immutable scalar candidate owns no external resources.
                }
            };
        }

        @Override public void close() {
            // Immutable scalar candidate owns no external resources.
        }
    }
}
