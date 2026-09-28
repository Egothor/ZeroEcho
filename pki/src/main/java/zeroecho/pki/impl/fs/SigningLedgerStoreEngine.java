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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransactionId;
import zeroecho.pki.spi.store.StagedContentStore;

/** Lifecycle owner for the v6 segmented transactional signing ledger. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidLiteralsInIfCondition", "PMD.AvoidSynchronizedAtMethodLevel",
        "PMD.AvoidSynchronizedStatement", "PMD.AvoidUsingVolatile", "PMD.CloseResource",
        "PMD.CommentRequired", "PMD.ControlStatementBraces", "PMD.CouplingBetweenObjects",
        "PMD.CyclomaticComplexity", "PMD.DoNotUseThreads",
        "PMD.LooseCoupling", "PMD.NcssCount", "PMD.PreserveStackTrace", "PMD.TooManyMethods",
        "PMD.UnusedPrivateField", "PMD.UseTryWithResources" })
final class SigningLedgerStoreEngine implements AutoCloseable {
    private static final StartFaultInjector NO_START_FAULT = (stage, wal, registry) -> { };
    private static final String WAL_ADMISSION_FULL_MESSAGE = "Metadata WAL admission is full";
    private static final String OUTCOME_NAMESPACE = SigningLedgerRecoveredState.OUTCOME_NAMESPACE;
    private static final String LEDGER_STATE_NAMESPACE =
            SigningLedgerRecoveredState.LEDGER_STATE_NAMESPACE;
    private static final String SIGN_ENVELOPE_NAMESPACE = "io.zeroecho.pki.signing-envelope";
    private static final String SIGN_BINDING_NAMESPACE =
            "io.zeroecho.pki.signing-candidate-binding";
    private static final String OUTER_CONTINUATION_NAMESPACE =
            "io.zeroecho.pki.domain-continuation";
    private static final MetadataKey WATERMARK_KEY = SigningLedgerRecoveredState.WATERMARK_KEY;
    private static final int MAXIMUM_COMMIT_QUEUE = 256;
    private static final int MAXIMUM_COMMIT_BATCH = 32;
    private static final long MAXIMUM_COORDINATOR_BYTES = 64L * 1024L * 1024L;
    private static final long REQUEST_FIXED_BYTES = 256L;
    private static final long MUTATION_FIXED_BYTES = 64L;
    private static final long MAINTENANCE_ROTATION_BYTES = 64L * 1024L * 1024L;
    private static final int COMPACTION_SEGMENTS = 8;
    private static final int MAXIMUM_RECLAIMS_PER_PASS = 8;
    private static final long DEFAULT_SOFT_LOW_SPACE_BYTES = 1024L * 1024L * 1024L;
    private static final long SPACE_WARNING_INTERVAL_NANOS = java.time.Duration.ofMinutes(1L).toNanos();
    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(
            SigningLedgerStoreEngine.class.getName());
    private static final AtomicBoolean IDENTITY_SEED = new AtomicBoolean();
    private static final AtomicReference<UsableSpaceObserver> USABLE_SPACE_OBSERVER =
            new AtomicReference<>();

    private final Path root;
    private final MetadataStoreId storeId;
    private final SigningGenerationRegistry generations;
    private final SigningIndexCapacityBudget capacity;
    private final SigningIndexCapacityBudget transientCapacity;
    private final SigningMvccIndex index;
    private final SigningDueWorkIndex due;
    private final SigningRetentionIndex retention;
    private final SigningDueWorkIndex owners;
    private final SigningWorkProjection workProjection;
    private final SigningArtifactCatalog artifacts;
    private SigningLedgerRecovery.Handle recoveryHandle;
    private final SigningLedgerRecovery.ActivatedOpen pendingRecovery;
    private final SigningLedgerMaintenance maintenance;
    private final Object stateLock = new Object();
    private final Object coordinatorLock = new Object();
    private final Object walAdmissionLock = new Object();
    private final Object watermarkAdvanceLock = new Object();
    private final Object maintenanceSignal = new Object();
    private final MaintenancePressure maintenancePressure = new MaintenancePressure();
    private final AtomicReference<SigningIndexCapacityBudget.CapacityExceededException>
            protectedProgressPressure = new AtomicReference<>();
    private final AtomicReference<Throwable> firstRecoveryFailure = new AtomicReference<>();
    private final AdmissionMaintenanceGate admissionGate;
    private final SigningProjectionCutoverGate projectionCutover =
            new SigningProjectionCutoverGate();
    private final ArrayDeque<CommitRequest> commitQueue = new ArrayDeque<>(MAXIMUM_COMMIT_QUEUE);
    private final Map<UUID, OutcomeSlot> outcomes = new HashMap<>();
    private final Thread coordinator;
    private final Thread maintenanceCoordinator;
    private volatile SigningActiveWal activeWal;
    // Cumulative writer counters of sealed WALs paired with the active WAL they
    // precede, published together so a lock-free reader always sees a consistent
    // pair. Replaced only under walAdmissionLock at each rotation.
    private volatile WriterMetricsEpoch writerMetricsEpoch;
    private volatile State state = State.OPEN;
    private long watermark;
    private long observedWatermark;
    private long nextGenerationIdentity;
    private long ledgerStateEpoch;
    private boolean maintenanceRequested;
    private boolean maintenanceStopping;
    private boolean maintenanceDeferred;
    private long maintenancePasses;
    private SigningLedgerMaintenance.DeferralReason maintenanceDeferralReason;
    private int coordinatorReservedRequests;
    private long coordinatorReservedBytes;
    private RecoveryProjectionStatistics recoveryProjectionStatistics =
            RecoveryProjectionStatistics.empty();
    private final SoftUsableSpaceObservation usableSpaceObservation =
            new SoftUsableSpaceObservation(SPACE_WARNING_INTERVAL_NANOS);

    private SigningLedgerStoreEngine(Path root, MetadataStoreId storeId,
            SigningGenerationRegistry generations, SigningIndexCapacityBudget capacity,
            SigningIndexCapacityBudget transientCapacity,
            SigningMvccIndex index, SigningDueWorkIndex due, SigningRetentionIndex retention,
            SigningDueWorkIndex owners,
            SigningArtifactCatalog artifacts,
            SigningLedgerRecovery.Handle recoveryHandle, SigningActiveWal activeWal,
            SigningManifestCodec.Manifest manifest, long nextGenerationIdentity,
            SigningActiveWal.Configuration activeWalConfiguration,
            StagedContentStore stagedContent) {
        this(root, storeId, generations, capacity, transientCapacity, index, due, retention,
                owners, artifacts, recoveryHandle, activeWal, manifest, nextGenerationIdentity,
                activeWalConfiguration, null, stagedContent, null);
    }

    private SigningLedgerStoreEngine(Path root, MetadataStoreId storeId,
            SigningGenerationRegistry generations, SigningIndexCapacityBudget capacity,
            SigningIndexCapacityBudget transientCapacity,
            SigningMvccIndex index, SigningDueWorkIndex due, SigningRetentionIndex retention,
            SigningDueWorkIndex owners, SigningArtifactCatalog artifacts,
            SigningLedgerRecovery.ActivatedOpen pendingRecovery,
            SigningManifestCodec.Manifest manifest, long nextGenerationIdentity,
            SigningActiveWal.Configuration activeWalConfiguration,
            StagedContentStore stagedContent) {
        this(root, storeId, generations, capacity, transientCapacity, index, due, retention,
                owners, artifacts, null, pendingRecovery.activeWal(), manifest,
                nextGenerationIdentity, activeWalConfiguration, null, stagedContent,
                pendingRecovery);
    }

    private SigningLedgerStoreEngine(Path root, MetadataStoreId storeId,
            SigningGenerationRegistry generations, SigningIndexCapacityBudget capacity,
            SigningIndexCapacityBudget transientCapacity,
            SigningMvccIndex index, SigningDueWorkIndex due, SigningRetentionIndex retention,
            SigningDueWorkIndex owners,
            SigningArtifactCatalog artifacts,
            SigningLedgerRecovery.Handle recoveryHandle, SigningActiveWal activeWal,
            SigningManifestCodec.Manifest manifest, long nextGenerationIdentity,
            SigningActiveWal.Configuration activeWalConfiguration,
            SigningLedgerMaintenance.FaultInjector maintenanceFaults,
            StagedContentStore stagedContent,
            SigningLedgerRecovery.ActivatedOpen pendingRecovery) {
        this.root = root;
        this.storeId = storeId;
        this.generations = generations;
        this.capacity = capacity;
        this.transientCapacity = transientCapacity;
        this.index = index;
        this.due = due;
        this.retention = retention;
        this.owners = owners;
        workProjection = new SigningWorkProjection(due, retention, owners, capacity,
                stagedContent);
        this.artifacts = artifacts;
        this.recoveryHandle = recoveryHandle;
        this.pendingRecovery = pendingRecovery;
        this.activeWal = activeWal;
        this.writerMetricsEpoch = new WriterMetricsEpoch(
                SigningActiveWal.Snapshot.writerBaseline(), activeWal);
        this.nextGenerationIdentity = nextGenerationIdentity;
        admissionGate = new AdmissionMaintenanceGate(
                walAdmissionLock, activeWalConfiguration.queueCapacity());
        maintenance = maintenanceFaults == null
                ? new SigningLedgerMaintenance(root, manifest, activeWal,
                        activeWalConfiguration, generations, index, artifacts)
                : new SigningLedgerMaintenance(root, manifest, activeWal,
                        activeWalConfiguration, generations, index, artifacts,
                        maintenanceFaults);
        coordinator = new Thread(this::runCoordinator, "zeroecho-metadata-commit-coordinator");
        coordinator.setDaemon(true);
        maintenanceCoordinator = new Thread(this::runMaintenance,
                "zeroecho-metadata-maintenance-coordinator");
        maintenanceCoordinator.setDaemon(true);
    }

    /** Starts WAL and engine coordinators only after deterministic reconstruction completes. */
    private void start() throws IOException {
        start(NO_START_FAULT);
    }

    private void start(StartFaultInjector faults) throws IOException {
        boolean coordinatorStarted = false;
        boolean maintenanceStarted = false;
        try {
            if (activeWal.snapshot().state() == SigningActiveWal.State.PASSIVE) {
                activeWal.startWriter();
            }
            faults.after(StartStage.WAL_WRITER, activeWal, generations);
            coordinator.start();
            coordinatorStarted = true;
            faults.after(StartStage.COMMIT_COORDINATOR, activeWal, generations);
            maintenanceCoordinator.start();
            maintenanceStarted = true;
            faults.after(StartStage.MAINTENANCE_COORDINATOR, activeWal, generations);
            if (pendingRecovery != null) {
                pendingRecovery.markThreadsStarted();
                recoveryHandle = pendingRecovery.transferToStartedEngine();
            }
        } catch (IOException | RuntimeException failure) {
            if (coordinatorStarted || maintenanceStarted) {
                try {
                    close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
            } else {
                try {
                    activeWal.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
            }
            throw failure;
        }
    }

    /* default */ static SigningLedgerStoreEngine create(Path root,
            MetadataStoreId storeId) throws IOException {
        return create(root, storeId, null, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                SigningActiveWal.Configuration.defaults(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ static SigningLedgerStoreEngine create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations) throws IOException {
        return create(root, storeId, walOperations, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                SigningActiveWal.Configuration.defaults(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ static SigningLedgerStoreEngine create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork) throws IOException {
        return create(root, storeId, walOperations, maximumSigningWork,
                SigningActiveWal.Configuration.defaults(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ static SigningLedgerStoreEngine create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork, SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes)
            throws IOException {
        return create(root, storeId, walOperations, maximumSigningWork, activeWalConfiguration,
                residentIndexBudgetBytes, compactionBudgetBytes, null, null);
    }

    /* default */ static SigningLedgerStoreEngine create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork, SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes,
            StagedContentStore stagedContent) throws IOException {
        return create(root, storeId, walOperations, maximumSigningWork, activeWalConfiguration,
                residentIndexBudgetBytes, compactionBudgetBytes, null,
                Objects.requireNonNull(stagedContent, "stagedContent"));
    }

    /* default */ static SigningLedgerStoreEngine create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork, SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes,
            SigningLedgerMaintenance.FaultInjector maintenanceFaults)
            throws IOException {
        return create(root, storeId, walOperations, maximumSigningWork, activeWalConfiguration,
                residentIndexBudgetBytes, compactionBudgetBytes, maintenanceFaults, null);
    }

    private static SigningLedgerStoreEngine create(Path root,
            MetadataStoreId storeId, SigningActiveWal.Operations walOperations,
            int maximumSigningWork, SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes,
            SigningLedgerMaintenance.FaultInjector maintenanceFaults,
            StagedContentStore stagedContent) throws IOException {
        Objects.requireNonNull(activeWalConfiguration, "activeWalConfiguration");
        SigningIndexCapacityBudget capacity = steadyCapacity(
                residentIndexBudgetBytes, activeWalConfiguration);
        SigningIndexCapacityBudget transientCapacity =
                new SigningIndexCapacityBudget(compactionBudgetBytes);
        requireRoot(root);
        if (hasEntry(root)) {
            throw formatUnsupported();
        }
        SigningLedgerRecovery.initializeFormat(root);
        long identity = 1L;
        SigningActiveWal.Descriptor descriptor = new SigningActiveWal.Descriptor(identity, 0L, 0L);
        Path activePath = root.resolve(SigningManifestCodec.activeName(identity));
        SigningActiveWal wal = null;
        try {
            wal = walOperations == null
                    ? SigningActiveWal.open(activePath, descriptor, activeWalConfiguration)
                    : SigningActiveWal.open(activePath, descriptor, activeWalConfiguration,
                            walOperations, System::nanoTime, java.util.concurrent.TimeUnit.NANOSECONDS::timedWait);
            SigningManifestCodec.ActiveWal active = activeDescriptor(descriptor);
            SigningManifestCodec.Manifest manifest = new SigningManifestCodec.Manifest(
                    0L, 0L, Optional.empty(), List.of(), active);
            byte[] encoded = SigningManifestCodec.encode(manifest);
            SigningFilePublisher.publishManifest(root.resolve(SigningLedgerRecovery.MANIFEST_FILE),
                    channel -> SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(encoded)));
            SigningGenerationRegistry generations = new SigningGenerationRegistry();
            generations.create(identity);
            generations.publish(identity);
            SigningMvccIndex index = new SigningMvccIndex(
                    indexConfiguration(), generations, capacity, transientCapacity);
            index.recover(0L, -1L, List.of());
            SigningDueWorkIndex due = new SigningDueWorkIndex(
                    maximumSigningWork, capacity, generations,
                    SigningGenerationRegistry.Owner.DUE);
            SigningRetentionIndex retention = new SigningRetentionIndex(
                    SigningDueWorkIndex.FOUR_GIB_ORDERED_LIMIT, capacity);
            SigningDueWorkIndex owners = new SigningDueWorkIndex(
                    SigningDueWorkIndex.FOUR_GIB_ORDERED_LIMIT, capacity, generations,
                    SigningGenerationRegistry.Owner.OWNER);
            SigningArtifactCatalog artifacts = new SigningArtifactCatalog();
            artifacts.register(new SigningArtifactCatalog.Artifact(identity, active.name(),
                    SigningArtifactCatalog.Kind.ACTIVE_WAL));
            SigningLedgerStoreEngine engine = new SigningLedgerStoreEngine(root, storeId,
                    generations, capacity, transientCapacity, index, due, retention, owners, artifacts,
                    null, wal, manifest, 2L, activeWalConfiguration, maintenanceFaults,
                    stagedContent, null);
            engine.start();
            wal = null;
            return engine;
        } finally {
            if (wal != null) wal.close();
        }
    }

    private static SigningIndexCapacityBudget steadyCapacity(long maximumBytes,
            SigningActiveWal.Configuration activeWalConfiguration) {
        long protectedProgressBytes = SigningTransitionWorkspaceSizing.derive(
                SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                activeWalConfiguration.queueCapacity()).workspaceFloorBytes();
        return new SigningIndexCapacityBudget(maximumBytes, protectedProgressBytes);
    }

    /* default */ static SigningLedgerStoreEngine open(Path root,
            MetadataStoreId storeId) throws IOException {
        return open(root, storeId, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                SigningActiveWal.Configuration.defaults(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ static SigningLedgerStoreEngine open(Path root,
            MetadataStoreId storeId, int maximumSigningWork) throws IOException {
        return open(root, storeId, maximumSigningWork,
                SigningActiveWal.Configuration.defaults(),
                FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES);
    }

    /* default */ static SigningLedgerStoreEngine open(Path root,
            MetadataStoreId storeId, int maximumSigningWork,
            SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes) throws IOException {
        return open(root, storeId, maximumSigningWork, activeWalConfiguration,
                residentIndexBudgetBytes, compactionBudgetBytes, null);
    }

    /* default */ static SigningLedgerStoreEngine open(Path root,
            MetadataStoreId storeId, int maximumSigningWork,
            SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes,
            StagedContentStore stagedContent) throws IOException {
        return open(root, storeId, maximumSigningWork, activeWalConfiguration,
                residentIndexBudgetBytes, compactionBudgetBytes, stagedContent,
                NO_START_FAULT);
    }

    /* default */ static SigningLedgerStoreEngine open(Path root,
            MetadataStoreId storeId, int maximumSigningWork,
            SigningActiveWal.Configuration activeWalConfiguration,
            long residentIndexBudgetBytes, long compactionBudgetBytes,
            StagedContentStore stagedContent, StartFaultInjector startFaults) throws IOException {
        Objects.requireNonNull(activeWalConfiguration, "activeWalConfiguration");
        Objects.requireNonNull(startFaults, "startFaults");
        requireRoot(root);
        SigningLedgerRecoveredState.RecoveryFold candidate =
                new SigningLedgerRecoveredState.RecoveryFold(root, storeId);
        SigningLedgerRecovery.PreparedOpen prepared = null;
        SigningLedgerRecovery.ActivatedOpen activated = null;
        final SigningRecoveryIntegrityValidator.ValidatedSigningRecovery validatedRecovery;
        try {
            prepared = SigningLedgerRecovery.prepare(root,
                    recoveryConfiguration(activeWalConfiguration), candidate);
            SigningLedgerRecovery.PreparedView preparedView = prepared.view();
            validatedRecovery = SigningRecoveryIntegrityValidator.validate(root,
                    preparedView.manifest(), candidate.preparedState(), stagedContent);
            activated = prepared.activate();
            activated.publishRecoveredState();
        } catch (SigningLedgerRecovery.RecoveryException
                | SigningRecoveryIntegrityValidator.IntegrityException failure) {
            closeRecoveryOpen(activated);
            closeRecoveryOpen(prepared);
            throw formatUnsupported();
        } finally {
            closeRecoveryOpen(prepared);
        }
        boolean transferred = false;
        SigningIndexCapacityBudget capacity = null;
        SigningIndexCapacityBudget transientCapacity = null;
        SigningMvccIndex index = null;
        SigningDueWorkIndex due = null;
        SigningRetentionIndex retention = null;
        SigningDueWorkIndex owners = null;
        SigningLedgerStoreEngine engine = null;
        try {
            SigningGenerationRegistry generations = activated.registry();
            startFaults.after(StartStage.RECOVERY_ACTIVATED,
                    activated.activeWal(), generations);
            capacity = steadyCapacity(residentIndexBudgetBytes, activeWalConfiguration);
            transientCapacity = new SigningIndexCapacityBudget(compactionBudgetBytes);
            index = new SigningMvccIndex(
                    indexConfiguration(), generations, capacity, transientCapacity);
            due = new SigningDueWorkIndex(maximumSigningWork, capacity, generations,
                    SigningGenerationRegistry.Owner.DUE);
            retention = new SigningRetentionIndex(
                    SigningDueWorkIndex.FOUR_GIB_ORDERED_LIMIT, capacity);
            owners = new SigningDueWorkIndex(
                    SigningDueWorkIndex.FOUR_GIB_ORDERED_LIMIT, capacity, generations,
                    SigningGenerationRegistry.Owner.OWNER);
            SigningArtifactCatalog artifacts =
                    SigningLedgerRecoveredState.catalog(activated.manifest());
            SigningLedgerRecoveredState.State recovered = candidate.state();
            index.recover(recovered.revision(), recovered.sequence(), recovered.records());
            activated.releaseTemporaryOwnership();
            long nextIdentity = nextIdentity(activated.manifest());
            engine = new SigningLedgerStoreEngine(root, storeId,
                    generations, capacity, transientCapacity, index, due, retention, owners, artifacts,
                    activated, activated.manifest(), nextIdentity, activeWalConfiguration,
                    stagedContent);
            synchronized (engine.stateLock) {
                for (Map.Entry<UUID, MetadataCommitResult> entry :
                        recovered.outcomes().entrySet()) {
                    engine.outcomes.put(entry.getKey(), new OutcomeSlot(entry.getValue(),
                            SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY));
                }
                engine.watermark = recovered.watermark();
                engine.recoverWorkProjection(recovered.records(), validatedRecovery);
            }
            activated.markEngineReconstructed();
            engine.closeAbandonedIssuancesDuringRecovery();
            activated.markRecoveryWritesForced();
            engine.start(startFaults);
            transferred = true;
            return engine;
        } finally {
            if (!transferred) {
                if (engine != null) {
                    closeRecoveryOpen(engine);
                } else {
                    closeIndex(owners);
                    closeIndex(retention);
                    closeIndex(due);
                    closeIndex(index);
                    if (capacity != null) capacity.clearReleaseSignal();
                    if (transientCapacity != null) transientCapacity.clearReleaseSignal();
                    closeRecoveryOpen(activated);
                }
            }
        }
    }

    private static void closeIndex(AutoCloseable closeable) {
        closeRecoveryOpen(closeable);
    }

    @SuppressWarnings("PMD.EmptyCatchBlock")
    private static void closeRecoveryOpen(AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception failure) {
                // The primary open failure remains authoritative and redacted.
            }
        }
    }

    /** Deterministic recovery construction and thread-start boundaries. */
    /* default */ enum StartStage {
        RECOVERY_ACTIVATED,
        WAL_WRITER,
        COMMIT_COORDINATOR,
        MAINTENANCE_COORDINATOR
    }

    /** Package-local fault seam for startup cleanup verification. */
    /* default */
    @FunctionalInterface
    interface StartFaultInjector {
        void after(StartStage stage, SigningActiveWal wal,
                SigningGenerationRegistry registry) throws IOException;
    }

    /* default */ MetadataStoreId storeId() { return storeId; }

    private static SigningLedgerRecovery.Configuration recoveryConfiguration(
            SigningActiveWal.Configuration activeWalConfiguration) {
        SigningLedgerRecovery.Configuration defaults = SigningLedgerRecovery.Configuration.defaults();
        return new SigningLedgerRecovery.Configuration(defaults.maximumRootEntries(),
                defaults.maximumArtifactBytes(), defaults.maximumCheckpointEntries(),
                activeWalConfiguration);
    }

    /* default */ MetadataTransactionId issue() throws IOException {
        return issue(SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ MetadataTransactionId issue(
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) throws IOException {
        requireOpen();
        UUID token = UUID.randomUUID();
        MetadataTransactionId transactionId = transactionId(token);
        publishFrame(SigningWalFrameCodec.RecordType.ISSUE, token,
                SigningTransactionPayloadCodec.issue(),
                SigningTransactionPayloadCodec.issuePayload(), admissionClass);
        return transactionId;
    }

    /* default */ MetadataCommitResult commit(MetadataTransactionId transactionId,
            List<SigningTransactionPayloadCodec.Mutation> mutations) throws IOException {
        return commit(transactionId, mutations, null,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ MetadataCommitResult commit(MetadataTransactionId transactionId,
            List<SigningTransactionPayloadCodec.Mutation> mutations,
            SigningAdmission signingAdmission) throws IOException {
        return commit(transactionId, mutations, signingAdmission,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ MetadataCommitResult commit(MetadataTransactionId transactionId,
            List<SigningTransactionPayloadCodec.Mutation> mutations,
            SigningAdmission signingAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) throws IOException {
        requireOwned(transactionId);
        requireOwned(signingAdmission);
        Objects.requireNonNull(admissionClass, "admissionClass");
        long reservedBytes;
        try {
            reservedBytes = coordinatorReservationBytes(mutations);
        } catch (IllegalArgumentException | ArithmeticException failure) {
            close(signingAdmission);
            return rejectedBeforeAdmission(transactionId,
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED);
        }
        long commitWatermark;
        synchronized (stateLock) {
            commitWatermark = observedWatermark;
        }
        return commitReserved(transactionId, mutations, reservedBytes, commitWatermark,
                signingAdmission, admissionClass);
    }

    /** Publishes one self-describing mutation frame without issuance or acknowledgement frames. */
    /* default */ MetadataCommitResult directCommit(
            List<SigningTransactionPayloadCodec.Mutation> mutations) throws IOException {
        return directCommit(mutations, null,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ MetadataCommitResult directCommit(
            List<SigningTransactionPayloadCodec.Mutation> mutations,
            SigningAdmission signingAdmission) throws IOException {
        return directCommit(mutations, signingAdmission,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    /* default */ MetadataCommitResult directProgressCommit(
            List<SigningTransactionPayloadCodec.Mutation> mutations) throws IOException {
        return directCommit(mutations, null,
                SigningTransitionWorkspaceSizing.AdmissionClass.PROTECTED_ACCEPTED_SIGNING);
    }

    private MetadataCommitResult directCommit(
            List<SigningTransactionPayloadCodec.Mutation> mutations,
            SigningAdmission signingAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) throws IOException {
        requireOpen();
        requireOwned(signingAdmission);
        Objects.requireNonNull(admissionClass, "admissionClass");
        List<SigningTransactionPayloadCodec.Mutation> values;
        try {
            values = List.copyOf(mutations);
        } catch (RuntimeException failure) {
            close(signingAdmission);
            throw failure;
        }
        AdmissionMaintenanceGate.Preparation preparation;
        try {
            preparation = beginLedgerPreparation();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            close(signingAdmission);
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.CANCELLED,
                    "Direct metadata commit was interrupted", failure);
        } catch (SigningActiveWal.OverloadedException overloaded) {
            close(signingAdmission);
            throw walAdmissionFull();
        }
        PreparedFrame prepared = null;
        try {
            synchronized (stateLock) {
                MetadataCommitResult.FailureCategory conflict = validate(values, new HashMap<>());
                if (conflict != null) {
                    return notCommitted(transactionId(UUID.randomUUID()), conflict);
                }
                long commitWatermark = observedWatermark;
                UUID token = UUID.randomUUID();
                prepared = prepareFrame(preparation, SigningWalFrameCodec.RecordType.COMMIT, token,
                        SigningTransactionPayloadCodec.directCommit(values, commitWatermark),
                        SigningTransactionPayloadCodec.directCommitPayload(values, commitWatermark),
                        signingAdmission, admissionClass);
            }
        } catch (SigningActiveWal.OverloadedException overloaded) {
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    WAL_ADMISSION_FULL_MESSAGE);
        } finally {
            if (prepared == null) preparation.close();
            close(signingAdmission);
        }
        return awaitAndPublish(prepared);
    }

    /** Admits a bounded cohort of independent singleton direct mutations before awaiting it. */
    /* default */ List<MetadataCommitResult> directCommitCohort(
            List<List<SigningTransactionPayloadCodec.Mutation>> mutationCohort) throws IOException {
        requireOpen();
        List<List<SigningTransactionPayloadCodec.Mutation>> cohort = mutationCohort.stream()
                .map(List::copyOf).toList();
        if (cohort.isEmpty() || cohort.size() > MAXIMUM_COMMIT_BATCH
                || cohort.stream().anyMatch(mutations -> mutations.size() != 1)) {
            throw new IllegalArgumentException("Direct metadata commit cohort is invalid");
        }

        List<DirectCohortMember> admitted = new ArrayList<>(cohort.size());
        List<AdmissionMaintenanceGate.Preparation> preparations;
        try {
            preparations = beginLedgerPreparations(cohort.size());
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.CANCELLED,
                    "Direct metadata commit cohort was interrupted", failure);
        } catch (SigningActiveWal.OverloadedException overloaded) {
            throw walAdmissionFull();
        }

        Throwable admissionFailure = null;
        try {
            synchronized (stateLock) {
                for (int index = 0; index < cohort.size(); index++) {
                    List<SigningTransactionPayloadCodec.Mutation> mutations = cohort.get(index);
                    AdmissionMaintenanceGate.Preparation preparation = preparations.get(index);
                    MetadataCommitResult.FailureCategory conflict =
                            validate(mutations, new HashMap<>());
                    if (conflict != null) {
                        preparation.close();
                        admitted.add(DirectCohortMember.completed(
                                notCommitted(transactionId(UUID.randomUUID()), conflict)));
                        continue;
                    }
                    long commitWatermark = observedWatermark;
                    UUID token = UUID.randomUUID();
                    try {
                        PreparedFrame frame = prepareFrame(preparation,
                                SigningWalFrameCodec.RecordType.COMMIT, token,
                                SigningTransactionPayloadCodec.directCommit(
                                        mutations, commitWatermark),
                                SigningTransactionPayloadCodec.directCommitPayload(
                                        mutations, commitWatermark), null,
                                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
                        admitted.add(DirectCohortMember.prepared(frame));
                    } catch (SigningActiveWal.OverloadedException overloaded) {
                        admissionFailure = new MetadataStoreException(
                                MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                                WAL_ADMISSION_FULL_MESSAGE);
                        break;
                    } catch (IOException | RuntimeException failure) {
                        admissionFailure = failure;
                        break;
                    }
                }
            }
        } finally {
            closePreparations(preparations);
        }

        List<MetadataCommitResult> results = new ArrayList<>(admitted.size());
        Throwable publicationFailure = null;
        for (DirectCohortMember member : admitted) {
            if (member.completed != null) {
                results.add(member.completed);
                continue;
            }
            try {
                results.add(awaitAndPublish(member.prepared));
            } catch (IOException | RuntimeException failure) {
                if (publicationFailure == null) {
                    publicationFailure = failure;
                }
            }
        }
        if (publicationFailure != null && admissionFailure != null) {
            publicationFailure.addSuppressed(admissionFailure);
        }
        rethrowCohortFailure(publicationFailure == null ? admissionFailure : publicationFailure);
        return List.copyOf(results);
    }

    private static void closePreparations(
            List<AdmissionMaintenanceGate.Preparation> preparations) {
        for (AdmissionMaintenanceGate.Preparation preparation : preparations) {
            preparation.close();
        }
    }

    private static void rethrowCohortFailure(Throwable failure) throws IOException {
        if (failure instanceof IOException ioFailure) {
            throw ioFailure;
        }
        if (failure instanceof RuntimeException runtimeFailure) {
            throw runtimeFailure;
        }
    }

    /** Chooses between complete direct mutation sets at WAL admission. */
    /* default */ ConditionalCommitResult directCommitAtAdmission(
            ConditionalDirectCommit decision) throws IOException {
        requireOpen();
        Objects.requireNonNull(decision, "decision");
        AdmissionMaintenanceGate.Preparation preparation;
        try {
            preparation = beginLedgerPreparation();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.CANCELLED,
                    "Direct metadata commit was interrupted", failure);
        } catch (SigningActiveWal.OverloadedException overloaded) {
            throw walAdmissionFull();
        }
        PreparedFrame prepared = null;
        boolean primaryAdmitted = false;
        try {
            synchronized (stateLock) {
                MetadataCommitResult.FailureCategory conflict =
                        validate(decision.primaryMutations(), new HashMap<>());
                if (conflict != null) {
                    return new ConditionalCommitResult(
                            notCommitted(transactionId(UUID.randomUUID()), conflict), false);
                }
                conflict = validate(decision.fallbackMutations(), new HashMap<>());
                if (conflict != null) {
                    return new ConditionalCommitResult(
                            notCommitted(transactionId(UUID.randomUUID()), conflict), false);
                }
                long primaryWatermark = observedWatermark;
                UUID primaryToken = UUID.randomUUID();
                Optional<PreparedFrame> primary = prepareFrameConditionally(preparation,
                        SigningWalFrameCodec.RecordType.COMMIT, primaryToken,
                        SigningTransactionPayloadCodec.directCommit(
                                decision.primaryMutations(), primaryWatermark),
                        SigningTransactionPayloadCodec.directCommitPayload(
                                decision.primaryMutations(), primaryWatermark),
                        new ConditionalAdmission(decision.primaryGuard(),
                                decision.beforePrimaryAdmission()),
                        SigningTransitionWorkspaceSizing.AdmissionClass
                                .PROTECTED_ACCEPTED_SIGNING);
                if (primary.isPresent()) {
                    prepared = primary.orElseThrow();
                    primaryAdmitted = true;
                } else {
                    long fallbackWatermark = observedWatermark;
                    UUID fallbackToken = UUID.randomUUID();
                    prepared = prepareFrame(preparation, SigningWalFrameCodec.RecordType.COMMIT,
                            fallbackToken, SigningTransactionPayloadCodec.directCommit(
                                    decision.fallbackMutations(), fallbackWatermark),
                            SigningTransactionPayloadCodec.directCommitPayload(
                                    decision.fallbackMutations(), fallbackWatermark), null,
                            SigningTransitionWorkspaceSizing.AdmissionClass
                                    .PROTECTED_ACCEPTED_SIGNING);
                }
            }
        } catch (SigningActiveWal.OverloadedException overloaded) {
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    WAL_ADMISSION_FULL_MESSAGE);
        } finally {
            if (prepared == null) preparation.close();
        }
        return new ConditionalCommitResult(awaitAndPublish(prepared), primaryAdmitted);
    }

    private MetadataCommitResult commitReserved(MetadataTransactionId transactionId,
            List<SigningTransactionPayloadCodec.Mutation> mutations, long reservedBytes,
            long commitWatermark, SigningAdmission signingAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass)
            throws IOException {
        boolean coordinatorReserved;
        try {
            coordinatorReserved = reserveCoordinator(reservedBytes);
        } catch (RuntimeException failure) {
            close(signingAdmission);
            throw failure;
        }
        if (!coordinatorReserved) {
            close(signingAdmission);
            return rejectedBeforeAdmission(transactionId,
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED);
        }
        List<SigningTransactionPayloadCodec.Mutation> values;
        byte[] payload;
        try {
            values = List.copyOf(mutations);
            payload = SigningTransactionPayloadCodec.commit(values, commitWatermark);
        } catch (RuntimeException failure) {
            releaseCoordinator(reservedBytes);
            close(signingAdmission);
            throw failure;
        }
        long requestReservedBytes = reservedBytes;
        CommitRequest request = new CommitRequest(transactionId, values, payload, commitWatermark,
                signingAdmission, admissionClass, () -> {
                    try {
                        releaseCoordinator(requestReservedBytes);
                    } finally {
                        close(signingAdmission);
                    }
                });
        synchronized (coordinatorLock) {
            try {
                requireOpen();
                commitQueue.addLast(request);
                coordinatorLock.notifyAll();
            } catch (RuntimeException failure) {
                request.release();
                throw failure;
            }
        }
        return request.await();
    }

    /* default */ static long coordinatorReservationBytes(
            List<SigningTransactionPayloadCodec.Mutation> mutations) {
        long encodedBytes = SigningTransactionPayloadCodec.encodedCommitSize(mutations);
        long result = Math.addExact(Math.multiplyExact(2L, encodedBytes),
                SigningTransactionPayloadCodec.retainedMutationBytes(mutations));
        result = Math.addExact(result, REQUEST_FIXED_BYTES);
        return Math.addExact(result, Math.multiplyExact(
                MUTATION_FIXED_BYTES, mutations.size()));
    }

    /* default */ CoordinatorStatistics coordinatorStatistics() {
        synchronized (coordinatorLock) {
            return new CoordinatorStatistics(coordinatorReservedRequests,
                    coordinatorReservedBytes, MAXIMUM_COORDINATOR_BYTES);
        }
    }

    /** Captures existing scalar index statistics only at an idle publication boundary. */
    /* default */ CapacityObservation capacityObservation() {
        synchronized (stateLock) {
            synchronized (coordinatorLock) {
                synchronized (walAdmissionLock) {
                    requireOpen();
                    if (coordinatorReservedRequests != 0 || !commitQueue.isEmpty()
                            || !admissionGate.isIdle()) {
                        throw new IllegalStateException(
                                "signing capacity observation requires a quiescent ledger");
                    }
                    SigningMvccIndex.Statistics current = index.statistics();
                    SigningDueWorkIndex.Statistics dueWork = due.statistics();
                    SigningRetentionIndex.Statistics retained = retention.statistics();
                    SigningDueWorkIndex.Statistics ownerWork = owners.statistics();
                    SigningWorkProjection.Statistics projection = workProjection.statistics();
                    SigningGenerationRegistry.Snapshot generation = generations.statistics();
                    CapacitySnapshot budgets = capacitySnapshot();
                    SigningIndexCapacityBudget.Snapshot steady = budgets.steady();
                    SigningIndexCapacityBudget.Snapshot transientBudget = budgets.transientBudget();
                    return new CapacityObservation(current.currentKeys(), current.liveSnapshots(),
                            current.canonicalKeyBytes(),
                            current.estimatedResidentBytes(), current.reservedBytes(),
                            dueWork.workCount(), dueWork.canonicalIdBytes(),
                            dueWork.estimatedResidentBytes(), dueWork.reservedBytes(),
                            retained.records(), retained.reservedBytes(),
                            ownerWork.workCount(), ownerWork.canonicalIdBytes(),
                            ownerWork.estimatedResidentBytes(), ownerWork.reservedBytes(),
                            projection.identities(), projection.reservedBytes(),
                            generation.registered(), generation.published(), generation.superseded(),
                            generation.reclaiming(), generation.reclaimable(),
                            generation.currentReferences(), generation.snapshotPins(),
                            steady.reservedBytes(), steady.highWaterReservedBytes(),
                            steady.maximumBytes(), transientBudget.reservedBytes(),
                            transientBudget.highWaterReservedBytes(), transientBudget.maximumBytes(),
                            budgets.combinedReservedBytes(), budgets.combinedHighWaterBytes(),
                            budgets.combinedMaximumBytes());
                }
            }
        }
    }

    /** Captures both resident-index budgets without requiring quiescence. */
    /* default */ CapacitySnapshot capacitySnapshot() {
        requireOpen();
        return new CapacitySnapshot(capacity.snapshot(), transientCapacity.snapshot());
    }

    /**
     * Returns the live snapshot of the current active WAL only. Its counters reset
     * to zero at each rotation; callers that need lifetime totals must use
     * {@link #cumulativeWriterSnapshot()}.
     *
     * @return live snapshot of the current active WAL
     */
    /* default */ SigningActiveWal.Snapshot writerSnapshot() {
        return activeWal.snapshot();
    }

    /**
     * Returns writer counters accumulated across every WAL rotation of this live
     * engine, so lifetime totals stay monotone even though each active WAL retains
     * only its own counters. Unlike {@link #writerSnapshot()}, which reports the
     * current active WAL alone and therefore drops to zero at each rotation, this
     * view never regresses when a WAL is sealed.
     *
     * @return cumulative writer counters spanning all sealed WALs and the active WAL
     */
    /* default */ SigningActiveWal.Snapshot cumulativeWriterSnapshot() {
        // The volatile epoch pairs the sealed-WAL totals with the exact active WAL
        // they precede, so folding the live counters onto the retired totals stays
        // monotone even if a rotation publishes a new epoch between these reads.
        WriterMetricsEpoch epoch = writerMetricsEpoch;
        return SigningActiveWal.Snapshot.accumulate(
                epoch.retiredTotals(), epoch.active().snapshot());
    }

    /**
     * Sealed-WAL cumulative writer totals bound to the active WAL that succeeds
     * them, published as one immutable pair so a lock-free reader never mixes the
     * retired totals of one rotation with the active WAL of another.
     *
     * @param retiredTotals summed counters and merged maxima of every sealed WAL
     * @param active        active WAL whose live counters extend {@code retiredTotals}
     */
    private record WriterMetricsEpoch(SigningActiveWal.Snapshot retiredTotals,
            SigningActiveWal active) {
    }

    /** Returns the first cause that forced this live engine to require recovery. */
    /* default */ Throwable firstRecoveryFailure() {
        return firstRecoveryFailure.get();
    }

    /** Returns immutable statistics from the recovery that opened this live engine. */
    /* default */ SigningLedgerRecovery.Statistics recoveryStatistics() {
        requireOpen();
        if (recoveryHandle == null) {
            throw new IllegalStateException("Metadata store was not opened by recovery");
        }
        return recoveryHandle.statistics();
    }

    /** Returns counters emitted by the actual production projection rebuild. */
    /* default */ RecoveryProjectionStatistics recoveryProjectionStatistics() {
        requireOpen();
        return recoveryProjectionStatistics;
    }

    /* default */ SigningAdmission reserveAcceptanceCapacity() {
        SigningProjectionCutoverGate.Capture capture = projectionCutover.tryEnter();
        if (capture == null) {
            throw new SigningActiveWal.OverloadedException();
        }
        try (capture) {
            requireOpen();
            return new SigningAdmission(this, due.reserveAdmission());
        }
    }

    /* default */ void requireSigningAdmission(SigningAdmission admission) {
        Objects.requireNonNull(admission, "signingAdmission");
        requireOwned(admission);
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Ephemeral admission ownership requires exact identity.
    private void requireOwned(SigningAdmission admission) {
        if (admission != null && admission.owner != this) {
            throw new IllegalArgumentException("Signing admission belongs to another metadata store");
        }
    }

    private static void close(SigningAdmission admission) {
        if (admission != null) admission.close();
    }

    private boolean reserveCoordinator(long bytes) {
        synchronized (coordinatorLock) {
            requireOpen();
            if (coordinatorReservedRequests >= MAXIMUM_COMMIT_QUEUE
                    || bytes > MAXIMUM_COORDINATOR_BYTES - coordinatorReservedBytes) {
                return false;
            }
            coordinatorReservedRequests++;
            coordinatorReservedBytes += bytes;
            return true;
        }
    }

    private void releaseCoordinator(long bytes) {
        synchronized (coordinatorLock) {
            coordinatorReservedRequests--;
            coordinatorReservedBytes -= bytes;
            if (coordinatorReservedRequests < 0 || coordinatorReservedBytes < 0L) {
                IllegalStateException failure = new IllegalStateException(
                        "Metadata coordinator reservation is inconsistent");
                recordRecoveryFailure(failure);
                state = State.RECOVERY_REQUIRED;
                throw failure;
            }
            coordinatorLock.notifyAll();
        }
    }

    /* default */ MetadataCommitResult reject(MetadataTransactionId transactionId,
            MetadataCommitResult.FailureCategory category) throws IOException {
        requireOwned(transactionId);
        return rejectedBeforeAdmission(transactionId, Objects.requireNonNull(category, "category"));
    }

    /* default */ MetadataCommitResult resolve(MetadataTransactionId transactionId)
            throws IOException {
        requireOwned(transactionId);
        synchronized (stateLock) {
            OutcomeSlot slot = outcomes.get(uuid(transactionId));
            if (slot == null || slot.value == null) {
                throw new MetadataStoreException(
                        MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                        "Metadata transaction was not issued by this store");
            }
            return slot.value;
        }
    }

    /* default */ void acknowledge(MetadataTransactionId transactionId) throws IOException {
        MetadataCommitResult retained = resolve(transactionId);
        if (retained.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                    "Unknown metadata transaction outcome cannot be acknowledged");
        }
        UUID token = uuid(transactionId);
        SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        synchronized (stateLock) {
            admissionClass = outcomes.get(token).admissionClass;
        }
        byte[] payload = SigningTransactionPayloadCodec.acknowledge();
        publishFrame(SigningWalFrameCodec.RecordType.ACK, token, payload,
                SigningTransactionPayloadCodec.acknowledgePayload(), admissionClass);
    }

    /* default */ SigningMvccIndex.Snapshot snapshot() throws MetadataStoreException {
        try (SigningProjectionCutoverGate.Capture ignored = enterProjectionCapture()) {
            requireOpen();
            return index.snapshot();
        }
    }

    /* default */ SigningCurrentSelection selectCurrentFirst(
            MetadataSnapshot.KeyRange range) throws MetadataStoreException {
        try (SigningProjectionCutoverGate.Capture ignored = enterProjectionCapture()) {
            requireOpen();
            MetadataSnapshot.KeyRange checked = Objects.requireNonNull(range, "range");
            return index.selectCurrentFirst(checked.namespace(),
                    checked.lowerInclusive().orElse("!"), checked.upperExclusive());
        }
    }

    /* default */ SigningCurrentSelection selectCurrentRange(
            MetadataSnapshot.KeyRange range) throws MetadataStoreException {
        try (SigningProjectionCutoverGate.Capture ignored = enterProjectionCapture()) {
            requireOpen();
            MetadataSnapshot.KeyRange checked = Objects.requireNonNull(range, "range");
            return index.selectCurrentRange(checked.namespace(),
                    checked.lowerInclusive().orElse("!"), checked.upperExclusive());
        }
    }

    /* default */ byte[] readValue(SigningMvccIndex.SnapshotRecord record) throws IOException {
        SigningWalFrameCodec.Frame frame = readFrame(record.pointer());
        SigningTransactionPayloadCodec.Payload payload =
                SigningTransactionPayloadCodec.decode(frame.payload());
        if (payload.kind() != SigningTransactionPayloadCodec.Kind.COMMIT
                && payload.kind() != SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT) {
            throw new IOException("Metadata record frame type is invalid");
        }
        for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
            if (mutation.key().equals(record.key()) && mutation.content() != null) {
                return mutation.content();
            }
        }
        throw new IOException("Metadata record is absent from its transaction frame");
    }

    /* default */ long advanceWatermark(long observed) throws IOException {
        if (observed < 0L) throw new IllegalArgumentException("observed");
        synchronized (watermarkAdvanceLock) {
            synchronized (stateLock) {
                requireOpen();
                if (observed <= watermark) return watermark;
            }
            UUID token = UUID.randomUUID();
            byte[] payload = SigningTransactionPayloadCodec.watermark(observed);
            publishFrame(SigningWalFrameCodec.RecordType.WATERMARK, token, payload,
                    SigningTransactionPayloadCodec.watermarkPayload(observed));
            synchronized (stateLock) { return watermark; }
        }
    }

    /* default */ void observeWatermark(long observed) {
        if (observed < 0L) throw new IllegalArgumentException("observed");
        synchronized (stateLock) {
            requireOpen();
            observedWatermark = Math.max(observedWatermark, observed);
        }
    }

    /* default */ long recoveredWatermark() {
        synchronized (stateLock) { return watermark; }
    }

    /* default */ static boolean internalNamespace(String namespace) {
        return OUTCOME_NAMESPACE.equals(namespace) || LEDGER_STATE_NAMESPACE.equals(namespace);
    }

    /* default */ Optional<SnapshotOutcome> snapshotOutcome(
            SigningMvccIndex.SnapshotRecord record) throws IOException {
        Objects.requireNonNull(record, "record");
        if (!OUTCOME_NAMESPACE.equals(record.key().namespace())) return Optional.empty();
        SigningWalFrameCodec.Frame frame = readFrame(record.pointer());
        SigningTransactionPayloadCodec.Payload payload =
                SigningTransactionPayloadCodec.decode(frame.payload());
        MetadataTransactionId id = transactionId(frame.transactionId());
        MetadataCommitResult result = switch (payload.kind()) {
            case ISSUE -> unknown(id);
            case COMMIT, DIRECT_COMMIT -> new MetadataCommitResult(id, MetadataCommitResult.Outcome.COMMITTED,
                    OptionalLong.of(record.revision()), Optional.empty());
            case REJECT -> notCommitted(id, payload.failure());
            case ACK, WATERMARK -> null;
        };
        if (result == null) {
            throw new IOException("Retained metadata outcome pointer is inconsistent");
        }
        return Optional.of(new SnapshotOutcome(frame.transactionId(), result));
    }

    /* default */ OptionalLong snapshotWatermark(SigningMvccIndex.SnapshotRecord record)
            throws IOException {
        Objects.requireNonNull(record, "record");
        if (!WATERMARK_KEY.equals(record.key())) return OptionalLong.empty();
        SigningWalFrameCodec.Frame frame = readFrame(record.pointer());
        SigningTransactionPayloadCodec.Payload payload =
                SigningTransactionPayloadCodec.decode(frame.payload());
        if (payload.kind() != SigningTransactionPayloadCodec.Kind.WATERMARK
                && (payload.kind() != SigningTransactionPayloadCodec.Kind.COMMIT
                        && payload.kind() != SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT
                        || payload.watermark() < 0L)) {
            throw new IOException("Metadata watermark pointer is inconsistent");
        }
        return OptionalLong.of(payload.watermark());
    }

    /* default */ void restoreOutcome(SnapshotOutcome snapshot) throws IOException {
        Objects.requireNonNull(snapshot, "snapshot");
        UUID token = snapshot.transactionId();
        synchronized (stateLock) {
            if (outcomes.containsKey(token)) {
                throw new IOException("Snapshot metadata outcome identity is duplicated");
            }
        }
        byte[] issued = SigningTransactionPayloadCodec.issue();
        publishFrame(SigningWalFrameCodec.RecordType.ISSUE, token, issued,
                SigningTransactionPayloadCodec.issuePayload());
        MetadataCommitResult retained = snapshot.result();
        if (retained.outcome() == MetadataCommitResult.Outcome.UNKNOWN) return;
        byte[] terminal = retained.outcome() == MetadataCommitResult.Outcome.COMMITTED
                ? SigningTransactionPayloadCodec.committedOutcome()
                : SigningTransactionPayloadCodec.reject(retained.failureCategory().orElseThrow());
        SigningWalFrameCodec.RecordType type = retained.outcome() == MetadataCommitResult.Outcome.COMMITTED
                ? SigningWalFrameCodec.RecordType.COMMIT : SigningWalFrameCodec.RecordType.REJECT;
        SigningTransactionPayloadCodec.Payload terminalPayload =
                retained.outcome() == MetadataCommitResult.Outcome.COMMITTED
                        ? SigningTransactionPayloadCodec.commitPayload(List.of())
                        : SigningTransactionPayloadCodec.rejectPayload(
                                retained.failureCategory().orElseThrow());
        publishFrame(type, token, terminal, terminalPayload);
    }

    private void recoverWorkProjection(List<SigningMvccIndex.RecoveredRecord> records,
            SigningRecoveryIntegrityValidator.ValidatedSigningRecovery validatedRecovery)
            throws IOException {
        List<SigningWorkProjection.RecoveredState> recoveredStates = new ArrayList<>();
        long envelopesVisited = 0L;
        long bindingsVisited = 0L;
        long outerRecordsVisited = 0L;
        for (SigningMvccIndex.RecoveredRecord recovered : records) {
            String namespace = recovered.key().namespace();
            if (SIGN_ENVELOPE_NAMESPACE.equals(namespace)) {
                envelopesVisited++;
            } else if (SIGN_BINDING_NAMESPACE.equals(namespace)) {
                bindingsVisited++;
            } else if (OUTER_CONTINUATION_NAMESPACE.equals(namespace)) {
                outerRecordsVisited++;
            } else if (SigningWorkProjection.STATE_NAMESPACE.equals(namespace)) {
                recoveredStates.add(new SigningWorkProjection.RecoveredState(recovered.key(),
                        readValue(new SigningMvccIndex.SnapshotRecord(recovered.key(),
                                recovered.pointer(), recovered.revision())),
                        recovered.pointer()));
            }
        }
        SigningWorkProjection.RecoveryStatistics projection =
                workProjection.recoverAll(recoveredStates,
                        validatedRecovery.schedulingByOperation());
        recoveryProjectionStatistics = new RecoveryProjectionStatistics(envelopesVisited,
                validatedRecovery.peakTrackedEnvelopeWorkspaceBytes(),
                validatedRecovery.currentTrackedEnvelopeWorkspaceBytes(),
                projection.statesVisited(), bindingsVisited, outerRecordsVisited,
                projection.activeEntriesBuilt(), projection.statePointersRetained());
    }

    /* default */ List<String> selectDue(Instant cutoff, int maximumResults)
            throws MetadataStoreException {
        try (SigningProjectionCutoverGate.Capture ignored = enterProjectionCapture()) {
            requireOpen();
            try (SigningDueWorkIndex.Selection selection =
                    due.selectThrough(cutoff, maximumResults)) {
                return selection.records().stream()
                        .map(SigningDueWorkIndex.WorkDescriptor::operationId).toList();
            }
        }
    }

    /* default */ DuePage pageDue(Instant cutoff, Optional<String> exclusiveCursor,
            Optional<String> inclusiveHighWatermark, int maximumResults)
            throws MetadataStoreException {
        try (SigningProjectionCutoverGate.Capture ignored = enterProjectionCapture()) {
            synchronized (stateLock) {
                requireOpen();
                try (SigningDueWorkIndex.IdentitySelection selection = due.pageThrough(cutoff,
                        exclusiveCursor, inclusiveHighWatermark, maximumResults)) {
                    List<DueCandidate> candidates = selection.records().stream()
                            .map(record -> new DueCandidate(record.operationId(),
                                    Objects.requireNonNull(record.scheduling(), "scheduling"),
                                    record.malformed()))
                            .toList();
                    Optional<String> highWatermark = inclusiveHighWatermark.isPresent()
                            ? inclusiveHighWatermark : selection.highWatermark();
                    return new DuePage(candidates, highWatermark, selection.endReached());
                }
            }
        }
    }

    /* default */ DueSnapshot pageOwners(Optional<String> exclusiveCursor, int maximumResults)
            throws MetadataStoreException {
        try (SigningProjectionCutoverGate.Capture ignored = enterProjectionCapture()) {
            synchronized (stateLock) {
                requireOpen();
                SigningDueWorkIndex.IdentitySelection selection = owners.pageThrough(Instant.MAX,
                        exclusiveCursor, Optional.empty(), maximumResults);
                boolean transferred = false;
                try {
                    DueSnapshot snapshot = new DueSnapshot(selection, index.snapshot());
                    transferred = true;
                    return snapshot;
                } finally {
                    if (!transferred) selection.close();
                }
            }
        }
    }

    private SigningProjectionCutoverGate.Capture enterProjectionCapture()
            throws MetadataStoreException {
        try {
            return projectionCutover.enter();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.CANCELLED,
                    "Metadata reservation capture was interrupted", failure);
        }
    }

    /* default */ boolean containsOwner(String operationId) {
        synchronized (stateLock) {
            requireOpen();
            return workProjection.containsOperation(operationId);
        }
    }

    /* default */ List<String> selectRetention(Instant createdAtCutoff, int maximumResults) {
        synchronized (stateLock) {
            return retention.selectThrough(createdAtCutoff, maximumResults);
        }
    }

    private void runCoordinator() {
        try {
            while (true) {
                List<CommitRequest> batch = takeCommitBatch();
                if (batch.isEmpty()) return;
                try {
                    commitBatch(batch);
                } catch (RuntimeException failure) {
                    transitionRecoveryRequired(failure);
                    for (CommitRequest request : batch) {
                        request.complete(unknown(request.transactionId));
                    }
                }
            }
        } catch (RuntimeException failure) {
            transitionRecoveryRequired(failure);
        }
    }

    private List<CommitRequest> takeCommitBatch() {
        synchronized (coordinatorLock) {
            while (commitQueue.isEmpty() && state == State.OPEN) {
                try {
                    coordinatorLock.wait();
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    recordRecoveryFailure(failure);
                    state = State.RECOVERY_REQUIRED;
                    break;
                }
            }
            if (commitQueue.isEmpty()) return List.of();
            List<CommitRequest> batch = new ArrayList<>(MAXIMUM_COMMIT_BATCH);
            while (!commitQueue.isEmpty() && batch.size() < MAXIMUM_COMMIT_BATCH) {
                batch.add(commitQueue.removeFirst());
            }
            return batch;
        }
    }

    private void commitBatch(List<CommitRequest> batch) {
        Map<MetadataKey, SigningMvccIndex.SnapshotRecord> shadow = new HashMap<>();
        List<PreparedCommit> prepared = new ArrayList<>(batch.size());
        for (CommitRequest request : batch) {
                AdmissionMaintenanceGate.Preparation preparation;
                try {
                    preparation = beginLedgerPreparation();
                } catch (InterruptedException cancelled) {
                    Thread.currentThread().interrupt();
                    request.completeFailure(new MetadataStoreException(
                            MetadataCommitResult.FailureCategory.CANCELLED,
                            "Metadata commit was cancelled before WAL admission"));
                    continue;
                } catch (SigningActiveWal.OverloadedException overloaded) {
                    request.completeFailure(walAdmissionFull());
                    continue;
                }
                synchronized (stateLock) {
                    OutcomeSlot outcome = outcomes.get(uuid(request.transactionId));
                    MetadataCommitResult retained = outcome == null ? null : outcome.value;
                    if (retained == null || retained.outcome() != MetadataCommitResult.Outcome.UNKNOWN) {
                        preparation.close();
                        request.completeFailure(new MetadataStoreException(
                                MetadataCommitResult.FailureCategory.TRANSACTION_NOT_ISSUED,
                                "Metadata transaction is not active"));
                        continue;
                    }
                    MetadataCommitResult.FailureCategory conflict = validate(request.mutations, shadow);
                    byte[] payload = conflict == null ? request.payload
                            : SigningTransactionPayloadCodec.reject(conflict);
                    SigningWalFrameCodec.RecordType type = conflict == null
                            ? SigningWalFrameCodec.RecordType.COMMIT : SigningWalFrameCodec.RecordType.REJECT;
                    try {
                        SigningTransactionPayloadCodec.Payload semanticPayload = conflict == null
                                ? SigningTransactionPayloadCodec.commitPayload(
                                        request.mutations, request.watermark)
                                : SigningTransactionPayloadCodec.rejectPayload(conflict);
                        PreparedFrame frame = prepareFrame(preparation, type,
                                uuid(request.transactionId), payload, semanticPayload,
                                request.signingAdmission, request.admissionClass);
                        prepared.add(new PreparedCommit(request, conflict, frame));
                        if (conflict == null) updateShadow(request.mutations, shadow);
                    } catch (SigningActiveWal.OverloadedException overloaded) {
                        preparation.close();
                        request.completeFailure(new MetadataStoreException(
                                MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                                WAL_ADMISSION_FULL_MESSAGE));
                    } catch (MetadataStoreException classified) {
                        preparation.close();
                        request.completeFailure(classified);
                    } catch (IOException malformedProjection) {
                        preparation.close();
                        request.completeFailure(new MetadataStoreException(
                                MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE,
                                "Metadata signing projection is invalid"));
                    } catch (RuntimeException unavailable) {
                        preparation.close();
                        request.completeFailure(new MetadataStoreException(
                                MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                                "Metadata WAL is unavailable"));
                    }
                }
        }
        for (PreparedCommit value : prepared) finishPrepared(value);
    }

    private void finishPrepared(PreparedCommit prepared) {
        try {
            MetadataCommitResult result = awaitAndPublish(prepared.frame);
            prepared.request.complete(result);
        } catch (IOException | RuntimeException failure) {
            transitionRecoveryRequired(failure);
            prepared.request.complete(unknown(prepared.request.transactionId));
        }
    }

    private MetadataCommitResult.FailureCategory validate(
            List<SigningTransactionPayloadCodec.Mutation> mutations,
            Map<MetadataKey, SigningMvccIndex.SnapshotRecord> shadow) {
        for (SigningTransactionPayloadCodec.Mutation mutation : mutations) {
            if (shadow.containsKey(mutation.key())) {
                return MetadataCommitResult.FailureCategory.CONFLICT;
            }
            SigningMvccIndex.SnapshotRecord current = index.lookupPrepared(mutation.key()).orElse(null);
            if (mutation.kind() == SigningTransactionPayloadCodec.MutationKind.CREATE) {
                if (current != null) return MetadataCommitResult.FailureCategory.CONFLICT;
            } else if (current == null || current.revision() != mutation.expectedRevision()) {
                return MetadataCommitResult.FailureCategory.CONFLICT;
            }
        }
        return null;
    }

    private void updateShadow(List<SigningTransactionPayloadCodec.Mutation> mutations,
            Map<MetadataKey, SigningMvccIndex.SnapshotRecord> shadow) {
        for (SigningTransactionPayloadCodec.Mutation mutation : mutations) {
            shadow.put(mutation.key(), null);
        }
    }

    private MetadataCommitResult applyPreparedFrame(PreparedFrame prepared) {
        try {
            SigningTransactionPayloadCodec.Kind kind = prepared.kind;
            UUID token = prepared.token;
            prepared.indexApply.publish();
            prepared.workProjection.publish();
            MetadataCommitResult result = prepared.result;
            if (kind == SigningTransactionPayloadCodec.Kind.ACK) {
                prepared.outcomeSlot.value = null;
                outcomes.remove(token, prepared.outcomeSlot);
            } else if (prepared.outcomeSlot != null) {
                prepared.outcomeSlot.value = result;
            }
            if (prepared.watermark >= 0L) {
                watermark = Math.max(watermark, prepared.watermark);
            }
            signalMaintenance();
            stateLock.notifyAll();
            return result;
        } catch (RuntimeException failure) {
            transitionRecoveryRequired(failure);
            throw failure;
        } finally {
            projectionCompleted();
        }
    }

    private static List<SigningMvccIndex.Mutation> semanticMutations(UUID token,
            SigningTransactionPayloadCodec.Payload payload,
            SigningMvccIndex.RecordPointer pointer) {
        List<SigningMvccIndex.Mutation> result = new ArrayList<>();
        if (payload.kind() == SigningTransactionPayloadCodec.Kind.COMMIT
                || payload.kind() == SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT) {
            for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
                result.add(mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE
                        ? SigningMvccIndex.Mutation.delete(mutation.key(), pointer.sequence())
                        : SigningMvccIndex.Mutation.upsert(mutation.key(), pointer));
            }
        }
        MetadataKey outcomeKey = outcomeKey(token);
        if (payload.kind() == SigningTransactionPayloadCodec.Kind.ISSUE
                || payload.kind() == SigningTransactionPayloadCodec.Kind.COMMIT
                || payload.kind() == SigningTransactionPayloadCodec.Kind.REJECT) {
            result.add(SigningMvccIndex.Mutation.upsert(outcomeKey, pointer));
        } else if (payload.kind() == SigningTransactionPayloadCodec.Kind.ACK) {
            result.add(SigningMvccIndex.Mutation.delete(outcomeKey, pointer.sequence()));
        } else if (payload.kind() == SigningTransactionPayloadCodec.Kind.WATERMARK) {
            result.add(SigningMvccIndex.Mutation.upsert(WATERMARK_KEY, pointer));
        }
        if ((payload.kind() == SigningTransactionPayloadCodec.Kind.COMMIT
                || payload.kind() == SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT)
                && payload.watermark() >= 0L) {
            result.add(SigningMvccIndex.Mutation.upsert(WATERMARK_KEY, pointer));
        }
        return List.copyOf(result);
    }

    private MetadataCommitResult publishFrame(SigningWalFrameCodec.RecordType type,
            UUID token, byte[] payload, SigningTransactionPayloadCodec.Payload semanticPayload)
            throws IOException {
        return publishFrame(type, token, payload, semanticPayload,
                SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY);
    }

    private MetadataCommitResult publishFrame(SigningWalFrameCodec.RecordType type,
            UUID token, byte[] payload, SigningTransactionPayloadCodec.Payload semanticPayload,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass)
            throws IOException {
        AdmissionMaintenanceGate.Preparation preparation;
        try {
            preparation = beginLedgerPreparation();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.CANCELLED,
                    "Metadata WAL preparation was interrupted", failure);
        } catch (SigningActiveWal.OverloadedException overloaded) {
            throw walAdmissionFull();
        }
        try {
            PreparedFrame prepared;
            synchronized (stateLock) {
                prepared = prepareFrame(preparation, type, token, payload, semanticPayload, null,
                        admissionClass);
            }
            return awaitAndPublish(prepared);
        } catch (SigningActiveWal.OverloadedException overloaded) {
            preparation.close();
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    WAL_ADMISSION_FULL_MESSAGE);
        } catch (RuntimeException failure) {
            preparation.close();
            throw failure;
        }
    }

    private AdmissionMaintenanceGate.Preparation beginLedgerPreparation()
            throws InterruptedException {
        synchronized (walAdmissionLock) {
            requireOpen();
            AdmissionMaintenanceGate.Preparation preparation = admissionGate.beginSingle();
            preparation.initializeEpoch(ledgerStateEpoch);
            return preparation;
        }
    }

    private List<AdmissionMaintenanceGate.Preparation> beginLedgerPreparations(int count)
            throws InterruptedException {
        synchronized (walAdmissionLock) {
            requireOpen();
            List<AdmissionMaintenanceGate.Preparation> preparations =
                    admissionGate.beginCohort(count);
            long epoch = ledgerStateEpoch;
            for (AdmissionMaintenanceGate.Preparation preparation : preparations) {
                preparation.initializeEpoch(epoch);
            }
            return preparations;
        }
    }

    private PreparedFrame prepareFrame(
            AdmissionMaintenanceGate.Preparation preparation,
            SigningWalFrameCodec.RecordType type,
            UUID token, byte[] encoded, SigningTransactionPayloadCodec.Payload payload,
            SigningAdmission signingAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass)
            throws IOException {
        return prepareFrameCandidate(preparation, type, token, encoded, payload,
                signingAdmission, null, admissionClass).orElseThrow(() -> new IllegalStateException(
                        "Unconditional WAL admission was declined"));
    }

    private Optional<PreparedFrame> prepareFrameConditionally(
            AdmissionMaintenanceGate.Preparation preparation,
            SigningWalFrameCodec.RecordType type,
            UUID token, byte[] encoded, SigningTransactionPayloadCodec.Payload payload,
            ConditionalAdmission admission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) throws IOException {
        return prepareFrameCandidate(preparation, type, token, encoded, payload, null,
                Objects.requireNonNull(admission, "admission"), admissionClass);
    }

    private Optional<PreparedFrame> prepareFrameCandidate(
            AdmissionMaintenanceGate.Preparation preparation,
            SigningWalFrameCodec.RecordType type,
            UUID token, byte[] encoded, SigningTransactionPayloadCodec.Payload payload,
            SigningAdmission signingAdmission, ConditionalAdmission conditionalAdmission,
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass)
            throws IOException {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(admissionClass, "admissionClass");
        requireOwned(signingAdmission);
        SigningActiveWal.FrameReservation reservation;
        synchronized (walAdmissionLock) {
            preparation.requireActive();
            if (preparation.epoch() != ledgerStateEpoch) {
                preparation.close();
                throw new IllegalStateException("Metadata prepared state epoch changed before WAL admission");
            }
            try {
                reservation = activeWal.reserve(type, token, encoded);
            } catch (SigningActiveWal.HeadroomExhaustedException exhausted) {
                signalMaintenancePressure();
                throw exhausted;
            }
            preparation.bind(reservation);
        }
        SigningMvccIndex.RecordPointer pointer = new SigningMvccIndex.RecordPointer(
                reservation.generationIdentity(), reservation.sequence(), reservation.revision(),
                type, reservation.pointerSlot());
        SigningMvccIndex.PreparedApply indexApply = null;
        SigningWorkProjection.Prepared projectedWork = null;
        OutcomeSlot outcomeSlot = null;
        boolean admitted = false;
        boolean declined = false;
        try {
            List<SigningMvccIndex.Mutation> mutations = semanticMutations(token, payload, pointer);
            try {
                indexApply = index.prepare(
                        reservation.revision(), reservation.sequence(), mutations, admissionClass);
                projectedWork = workProjection.prepare(payload, pointer,
                        signingAdmission == null ? null : signingAdmission.dueAdmission);
            } catch (SigningIndexCapacityBudget.CapacityExceededException exhausted) {
                throw classifyPreparationCapacityFailure(admissionClass, exhausted);
            }
            close(signingAdmission);
            MetadataCommitResult result = switch (payload.kind()) {
                case ISSUE -> unknown(transactionId(token));
                case COMMIT, DIRECT_COMMIT -> new MetadataCommitResult(transactionId(token),
                        MetadataCommitResult.Outcome.COMMITTED,
                        OptionalLong.of(pointer.revision()), Optional.empty());
                case REJECT -> notCommitted(transactionId(token), payload.failure());
                case ACK, WATERMARK -> null;
            };
            outcomeSlot = outcomes.get(token);
            if (payload.kind() == SigningTransactionPayloadCodec.Kind.ISSUE) {
                if (outcomeSlot != null) {
                    throw new IllegalStateException("Metadata issuance identity is duplicated");
                }
                outcomeSlot = new OutcomeSlot(null, admissionClass);
                outcomes.put(token, outcomeSlot);
            } else if (payload.kind() != SigningTransactionPayloadCodec.Kind.WATERMARK
                    && payload.kind() != SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT
                    && outcomeSlot == null) {
                throw new IllegalStateException("Metadata outcome identity is absent");
            }
            Optional<SigningActiveWal.Acknowledgement> acknowledgement =
                    admitReservation(preparation, reservation, conditionalAdmission);
            if (acknowledgement.isEmpty()) {
                declined = true;
                return Optional.empty();
            }
            admitted = true;
            return Optional.of(new PreparedFrame(token, payload.kind(), payload.watermark(), pointer,
                    indexApply, outcomeSlot, projectedWork, result, acknowledgement.orElseThrow()));
        } finally {
            close(signingAdmission);
            if (!admitted) {
                if (payload.kind() == SigningTransactionPayloadCodec.Kind.ISSUE
                        && outcomeSlot != null) outcomes.remove(token, outcomeSlot);
                if (projectedWork != null) projectedWork.close();
                if (indexApply != null) indexApply.close();
            }
            reservation.close();
            if (!declined) preparation.close();
        }
    }

    private RuntimeException classifyPreparationCapacityFailure(
            SigningTransitionWorkspaceSizing.AdmissionClass admissionClass,
            SigningIndexCapacityBudget.CapacityExceededException exhausted)
            throws MetadataStoreException {
        if (admissionClass == SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "Metadata signing index capacity is full", exhausted);
        }
        signalProtectedProgressPressure(exhausted);
        return exhausted;
    }

    private Optional<SigningActiveWal.Acknowledgement> admitReservation(
            AdmissionMaintenanceGate.Preparation preparation,
            SigningActiveWal.FrameReservation reservation,
            ConditionalAdmission conditionalAdmission) {
        synchronized (walAdmissionLock) {
            preparation.requireActive();
            if (preparation.epoch() != ledgerStateEpoch) {
                throw new IllegalStateException(
                        "Metadata prepared state epoch changed before WAL admission");
            }
            SigningActiveWal.Acknowledgement acknowledgement;
            if (conditionalAdmission == null) {
                acknowledgement = reservation.admit();
            } else {
                conditionalAdmission.beforeAdmission().run();
                Optional<SigningActiveWal.Acknowledgement> guarded =
                        reservation.admitIf(conditionalAdmission.guard());
                if (guarded.isEmpty()) return Optional.empty();
                acknowledgement = guarded.orElseThrow();
            }
            preparation.transferToAdmittedLocked();
            return Optional.of(acknowledgement);
        }
    }

    private MetadataCommitResult awaitAndPublish(PreparedFrame prepared) throws IOException {
        boolean interrupted = false;
        boolean projectionPending = true;
        try {
            while (true) {
                try {
                    prepared.acknowledgement.await();
                    break;
                } catch (InterruptedException failure) {
                    interrupted = true;
                }
            }
            synchronized (stateLock) {
                while (index.currentRevision() + 1L != prepared.pointer.revision()
                        && state != State.RECOVERY_REQUIRED && state != State.CLOSED) {
                    try {
                        stateLock.wait();
                    } catch (InterruptedException failure) {
                        interrupted = true;
                    }
                }
                requireOpen();
                projectionPending = false;
                return applyPreparedFrame(prepared);
            }
        } catch (ExecutionException failure) {
            prepared.workProjection.close();
            prepared.indexApply.close();
            Throwable actualFailure = failure.getCause() == null ? failure : failure.getCause();
            transitionRecoveryRequired(actualFailure);
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                    "Metadata WAL durability is uncertain", actualFailure);
        } finally {
            if (projectionPending) projectionCompleted();
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private void projectionCompleted() {
        Throwable recoveryFailure = null;
        synchronized (walAdmissionLock) {
            if (!admissionGate.releaseAdmitted()) {
                recoveryFailure = new IllegalStateException(
                        "Metadata WAL admission release is inconsistent");
                recordRecoveryFailure(recoveryFailure);
                state = State.RECOVERY_REQUIRED;
            }
            walAdmissionLock.notifyAll();
        }
        if (recoveryFailure != null) {
            transitionRecoveryRequired(recoveryFailure);
        }
    }

    private void signalMaintenance() {
        synchronized (maintenanceSignal) {
            if (maintenanceDeferred) {
                return;
            }
            maintenanceRequested = true;
            maintenanceSignal.notifyAll();
        }
    }

    private void signalDeferredMaintenance() {
        synchronized (maintenanceSignal) {
            if (!maintenanceDeferred) {
                return;
            }
            boolean protectedProgress = maintenanceDeferralReason
                    == SigningLedgerMaintenance.DeferralReason.PROTECTED_PROGRESS;
            maintenanceDeferred = false;
            maintenanceDeferralReason = null;
            if (protectedProgress) {
                maintenancePressure.signalProtectedProgress();
            } else {
                maintenancePressure.signal();
            }
            clearDeferredMaintenanceSignals();
            maintenanceRequested = true;
            maintenanceSignal.notifyAll();
        }
    }

    private void signalMaintenancePressure() {
        synchronized (maintenanceSignal) {
            if (maintenanceDeferred) {
                maintenancePressure.signal();
                return;
            }
            maintenancePressure.signal();
            maintenanceRequested = true;
            maintenanceSignal.notifyAll();
        }
    }

    /* default */ void signalProtectedProgressPressure(
            SigningIndexCapacityBudget.CapacityExceededException exhausted) {
        protectedProgressPressure.set(Objects.requireNonNull(exhausted, "exhausted"));
        capacity.signalOnReleaseAfter(exhausted.releaseEpoch(),
                this::protectedProgressCapacityReleased);
        synchronized (maintenanceSignal) {
            maintenancePressure.signalProtectedProgress();
            if (!maintenanceDeferred) {
                maintenanceRequested = true;
                maintenanceSignal.notifyAll();
            }
        }
    }

    private void protectedProgressCapacityReleased() {
        if (protectedProgressPressure.getAndSet(null) == null) {
            return;
        }
        synchronized (maintenanceSignal) {
            maintenancePressure.signalProtectedProgress();
            if (!maintenanceDeferred) {
                maintenanceRequested = true;
                maintenanceSignal.notifyAll();
            }
        }
    }

    private void runMaintenance() {
        while (true) {
            PressureReason pressureReason;
            SigningIndexCapacityBudget.CapacityExceededException protectedBaseline;
            synchronized (maintenanceSignal) {
                while (!maintenanceRequested && !maintenanceStopping) {
                    try {
                        maintenanceSignal.wait();
                    } catch (InterruptedException failure) {
                        Thread.currentThread().interrupt();
                        transitionRecoveryRequired(failure);
                        return;
                    }
                }
                if (maintenanceStopping) return;
                maintenanceRequested = false;
                pressureReason = maintenancePressure.beginPass();
                protectedBaseline = protectedProgressPressure.get();
            }
            boolean pressurePass = pressureReason != null;
            if (!pressurePass
                    && activeWal.snapshot().bytesAppended() < MAINTENANCE_ROTATION_BYTES) {
                continue;
            }
            if (pressureReason == PressureReason.PROTECTED_PROGRESS) {
                synchronized (maintenanceSignal) {
                    maintenancePasses = Math.incrementExact(maintenancePasses);
                    maintenancePressure.completePass(true, true);
                    if (maintenancePressure.pending()) {
                        maintenanceRequested = true;
                        maintenanceSignal.notifyAll();
                    }
                }
                continue;
            }
            try {
                synchronized (maintenanceSignal) {
                    maintenancePasses = Math.incrementExact(maintenancePasses);
                }
                MaintenanceResult result = maintainLedger(protectedBaseline);
                synchronized (maintenanceSignal) {
                    if (result.outcome() == MaintenanceOutcome.DEFERRED) {
                        maintenancePressure.deferPass(pressurePass);
                        if (result.deferralReason()
                                != SigningLedgerMaintenance.DeferralReason.PROTECTED_PROGRESS) {
                            armDeferredMaintenance(result.deferralReason(),
                                    result.capacityReleaseEpoch());
                        }
                    } else {
                        maintenancePressure.completePass(
                                pressurePass, result.outcome() == MaintenanceOutcome.RESTORED);
                    }
                    if (result.outcome() != MaintenanceOutcome.DEFERRED) {
                        protectedProgressPressure.compareAndSet(protectedBaseline, null);
                    }
                    if (maintenancePressure.pending()) {
                        maintenanceRequested = true;
                        maintenanceSignal.notifyAll();
                    }
                }
            } catch (IOException | RuntimeException failure) {
                transitionRecoveryRequired(failure);
                return;
            }
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // A new signal is defined by exception identity.
    private SigningIndexCapacityBudget.CapacityExceededException newlyRaisedProtectedPressure(
            SigningIndexCapacityBudget.CapacityExceededException baseline) {
        SigningIndexCapacityBudget.CapacityExceededException current =
                protectedProgressPressure.get();
        return current == baseline ? null : current;
    }

    private MaintenanceResult maintainLedger(
            SigningIndexCapacityBudget.CapacityExceededException protectedBaseline)
            throws IOException {
        observeUsableSpace();
        try {
            if (!admissionGate.beginMaintenanceAndDrain()) {
                return new MaintenanceResult(MaintenanceOutcome.UNCHANGED, null, -1L);
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IOException("Metadata maintenance boundary was interrupted", failure);
        }
        AtomicBoolean gateReleased = new AtomicBoolean();
        try {
            if (maintenance.manifest().sealedSegments().size()
                    >= COMPACTION_SEGMENTS) {
                long checkpointIdentity = nextGenerationIdentity;
                long activeIdentity = Math.incrementExact(checkpointIdentity);
                try {
                    maintenance.compactOnline(checkpointIdentity, activeIdentity,
                            this::publishMaintenanceBoundary,
                            this::closeFinalCutoverAndDrain, stateLock,
                            this::decodeCandidateMutations,
                            () -> newlyRaisedProtectedPressure(protectedBaseline));
                } finally {
                    if (maintenance.manifest().activeWal().identity() == activeIdentity) {
                        nextGenerationIdentity = Math.incrementExact(activeIdentity);
                    }
                }
                synchronized (stateLock) {
                    ledgerStateEpoch = Math.incrementExact(ledgerStateEpoch);
                }
                publishMaintenanceBoundary();
                gateReleased.set(true);
            } else {
                maintenance.rotate(nextGenerationIdentity++);
                publishMaintenanceBoundary();
                gateReleased.set(true);
            }
            maintenance.reclaim(MAXIMUM_RECLAIMS_PER_PASS);
            return new MaintenanceResult(MaintenanceOutcome.RESTORED, null, -1L);
        } catch (SigningLedgerMaintenance.CompactionDeferredException deferred) {
            publishMaintenanceBoundary();
            gateReleased.set(true);
            return new MaintenanceResult(MaintenanceOutcome.DEFERRED, deferred.reason(),
                    capacityReleaseEpoch(deferred));
        } catch (IOException | RuntimeException failure) {
            transitionRecoveryRequired(failure);
            throw failure;
        } finally {
            if (!gateReleased.get()) {
                synchronized (walAdmissionLock) {
                    state = State.RECOVERY_REQUIRED;
                    admissionGate.closeAdmissions();
                }
            }
        }
    }

    private void observeUsableSpace() {
        try {
            UsableSpaceObserver observer = USABLE_SPACE_OBSERVER.get();
            long now = observer == null ? System.nanoTime() : observer.nanoTime();
            if (!usableSpaceObservation.beginProbe(now)) {
                return;
            }
            if (observer != null) {
                observer.observe(Thread.currentThread());
            }
            long configured = Long.getLong("zeroecho.pki.filesystem.softLowSpaceBytes",
                    DEFAULT_SOFT_LOW_SPACE_BYTES);
            long threshold = configured > 0L ? configured : DEFAULT_SOFT_LOW_SPACE_BYTES;
            long usable = Files.getFileStore(root).getUsableSpace();
            if (usableSpaceObservation.observe(usable, threshold, now)
                    && LOG.isLoggable(java.util.logging.Level.WARNING)) {
                LOG.log(java.util.logging.Level.WARNING,
                        usableSpaceWarning(usable, threshold));
            }
        } catch (IOException | RuntimeException observationFailure) { // NOPMD - observational only
            // Soft observation must never affect maintenance, readiness, or durable state.
        }
    }

    /* default */ static String usableSpaceWarning(long usable, long threshold) {
        return "Filesystem usable space is low: code=FILESYSTEM_USABLE_SPACE_LOW usable="
                + usable + " threshold=" + threshold
                + "; recovery may require operator action";
    }

    /* default */ static void installUsableSpaceObserver(UsableSpaceObserver observer) {
        if (!USABLE_SPACE_OBSERVER.compareAndSet(null,
                Objects.requireNonNull(observer, "observer"))) {
            throw new IllegalStateException("Usable-space observer is already installed");
        }
    }

    /* default */ static void clearUsableSpaceObserver() {
        USABLE_SPACE_OBSERVER.set(null);
    }

    private void closeFinalCutoverAndDrain() throws IOException {
        try {
            if (!admissionGate.closeBoundaryAndDrain()) {
                throw new IOException("Metadata compaction drain requires an open ledger");
            }
            projectionCutover.closeCutoverAndDrain();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IOException("Metadata compaction drain was interrupted", failure);
        }
    }

    private List<SigningMvccIndex.Mutation> decodeCandidateMutations(
            SigningWalFrameCodec.ScannedFrame scanned,
            SigningMvccIndex.RecordPointer pointer) throws IOException {
        SigningWalFrameCodec.Frame frame = scanned.frame();
        SigningTransactionPayloadCodec.Payload payload =
                SigningTransactionPayloadCodec.decode(frame.payload());
        return semanticMutations(frame.transactionId(), payload, pointer);
    }

    // A WAL rotation is an identity change of the active WAL instance; equality is
    // meaningless here because two distinct WALs never share operational counters.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    private void publishMaintenanceBoundary() {
        synchronized (walAdmissionLock) {
            SigningActiveWal rotated = maintenance.activeWal();
            if (rotated != activeWal) {
                // The predecessor is sealed and accepts no further writes, so its
                // final snapshot folds exactly once into the cumulative retired
                // totals before the successor becomes visible to metric readers.
                SigningActiveWal.Snapshot retired = SigningActiveWal.Snapshot.accumulate(
                        writerMetricsEpoch.retiredTotals(), activeWal.snapshot());
                activeWal = rotated;
                writerMetricsEpoch = new WriterMetricsEpoch(retired, rotated);
            }
            admissionGate.reopenBoundary();
        }
        projectionCutover.reopenCutover();
    }

    private MetadataCommitResult rejectedBeforeAdmission(MetadataTransactionId id,
            MetadataCommitResult.FailureCategory category) throws IOException {
        byte[] payload = SigningTransactionPayloadCodec.reject(category);
        SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        synchronized (stateLock) {
            OutcomeSlot slot = outcomes.get(uuid(id));
            admissionClass = slot == null
                    ? SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY
                    : slot.admissionClass;
        }
        return publishFrame(SigningWalFrameCodec.RecordType.REJECT, uuid(id), payload,
                SigningTransactionPayloadCodec.rejectPayload(category), admissionClass);
    }

    private void closeAbandonedIssuancesDuringRecovery() throws IOException {
        List<MetadataTransactionId> abandoned = new ArrayList<>();
        synchronized (stateLock) {
            for (OutcomeSlot slot : outcomes.values()) {
                MetadataCommitResult value = slot.value;
                if (value != null
                        && value.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
                    abandoned.add(value.transactionId());
                }
            }
        }
        abandoned.sort(java.util.Comparator.comparing(
                MetadataTransactionId::token));
        for (MetadataTransactionId id : abandoned) {
            closeAbandonedIssuanceDuringRecovery(id);
        }
    }

    private void closeAbandonedIssuanceDuringRecovery(MetadataTransactionId id)
            throws IOException {
        MetadataCommitResult.FailureCategory category =
                MetadataCommitResult.FailureCategory.ABANDONED_BY_RECOVERY;
        byte[] encoded = SigningTransactionPayloadCodec.reject(category);
        SigningTransactionPayloadCodec.Payload payload =
                SigningTransactionPayloadCodec.rejectPayload(category);
        SigningActiveWal.CommitResult committed = activeWal.appendRecovery(
                SigningWalFrameCodec.RecordType.REJECT, uuid(id), encoded);
        SigningMvccIndex.RecordPointer pointer = new SigningMvccIndex.RecordPointer(
                committed.generationIdentity(), committed.offset(), committed.frameLength(),
                committed.sequence(), committed.revision(),
                SigningWalFrameCodec.RecordType.REJECT);
        try {
            try (SigningMvccIndex.PreparedApply prepared = index.prepare(
                    committed.revision(), committed.sequence(),
                    semanticMutations(uuid(id), payload, pointer),
                    SigningTransitionWorkspaceSizing.AdmissionClass.ORDINARY)) {
                prepared.publish();
            }
        } catch (SigningIndexCapacityBudget.CapacityExceededException exhausted) {
            throw new MetadataStoreException(
                    MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                    "Metadata signing index capacity is full", exhausted);
        }
        synchronized (stateLock) {
            OutcomeSlot outcome = outcomes.get(uuid(id));
            if (outcome == null
                    || outcome.value.outcome() != MetadataCommitResult.Outcome.UNKNOWN) {
                throw new IllegalStateException(
                        "Metadata recovery outcome identity is inconsistent");
            }
            outcome.value = notCommitted(id, category);
        }
    }

    private SigningWalFrameCodec.Frame readFrame(SigningMvccIndex.RecordPointer pointer)
            throws IOException {
        SigningArtifactCatalog.Artifact artifact = artifacts.readable(pointer.generationId());
        byte[] encoded = new byte[pointer.frameLength()];
        try (FileChannel channel = FileChannel.open(root.resolve(artifact.name()),
                StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            channel.position(pointer.frameOffset());
            SigningFormatSupport.readFully(channel, ByteBuffer.wrap(encoded),
                    "metadata transaction frame is truncated");
        }
        SigningWalFrameCodec.Frame frame = SigningWalFrameCodec.decode(encoded);
        if (frame.sequence() != pointer.sequence() || frame.recordType() != pointer.recordType()) {
            throw new IOException("Metadata transaction frame pointer is inconsistent");
        }
        return frame;
    }

    private void requireOwned(MetadataTransactionId transactionId) throws MetadataStoreException {
        Objects.requireNonNull(transactionId, "transactionId");
        if (!storeId.equals(transactionId.storeId())) {
            throw new MetadataStoreException(MetadataCommitResult.FailureCategory.FOREIGN_TRANSACTION,
                    "Metadata transaction belongs to a different store");
        }
    }

    private void requireOpen() {
        if (state != State.OPEN) throw new IllegalStateException("Metadata store requires recovery");
    }

    private void transitionRecoveryRequired(Throwable failure) {
        recordRecoveryFailure(failure);
        synchronized (coordinatorLock) {
            state = State.RECOVERY_REQUIRED;
            while (!commitQueue.isEmpty()) {
                CommitRequest request = commitQueue.removeFirst();
                request.complete(unknown(request.transactionId));
            }
            coordinatorLock.notifyAll();
        }
        synchronized (walAdmissionLock) {
            admissionGate.closeAdmissions();
        }
        projectionCutover.close();
        synchronized (maintenanceSignal) {
            maintenanceSignal.notifyAll();
        }
    }

    private void recordRecoveryFailure(Throwable failure) {
        if (failure != null) {
            firstRecoveryFailure.compareAndSet(null, failure);
        }
    }

    @Override
    public void close() throws IOException {
        synchronized (coordinatorLock) {
            if (state == State.CLOSED) return;
            if (state == State.OPEN) state = State.CLOSING;
            coordinatorLock.notifyAll();
        }
        synchronized (walAdmissionLock) {
            admissionGate.closeAdmissions();
        }
        projectionCutover.close();
        boolean interrupted = false;
        while (coordinator.isAlive()) {
            try { coordinator.join(); }
            catch (InterruptedException failure) { interrupted = true; }
        }
        synchronized (maintenanceSignal) {
            maintenanceStopping = true;
            maintenanceDeferred = false;
            maintenanceDeferralReason = null;
            maintenanceSignal.notifyAll();
        }
        while (maintenanceCoordinator.isAlive()) {
            try { maintenanceCoordinator.join(); }
            catch (InterruptedException failure) { interrupted = true; }
        }
        IOException failure = null;
        try { maintenance.close(); }
        catch (IOException closeFailure) {
            recordRecoveryFailure(closeFailure);
            failure = mergeFailure(failure, closeFailure);
        }
        workProjection.close();
        due.close();
        retention.close();
        owners.close();
        capacity.clearReleaseSignal();
        transientCapacity.clearReleaseSignal();
        index.close();
        if (recoveryHandle != null) {
            try { recoveryHandle.close(); }
            catch (IOException closeFailure) {
                recordRecoveryFailure(closeFailure);
                failure = mergeFailure(failure, closeFailure);
            }
        } else if (pendingRecovery != null) {
            try { pendingRecovery.close(); }
            catch (IOException closeFailure) {
                recordRecoveryFailure(closeFailure);
                failure = mergeFailure(failure, closeFailure);
            }
        } else {
            try { activeWal.close(); }
            catch (IOException closeFailure) {
                recordRecoveryFailure(closeFailure);
                failure = mergeFailure(failure, closeFailure);
            }
            generations.close();
        }
        state = State.CLOSED;
        if (interrupted) Thread.currentThread().interrupt();
        if (failure != null) throw failure;
        if (interrupted) throw new IOException("Metadata store close was interrupted");
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Identity prevents Throwable self-suppression.
    private static IOException mergeFailure(IOException current, IOException addition) {
        if (current == null) return addition;
        if (current != addition) current.addSuppressed(addition);
        return current;
    }

    private static SigningManifestCodec.ActiveWal activeDescriptor(
            SigningActiveWal.Descriptor descriptor) {
        byte[] header = SigningWalContainerCodec.encode(new SigningWalContainerCodec.Header(
                descriptor.identity(), descriptor.firstSequence(), descriptor.baselineRevision()));
        return new SigningManifestCodec.ActiveWal(descriptor.identity(), descriptor.firstSequence(),
                descriptor.baselineRevision(), SigningWalContainerCodec.HEADER_BYTES,
                SigningFormatSupport.sha256().digest(header),
                SigningManifestCodec.activeName(descriptor.identity()));
    }

    private static SigningMvccIndex.Configuration indexConfiguration() {
        return new SigningMvccIndex.Configuration(SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS,
                1024, 10_000_000L, 0L);
    }

    private static long nextIdentity(SigningManifestCodec.Manifest manifest) {
        long maximum = manifest.activeWal().identity();
        if (manifest.checkpoint().isPresent()) maximum = Math.max(maximum,
                manifest.checkpoint().orElseThrow().generationIdentity());
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments())
            maximum = Math.max(maximum, segment.generationIdentity());
        return Math.incrementExact(maximum);
    }

    private static boolean hasEntry(Path root) throws IOException {
        try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(root)) {
            return entries.iterator().hasNext();
        }
    }

    private static void requireRoot(Path root) {
        Objects.requireNonNull(root, "root");
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(root))
            throw new IllegalArgumentException("Metadata ledger root is invalid");
    }

    private static FormatUnsupportedException formatUnsupported() {
        return new FormatUnsupportedException();
    }

    /** Cause-free marker for malformed persistent metadata. */
    /* default */ static final class FormatUnsupportedException extends IOException {
        private static final long serialVersionUID = 1L;

        private FormatUnsupportedException() {
            super("Metadata ledger format unsupported: code=METADATA_FORMAT_UNSUPPORTED");
        }
    }

    private static MetadataKey outcomeKey(UUID token) {
        return SigningLedgerRecoveredState.outcomeKey(token);
    }

    private MetadataTransactionId transactionId(UUID token) { return transactionId(storeId, token); }
    private static MetadataTransactionId transactionId(MetadataStoreId storeId, UUID token) {
        return SigningLedgerRecoveredState.transactionId(storeId, token);
    }
    private static UUID uuid(MetadataTransactionId id) {
        String value = id.token();
        return new UUID(Long.parseUnsignedLong(value.substring(0, 16), 16),
                Long.parseUnsignedLong(value.substring(16), 16));
    }
    private static MetadataCommitResult unknown(MetadataTransactionId id) {
        return SigningLedgerRecoveredState.unknown(id);
    }
    private static MetadataCommitResult notCommitted(MetadataTransactionId id,
            MetadataCommitResult.FailureCategory category) {
        return SigningLedgerRecoveredState.notCommitted(id, category);
    }

    private static MetadataStoreException walAdmissionFull() {
        return new MetadataStoreException(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                WAL_ADMISSION_FULL_MESSAGE);
    }

    /** Sticky headroom pressure owned by the maintenance-signal monitor. */
    /* default */ static final class MaintenancePressure {
        private boolean walPending;
        private boolean protectedProgressPending;
        private boolean passActive;
        private boolean raisedDuringPass;
        private PressureReason activeReason;

        /* default */ void signal() {
            signal(PressureReason.WAL);
        }

        /* default */ void signalProtectedProgress() {
            signal(PressureReason.PROTECTED_PROGRESS);
        }

        private void signal(PressureReason raised) {
            if (raised == PressureReason.PROTECTED_PROGRESS) {
                protectedProgressPending = true;
            } else {
                walPending = true;
            }
            if (passActive) {
                raisedDuringPass = true;
            }
        }

        /* default */ PressureReason beginPass() {
            if (!pending()) {
                return null;
            }
            if (passActive) {
                throw new IllegalStateException("Metadata maintenance pressure pass overlaps");
            }
            if (protectedProgressPending) {
                activeReason = PressureReason.PROTECTED_PROGRESS;
                protectedProgressPending = false;
            } else {
                activeReason = PressureReason.WAL;
                walPending = false;
            }
            passActive = true;
            raisedDuringPass = false;
            return activeReason;
        }

        /* default */ void deferPass(boolean pressurePass) {
            if (!pressurePass) {
                return;
            }
            if (!passActive) {
                throw new IllegalStateException("Metadata maintenance pressure pass is absent");
            }
            passActive = false;
            raisedDuringPass = false;
            activeReason = null;
        }

        /* default */ boolean completePass(boolean pressurePass, boolean headroomRestored) {
            if (!pressurePass) {
                return false;
            }
            if (!passActive) {
                throw new IllegalStateException("Metadata maintenance pressure pass is absent");
            }
            boolean restored = headroomRestored && !raisedDuringPass;
            if (!headroomRestored && !pending()) {
                if (activeReason == PressureReason.PROTECTED_PROGRESS) {
                    protectedProgressPending = true;
                } else {
                    walPending = true;
                }
            }
            passActive = false;
            raisedDuringPass = false;
            activeReason = null;
            return restored;
        }

        /* default */ boolean pending() {
            return walPending || protectedProgressPending;
        }

        /* default */ PressureReason reason() {
            if (protectedProgressPending) {
                return PressureReason.PROTECTED_PROGRESS;
            }
            if (walPending) {
                return PressureReason.WAL;
            }
            return activeReason;
        }
    }

    /* default */ enum PressureReason {
        WAL,
        PROTECTED_PROGRESS
    }

    private static long capacityReleaseEpoch(
            SigningLedgerMaintenance.CompactionDeferredException deferred) {
        if (deferred.reason() == SigningLedgerMaintenance.DeferralReason.SNAPSHOT) {
            return -1L;
        }
        return ((SigningIndexCapacityBudget.CapacityExceededException)
                deferred.getCause()).releaseEpoch();
    }

    private void armDeferredMaintenance(SigningLedgerMaintenance.DeferralReason reason,
            long capacityReleaseEpoch) {
        if (!Thread.holdsLock(maintenanceSignal)) {
            throw new IllegalStateException("Metadata maintenance signal lock is not held");
        }
        maintenanceDeferred = true;
        maintenanceDeferralReason = reason;
        switch (reason) {
            case TRANSIENT_CAPACITY -> transientCapacity.signalOnReleaseAfter(
                    capacityReleaseEpoch, this::signalDeferredMaintenance);
            case STEADY_CAPACITY -> capacity.signalOnReleaseAfter(
                    capacityReleaseEpoch, this::signalDeferredMaintenance);
            case SNAPSHOT -> index.signalWhenSnapshotsClose(this::signalDeferredMaintenance);
            case PROTECTED_PROGRESS -> throw new IllegalArgumentException(
                    "Protected signing progress does not defer maintenance");
        }
    }

    private void clearDeferredMaintenanceSignals() {
        capacity.clearReleaseSignal();
        transientCapacity.clearReleaseSignal();
        index.clearSnapshotCloseSignal();
    }

    /** Returns package-internal coordinator state for deterministic lifecycle verification. */
    /* default */ MaintenanceCoordinatorSnapshot maintenanceCoordinatorSnapshot() {
        synchronized (maintenanceSignal) {
            return new MaintenanceCoordinatorSnapshot(maintenancePasses, maintenanceRequested,
                    maintenanceDeferred, maintenanceDeferralReason);
        }
    }

    private enum MaintenanceOutcome {
        RESTORED,
        UNCHANGED,
        DEFERRED
    }

    private record MaintenanceResult(MaintenanceOutcome outcome,
            SigningLedgerMaintenance.DeferralReason deferralReason,
            long capacityReleaseEpoch) {
        private MaintenanceResult {
            Objects.requireNonNull(outcome, "outcome");
            if ((outcome == MaintenanceOutcome.DEFERRED) != (deferralReason != null)) {
                throw new IllegalArgumentException("Metadata maintenance result is inconsistent");
            }
            boolean nonCapacityDeferral = deferralReason == null
                    || deferralReason == SigningLedgerMaintenance.DeferralReason.SNAPSHOT;
            if (nonCapacityDeferral && capacityReleaseEpoch != -1L) {
                throw new IllegalArgumentException("Metadata maintenance deferral epoch is inconsistent");
            }
        }
    }

    /** Test-only observation of the thread that performs a filesystem-space probe. */
    /* default */ @FunctionalInterface
    interface UsableSpaceObserver {
        /** Records one probe immediately before the filesystem query. */
        void observe(Thread thread);

        /** Supplies the monotonic probe clock; overridden only by deterministic tests. */
        default long nanoTime() {
            return System.nanoTime();
        }
    }

    /** Hysteretic, rate-limited scalar state for the maintenance-thread probe. */
    /* default */ static final class SoftUsableSpaceObservation {
        private final long warningIntervalNanos;
        private long lastProbeNanos = Long.MIN_VALUE;
        private long lastWarningNanos = Long.MIN_VALUE;
        private boolean low;

        /* default */ SoftUsableSpaceObservation(long warningIntervalNanos) {
            if (warningIntervalNanos <= 0L) {
                throw new IllegalArgumentException("warningIntervalNanos must be positive");
            }
            this.warningIntervalNanos = warningIntervalNanos;
        }

        /* default */ boolean beginProbe(long nowNanos) {
            if (!elapsedAtLeast(nowNanos, lastProbeNanos, warningIntervalNanos)) {
                return false;
            }
            lastProbeNanos = nowNanos;
            return true;
        }

        /* default */ boolean observe(long usable, long threshold, long nowNanos) {
            if (usable < 0L || threshold <= 0L) {
                throw new IllegalArgumentException("usable and threshold must be non-negative");
            }
            if (usable < threshold) {
                boolean warn = !low || elapsedAtLeast(nowNanos, lastWarningNanos,
                        warningIntervalNanos);
                low = true;
                if (warn) {
                    lastWarningNanos = nowNanos;
                }
                return warn;
            }
            if (usable - threshold >= threshold) {
                low = false;
            }
            return false;
        }

        private static boolean elapsedAtLeast(long now, long before, long interval) {
            return before == Long.MIN_VALUE || now - before >= interval;
        }
    }

    /* default */ record MaintenanceCoordinatorSnapshot(long passes, boolean requested,
            boolean deferred, SigningLedgerMaintenance.DeferralReason deferralReason) {
    }

    /** Constant-space lifecycle accounting used only under the WAL-admission lock. */
    /* default */ static final class LifecycleSlots {
        private final int capacity;
        private int prepared;
        private int admitted;

        /* default */ LifecycleSlots(int capacity) {
            if (capacity <= 0) {
                throw new IllegalArgumentException("Metadata lifecycle capacity is invalid");
            }
            this.capacity = capacity;
        }

        /* default */ void acquirePrepared() {
            acquirePrepared(1);
        }

        /* default */ void acquirePrepared(int count) {
            if (count <= 0) {
                throw new IllegalArgumentException("Metadata lifecycle acquisition is invalid");
            }
            int owned = Math.addExact(prepared, admitted);
            if (count > capacity - owned) {
                throw new SigningActiveWal.OverloadedException();
            }
            prepared = Math.addExact(prepared, count);
            requireBound();
        }

        /* default */ void transferPreparedToAdmitted() {
            if (prepared <= 0) {
                throw new IllegalStateException("Metadata lifecycle transfer is inconsistent");
            }
            prepared--;
            admitted++;
            requireBound();
        }

        /* default */ boolean releasePrepared() {
            if (prepared <= 0) {
                return false;
            }
            prepared--;
            requireBound();
            return true;
        }

        /* default */ boolean releaseAdmitted() {
            if (admitted <= 0) {
                return false;
            }
            admitted--;
            requireBound();
            return true;
        }

        private boolean isEmpty() {
            return prepared == 0 && admitted == 0;
        }

        /* default */ LifecycleSnapshot snapshot() {
            return new LifecycleSnapshot(prepared, admitted, capacity);
        }

        private void requireBound() {
            if (prepared < 0 || admitted < 0 || prepared + admitted > capacity) {
                throw new IllegalStateException("Metadata lifecycle accounting is inconsistent");
            }
        }
    }

    /* default */ record LifecycleSnapshot(int prepared, int admitted, int capacity) { }

    /** One monitor-owned admission, maintenance-gate, and lifecycle domain. */
    /* default */ static final class AdmissionMaintenanceGate {
        private final Object monitor;
        private final LifecycleSlots slots;
        private boolean maintenanceActive;
        private boolean closed;

        /* default */ AdmissionMaintenanceGate(Object monitor, int capacity) {
            this.monitor = Objects.requireNonNull(monitor, "monitor");
            slots = new LifecycleSlots(capacity);
        }

        /* default */ Preparation beginSingle() throws InterruptedException {
            synchronized (monitor) {
                awaitAdmission();
                Preparation preparation = new Preparation(this);
                slots.acquirePrepared();
                return preparation;
            }
        }

        /* default */ List<Preparation> beginCohort(int count) throws InterruptedException {
            if (count <= 0 || count > MAXIMUM_COMMIT_BATCH) {
                throw new IllegalArgumentException("Metadata cohort lifecycle count is invalid");
            }
            synchronized (monitor) {
                awaitAdmission();
                List<Preparation> preparations = new ArrayList<>(count);
                for (int index = 0; index < count; index++) {
                    preparations.add(new Preparation(this));
                }
                slots.acquirePrepared(count);
                return preparations;
            }
        }

        private void awaitAdmission() throws InterruptedException {
            while (maintenanceActive && !closed) {
                monitor.wait();
            }
            requireOpen();
        }

        /* default */ boolean beginMaintenanceAndDrain() throws InterruptedException {
            synchronized (monitor) {
                if (maintenanceActive || closed) {
                    return false;
                }
                maintenanceActive = true;
                return drainForMaintenance();
            }
        }

        /* default */ boolean closeBoundaryAndDrain() throws InterruptedException {
            synchronized (monitor) {
                if (closed) {
                    return false;
                }
                maintenanceActive = true;
                return drainForMaintenance();
            }
        }

        private boolean drainForMaintenance() throws InterruptedException {
            while (!slots.isEmpty() && !closed) {
                monitor.wait();
            }
            if (closed) {
                maintenanceActive = false;
                monitor.notifyAll();
                return false;
            }
            return true;
        }

        /* default */ void reopenBoundary() {
            synchronized (monitor) {
                maintenanceActive = false;
                monitor.notifyAll();
            }
        }

        /* default */ void closeAdmissions() {
            synchronized (monitor) {
                closed = true;
                maintenanceActive = false;
                monitor.notifyAll();
            }
        }

        /* default */ boolean releaseAdmitted() {
            synchronized (monitor) {
                boolean released = slots.releaseAdmitted();
                monitor.notifyAll();
                return released;
            }
        }

        /* default */ boolean isIdle() {
            synchronized (monitor) {
                return slots.isEmpty() && !maintenanceActive;
            }
        }

        /* default */ GateSnapshot snapshot() {
            synchronized (monitor) {
                return new GateSnapshot(slots.snapshot(), maintenanceActive, closed);
            }
        }

        private void initializeEpoch(Preparation preparation, long epoch) {
            synchronized (monitor) {
                requireOwnedActive(preparation);
                if (preparation.epochInitialized) {
                    throw new IllegalStateException("Metadata preparation epoch is already set");
                }
                preparation.epoch = epoch;
                preparation.epochInitialized = true;
            }
        }

        private long epoch(Preparation preparation) {
            synchronized (monitor) {
                requireOwnedActive(preparation);
                if (!preparation.epochInitialized) {
                    throw new IllegalStateException("Metadata preparation epoch is absent");
                }
                return preparation.epoch;
            }
        }

        private void requireActive(Preparation preparation) {
            synchronized (monitor) {
                requireOwnedActive(preparation);
            }
        }

        private void bind(Preparation preparation,
                SigningActiveWal.FrameReservation reservation) {
            Objects.requireNonNull(reservation, "reservation");
            synchronized (monitor) {
                requireOwnedActive(preparation);
            }
        }

        private void transferToAdmitted(Preparation preparation) {
            synchronized (monitor) {
                requireOwnedActive(preparation);
                slots.transferPreparedToAdmitted();
                preparation.active = false;
                monitor.notifyAll();
            }
        }

        private void releasePrepared(Preparation preparation) {
            synchronized (monitor) {
                requireOwned(preparation);
                if (!preparation.active) {
                    return;
                }
                preparation.active = false;
                if (!slots.releasePrepared()) {
                    closed = true;
                    maintenanceActive = false;
                    monitor.notifyAll();
                    throw new IllegalStateException(
                            "Metadata preparation accounting is inconsistent");
                }
                monitor.notifyAll();
            }
        }

        private void requireOwnedActive(Preparation preparation) {
            requireOwned(preparation);
            if (!preparation.active) {
                throw new IllegalStateException("Metadata preparation token is closed");
            }
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals")
        private void requireOwned(Preparation preparation) {
            if (preparation == null || preparation.owner != this) {
                throw new IllegalArgumentException("Metadata preparation token is foreign");
            }
        }

        private void requireOpen() {
            if (closed) {
                throw new IllegalStateException("Metadata store requires recovery");
            }
        }

        /** Existing short-lived preparation ownership, now gate-owned. */
        /* default */ static final class Preparation implements AutoCloseable {
            private final AdmissionMaintenanceGate owner;
            private long epoch;
            private boolean epochInitialized;
            private boolean active = true;

            private Preparation(AdmissionMaintenanceGate owner) {
                this.owner = owner;
            }

            /* default */ void initializeEpoch(long epoch) {
                owner.initializeEpoch(this, epoch);
            }

            /* default */ long epoch() {
                return owner.epoch(this);
            }

            /* default */ void requireActive() {
                owner.requireActive(this);
            }

            /* default */ void bind(SigningActiveWal.FrameReservation reservation) {
                owner.bind(this, reservation);
            }

            /* default */ void transferToAdmittedLocked() {
                owner.transferToAdmitted(this);
            }

            @Override public void close() {
                owner.releasePrepared(this);
            }
        }
    }

    /* default */ record GateSnapshot(
            LifecycleSnapshot lifecycle, boolean maintenanceActive, boolean closed) { }

    private enum State { OPEN, CLOSING, RECOVERY_REQUIRED, CLOSED }

    private static final class CommitRequest {
        private final MetadataTransactionId transactionId;
        private final List<SigningTransactionPayloadCodec.Mutation> mutations;
        private final byte[] payload;
        private final long watermark;
        private final SigningAdmission signingAdmission;
        private final SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        private final Runnable reservationRelease;
        private final AtomicBoolean reservationReleased = new AtomicBoolean();
        private MetadataCommitResult result;
        private IOException failure;
        private boolean complete;
        private CommitRequest(MetadataTransactionId transactionId,
                List<SigningTransactionPayloadCodec.Mutation> mutations, byte[] payload, long watermark,
                SigningAdmission signingAdmission,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass,
                Runnable reservationRelease) {
            this.transactionId = transactionId;
            this.mutations = mutations;
            this.payload = payload;
            this.watermark = watermark;
            this.signingAdmission = signingAdmission;
            this.admissionClass = admissionClass;
            this.reservationRelease = reservationRelease;
        }
        private synchronized MetadataCommitResult await() throws IOException {
            boolean interrupted = false;
            while (!complete) {
                try { wait(); } catch (InterruptedException value) { interrupted = true; }
            }
            if (interrupted) Thread.currentThread().interrupt();
            if (failure != null) throw failure;
            return result;
        }
        private void complete(MetadataCommitResult value) {
            boolean completed = false;
            synchronized (this) {
                if (!complete) { result = value; complete = true; completed = true; notifyAll(); }
            }
            if (completed) release();
        }
        private void completeFailure(IOException value) {
            boolean completed = false;
            synchronized (this) {
                if (!complete) { failure = value; complete = true; completed = true; notifyAll(); }
            }
            if (completed) release();
        }
        private void release() {
            if (reservationReleased.compareAndSet(false, true)) reservationRelease.run();
        }
    }

    private record PreparedCommit(CommitRequest request,
            MetadataCommitResult.FailureCategory failure, PreparedFrame frame) { }

    private record DirectCohortMember(
            MetadataCommitResult completed, PreparedFrame prepared) {
        private static DirectCohortMember completed(MetadataCommitResult result) {
            return new DirectCohortMember(Objects.requireNonNull(result, "result"), null);
        }

        private static DirectCohortMember prepared(PreparedFrame frame) {
            return new DirectCohortMember(null, Objects.requireNonNull(frame, "frame"));
        }
    }

    /**
     * Complete primary and fallback direct mutations for guarded WAL admission.
     * The primary guard obeys the bounded-work contract of
     * {@link SigningActiveWal.FrameReservation#admitIf(BooleanSupplier)}. The
     * observation seam is test-only and runs immediately before guarded admission,
     * outside the active WAL lock.
     */
    /* default */ record ConditionalDirectCommit(
            List<SigningTransactionPayloadCodec.Mutation> primaryMutations,
            List<SigningTransactionPayloadCodec.Mutation> fallbackMutations,
            BooleanSupplier primaryGuard, Runnable beforePrimaryAdmission) {
        ConditionalDirectCommit {
            primaryMutations = List.copyOf(primaryMutations);
            fallbackMutations = List.copyOf(fallbackMutations);
            Objects.requireNonNull(primaryGuard, "primaryGuard");
            Objects.requireNonNull(beforePrimaryAdmission, "beforePrimaryAdmission");
        }
    }

    /** Result and selected branch of one conditional direct commit. */
    /* default */ record ConditionalCommitResult(
            MetadataCommitResult result, boolean primaryAdmitted) {
        ConditionalCommitResult {
            Objects.requireNonNull(result, "result");
        }
    }

    /** Bounded admission guard evaluated after its test-only observation seam. */
    private record ConditionalAdmission(BooleanSupplier guard, Runnable beforeAdmission) {
        ConditionalAdmission {
            Objects.requireNonNull(guard, "guard");
            Objects.requireNonNull(beforeAdmission, "beforeAdmission");
        }
    }

    /** Store-owned ephemeral carrier deliberately absent from every durable representation. */
    /* default */ static final class SigningAdmission implements AutoCloseable {
        private final SigningLedgerStoreEngine owner;
        private final SigningDueWorkIndex.Admission dueAdmission;

        private SigningAdmission(SigningLedgerStoreEngine owner,
                SigningDueWorkIndex.Admission dueAdmission) {
            this.owner = owner;
            this.dueAdmission = dueAdmission;
        }

        @Override public void close() { dueAdmission.close(); }
    }

    /** Entire fallible in-memory publication prepared before WAL admission. */
    private record PreparedFrame(UUID token, SigningTransactionPayloadCodec.Kind kind,
            long watermark, SigningMvccIndex.RecordPointer pointer,
            SigningMvccIndex.PreparedApply indexApply,
            OutcomeSlot outcomeSlot, SigningWorkProjection.Prepared workProjection,
            MetadataCommitResult result,
            SigningActiveWal.Acknowledgement acknowledgement) { }

    /* default */ record CoordinatorStatistics(int reservedRequests, long reservedBytes,
            long maximumBytes) { }

    /** Constant-space quiescent capacity evidence assembled from existing indexes. */
    /* default */ record CapacityObservation(int currentKeys, int mvccLiveSnapshots,
            long canonicalKeyBytes,
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
            long transientHighWaterBytes, long transientMaximumBytes,
            long combinedReservedBytes, long combinedHighWaterBytes,
            long combinedMaximumBytes) {
    }

    /** One constant-space observation of the independent steady and transient budgets. */
    /* default */ record CapacitySnapshot(SigningIndexCapacityBudget.Snapshot steady,
            SigningIndexCapacityBudget.Snapshot transientBudget) {
        CapacitySnapshot {
            Objects.requireNonNull(steady, "steady");
            Objects.requireNonNull(transientBudget, "transientBudget");
        }

        /* default */ long combinedReservedBytes() {
            return Math.addExact(steady.reservedBytes(), transientBudget.reservedBytes());
        }

        /* default */ long combinedHighWaterBytes() {
            return Math.addExact(steady.highWaterReservedBytes(),
                    transientBudget.highWaterReservedBytes());
        }

        /* default */ long combinedMaximumBytes() {
            return Math.addExact(steady.maximumBytes(), transientBudget.maximumBytes());
        }
    }

    /** Visit, tracked envelope-workspace, and retained-state counts from recovery. */
    /* default */ record RecoveryProjectionStatistics(long envelopesVisited,
            long peakTrackedEnvelopeWorkspaceBytes, // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.
            long currentTrackedEnvelopeWorkspaceBytes, long statesVisited, // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.
            long bindingsVisited, long outerRecordsVisited, long activeEntriesBuilt,
            long statePointersRetained) {
        private static RecoveryProjectionStatistics empty() {
            return new RecoveryProjectionStatistics(0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L);
        }
    }

    /** Preallocated outcome hash slot mutated without allocation after durability. */
    private static final class OutcomeSlot {
        private MetadataCommitResult value;
        private final SigningTransitionWorkspaceSizing.AdmissionClass admissionClass;
        private OutcomeSlot(MetadataCommitResult value,
                SigningTransitionWorkspaceSizing.AdmissionClass admissionClass) {
            this.value = value;
            this.admissionClass = Objects.requireNonNull(admissionClass, "admissionClass");
        }
    }
    /* default */ record SnapshotOutcome(UUID transactionId, MetadataCommitResult result) {
        SnapshotOutcome {
            Objects.requireNonNull(transactionId, "transactionId");
            Objects.requireNonNull(result, "result");
        }
    }

    /* default */ record DueCandidate(String operationId,
            zeroecho.pki.spi.store.SignWorkflowStore.SchedulingCoordinates scheduling,
            boolean malformed) {
        DueCandidate {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(scheduling, "scheduling");
        }
    }

    /* default */ record DuePage(List<DueCandidate> candidates,
            Optional<String> highWatermark, boolean endReached) {
        DuePage {
            candidates = List.copyOf(Objects.requireNonNull(candidates, "candidates"));
            highWatermark = Objects.requireNonNull(highWatermark, "highWatermark");
        }
    }

    /** One atomic owner selection and MVCC revision used for bulk candidate decoding. */
    /* default */ static final class DueSnapshot implements AutoCloseable {
        private final SigningDueWorkIndex.IdentitySelection selection;
        private final SigningMvccIndex.Snapshot snapshot;
        private final AtomicBoolean closed = new AtomicBoolean();
        private DueSnapshot(SigningDueWorkIndex.IdentitySelection selection,
                SigningMvccIndex.Snapshot snapshot) {
            this.selection = selection;
            this.snapshot = snapshot;
        }
        /* default */ SigningDueWorkIndex.IdentitySelection selection() {
            requireOpen();
            return selection;
        }
        /* default */ SigningMvccIndex.Snapshot snapshot() {
            requireOpen();
            return snapshot;
        }
        private void requireOpen() {
            if (closed.get()) throw new IllegalStateException("signing due snapshot is closed");
        }
        @Override public void close() {
            if (closed.compareAndSet(false, true)) {
                snapshot.close();
                selection.close();
            }
        }
    }

}
