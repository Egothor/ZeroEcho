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

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Phaser;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.async.SigningExecutionRuntime;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSignatureWorkflowProvider;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.impl.fs.SigningPopulationFixture;
import zeroecho.pki.impl.fs.SigningRecoveryFailureDiagnostics;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.util.async.AsyncState;
import zeroecho.pki.util.async.AsyncStatus;

/** Entry point for the explicitly opt-in open-loop signing persistence benchmark. */
@SuppressWarnings({ "PMD.CommentDefaultAccessModifier", "PMD.CloseResource", "PMD.DoNotUseThreads",
        "PMD.AvoidLiteralsInIfCondition", "PMD.AvoidCatchingGenericException", "PMD.CommentRequired", "PMD.NcssCount",
        "PMD.ConsecutiveAppendsShouldReuse", "PMD.ConsecutiveLiteralAppends",
        "PMD.DoNotThrowExceptionInFinally", "PMD.CouplingBetweenObjects", "PMD.NPathComplexity",
        "PMD.AvoidDeeplyNestedIfStmts", "PMD.AvoidDuplicateLiterals", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.ExcessiveParameterList" })
public final class SigningPerformanceBenchmark {

    private static final long NANOS_PER_SECOND = 1_000_000_000L;
    private static final long MINIMUM_SUPPORTED_HEAP = 4L * 1_024L * 1_024L * 1_024L;
    private static final int MAXIMUM_LANES = 32;
    private static final int MAXIMUM_QUEUE_CAPACITY = 64;
    private static final int MAXIMUM_RATE = 1_100;
    private static final int MAXIMUM_WARMUP_SECONDS = 30;
    private static final int MAXIMUM_DURATION_SECONDS = 300;
    private static final int MAXIMUM_DRAIN_SECONDS = 120;
    // Matches SigningExecutionSupport's production polling cadence while keeping
    // the bounded observation delay well within the benchmark's 100 ms p99 budget.
    private static final long NATIVE_OBSERVATION_POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(10L);
    private static final Principal OWNER = new Principal("SERVICE", "signing-performance");
    private static final AccessContext ACCESS = new AccessContext(OWNER, new Purpose("SIGNING_PERFORMANCE"),
            Optional.empty(), Optional.empty());
    private static final KeyRef LEGACY_KEY_REF = new KeyRef("benchmark:local-key");
    private static final KeyRef NATIVE_KEY_REF = new KeyRef("zeroecho-lib:sign.prv");
    private static final int NATIVE_DURABLE_OPERATIONS = 3;
    private static final NanoClock SYSTEM_NANO_CLOCK = System::nanoTime;
    private static final NanoParker SYSTEM_NANO_PARKER = LockSupport::parkNanos;
    private static final Logger OBSERVABILITY_LOGGER = Logger.getLogger("zeroecho.benchmark.signing");

    private SigningPerformanceBenchmark() {
    }

    /**
     * Runs one process-local benchmark and writes its machine-readable report.
     *
     * @param arguments strict {@code --name=value} benchmark arguments
     * @throws IOException          if benchmark storage or report output fails
     * @throws InterruptedException if the scheduler or lane shutdown is interrupted
     */
    public static void main(String[] arguments) throws IOException, InterruptedException {
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(arguments);
        BenchmarkDiagnostics diagnostics = new BenchmarkDiagnostics(configuration);
        try {
            Files.deleteIfExists(configuration.output());
            diagnostics.phaseStarted("preflight");
            verifyCellConfiguration(configuration);
            long maximumHeap = Runtime.getRuntime().maxMemory();
            if (!"smoke".equals(configuration.profile()) && maximumHeap < MINIMUM_SUPPORTED_HEAP) {
                throw new IllegalStateException("signing benchmark requires a maximum heap of at least 4 GiB");
            }
            Environment environment = Environment.capturePreflight(configuration.workRoot());
            diagnostics.environment(environment);
            PreflightAssessment preflight = PreflightAssessment.assess(configuration, environment);
            diagnostics.preflight(preflight);
            if (!preflight.proceed()) {
                throw new SigningBenchmarkGrid.ContractException(
                        "PREFLIGHT_ENVIRONMENT_MISMATCH", preflight.mismatchReasons());
            }
            diagnostics.phaseCompleted("preflight");
            Result result = runVerified(configuration, preflight, diagnostics);
            Files.deleteIfExists(failureOutput(configuration.output()));
            diagnostics.finalVerdict(result.acceptance());
            System.out.println(result.humanSummary(configuration.output()));
        } catch (SigningBenchmarkGrid.ContractException failure) {
            if ("UNSUPPORTED_MAX_32".equals(failure.reasonCode())) {
                SigningContractRejectionReport.write(configuration, failure.reasonCode());
                diagnostics.recordDeviation("BENCHMARK_CONTRACT_REJECTED", failure);
                diagnostics.failed(failure);
            } else {
                reportFailure(configuration, diagnostics, failure);
            }
            throw failure;
        } catch (IOException | InterruptedException | RuntimeException failure) {
            reportFailure(configuration, diagnostics, failure);
            throw failure;
        }
    }

    static Result run(SigningBenchmarkConfig configuration) throws IOException, InterruptedException {
        verifyCellConfiguration(configuration);
        Environment environment = Environment.capturePreflight(configuration.workRoot());
        PreflightAssessment preflight = PreflightAssessment.assess(configuration, environment);
        return runVerified(configuration, preflight, new BenchmarkDiagnostics(configuration));
    }

    static Result run(SigningBenchmarkConfig configuration, Environment environment)
            throws IOException, InterruptedException {
        verifyCellConfiguration(configuration);
        PreflightAssessment preflight = PreflightAssessment.assess(configuration, environment);
        return runVerified(configuration, preflight, new BenchmarkDiagnostics(configuration));
    }

    private static Result runVerified(SigningBenchmarkConfig configuration, PreflightAssessment preflight,
            BenchmarkDiagnostics diagnostics)
            throws IOException, InterruptedException {
        if (!preflight.proceed()) {
            throw new SigningBenchmarkGrid.ContractException(
                    "PREFLIGHT_ENVIRONMENT_MISMATCH", preflight.mismatchReasons());
        }
        BenchmarkTarget target = switch (configuration.targetMode()) {
            case LEGACY_FILESYSTEM_DIAGNOSTIC -> SigningPerformanceBenchmark::runLegacy;
            case NATIVE_SHARED_LEDGER -> new NativeSharedLedgerTarget();
        };
        return target.run(configuration, preflight, diagnostics);
    }

    private static void verifyCellConfiguration(SigningBenchmarkConfig configuration) {
        SigningBenchmarkGrid.cells();
        if (configuration.groupSize() == 64) {
            throw new SigningBenchmarkGrid.ContractException("UNSUPPORTED_MAX_32");
        }
        verifyExecutionEnvelope(configuration);
        switch (configuration.cellMode()) {
            case GRID -> {
                SigningBenchmarkGrid.Cell cell = SigningBenchmarkGrid.requireSelected(configuration);
                SigningPopulationPlan.forCell(cell, configuration);
            }
            case CONTROLLED_DIAGNOSTIC -> {
                if (!"diagnostic".equals(configuration.profile())
                        || configuration.targetMode()
                                != SigningBenchmarkConfig.TargetMode.LEGACY_FILESYSTEM_DIAGNOSTIC) {
                    throw new SigningBenchmarkGrid.ContractException("CELL_MODE_PROFILE_MISMATCH");
                }
            }
            case NATIVE_DIAGNOSTIC -> {
                if (!"native-diagnostic".equals(configuration.profile())
                        || configuration.targetMode() != SigningBenchmarkConfig.TargetMode.NATIVE_SHARED_LEDGER
                        || !("native-diagnostic-m1000-w10-l16-g" + configuration.groupSize())
                                .equals(configuration.cellId())
                        || configuration.retainedPopulation() != 1_000
                        || configuration.activePopulation() != 10
                        || configuration.lanes() != 16
                        || configuration.providerMeanMillis() != 0 || configuration.providerJitterMillis() != 0) {
                    throw new SigningBenchmarkGrid.ContractException("NATIVE_DIAGNOSTIC_FINGERPRINT_MISMATCH");
                }
            }
            case SMOKE -> {
                if (!"smoke".equals(configuration.profile())
                        || configuration.targetMode() != SigningBenchmarkConfig.TargetMode.NATIVE_SHARED_LEDGER) {
                    throw new SigningBenchmarkGrid.ContractException("CELL_MODE_PROFILE_MISMATCH");
                }
            }
        }
    }

    private static void verifyExecutionEnvelope(SigningBenchmarkConfig configuration) {
        if (configuration.lanes() > MAXIMUM_LANES
                || configuration.queueCapacity() > MAXIMUM_QUEUE_CAPACITY
                || configuration.rate() > MAXIMUM_RATE
                || configuration.warmupSeconds() > MAXIMUM_WARMUP_SECONDS
                || configuration.durationSeconds() > MAXIMUM_DURATION_SECONDS
                || configuration.drainSeconds() > MAXIMUM_DRAIN_SECONDS) {
            throw new SigningBenchmarkGrid.ContractException("EXECUTION_ENVELOPE_EXCEEDED");
        }
        boolean targetMatchesProfile = switch (configuration.profile()) {
            case "acceptance", "native-diagnostic", "smoke" -> configuration.targetMode()
                    == SigningBenchmarkConfig.TargetMode.NATIVE_SHARED_LEDGER;
            case "diagnostic" -> configuration.targetMode()
                    == SigningBenchmarkConfig.TargetMode.LEGACY_FILESYSTEM_DIAGNOSTIC;
            default -> false;
        };
        if (!targetMatchesProfile) {
            throw new SigningBenchmarkGrid.ContractException("PROFILE_TARGET_MISMATCH");
        }
    }

    private static int nativeConcurrency(SigningBenchmarkConfig configuration) {
        return Math.min(configuration.activePopulation(),
                Math.addExact(configuration.lanes(), configuration.queueCapacity()));
    }

    private static FsPkiStoreOptions benchmarkStoreOptions(SigningBenchmarkConfig configuration) {
        return FsPkiStoreOptions.defaults()
                .withSigningMaximumGroupSize(configuration.groupSize())
                .withSigningResidentIndexBudgetBytes(configuration.residentIndexBudgetBytes())
                .withSigningCompactionTransientBudgetBytes(configuration.compactionTransientBudgetBytes());
    }

    private static Result runLegacy(SigningBenchmarkConfig configuration, PreflightAssessment preflight,
            BenchmarkDiagnostics diagnostics)
            throws IOException, InterruptedException {
        Logger benchmarkLogger = Logger.getLogger("zeroecho.pki");
        Level previousLevel = benchmarkLogger.getLevel();
        benchmarkLogger.setLevel(Level.WARNING);
        diagnostics.phaseStarted("work-setup");
        Files.createDirectories(configuration.workRoot());
        Path work = Files.createTempDirectory(configuration.workRoot(), "run-").toAbsolutePath().normalize();
        diagnostics.phaseCompleted("work-setup");
        byte[] payload = payload(configuration.payloadBytes(), configuration.seed());
        ThreadPoolExecutor lanes = executor(configuration);
        RunMetrics metrics = new RunMetrics(configuration.sampleCapacity(), configuration.seed());
        GcSnapshot before;
        GcSnapshot after;
        ProviderMetrics providerMetrics;
        IndexCapacityMetrics indexCapacityMetrics;
        SigningExecutionRuntime.Metrics runtimeMetrics;
        SigningExecutionRuntime runtime;
        long measurementStart;
        long measurementEnd;
        boolean cleanupAttempted = false;
        try {
            diagnostics.phaseStarted("population");
            diagnostics.phaseCompleted("population");
            FilesystemPkiStore store = new FilesystemPkiStore(work.resolve("store"),
                    benchmarkStoreOptions(configuration));
            try (store;
                    DeterministicDurableSignatureWorkflow provider = new DeterministicDurableSignatureWorkflow(
                            work.resolve("provider"), configuration.providerMeanMillis(),
                            configuration.providerJitterMillis(), configuration.seed(),
                            configuration.sampleCapacity());
                    PkiSigningBus bus = new PkiSigningBus(store, provider, authority(provider))) {
                runtime = bus.executionRuntime();
                diagnostics.runtime(runtime);
                try {
                    diagnostics.phaseStarted("warmup");
                    runPhase(configuration.warmupArrivals(), configuration.rate(), false, configuration, bus,
                            provider, lanes, payload, metrics);
                    diagnostics.phaseCompleted("warmup");
                    provider.resetMetrics();
                    metrics.reset();
                    before = GcSnapshot.capture();
                    diagnostics.phaseStarted("measurement");
                    measurementStart = runPhase(configuration.measurementArrivals(), configuration.rate(), true,
                            configuration, bus,
                            provider, lanes, payload, metrics);
                    diagnostics.windowClosed();
                    diagnostics.phaseCompleted("measurement");
                    measurementEnd = metrics.measurementDeadlineNanos.get();
                    after = GcSnapshot.capture();
                    providerMetrics = ProviderMetrics.deterministic(provider.metrics());
                } finally {
                    diagnostics.phaseStarted("drain");
                    lanes.shutdownNow();
                    if (!lanes.awaitTermination(configuration.drainSeconds(), TimeUnit.SECONDS)) {
                        throw new IllegalStateException("benchmark lanes did not terminate");
                    }
                    diagnostics.phaseCompleted("drain");
                }
                indexCapacityMetrics = IndexCapacityMetrics.from(
                        store.localSigningIndexCapacityMetrics());
            } finally {
                diagnostics.recordStoreRecoveryFailure(
                        SigningRecoveryFailureDiagnostics.firstFailure(store));
            }
            runtimeMetrics = runtime.metrics();
            diagnostics.snapshot(metrics, runtimeMetrics);
            Result preliminary = Result.of(configuration, configuration.measurementArrivals(), metrics,
                    providerMetrics, runtimeMetrics, before, after,
                    Math.max(1L, measurementEnd - measurementStart), preflight, CleanupOutcome.pending(),
                    indexCapacityMetrics);
            diagnostics.phaseStarted("report");
            writeReport(configuration.output(), preliminary.toJson());
            CleanupOutcome cleanup;
            diagnostics.cleanupStarted();
            try {
                cleanupAttempted = true;
                deleteTree(work);
                cleanup = CleanupOutcome.success();
            } catch (IOException failure) {
                cleanup = CleanupOutcome.failure("WORK_ROOT_DELETE_FAILED");
            }
            diagnostics.cleanup(cleanup);
            diagnostics.cleanupCompleted();
            Result completed = preliminary.withCleanup(cleanup);
            writeReport(configuration.output(), completed.toJson());
            diagnostics.phaseCompleted("report");
            return completed;
        } finally {
            if (!lanes.isShutdown()) {
                lanes.shutdownNow();
                lanes.awaitTermination(configuration.drainSeconds(), TimeUnit.SECONDS);
            }
            if (!cleanupAttempted) {
                diagnostics.cleanupStarted();
                try {
                    deleteTree(work);
                    diagnostics.cleanup(CleanupOutcome.success());
                } catch (IOException ignored) {
                    // Primary benchmark/report failure remains authoritative.
                    diagnostics.cleanup(CleanupOutcome.failure("WORK_ROOT_DELETE_FAILED"));
                }
                diagnostics.cleanupCompleted();
            }
            benchmarkLogger.setLevel(previousLevel);
        }
    }

    @FunctionalInterface
    private interface BenchmarkTarget {
        Result run(SigningBenchmarkConfig configuration, PreflightAssessment preflight,
                BenchmarkDiagnostics diagnostics)
                throws IOException, InterruptedException;
    }

    /** Increment-11 smoke boundary for the production admission/shared-ledger path. */
    private static final class NativeSharedLedgerTarget implements BenchmarkTarget {
        @Override
        public Result run(SigningBenchmarkConfig configuration, PreflightAssessment preflight,
                BenchmarkDiagnostics diagnostics)
                throws IOException, InterruptedException {
            if (!"smoke".equals(configuration.profile())) {
                return runNativeOpenLoop(configuration, preflight, diagnostics);
            }
            if (configuration.lanes() != 1 || configuration.queueCapacity() != 1
                    || configuration.measurementArrivals() != NATIVE_DURABLE_OPERATIONS
                    || configuration.providerMeanMillis() != 0 || configuration.providerJitterMillis() != 0) {
                throw new IllegalArgumentException(
                        "native signing smoke requires its controlled 1-lane/1-ready/3-operation local topology");
            }
            return runNativeSmoke(configuration, preflight, diagnostics);
        }
    }

    private static Result runNativeOpenLoop(SigningBenchmarkConfig configuration, PreflightAssessment preflight,
            BenchmarkDiagnostics diagnostics)
            throws IOException, InterruptedException {
        Logger benchmarkLogger = Logger.getLogger("zeroecho.pki");
        Level previousLevel = benchmarkLogger.getLevel();
        benchmarkLogger.setLevel(Level.WARNING);
        diagnostics.phaseStarted("work-setup");
        Files.createDirectories(configuration.workRoot());
        Path work = Files.createTempDirectory(configuration.workRoot(), "native-run-")
                .toAbsolutePath().normalize();
        diagnostics.phaseCompleted("work-setup");
        boolean cleanupAttempted = false;
        char[] unlockMaterial = null;
        try {
            SigningPopulationPlan.Plan populationPlan = configuration.cellMode()
                    == SigningBenchmarkConfig.CellMode.GRID
                            ? SigningPopulationPlan.forCell(
                                    SigningBenchmarkGrid.requireSelected(configuration), configuration)
                            : null;
            boolean retainedOnly = populationPlan != null
                    && populationPlan.mode() == SigningPopulationPlan.Mode.RETAINED_ONLY;
            Path keyringPath = null;
            KeyringUnlockProvider unlockProvider = null;
            if (!retainedOnly) {
                keyringPath = work.resolve("keyring.zek");
                char[] createdUnlockMaterial = nativeUnlockMaterial();
                unlockMaterial = createdUnlockMaterial;
                unlockProvider = () -> new KeyringPassword(createdUnlockMaterial.clone());
                createNativeSigningKey(keyringPath, unlockProvider);
            }
            PopulationMetrics population = PopulationMetrics.none();
            Path storeRoot = work.resolve("store");
            FsPkiStoreOptions storeOptions = FsPkiStoreOptions.defaults()
                    .withSigningMaximumGroupSize(configuration.groupSize())
                    .withSigningResidentIndexBudgetBytes(configuration.residentIndexBudgetBytes())
                    .withSigningCompactionTransientBudgetBytes(configuration.compactionTransientBudgetBytes());
            if (populationPlan != null) {
                diagnostics.phaseStarted("population");
                SigningPopulationFixture.Artifact observed = SigningPopulationFixture.populate(
                        storeRoot, storeOptions, Instant.now(), populationPlan.genericRecords(),
                        populationPlan.activePreload(), SigningPerformanceBenchmark::quiescentJvm,
                        diagnostics.populationProgress());
                population = PopulationMetrics.observed(populationPlan, observed,
                        configuration.residentIndexBudgetBytes(),
                        configuration.compactionTransientBudgetBytes());
                diagnostics.population(population);
                diagnostics.phaseCompleted("population");
            }
            PopulationAccounting populationAccounting = new PopulationAccounting(population);
            Result preliminary;
            FilesystemPkiStore store = new FilesystemPkiStore(storeRoot, storeOptions);
            try (store) {
                if (retainedOnly) {
                    preliminary = retainedOnlyResult(configuration, preflight, store, population);
                } else {
                KeyringUnlockProvider exactUnlockProvider = Objects.requireNonNull(
                        unlockProvider, "native unlock provider");
                Path exactKeyringPath = Objects.requireNonNull(keyringPath, "native keyring path");
                SignatureWorkflow opened = new ZeroEchoLibSignatureWorkflowProvider(exactUnlockProvider)
                        .allocate(new ProviderConfig("zeroecho-lib",
                                Map.of("keyringPath", exactKeyringPath.toString())),
                                SignatureWorkflowRuntimeDependencies.local(exactUnlockProvider, store));
                try (SignatureWorkflow provider = opened;
                        SigningExecutionRuntime runtime = new SigningExecutionRuntime(configuration.lanes(),
                                configuration.queueCapacity(), Duration.ofSeconds(configuration.drainSeconds()),
                                Duration.ofSeconds(configuration.drainSeconds()));
                        PkiSigningBus bus = PkiSigningBus.attach(store, provider, authority(provider), runtime)) {
                    diagnostics.runtime(runtime);
                    byte[] payload = payload(configuration.payloadBytes(), configuration.seed());
                    RunMetrics metrics = new RunMetrics(configuration.sampleCapacity(), configuration.seed());
                    diagnostics.metrics(metrics);
                    NativeWorkflowStepHandler handler = new NativeWorkflowStepHandler(
                            bus, payload, metrics, populationAccounting, diagnostics);
                    try (NativeWorkflowMultiplexer multiplexer = new NativeWorkflowMultiplexer(
                            configuration.activePopulation(), nativeConcurrency(configuration), handler)) {
                        diagnostics.multiplexer(configuration.activePopulation(),
                                nativeConcurrency(configuration));
                        boolean diagnostic = preflight.diagnosticOnly();
                        diagnostics.phaseStarted("warmup");
                        runNativePhase(configuration.warmupArrivals(), configuration.rate(), false,
                                configuration, multiplexer, metrics, diagnostic, diagnostics);
                        SigningExecutionRuntime.Metrics warmupRuntime = runtime.metrics();
                        diagnostics.snapshot(metrics, warmupRuntime);
                        requireCleanPhase(metrics, warmupRuntime, configuration.warmupArrivals(),
                                diagnostic, diagnostics);
                        diagnostics.phaseCompleted("warmup");
                        metrics.reset();
                        multiplexer.resetPeakResidentContextsWhenIdle();
                        resetPeakHeap();
                        GcSnapshot before = GcSnapshot.capture();
                        long baselineHeap = before.usedHeapBytes();
                        FilesystemPkiStore.LocalSigningWriterMetrics writerBefore = store.localSigningWriterMetrics();
                        SigningExecutionRuntime.Metrics runtimeBefore = runtime.metrics();
                        diagnostics.phaseStarted("measurement");
                        long measurementStart = runNativePhase(configuration.measurementArrivals(),
                                configuration.rate(), true, configuration, multiplexer, metrics,
                                diagnostic, diagnostics);
                        diagnostics.phaseCompleted("measurement");
                        long measurementEnd = Math.addExact(measurementStart,
                                Duration.ofSeconds(configuration.durationSeconds()).toNanos());
                        GcSnapshot after = GcSnapshot.capture();
                        long peakHeap = peakHeapBytes();
                        FilesystemPkiStore.LocalSigningWriterMetrics writerAfter = store.localSigningWriterMetrics();
                        SigningExecutionRuntime.Metrics runtimeAfter = runtime.metrics();
                        diagnostics.snapshot(metrics, runtimeAfter);
                        requireFullyDrainedRuntime(runtimeAfter, "measurement", diagnostic, diagnostics);
                        int retainedOperations = configuration.cellMode()
                                == SigningBenchmarkConfig.CellMode.NATIVE_DIAGNOSTIC ? countUnretired(store) : -1;
                        population = populationAccounting.finish();
                        diagnostics.population(population);
                        int accountedEventHighWaterRecords = populationPlan == null ? -1
                                : Math.toIntExact(population.accountedEventHighWaterRecords());
                        ProviderMetrics providerMetrics = ProviderMetrics.nativeLocal(
                                metrics.providerSubmitNanos.sum(), metrics.accepted.sum(), metrics.accepted.sum(),
                                retainedOperations, accountedEventHighWaterRecords, writerBefore, writerAfter);
                        preliminary = Result.of(configuration, configuration.measurementArrivals(), metrics,
                                providerMetrics, runtimeDelta(runtimeBefore, runtimeAfter), before, after,
                                Math.max(1L, measurementEnd - measurementStart), preflight,
                                CleanupOutcome.pending(), baselineHeap, after.usedHeapBytes(), peakHeap, population,
                                IndexCapacityMetrics.from(store.localSigningIndexCapacityMetrics()));
                    }
                }
                }
            } finally {
                diagnostics.recordStoreRecoveryFailure(
                        SigningRecoveryFailureDiagnostics.firstFailure(store));
            }
            diagnostics.phaseStarted("report");
            writeReport(configuration.output(), preliminary.toJson());
            CleanupOutcome cleanup;
            diagnostics.cleanupStarted();
            try {
                cleanupAttempted = true;
                deleteTree(work);
                cleanup = CleanupOutcome.success();
            } catch (IOException failure) {
                cleanup = CleanupOutcome.failure("WORK_ROOT_DELETE_FAILED");
            }
            diagnostics.cleanup(cleanup);
            diagnostics.cleanupCompleted();
            Result completed = preliminary.withCleanup(cleanup);
            writeReport(configuration.output(), completed.toJson());
            diagnostics.phaseCompleted("report");
            return completed;
        } finally {
            if (unlockMaterial != null) {
                java.util.Arrays.fill(unlockMaterial, '\0');
            }
            if (!cleanupAttempted) {
                diagnostics.cleanupStarted();
                try {
                    deleteTree(work);
                    diagnostics.cleanup(CleanupOutcome.success());
                } catch (IOException ignored) {
                    // Primary benchmark/report failure remains authoritative.
                    diagnostics.cleanup(CleanupOutcome.failure("WORK_ROOT_DELETE_FAILED"));
                }
                diagnostics.cleanupCompleted();
            }
            benchmarkLogger.setLevel(previousLevel);
        }
    }

    private static Result retainedOnlyResult(SigningBenchmarkConfig configuration,
            PreflightAssessment preflight, FilesystemPkiStore store, PopulationMetrics population) {
        RunMetrics metrics = new RunMetrics(configuration.sampleCapacity(), configuration.seed());
        GcSnapshot before = GcSnapshot.capture();
        FilesystemPkiStore.LocalSigningWriterMetrics writer = store.localSigningWriterMetrics();
        SigningExecutionRuntime.Metrics runtimeMetrics;
        try (SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                Duration.ofSeconds(configuration.drainSeconds()),
                Duration.ofSeconds(configuration.drainSeconds()))) {
            runtimeMetrics = runtime.metrics();
        }
        GcSnapshot after = GcSnapshot.capture();
        ProviderMetrics provider = ProviderMetrics.nativeLocal(0L, 0L, 0L, -1,
                Math.toIntExact(population.accountedEventHighWaterRecords()), writer, writer);
        return Result.of(configuration, 0L, metrics, provider, runtimeMetrics, before, after,
                1L, preflight, CleanupOutcome.pending(), before.usedHeapBytes(),
                after.usedHeapBytes(), Math.max(before.usedHeapBytes(), after.usedHeapBytes()), population,
                IndexCapacityMetrics.from(store.localSigningIndexCapacityMetrics()));
    }

    private static SigningPopulationFixture.QuiescentJvm quiescentJvm() {
        GcSnapshot snapshot = GcSnapshot.capture();
        return new SigningPopulationFixture.QuiescentJvm(snapshot.usedHeapBytes(),
                snapshot.allocatedBytes(), snapshot.collections(), snapshot.collectionMillis());
    }

    private static long runNativePhase(long arrivals, int rate, boolean measured,
            SigningBenchmarkConfig configuration, NativeWorkflowMultiplexer multiplexer,
            RunMetrics metrics, boolean diagnostic, BenchmarkDiagnostics diagnostics)
            throws InterruptedException {
        try {
            return runNativePhaseBody(arrivals, rate, measured, configuration, multiplexer, metrics,
                    diagnostic, diagnostics);
        } finally {
            metrics.peakResidentContexts.accumulateAndGet(multiplexer.peakResidentContexts(), Math::max);
        }
    }

    private static long runNativePhaseBody(long arrivals, int rate, boolean measured,
            SigningBenchmarkConfig configuration, NativeWorkflowMultiplexer multiplexer,
            RunMetrics metrics, boolean diagnostic, BenchmarkDiagnostics diagnostics)
            throws InterruptedException {
        long phaseStart = SYSTEM_NANO_CLOCK.nanoTime() + TimeUnit.MILLISECONDS.toNanos(10L);
        long deadline = measured
                ? Math.addExact(phaseStart, Duration.ofSeconds(configuration.durationSeconds()).toNanos())
                : Long.MAX_VALUE;
        metrics.measurementDeadlineNanos.set(deadline);
        for (long sequence = 0L; sequence < arrivals; sequence++) {
            metrics.attemptedArrivals.increment();
            long scheduled = scheduledTime(phaseStart, sequence, rate);
            parkUntil(scheduled, SYSTEM_NANO_CLOCK, SYSTEM_NANO_PARKER);
            NativeWorkflowMultiplexer.WorkflowContext context =
                    new NativeWorkflowMultiplexer.WorkflowContext(sequence, scheduled, measured);
            boolean submitted;
            try {
                submitted = multiplexer.trySubmit(context, scheduled);
            } catch (RuntimeException workerFailure) {
                diagnostics.recordDeviation("MULTIPLEXER_WORKER_FAILURE", workerFailure);
                throw workerFailure;
            }
            if (!submitted) {
                metrics.contextCapacityRejected.increment();
                diagnostics.recordDeviation("HARNESS_CONTEXT_CAPACITY_EXHAUSTED", null);
            } else {
                metrics.workflowContextsAdmitted.increment();
            }
        }
        if (measured) {
            parkUntil(deadline, SYSTEM_NANO_CLOCK, SYSTEM_NANO_PARKER);
            diagnostics.windowClosed();
        }
        diagnostics.phaseStarted("drain");
        int outstanding;
        try {
            outstanding = multiplexer.awaitIdleOrRemaining(
                    configuration.drainSeconds(), TimeUnit.SECONDS);
        } catch (RuntimeException workerFailure) {
            diagnostics.recordDeviation("MULTIPLEXER_WORKER_FAILURE", workerFailure);
            throw workerFailure;
        }
        if (outstanding != 0) {
            TimeoutException timeout = new TimeoutException("native workflow contexts did not drain");
            metrics.uncertain.add(outstanding);
            diagnostics.recordDeviation("DRAIN_TIMEOUT", timeout);
            // A diagnostic run on non-reference hardware may offer more load than the
            // host can drain; the undrained backlog is counted as uncertain and the
            // measured throughput is still reported. An evaluable acceptance run must
            // drain fully, so there the timeout remains fatal.
            if (!diagnostic) {
                throw new IllegalStateException("native benchmark drain timeout", timeout);
            }
        }
        if (measured) {
            metrics.backlogAtWindowClose.set(backlogAtDeadline(metrics.admittedWithinWindow.sum(),
                    metrics.admittedTerminalWithinWindow.sum()));
        }
        diagnostics.phaseCompleted("drain");
        return phaseStart;
    }

    private static void recordAuthoritativeTerminal(RunMetrics metrics, AsyncState state, long timestamp) {
        if (terminalWindow(state, timestamp,
                metrics.measurementDeadlineNanos.get()) == TerminalWindow.WITHIN) {
            metrics.admittedTerminalWithinWindow.increment();
        } else {
            metrics.terminalAfterWindow.increment();
        }
    }

    enum TerminalWindow { WITHIN, AFTER }

    static TerminalWindow terminalWindow(AsyncState terminalState, long timestamp, long deadline) {
        if (!terminalFailure(terminalState) && terminalState != AsyncState.SUCCEEDED) {
            throw new IllegalArgumentException("state is not authoritative terminal");
        }
        return timestamp <= deadline ? TerminalWindow.WITHIN : TerminalWindow.AFTER;
    }

    private static void rollbackAdmission(RunMetrics metrics, boolean admitted, boolean admittedWithinWindow) {
        if (admitted) {
            metrics.admitted.decrement();
        }
        if (admittedWithinWindow) {
            metrics.admittedWithinWindow.decrement();
        }
    }

    private static void requireCleanPhase(RunMetrics metrics, SigningExecutionRuntime.Metrics runtime,
            long expectedArrivals, boolean diagnostic, BenchmarkDiagnostics diagnostics) {
        RunMetricsSnapshot snapshot = RunMetricsSnapshot.capture(metrics);
        List<String> reasons = new ArrayList<>();
        expectEqual(reasons, "attemptedArrivals", snapshot.attemptedArrivals(), expectedArrivals);
        expectEqual(reasons, "contextCapacityRejected", snapshot.contextCapacityRejected(), 0L);
        expectEqual(reasons, "rejected", snapshot.rejected(), 0L);
        expectEqual(reasons, "preAcceptFailure", snapshot.preAcceptFailure(), 0L);
        expectEqual(reasons, "failed", snapshot.failed(), 0L);
        expectEqual(reasons, "uncertain", snapshot.uncertain(), 0L);
        expectEqual(reasons, "acceptedVsCompleted", snapshot.accepted(), snapshot.completed());
        expectEqual(reasons, "workflowContextsAdmittedVsAdmitted",
                snapshot.workflowContextsAdmitted(), snapshot.admitted());
        expectEqual(reasons, "admittedVsAccepted", snapshot.admitted(), snapshot.accepted());
        expectEqual(reasons, "retirementFailure", snapshot.retirementFailure(), 0L);
        expectEqual(reasons, "completedVsRetired", snapshot.completed(), snapshot.retired());
        addRuntimeDrainReasons(reasons, runtime);
        if (!reasons.isEmpty()) {
            diagnostics.failureReasons(reasons);
            // A diagnostic run tolerates an unclean warmup (e.g. an undrained backlog
            // on a host that cannot keep up) so the measurement still produces a
            // throughput figure; an evaluable acceptance run must warm up cleanly.
            if (!diagnostic) {
                throw new PhaseInvariantException("warmup", reasons);
            }
        }
    }

    private static void expectEqual(List<String> reasons, String invariant, long actual, long expected) {
        if (actual != expected) {
            reasons.add(invariant + " actual=" + actual + " expected=" + expected);
        }
    }

    interface NanoClock {
        long nanoTime();
    }

    interface NanoParker {
        void parkNanos(long nanos);
    }

    /** Executes exactly one benchmark-native workflow transition per invocation. */
    static final class NativeWorkflowStepHandler implements NativeWorkflowMultiplexer.StepHandler {
        private final PkiSigningBus bus;
        private final byte[] payloadTemplate;
        private final RunMetrics metrics;
        private final PopulationAccounting population;
        private final BenchmarkDiagnostics diagnostics;

        NativeWorkflowStepHandler(PkiSigningBus bus, byte[] payloadTemplate, RunMetrics metrics,
                PopulationAccounting population, BenchmarkDiagnostics diagnostics) {
            this.bus = Objects.requireNonNull(bus, "bus");
            this.payloadTemplate = Objects.requireNonNull(payloadTemplate, "payloadTemplate").clone();
            this.metrics = Objects.requireNonNull(metrics, "metrics");
            this.population = Objects.requireNonNull(population, "population");
            this.diagnostics = Objects.requireNonNull(diagnostics, "diagnostics");
        }

        @Override public NativeWorkflowMultiplexer.StepResult execute(
                NativeWorkflowMultiplexer.WorkflowContext context) {
            Objects.requireNonNull(context, "context");
            metrics.workflowTransitionsExecuted.increment();
            if (context.state() == NativeWorkflowMultiplexer.WorkflowState.OBSERVE) {
                metrics.observationAttempts.increment();
            }
            return switch (context.state()) {
                case SUBMIT -> submit(context);
                case OBSERVE -> observe(context);
                case CONSUME -> consume(context);
                case RETIRE_SUCCESS -> retire(context, "native-benchmark-consumed");
                case RETIRE_FAILURE -> retire(context, "native-benchmark-terminal-failure");
                case DONE -> throw new IllegalStateException("completed workflow cannot execute another step");
            };
        }

        private NativeWorkflowMultiplexer.StepResult submit(
                NativeWorkflowMultiplexer.WorkflowContext context) {
            byte[] operationPayload = operationPayload(payloadTemplate, context.sequence());
            DurableContentReference content = null;
            long started = System.nanoTime();
            if (context.measured()) {
                metrics.queueLatency.add(Math.max(0L, started - context.scheduledNanos()));
            }
            try (PkiSigningBus.ForegroundCall foreground =
                    bus.registerForegroundCall(CancellationSignal.NONE)) {
                PkiSigningBus.NewSignAdmission reserved;
                try {
                    reserved = bus.reserveNewSignAdmission();
                } catch (zeroecho.pki.api.SigningExecutionException classified) {
                    classifyReservationFailure(classified);
                    return NativeWorkflowMultiplexer.StepResult.completed();
                }
                try (PkiSigningBus.NewSignAdmission admission = reserved) {
                    long admittedAt = System.nanoTime();
                    metrics.admitted.increment();
                    boolean admittedWithinWindow = admittedAt <= metrics.measurementDeadlineNanos.get();
                    if (admittedWithinWindow) {
                        metrics.admittedWithinWindow.increment();
                    }
                    context.recordAdmission(admittedWithinWindow);
                    try (ContentSink sink = bus.beginSigningContent(Encoding.BINARY);
                            OutputStream output = sink.outputStream()) {
                        output.write(operationPayload);
                        content = sink.complete();
                    }
                    context.assignOperationId(bus.newSubmissionId());
                    String algorithm = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm();
                    PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(ACCESS,
                            algorithm, content, NATIVE_KEY_REF, Encoding.BINARY, Optional.empty());
                    PkiId operationId = context.operationId();
                    Duration timeToLive = Duration.ofMinutes(5);
                    Optional<EncodedObject> workflowPayload = Optional.of(continuation.encode());
                    long submitStarted = System.nanoTime();
                    context.markSubmissionInvoked();
                    try {
                        bus.submitInitialSign(admission, operationId, OWNER, NATIVE_KEY_REF,
                                algorithm, content, timeToLive, workflowPayload, foreground);
                    } finally {
                        metrics.providerSubmitNanos.add(Math.max(0L, System.nanoTime() - submitStarted));
                    }
                    confirmAcceptance(context);
                    return observeNext();
                }
            } catch (zeroecho.pki.api.SigningExecutionException classified) {
                if (context.submissionInvoked()) {
                    recordPostAcceptFailure(context, WorkflowDiagnosticSite.SUBMIT_AFTER_INVOCATION,
                            classified);
                    return observeNext();
                }
                classifyPreInvocationFailure(context, classified);
                return NativeWorkflowMultiplexer.StepResult.completed();
            } catch (IOException | RuntimeException failure) {
                if (context.submissionInvoked()) {
                    recordPostAcceptFailure(context, WorkflowDiagnosticSite.SUBMIT_AFTER_INVOCATION,
                            failure);
                    return observeNext();
                }
                classifyPreInvocationFailure(context, failure);
                return NativeWorkflowMultiplexer.StepResult.completed();
            } finally {
                try {
                    if (!context.submissionInvoked() && content != null) {
                        releasePreInvocationContent(content);
                    }
                } finally {
                    java.util.Arrays.fill(operationPayload, (byte) 0);
                }
            }
        }

        private void classifyReservationFailure(zeroecho.pki.api.SigningExecutionException failure) {
            if (failure.classification()
                    == zeroecho.pki.api.SigningExecutionException.Classification.OVERLOADED) {
                metrics.rejected.increment();
                metrics.productionAdmissionRejected.increment();
                diagnostics.recordDeviation("PRODUCTION_ADMISSION_REJECTED", failure);
            } else {
                metrics.preAcceptFailure.increment();
                diagnostics.recordDeviation("PRE_ACCEPT_FAILURE", failure);
            }
        }

        private void classifyPreInvocationFailure(NativeWorkflowMultiplexer.WorkflowContext context,
                Throwable failure) {
            boolean rolledBack = context.rollbackUnconfirmedAdmission();
            rollbackAdmission(metrics, rolledBack, rolledBack && context.admittedWithinWindow());
            metrics.preAcceptFailure.increment();
            diagnostics.recordDeviation("PRE_ACCEPT_FAILURE", failure);
        }

        private void releasePreInvocationContent(DurableContentReference content) {
            try {
                bus.releaseContent(content);
            } catch (RuntimeException cleanupFailure) {
                diagnostics.recordDeviation("PRE_ACCEPT_FAILURE", cleanupFailure);
            }
        }

        private void confirmAcceptance(NativeWorkflowMultiplexer.WorkflowContext context) {
            if (context.confirmAcceptance()) {
                metrics.accepted.increment();
                population.ownerAdmitted();
            }
        }

        private void recordPostAcceptFailure(NativeWorkflowMultiplexer.WorkflowContext context,
                WorkflowDiagnosticSite site, Throwable failure) {
            diagnostics.recordWorkflowFailure(site, "POST_ACCEPT_FAILURE", failure);
            if (context.recordPostAcceptFailure()) {
                diagnostics.recordDeviation("POST_ACCEPT_FAILURE", failure);
            }
        }

        private NativeWorkflowMultiplexer.StepResult observe(
                NativeWorkflowMultiplexer.WorkflowContext context) {
            if (!context.acceptanceConfirmed()) {
                Optional<AsyncStatus> status;
                try {
                    status = bus.status(context.operationId(), CancellationSignal.NONE);
                } catch (RuntimeException failure) {
                    recordPostAcceptFailure(context, WorkflowDiagnosticSite.ACCEPTANCE_STATUS, failure);
                    return observeAfterPollInterval();
                }
                if (status.isEmpty()) {
                    diagnostics.recordWorkflowFailure(WorkflowDiagnosticSite.ACCEPTANCE_STATUS,
                            "PRE_ACCEPT_FAILURE", null);
                    classifyPreInvocationFailure(context, null);
                    return NativeWorkflowMultiplexer.StepResult.completed();
                }
                confirmAcceptance(context);
            }
            PkiSigningBus.SigningObservation observation;
            try {
                observation = bus.observeSigningResult(context.operationId(), CancellationSignal.NONE);
            } catch (RuntimeException failure) {
                recordPostAcceptFailure(context, WorkflowDiagnosticSite.OBSERVE_RESULT, failure);
                return observeAfterPollInterval();
            }
            if (observation instanceof PkiSigningBus.SigningObservation.Pending) {
                return observeAfterPollInterval();
            }
            long terminalAt = System.nanoTime();
            if (observation instanceof PkiSigningBus.SigningObservation.Completed completed) {
                recordAuthoritativeTerminal(metrics, AsyncState.SUCCEEDED, terminalAt);
                context.takeOwnershipOfExpectedSignature(completed.signature().bytes(), terminalAt);
                return NativeWorkflowMultiplexer.StepResult.requeue(
                        NativeWorkflowMultiplexer.WorkflowState.CONSUME, terminalAt);
            }
            PkiSigningBus.SigningObservation.Failed terminalFailure =
                    (PkiSigningBus.SigningObservation.Failed) observation;
            recordAuthoritativeTerminal(metrics, terminalFailure.state(), terminalAt);
            metrics.failed.increment();
            diagnostics.recordWorkflowFailure(WorkflowDiagnosticSite.OBSERVE_RESULT,
                    "SIGNING_TERMINAL_FAILURE", null);
            diagnostics.recordDeviation("SIGNING_TERMINAL_FAILURE", null);
            return NativeWorkflowMultiplexer.StepResult.requeue(
                    NativeWorkflowMultiplexer.WorkflowState.RETIRE_FAILURE, terminalAt);
        }

        private NativeWorkflowMultiplexer.StepResult consume(
                NativeWorkflowMultiplexer.WorkflowContext context) {
            byte[] expectedSignature = context.takeExpectedSignature();
            try {
                Optional<EncodedObject> consumed = bus.consumeResult(
                        context.operationId(), CancellationSignal.NONE);
                if (consumed.isEmpty()
                        || !java.util.Arrays.equals(expectedSignature, consumed.orElseThrow().bytes())) {
                    metrics.uncertain.increment();
                    diagnostics.recordWorkflowFailure(WorkflowDiagnosticSite.CONSUME_RESULT,
                            "RESULT_CONTENT_MISMATCH", null);
                    diagnostics.recordDeviation("RESULT_CONTENT_MISMATCH", null);
                    return retireSuccessfulSigning();
                }
                long terminalAt = context.terminalNanos();
                metrics.completed.increment();
                if (terminalWindow(AsyncState.SUCCEEDED, terminalAt,
                        metrics.measurementDeadlineNanos.get()) == TerminalWindow.WITHIN) {
                    metrics.completedWithinWindow.increment();
                } else {
                    metrics.completedAfterWindow.increment();
                }
                if (context.measured()) {
                    metrics.endToEndLatency.add(Math.max(0L, terminalAt - context.scheduledNanos()));
                    metrics.lastCompletionNanos.accumulateAndGet(terminalAt, Math::max);
                }
                return NativeWorkflowMultiplexer.StepResult.requeue(
                        NativeWorkflowMultiplexer.WorkflowState.RETIRE_SUCCESS, System.nanoTime());
            } catch (RuntimeException failure) {
                metrics.uncertain.increment();
                recordPostAcceptFailure(context, WorkflowDiagnosticSite.CONSUME_RESULT, failure);
                return retireSuccessfulSigning();
            }
        }

        private NativeWorkflowMultiplexer.StepResult retire(
                NativeWorkflowMultiplexer.WorkflowContext context, String reason) {
            try {
                bus.retireSignOperation(context.operationId(), reason);
                metrics.retired.increment();
                population.ownerRetired();
            } catch (RuntimeException retirementFailure) {
                metrics.retirementFailure.increment();
                diagnostics.recordWorkflowFailure(WorkflowDiagnosticSite.RETIRE,
                        "RETIREMENT_FAILURE", retirementFailure);
                diagnostics.recordDeviation("RETIREMENT_FAILURE", retirementFailure);
            }
            return NativeWorkflowMultiplexer.StepResult.completed();
        }

        private static NativeWorkflowMultiplexer.StepResult observeNext() {
            return NativeWorkflowMultiplexer.StepResult.requeue(
                    NativeWorkflowMultiplexer.WorkflowState.OBSERVE, System.nanoTime());
        }

        private static NativeWorkflowMultiplexer.StepResult observeAfterPollInterval() {
            return NativeWorkflowMultiplexer.StepResult.requeue(
                    NativeWorkflowMultiplexer.WorkflowState.OBSERVE,
                    System.nanoTime() + NATIVE_OBSERVATION_POLL_NANOS);
        }

        private static NativeWorkflowMultiplexer.StepResult retireSuccessfulSigning() {
            return NativeWorkflowMultiplexer.StepResult.requeue(
                    NativeWorkflowMultiplexer.WorkflowState.RETIRE_SUCCESS, System.nanoTime());
        }
    }

    private static Result runNativeSmoke(SigningBenchmarkConfig configuration, PreflightAssessment preflight,
            BenchmarkDiagnostics diagnostics)
            throws IOException {
        Logger benchmarkLogger = Logger.getLogger("zeroecho.pki");
        Level previousLevel = benchmarkLogger.getLevel();
        benchmarkLogger.setLevel(Level.WARNING);
        diagnostics.phaseStarted("work-setup");
        Files.createDirectories(configuration.workRoot());
        Path work = Files.createTempDirectory(configuration.workRoot(), "native-run-")
                .toAbsolutePath().normalize();
        diagnostics.phaseCompleted("work-setup");
        byte[] payload = payload(configuration.payloadBytes(), configuration.seed());
        RunMetrics metrics = new RunMetrics(configuration.sampleCapacity(), configuration.seed());
        diagnostics.metrics(metrics);
        GcSnapshot before = GcSnapshot.capture();
        GcSnapshot after;
        ProviderMetrics providerMetrics;
        IndexCapacityMetrics indexCapacityMetrics;
        SigningExecutionRuntime.Metrics runtimeMetrics;
        long measurementStart;
        long measurementEnd;
        boolean cleanupAttempted = false;
        char[] unlockMaterial = null;
        try {
            diagnostics.phaseStarted("population");
            diagnostics.phaseCompleted("population");
            diagnostics.phaseStarted("warmup");
            diagnostics.phaseCompleted("warmup");
            Path keyringPath = work.resolve("keyring.zek");
            char[] createdUnlockMaterial = nativeUnlockMaterial();
            unlockMaterial = createdUnlockMaterial;
            KeyringUnlockProvider unlockProvider = () -> new KeyringPassword(createdUnlockMaterial.clone());
            createNativeSigningKey(keyringPath, unlockProvider);
            SigningExecutionRuntime runtime = null;
            FilesystemPkiStore store = new FilesystemPkiStore(work.resolve("store"),
                    benchmarkStoreOptions(configuration));
            try (store) {
                FilesystemPkiStore.LocalSigningWriterMetrics writerBefore = store.localSigningWriterMetrics();
                SignatureWorkflow opened = new ZeroEchoLibSignatureWorkflowProvider(unlockProvider)
                        .allocate(new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyringPath.toString())),
                                SignatureWorkflowRuntimeDependencies.local(unlockProvider, store));
                try (SignatureWorkflow provider = opened) {
                    SigningExecutionRuntime openedRuntime = new SigningExecutionRuntime(configuration.lanes(),
                            configuration.queueCapacity(),
                            Duration.ofSeconds(configuration.drainSeconds()),
                            Duration.ofSeconds(configuration.drainSeconds()));
                    runtime = openedRuntime;
                    diagnostics.runtime(openedRuntime);
                    List<PkiId> durableOperations = new ArrayList<>(NATIVE_DURABLE_OPERATIONS);
                    int accountedEventHighWaterRecords = 0;
                    long submitNanos = 0L;
                    try (openedRuntime;
                            PkiSigningBus bus = PkiSigningBus.attach(store, provider, authority(provider),
                                    openedRuntime)) {
                        diagnostics.phaseStarted("measurement");
                        measurementStart = System.nanoTime();
                        metrics.measurementDeadlineNanos.set(measurementStart
                                + Duration.ofSeconds(configuration.durationSeconds()).toNanos());
                        for (long sequence = 0L; sequence < NATIVE_DURABLE_OPERATIONS; sequence++) {
                            metrics.attemptedArrivals.increment();
                            long scheduled = scheduledTime(measurementStart, sequence, configuration.rate());
                            parkUntil(scheduled);
                            long submitStarted = System.nanoTime();
                            PkiId operationId = executeOneNative(bus, payload, sequence, scheduled, metrics);
                            submitNanos = Math.addExact(submitNanos, System.nanoTime() - submitStarted);
                            durableOperations.add(operationId);
                            requireDrainedRuntime(openedRuntime.metrics());
                            int durablePopulation = countUnretired(store);
                            accountedEventHighWaterRecords = Math.max(
                                    accountedEventHighWaterRecords, durablePopulation);
                            if (durablePopulation != durableOperations.size()) {
                                throw new IllegalStateException("native durable workflow population is inconsistent");
                            }
                        }
                        diagnostics.windowClosed();
                        diagnostics.phaseStarted("drain");
                        FilesystemPkiStore.LocalSigningWriterMetrics writerAfter = store.localSigningWriterMetrics();
                        for (PkiId operationId : durableOperations) {
                            bus.retireSignOperation(operationId, "native-smoke-cleanup");
                        }
                        requireDrainedRuntime(openedRuntime.metrics());
                        diagnostics.phaseCompleted("drain");
                        int retainedOperations = countUnretired(store);
                        providerMetrics = ProviderMetrics.nativeLocal(submitNanos, NATIVE_DURABLE_OPERATIONS,
                                NATIVE_DURABLE_OPERATIONS,
                                retainedOperations, accountedEventHighWaterRecords, writerBefore, writerAfter);
                        measurementEnd = Math.max(measurementStart + 1L, System.nanoTime());
                        metrics.backlogAtWindowClose.set(backlogAtDeadline(metrics.admitted.sum(),
                                metrics.admittedTerminalWithinWindow.sum()));
                        after = GcSnapshot.capture();
                        diagnostics.snapshot(metrics, openedRuntime.metrics());
                        diagnostics.phaseCompleted("measurement");
                        indexCapacityMetrics = IndexCapacityMetrics.from(
                                store.localSigningIndexCapacityMetrics());
                    }
                }
            } finally {
                diagnostics.recordStoreRecoveryFailure(
                        SigningRecoveryFailureDiagnostics.firstFailure(store));
            }
            runtimeMetrics = Objects.requireNonNull(runtime, "runtime").metrics();
            Result preliminary = Result.of(configuration, NATIVE_DURABLE_OPERATIONS, metrics, providerMetrics,
                    runtimeMetrics, before, after,
                    measurementEnd - measurementStart, preflight, CleanupOutcome.pending(),
                    indexCapacityMetrics);
            diagnostics.phaseStarted("report");
            writeReport(configuration.output(), preliminary.toJson());
            CleanupOutcome cleanup;
            diagnostics.cleanupStarted();
            try {
                cleanupAttempted = true;
                deleteTree(work);
                cleanup = CleanupOutcome.success();
            } catch (IOException failure) {
                cleanup = CleanupOutcome.failure("WORK_ROOT_DELETE_FAILED");
            }
            diagnostics.cleanup(cleanup);
            diagnostics.cleanupCompleted();
            Result completed = preliminary.withCleanup(cleanup);
            writeReport(configuration.output(), completed.toJson());
            diagnostics.phaseCompleted("report");
            return completed;
        } finally {
            if (unlockMaterial != null) {
                java.util.Arrays.fill(unlockMaterial, '\0');
            }
            if (!cleanupAttempted) {
                diagnostics.cleanupStarted();
                try {
                    deleteTree(work);
                    diagnostics.cleanup(CleanupOutcome.success());
                } catch (IOException ignored) {
                    // Primary benchmark/report failure remains authoritative.
                    diagnostics.cleanup(CleanupOutcome.failure("WORK_ROOT_DELETE_FAILED"));
                }
                diagnostics.cleanupCompleted();
            }
            benchmarkLogger.setLevel(previousLevel);
        }
    }

    private static PkiId executeOneNative(PkiSigningBus bus, byte[] payloadTemplate, long sequence,
            long scheduled, RunMetrics metrics) {
        byte[] operationPayload = operationPayload(payloadTemplate, sequence);
        long started = System.nanoTime();
        metrics.queueLatency.add(Math.max(0L, started - scheduled));
        PkiId operationId = null;
        try (PkiSigningBus.ForegroundCall foreground = bus.registerForegroundCall(CancellationSignal.NONE);
                PkiSigningBus.NewSignAdmission admission = bus.reserveNewSignAdmission();
                ContentSink sink = bus.beginSigningContent(Encoding.BINARY)) {
            metrics.admitted.increment();
            sink.outputStream().write(operationPayload);
            DurableContentReference content = sink.complete();
            operationId = bus.newSubmissionId();
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(ACCESS,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), content, NATIVE_KEY_REF,
                    Encoding.BINARY, Optional.empty());
            bus.submitInitialSign(admission, operationId, OWNER, NATIVE_KEY_REF,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), content, Duration.ofMinutes(5),
                    Optional.of(continuation.encode()), foreground);
            metrics.accepted.increment();
            metrics.completed.increment();
            long completed = System.nanoTime();
            if (completed <= metrics.measurementDeadlineNanos.get()) {
                metrics.completedWithinWindow.increment();
                metrics.admittedTerminalWithinWindow.increment();
            } else {
                metrics.completedAfterWindow.increment();
            }
            metrics.endToEndLatency.add(Math.max(0L, completed - scheduled));
            metrics.lastCompletionNanos.accumulateAndGet(completed, Math::max);
            return operationId;
        } catch (zeroecho.pki.api.SigningExecutionException overload) {
            metrics.rejected.increment();
            throw overload;
        } catch (IOException | RuntimeException failure) {
            metrics.uncertain.increment();
            throw new IllegalStateException("native signing smoke operation failed", failure);
        } finally {
            java.util.Arrays.fill(operationPayload, (byte) 0);
        }
    }

    private static void requireDrainedRuntime(SigningExecutionRuntime.Metrics metrics) {
        if (metrics.schedulerReserved() != 0 || metrics.running() != 0 || metrics.ready() != 0) {
            throw new IllegalStateException("native signing runtime did not drain");
        }
    }

    private static void requireFullyDrainedRuntime(SigningExecutionRuntime.Metrics metrics) {
        requireDrainedRuntime(metrics);
        if (metrics.pendingAdvisories() != 0) {
            throw new IllegalStateException("native signing advisories did not drain");
        }
    }

    private static void requireFullyDrainedRuntime(SigningExecutionRuntime.Metrics metrics, String phase,
            boolean diagnostic, BenchmarkDiagnostics diagnostics) {
        List<String> reasons = new ArrayList<>();
        addRuntimeDrainReasons(reasons, metrics);
        if (!reasons.isEmpty()) {
            diagnostics.failureReasons(reasons);
            // A diagnostic run may leave scheduler work in flight when the host cannot
            // keep up; the measured throughput is still reported. An evaluable
            // acceptance run must drain its runtime completely.
            if (!diagnostic) {
                throw new PhaseInvariantException(phase, reasons);
            }
        }
    }

    private static void addRuntimeDrainReasons(List<String> reasons,
            SigningExecutionRuntime.Metrics metrics) {
        expectEqual(reasons, "runtime.schedulerReserved", metrics.schedulerReserved(), 0L);
        expectEqual(reasons, "runtime.running", metrics.running(), 0L);
        expectEqual(reasons, "runtime.ready", metrics.ready(), 0L);
        expectEqual(reasons, "runtime.pendingAdvisories", metrics.pendingAdvisories(), 0L);
    }

    private static SigningExecutionRuntime.Metrics runtimeDelta(SigningExecutionRuntime.Metrics before,
            SigningExecutionRuntime.Metrics after) {
        return new SigningExecutionRuntime.Metrics(after.schedulerReserved(), after.running(), after.ready(),
                after.pendingAdvisories(), after.highWaterSchedulerReserved(),
                metricDelta(after.schedulingRejected(), before.schedulingRejected()),
                metricDelta(after.callbackCoalesced(), before.callbackCoalesced()),
                metricDelta(after.callbackDropped(), before.callbackDropped()),
                metricDelta(after.callbackWake(), before.callbackWake()), after.state());
    }

    private static long metricDelta(long after, long before) {
        if (after < before) {
            throw new IllegalStateException("native runtime counter regressed");
        }
        return after - before;
    }

    private static int countUnretired(FilesystemPkiStore store) {
        return (int) store.listSignRecords().stream()
                .filter(record -> record.state() != zeroecho.pki.spi.store.SignWorkflowStore.State.RETIRED)
                .count();
    }

    private static char[] nativeUnlockMaterial() {
        return new char[] { 'Z', 'e', 'r', 'o', 'E', 'c', 'h', 'o', '-', 's', 'm', 'o', 'k', 'e', '-', '2', '0',
                '2', '6' };
    }

    private static void createNativeSigningKey(Path keyringPath, KeyringUnlockProvider unlockProvider)
            throws IOException {
        try (KeyringPassword password = unlockProvider.acquire();
                KeyringStore keyring = KeyringStore.create(keyringPath, password)) {
            keyring.putPrivate("sign.prv", "RSA", KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate());
        } catch (GeneralSecurityException failure) {
            throw new IOException("native signing smoke key creation failed", failure);
        }
    }

    private static long runPhase(long arrivals, int rate, boolean measured, SigningBenchmarkConfig configuration,
            PkiSigningBus bus, DeterministicDurableSignatureWorkflow provider, ThreadPoolExecutor lanes,
            byte[] payload, RunMetrics metrics)
            throws InterruptedException {
        if (arrivals == 0L) {
            return System.nanoTime();
        }
        Phaser completion = new Phaser(1);
        long phaseStart = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(10L);
        if (measured) {
            metrics.measurementDeadlineNanos.set(
                    phaseStart + Duration.ofSeconds(configuration.durationSeconds()).toNanos());
        }
        for (long sequence = 0L; sequence < arrivals; sequence++) {
            metrics.attemptedArrivals.increment();
            long scheduled = scheduledTime(phaseStart, sequence, rate);
            long arrivalSequence = sequence;
            parkUntil(scheduled);
            completion.register();
            try {
                lanes.execute(() -> {
                    try {
                        executeOne(bus, provider, payload, arrivalSequence, scheduled, measured, metrics);
                    } finally {
                        if (measured && System.nanoTime() <= metrics.measurementDeadlineNanos.get()) {
                            metrics.admittedTerminalWithinWindow.increment();
                        }
                        completion.arriveAndDeregister();
                    }
                });
                if (measured) {
                    metrics.admitted.increment();
                }
            } catch (RejectedExecutionException overloaded) {
                completion.arriveAndDeregister();
                if (measured) {
                    metrics.rejected.increment();
                }
            }
        }
        if (measured) {
            parkUntil(metrics.measurementDeadlineNanos.get());
        }
        int phase = completion.arrive();
        try {
            completion.awaitAdvanceInterruptibly(phase, configuration.drainSeconds(), TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            if (measured) {
                metrics.uncertain.add(Math.max(1, completion.getRegisteredParties()));
            }
            throw new IllegalStateException("benchmark drain timeout", timeout);
        }
        if (measured) {
            metrics.backlogAtWindowClose.set(backlogAtDeadline(metrics.admitted.sum(),
                    metrics.admittedTerminalWithinWindow.sum()));
        }
        return phaseStart;
    }

    static long backlogAtDeadline(long admitted, long terminalWithinWindow) {
        if (admitted < 0L || terminalWithinWindow < 0L || terminalWithinWindow > admitted) {
            throw new IllegalArgumentException("invalid admitted/terminal accounting");
        }
        return admitted - terminalWithinWindow;
    }

    private static void executeOne(PkiSigningBus bus, DeterministicDurableSignatureWorkflow provider,
            byte[] payloadTemplate, long arrivalSequence, long scheduled, boolean measured, RunMetrics metrics) {
        long laneStarted = System.nanoTime();
        if (measured) {
            metrics.queueLatency.add(Math.max(0L, laneStarted - scheduled));
        }
        DurableContentReference content = null;
        boolean submissionInvoked = false;
        try {
            byte[] payload = operationPayload(payloadTemplate, arrivalSequence);
            try (ContentSink sink = bus.beginSigningContent(Encoding.BINARY);
                    OutputStream output = sink.outputStream()) {
                output.write(payload);
                content = sink.complete();
            }
            PkiId operationId = bus.newSubmissionId();
            PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(ACCESS,
                    DeterministicDurableSignatureWorkflow.ALGORITHM, content, LEGACY_KEY_REF, Encoding.BINARY,
                    Optional.empty());
            submissionInvoked = true;
            bus.submitSign(operationId, OWNER, LEGACY_KEY_REF, DeterministicDurableSignatureWorkflow.ALGORITHM, content,
                    Duration.ofMinutes(5), Optional.of(continuation.encode()));
            if (measured) {
                metrics.accepted.increment();
            }
            Optional<AsyncStatus> status = bus.status(operationId);
            Optional<EncodedObject> result = bus.consumeResult(operationId);
            if (result.isPresent()) {
                retire(bus, provider, operationId, "benchmark-consumed");
                long completed = System.nanoTime();
                if (measured) {
                    metrics.completed.increment();
                    if (completed <= metrics.measurementDeadlineNanos.get()) {
                        metrics.completedWithinWindow.increment();
                    } else {
                        metrics.completedAfterWindow.increment();
                    }
                    metrics.endToEndLatency.add(Math.max(0L, completed - scheduled));
                    metrics.lastCompletionNanos.accumulateAndGet(completed, Math::max);
                }
            } else if (status.map(AsyncStatus::state).filter(SigningPerformanceBenchmark::terminalFailure)
                    .isPresent()) {
                retire(bus, provider, operationId, "benchmark-terminal-failure");
                if (measured) {
                    metrics.failed.increment();
                }
            } else if (measured) {
                metrics.uncertain.increment();
            }
        } catch (IOException | RuntimeException failure) {
            if (measured) {
                metrics.uncertain.increment();
            }
            if (!submissionInvoked && content != null) {
                bus.releaseContent(content);
            }
        }
    }

    private static boolean terminalFailure(AsyncState state) {
        return state == AsyncState.FAILED || state == AsyncState.CANCELLED || state == AsyncState.EXPIRED;
    }

    private static void retire(PkiSigningBus bus, DeterministicDurableSignatureWorkflow provider,
            PkiId operationId, String reason) {
        try {
            bus.retireSignOperation(operationId, reason);
        } finally {
            provider.retire(operationId);
        }
    }

    static long scheduledTime(long start, long sequence, int rate) {
        long wholeSeconds = sequence / rate;
        long fraction = sequence % rate;
        return Math.addExact(start, Math.addExact(Math.multiplyExact(wholeSeconds, NANOS_PER_SECOND),
                Math.multiplyExact(fraction, NANOS_PER_SECOND) / rate));
    }

    private static void parkUntil(long deadline) {
        parkUntil(deadline, SYSTEM_NANO_CLOCK, SYSTEM_NANO_PARKER);
    }

    static void parkUntil(long deadline, NanoClock clock, NanoParker parker) {
        long remaining = deadline - clock.nanoTime();
        while (remaining > 0L) {
            parker.parkNanos(remaining);
            if (Thread.currentThread().isInterrupted()) {
                throw new IllegalStateException("benchmark arrival scheduler interrupted");
            }
            remaining = deadline - clock.nanoTime();
        }
    }

    private static ThreadPoolExecutor executor(SigningBenchmarkConfig configuration) {
        AtomicLong laneNumber = new AtomicLong();
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "signing-performance-lane-" + laneNumber.incrementAndGet());
            thread.setDaemon(false);
            return thread;
        };
        BlockingQueue<Runnable> queue = configuration.queueCapacity() == 0 ? new SynchronousQueue<>()
                : new ArrayBlockingQueue<>(configuration.queueCapacity());
        ThreadPoolExecutor executor = new ThreadPoolExecutor(configuration.lanes(), configuration.lanes(), 0L,
                TimeUnit.MILLISECONDS, queue, factory, new ThreadPoolExecutor.AbortPolicy());
        executor.prestartAllCoreThreads();
        return executor;
    }

    private static X509AuthoritySnapshot authority(SignatureWorkflow workflow) {
        Set<String> supported = Set.copyOf(workflow.supportedAlgorithms());
        Set<AlgorithmIdentity> identities = BootstrapAlgorithmIdentities.catalog().identities().stream()
                .filter(identity -> identity.kind() == AlgorithmIdentity.Kind.SIGNATURE)
                .filter(identity -> supported.contains(identity.canonicalForm())
                        || BootstrapAlgorithmIdentities.compatibilityAliases().entrySet().stream()
                                .anyMatch(entry -> entry.getValue().equals(identity)
                                        && supported.contains(entry.getKey())))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return "workflow." + workflow.id();
            }

            @Override
            public String domainFingerprint() {
                return "signing-performance-provider-v1";
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == Direction.SIGN && identities.contains(identity)
                        && identity.equals(suite.signature());
            }
        };
        AlgorithmExecutionCapabilityProvider provider = () -> List.of(capability);
        X509AlgorithmResolver.Policy policy = new X509AlgorithmResolver.Policy() {
            @Override
            public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                return direction == AlgorithmExecutionCapability.Direction.SIGN;
            }

            @Override
            public String semanticFingerprint() {
                return "signing-performance-policy-v1";
            }
        };
        return X509AuthoritySnapshot.compose(List.of(), List.of(provider),
                List.of(X509AuthoritySnapshot.bindExecutor(capability.implementationId(),
                        AlgorithmExecutionCapability.Direction.SIGN, workflow)), policy);
    }

    private static byte[] payload(int size, long seed) {
        byte[] payload = new byte[size];
        long value = seed;
        for (int index = 0; index < payload.length; index++) {
            value ^= value << 13;
            value ^= value >>> 7;
            value ^= value << 17;
            payload[index] = (byte) value;
        }
        return payload;
    }

    private static byte[] operationPayload(byte[] template, long sequence) {
        byte[] payload = template.clone();
        int encodedBytes = Math.min(Long.BYTES, payload.length);
        for (int index = 0; index < encodedBytes; index++) {
            payload[index] = (byte) (sequence >>> (index * Byte.SIZE));
        }
        return payload;
    }

    private static void writeReport(Path output, String json) throws IOException {
        Path parent = output.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(output, json + System.lineSeparator(), StandardCharsets.UTF_8);
    }

    private static Path failureOutput(Path output) {
        String name = output.getFileName().toString();
        String base = name.endsWith(".json") ? name.substring(0, name.length() - ".json".length()) : name;
        return output.resolveSibling(base + ".failure.json");
    }

    private static void reportFailure(SigningBenchmarkConfig configuration,
            BenchmarkDiagnostics diagnostics, Exception primary) {
        diagnostics.recordDeviation(failureCategory(primary), primary);
        diagnostics.failed(primary);
        try {
            Files.deleteIfExists(configuration.output());
        } catch (IOException removalFailure) {
            primary.addSuppressed(removalFailure);
        }
        try {
            writeReport(failureOutput(configuration.output()), diagnostics.failureJson());
        } catch (IOException reportFailure) {
            primary.addSuppressed(reportFailure);
        }
    }

    private static String failureCategory(Exception failure) {
        if (failure instanceof PhaseInvariantException invariant) {
            return invariant.phase().toUpperCase(java.util.Locale.ROOT).replace('-', '_') + "_INVARIANT";
        }
        if (failure instanceof SigningBenchmarkGrid.ContractException) {
            return "BENCHMARK_CONTRACT_REJECTED";
        }
        if (failure instanceof InterruptedException) {
            return "BENCHMARK_INTERRUPTED";
        }
        if (failure instanceof IOException) {
            return "BENCHMARK_IO_FAILURE";
        }
        return "BENCHMARK_RUNTIME_FAILURE";
    }

    private static String completeStackTrace(Throwable failure) {
        if (failure == null) {
            return null;
        }
        StringWriter stackTrace = new StringWriter();
        try (PrintWriter writer = new PrintWriter(stackTrace)) {
            failure.printStackTrace(writer);
        }
        return stackTrace.toString();
    }

    /* default */ static String storeRecoveryFailureJson(Throwable failure) {
        return appendStoreRecoveryFailure(new StringBuilder(),
                StoreRecoveryFailureDiagnostic.capture(failure)).toString();
    }

    private static StringBuilder appendStoreRecoveryFailure(StringBuilder json,
            StoreRecoveryFailureDiagnostic failure) {
        if (failure == null) {
            return json.append("null");
        }
        json.append('{');
        field(json, "type", failure.type()).append(',');
        if (failure.message() == null) {
            json.append("\"message\":null,");
        } else {
            field(json, "message", failure.message()).append(',');
        }
        field(json, "stackTrace", failure.stackTrace()).append(',');
        json.append("\"causalChain\":[");
        for (int index = 0; index < failure.causalChain().size(); index++) {
            if (index > 0) {
                json.append(',');
            }
            CauseDiagnostic cause = failure.causalChain().get(index);
            json.append('{');
            field(json, "type", cause.type()).append(',');
            if (cause.message() == null) {
                json.append("\"message\":null");
            } else {
                field(json, "message", cause.message());
            }
            json.append('}');
        }
        return json.append("]}");
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                Files.deleteIfExists(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path directory, IOException failure) throws IOException {
                if (failure != null) {
                    throw failure;
                }
                Files.deleteIfExists(directory);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static final class RunMetrics {
        private final LongAdder attemptedArrivals = new LongAdder();
        private final LongAdder admitted = new LongAdder();
        private final LongAdder workflowContextsAdmitted = new LongAdder();
        private final LongAdder admittedWithinWindow = new LongAdder();
        private final LongAdder accepted = new LongAdder();
        private final LongAdder rejected = new LongAdder();
        private final LongAdder productionAdmissionRejected = new LongAdder();
        private final LongAdder preAcceptFailure = new LongAdder();
        private final LongAdder contextCapacityRejected = new LongAdder();
        private final LongAdder workflowTransitionsExecuted = new LongAdder();
        private final LongAdder observationAttempts = new LongAdder();
        private final LongAdder completed = new LongAdder();
        private final LongAdder completedWithinWindow = new LongAdder();
        private final LongAdder completedAfterWindow = new LongAdder();
        private final LongAdder failed = new LongAdder();
        private final LongAdder uncertain = new LongAdder();
        private final LongAdder admittedTerminalWithinWindow = new LongAdder();
        private final LongAdder terminalAfterWindow = new LongAdder();
        private final LongAdder retired = new LongAdder();
        private final LongAdder retirementFailure = new LongAdder();
        private final LongAdder providerSubmitNanos = new LongAdder();
        private final BoundedLatencySamples endToEndLatency;
        private final BoundedLatencySamples queueLatency;
        private final AtomicLong lastCompletionNanos = new AtomicLong();
        private final AtomicLong measurementDeadlineNanos = new AtomicLong();
        private final AtomicLong backlogAtWindowClose = new AtomicLong();
        private final AtomicLong peakResidentContexts = new AtomicLong();

        private RunMetrics(int capacity, long seed) {
            endToEndLatency = new BoundedLatencySamples(capacity, seed ^ 0x7e57_1a7eL);
            queueLatency = new BoundedLatencySamples(capacity, seed ^ 0x0a11_ce55L);
        }

        private void reset() {
            attemptedArrivals.reset();
            admitted.reset();
            workflowContextsAdmitted.reset();
            admittedWithinWindow.reset();
            accepted.reset();
            rejected.reset();
            productionAdmissionRejected.reset();
            preAcceptFailure.reset();
            contextCapacityRejected.reset();
            workflowTransitionsExecuted.reset();
            observationAttempts.reset();
            completed.reset();
            completedWithinWindow.reset();
            completedAfterWindow.reset();
            failed.reset();
            uncertain.reset();
            admittedTerminalWithinWindow.reset();
            terminalAfterWindow.reset();
            retired.reset();
            retirementFailure.reset();
            providerSubmitNanos.reset();
            endToEndLatency.reset();
            queueLatency.reset();
            lastCompletionNanos.set(0L);
            measurementDeadlineNanos.set(0L);
            backlogAtWindowClose.set(0L);
            peakResidentContexts.set(0L);
        }
    }

    record RunMetricsSnapshot(long attemptedArrivals, long admitted, long workflowContextsAdmitted,
            long admittedWithinWindow,
            long accepted, long rejected, long productionAdmissionRejected, long preAcceptFailure,
            long contextCapacityRejected, long workflowTransitionsExecuted, long observationAttempts,
            long peakResidentContexts, long completed, long completedWithinWindow, long completedAfterWindow,
            long failed, long uncertain, long admittedTerminalWithinWindow, long terminalAfterWindow,
            long retired, long retirementFailure, long providerSubmitNanos, long lastCompletionNanos,
            long measurementDeadlineNanos, long backlogAtWindowClose,
            BoundedLatencySamples.Summary endToEndLatency, BoundedLatencySamples.Summary queueLatency) {

        private static RunMetricsSnapshot capture(RunMetrics metrics) {
            return new RunMetricsSnapshot(metrics.attemptedArrivals.sum(), metrics.admitted.sum(),
                    metrics.workflowContextsAdmitted.sum(),
                    metrics.admittedWithinWindow.sum(), metrics.accepted.sum(), metrics.rejected.sum(),
                    metrics.productionAdmissionRejected.sum(), metrics.preAcceptFailure.sum(),
                    metrics.contextCapacityRejected.sum(), metrics.workflowTransitionsExecuted.sum(),
                    metrics.observationAttempts.sum(), metrics.peakResidentContexts.get(), metrics.completed.sum(),
                    metrics.completedWithinWindow.sum(), metrics.completedAfterWindow.sum(),
                    metrics.failed.sum(), metrics.uncertain.sum(), metrics.admittedTerminalWithinWindow.sum(),
                    metrics.terminalAfterWindow.sum(), metrics.retired.sum(), metrics.retirementFailure.sum(),
                    metrics.providerSubmitNanos.sum(), metrics.lastCompletionNanos.get(),
                    metrics.measurementDeadlineNanos.get(), metrics.backlogAtWindowClose.get(),
                    metrics.endToEndLatency.summarize(), metrics.queueLatency.summarize());
        }

        private static RunMetricsSnapshot empty() {
            BoundedLatencySamples.Summary empty = new BoundedLatencySamples.Summary(
                    0L, 0, 0L, 0L, 0L, 0L);
            return new RunMetricsSnapshot(0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, empty, empty);
        }
    }

    private record FirstDeviation(String category, String causeType) {
        private FirstDeviation {
            Objects.requireNonNull(category, "category");
        }
    }

    private enum WorkflowDiagnosticSite {
        SUBMIT_AFTER_INVOCATION("submit-after-invocation"),
        ACCEPTANCE_STATUS("acceptance-status"),
        OBSERVE_RESULT("observe-result"),
        CONSUME_RESULT("consume-result"),
        RETIRE("retire");

        private final String jsonName;

        WorkflowDiagnosticSite(String jsonName) {
            this.jsonName = jsonName;
        }

        private String jsonName() {
            return jsonName;
        }
    }

    private record WorkflowFailureDiagnostic(WorkflowDiagnosticSite site, String category,
            String type, String message, String stackTrace) {
        private WorkflowFailureDiagnostic {
            Objects.requireNonNull(site, "site");
            Objects.requireNonNull(category, "category");
        }
    }

    private record CauseDiagnostic(String type, String message) {
        private CauseDiagnostic {
            Objects.requireNonNull(type, "type");
        }
    }

    private record StoreRecoveryFailureDiagnostic(String type, String message,
            String stackTrace, List<CauseDiagnostic> causalChain) {
        private StoreRecoveryFailureDiagnostic {
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(stackTrace, "stackTrace");
            causalChain = List.copyOf(causalChain);
        }

        private static StoreRecoveryFailureDiagnostic capture(Throwable failure) {
            if (failure == null) {
                return null;
            }
            List<CauseDiagnostic> chain = new ArrayList<>();
            Set<Throwable> observed = Collections.newSetFromMap(new IdentityHashMap<>());
            Throwable current = failure;
            while (current != null && observed.add(current)) {
                chain.add(new CauseDiagnostic(current.getClass().getName(), current.getMessage()));
                current = current.getCause();
            }
            return new StoreRecoveryFailureDiagnostic(failure.getClass().getName(),
                    failure.getMessage(), completeStackTrace(failure), chain);
        }
    }

    private record PopulationProgressSnapshot(String stage, String state, long completed, long total) {
        private static PopulationProgressSnapshot none() {
            return new PopulationProgressSnapshot("none", "NOT_STARTED", 0L, 0L);
        }
    }

    private static final class PhaseInvariantException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final String phase;
        private final List<String> reasons;

        private PhaseInvariantException(String phase, List<String> reasons) {
            super("signing benchmark " + phase + " invariants failed: " + String.join("; ", reasons));
            this.phase = Objects.requireNonNull(phase, "phase");
            this.reasons = List.copyOf(reasons);
        }

        private String phase() {
            return phase;
        }

        private List<String> reasons() {
            return reasons;
        }
    }

    private static final class BenchmarkDiagnostics {
        private final SigningBenchmarkConfig configuration;
        private final long startedNanos = System.nanoTime();
        private final AtomicReference<FirstDeviation> firstDeviation = new AtomicReference<>();
        private final AtomicReference<StoreRecoveryFailureDiagnostic> firstStoreRecoveryFailure =
                new AtomicReference<>();
        private final AtomicReferenceArray<WorkflowFailureDiagnostic> workflowFailures =
                new AtomicReferenceArray<>(WorkflowDiagnosticSite.values().length);
        private volatile String phase = "configuration";
        private volatile Environment environment;
        private volatile RunMetrics metrics;
        private volatile SigningExecutionRuntime runtimeSource;
        private volatile int contextCapacity;
        private volatile int stepWorkers;
        private volatile RunMetricsSnapshot latestCounters = RunMetricsSnapshot.empty();
        private volatile SigningExecutionRuntime.Metrics latestRuntime;
        private volatile PopulationProgressSnapshot populationProgress = PopulationProgressSnapshot.none();
        private volatile PopulationMetrics population = PopulationMetrics.none();
        private volatile CleanupOutcome cleanup = CleanupOutcome.pending();
        private volatile List<String> reasons = List.of();

        private BenchmarkDiagnostics(SigningBenchmarkConfig configuration) {
            this.configuration = Objects.requireNonNull(configuration, "configuration");
        }

        private void phaseStarted(String name) {
            phase = Objects.requireNonNull(name, "name");
            event("phase", "state=start phase=" + name);
        }

        private void phaseCompleted(String name) {
            phase = Objects.requireNonNull(name, "name");
            event("phase", "state=complete phase=" + name);
        }

        private void windowClosed() {
            event("window-close", "state=deadline-reached phase=measurement");
        }

        private void cleanupStarted() {
            event("phase", "state=start phase=cleanup");
        }

        private void cleanupCompleted() {
            event("phase", "state=complete phase=cleanup");
        }

        private void environment(Environment value) {
            environment = Objects.requireNonNull(value, "value");
        }

        private void preflight(PreflightAssessment assessment) {
            environment(assessment.environment());
            reasons = assessment.mismatchReasons();
            event("preflight", "proceed=" + assessment.proceed()
                    + " diagnosticOnly=" + assessment.diagnosticOnly()
                    + " mismatchCount=" + assessment.mismatchReasons().size()
                    + " java=" + safeLogToken(assessment.environment().javaVersion())
                    + " cpu=" + safeLogToken(assessment.environment().cpuModel())
                    + " processors=" + assessment.environment().processors()
                    + " filesystem=" + safeLogToken(assessment.environment().filesystemType())
                    + " localNvme=" + assessment.environment().localNvmeVerified());
        }

        private void metrics(RunMetrics value) {
            metrics = Objects.requireNonNull(value, "value");
        }

        private void runtime(SigningExecutionRuntime value) {
            runtimeSource = Objects.requireNonNull(value, "value");
        }

        private void multiplexer(int capacity, int workers) {
            contextCapacity = capacity;
            stepWorkers = workers;
        }

        private void snapshot(RunMetrics value, SigningExecutionRuntime.Metrics runtime) {
            latestCounters = RunMetricsSnapshot.capture(value);
            latestRuntime = Objects.requireNonNull(runtime, "runtime");
        }

        private void population(PopulationMetrics value) {
            population = Objects.requireNonNull(value, "value");
        }

        private SigningPopulationFixture.PopulationProgress populationProgress() {
            return new SigningPopulationFixture.PopulationProgress() {
                @Override public void started(String stage, long total) {
                    populationProgress = new PopulationProgressSnapshot(stage, "STARTED", 0L, total);
                    event("population", "state=start stage=" + stage + " completed=0 total=" + total);
                }

                @Override public void milestone(String stage, long completed, long total) {
                    populationProgress = new PopulationProgressSnapshot(stage, "IN_PROGRESS", completed, total);
                    event("population", "state=progress stage=" + stage + " completed=" + completed
                            + " total=" + total);
                }

                @Override public void completed(String stage, long total) {
                    populationProgress = new PopulationProgressSnapshot(stage, "COMPLETED", total, total);
                    event("population", "state=complete stage=" + stage + " completed=" + total
                            + " total=" + total);
                }
            };
        }

        private void cleanup(CleanupOutcome outcome) {
            cleanup = Objects.requireNonNull(outcome, "outcome");
            event("cleanup", "state=" + outcome.state()
                    + " reason=" + outcome.reason().orElse("none"));
        }

        private void failureReasons(List<String> value) {
            reasons = List.copyOf(value);
        }

        private void recordDeviation(String category, Throwable cause) {
            String causeType = cause == null ? null : cause.getClass().getName();
            firstDeviation.compareAndSet(null,
                    new FirstDeviation(Objects.requireNonNull(category, "category"), causeType));
        }

        private void recordStoreRecoveryFailure(Throwable failure) {
            if (failure != null && firstStoreRecoveryFailure.get() == null) {
                firstStoreRecoveryFailure.compareAndSet(
                        null, StoreRecoveryFailureDiagnostic.capture(failure));
            }
        }

        private void recordWorkflowFailure(WorkflowDiagnosticSite site, String category,
                Throwable cause) {
            Objects.requireNonNull(site, "site");
            Objects.requireNonNull(category, "category");
            int slot = site.ordinal();
            if (workflowFailures.get(slot) != null) {
                return;
            }
            String causeType = cause == null ? null : cause.getClass().getName();
            String causeMessage = cause == null ? null : cause.getMessage();
            String stackTrace = completeStackTrace(cause);
            WorkflowFailureDiagnostic diagnostic = new WorkflowFailureDiagnostic(
                    site, category, causeType, causeMessage, stackTrace);
            if (!workflowFailures.compareAndSet(slot, null, diagnostic)) {
                return;
            }
            String warning = "event=workflow-failure site=" + site.jsonName()
                    + " category=" + category
                    + " type=" + (causeType == null ? "null" : causeType)
                    + " message=" + (causeMessage == null ? "null" : causeMessage);
            if (cause == null) {
                OBSERVABILITY_LOGGER.log(Level.WARNING, warning);
            } else {
                OBSERVABILITY_LOGGER.log(Level.WARNING, warning, cause);
            }
        }

        private FirstDeviation firstDeviation() {
            return firstDeviation.get();
        }

        private void finalVerdict(AcceptanceAssessment acceptance) {
            event("final-verdict", "status=completed evaluable=" + acceptance.evaluable()
                    + " targetMet=" + acceptance.targetMet()
                    + " reasonCount=" + acceptance.reasons().size()
                    + " reasons=" + safeReasonList(acceptance.reasons()));
        }

        private void failed(Exception failure) {
            if (failure instanceof PhaseInvariantException invariant) {
                phase = invariant.phase();
                reasons = invariant.reasons();
            } else {
                String category = failureCategory(failure);
                if (!reasons.contains(category)) {
                    List<String> combined = new ArrayList<>(reasons);
                    combined.add(category);
                    reasons = List.copyOf(combined);
                }
            }
            RunMetrics current = metrics;
            if (current != null) {
                latestCounters = RunMetricsSnapshot.capture(current);
            }
            SigningExecutionRuntime currentRuntime = runtimeSource;
            if (currentRuntime != null) {
                latestRuntime = currentRuntime.metrics();
            }
            event("final-verdict", "status=failed phase=" + phase
                    + " category=" + failureCategory(failure)
                    + " reasonCount=" + reasons.size()
                    + " reasons=" + safeReasonList(reasons)
                    + " cleanup=" + cleanup.state());
        }

        private String failureJson() {
            StringBuilder json = new StringBuilder(4_096);
            json.append('{');
            field(json, "schema", "zeroecho-signing-performance-failure-v2").append(',');
            field(json, "generatedAt", Instant.now().toString()).append(',');
            field(json, "phase", phase).append(',');
            number(json, "elapsedMillis", elapsedMillis()).append(',');
            stringArray(json, "reasons", reasons).append(',');
            appendConfiguration(json).append(',');
            appendEnvironment(json).append(',');
            appendPopulation(json).append(',');
            appendCounters(json).append(',');
            appendRuntime(json).append(',');
            appendCleanup(json).append(',');
            appendWorkflowFailureDiagnostics(json).append(',');
            appendFirstStoreRecoveryFailure(json).append(',');
            appendFirstDeviation(json);
            return json.append('}').toString();
        }

        private StringBuilder appendConfiguration(StringBuilder json) {
            json.append("\"configuration\":{");
            field(json, "profile", configuration.profile()).append(',');
            field(json, "target", configuration.targetMode().commandValue()).append(',');
            field(json, "cellId", configuration.cellId()).append(',');
            field(json, "cellMode", configuration.cellMode().commandValue()).append(',');
            number(json, "retainedPopulation", configuration.retainedPopulation()).append(',');
            number(json, "activePopulation", configuration.activePopulation()).append(',');
            number(json, "groupSize", configuration.groupSize()).append(',');
            number(json, "residentIndexBudgetBytes", configuration.residentIndexBudgetBytes()).append(',');
            number(json, "compactionTransientBudgetBytes",
                    configuration.compactionTransientBudgetBytes()).append(',');
            number(json, "warmupSeconds", configuration.warmupSeconds()).append(',');
            number(json, "durationSeconds", configuration.durationSeconds()).append(',');
            number(json, "offeredRatePerSecond", configuration.rate()).append(',');
            number(json, "lanes", configuration.lanes()).append(',');
            number(json, "queueCapacity", configuration.queueCapacity()).append(',');
            number(json, "providerMeanMillis", configuration.providerMeanMillis()).append(',');
            number(json, "providerJitterMillis", configuration.providerJitterMillis()).append(',');
            number(json, "payloadBytes", configuration.payloadBytes()).append(',');
            number(json, "sampleCapacity", configuration.sampleCapacity()).append(',');
            number(json, "drainSeconds", configuration.drainSeconds()).append(',');
            number(json, "seed", configuration.seed()).append(',');
            bool(json, "diagnosticEnvironmentOverride", configuration.diagnosticEnvironmentOverride()).append(',');
            field(json, "workRoot", configuration.workRoot().toString()).append(',');
            field(json, "output", configuration.output().toString()).append(',');
            field(json, "argumentsFingerprint", configuration.argumentsFingerprint());
            return json.append('}');
        }

        private StringBuilder appendEnvironment(StringBuilder json) {
            json.append("\"environment\":");
            Environment value = environment;
            if (value == null) {
                return json.append("null");
            }
            json.append('{');
            field(json, "javaVersion", value.javaVersion()).append(',');
            field(json, "javaVendor", value.javaVendor()).append(',');
            field(json, "vmName", value.vmName()).append(',');
            field(json, "osName", value.osName()).append(',');
            field(json, "osVersion", value.osVersion()).append(',');
            field(json, "osArchitecture", value.osArchitecture()).append(',');
            field(json, "cpuModel", value.cpuModel()).append(',');
            number(json, "processors", value.processors()).append(',');
            number(json, "maximumHeapBytes", value.maximumHeapBytes()).append(',');
            field(json, "garbageCollectors", value.garbageCollectors()).append(',');
            field(json, "jvmArguments", value.jvmArguments()).append(',');
            field(json, "filesystemType", value.filesystemType()).append(',');
            number(json, "filesystemUsableBytes", value.filesystemUsableBytes()).append(',');
            field(json, "mountPoint", value.mountPoint()).append(',');
            field(json, "mountSource", value.mountSource()).append(',');
            field(json, "mountOptions", value.mountOptions()).append(',');
            bool(json, "localNvmeVerified", value.localNvmeVerified()).append(',');
            field(json, "localNvmeEvidence", value.localNvmeEvidence()).append(',');
            field(json, "containerConstraints", value.containerConstraints()).append(',');
            field(json, "powerConstraints", value.powerConstraints()).append(',');
            field(json, "hostname", value.hostname());
            return json.append('}');
        }

        private StringBuilder appendPopulation(StringBuilder json) {
            json.append("\"populationProgress\":{");
            field(json, "stage", populationProgress.stage()).append(',');
            field(json, "state", populationProgress.state()).append(',');
            number(json, "completed", populationProgress.completed()).append(',');
            number(json, "total", populationProgress.total()).append(',');
            field(json, "mode", population.mode()).append(',');
            number(json, "observedPreloadCurrentRecords", population.observedPreloadCurrentRecords());
            return json.append('}');
        }

        private StringBuilder appendCounters(StringBuilder json) {
            RunMetricsSnapshot value = latestCounters;
            json.append("\"latestCounters\":{");
            number(json, "contextCapacity", contextCapacity).append(',');
            number(json, "stepWorkers", stepWorkers).append(',');
            number(json, "attemptedArrivals", value.attemptedArrivals()).append(',');
            number(json, "admitted", value.admitted()).append(',');
            number(json, "workflowContextsAdmitted", value.workflowContextsAdmitted()).append(',');
            number(json, "admittedWithinWindow", value.admittedWithinWindow()).append(',');
            number(json, "accepted", value.accepted()).append(',');
            number(json, "rejected", value.rejected()).append(',');
            number(json, "productionAdmissionRejected", value.productionAdmissionRejected()).append(',');
            number(json, "preAcceptFailure", value.preAcceptFailure()).append(',');
            number(json, "contextCapacityRejected", value.contextCapacityRejected()).append(',');
            number(json, "workflowTransitionsExecuted", value.workflowTransitionsExecuted()).append(',');
            number(json, "observationAttempts", value.observationAttempts()).append(',');
            number(json, "peakResidentContexts", value.peakResidentContexts()).append(',');
            number(json, "completed", value.completed()).append(',');
            number(json, "completedWithinWindow", value.completedWithinWindow()).append(',');
            number(json, "completedAfterWindow", value.completedAfterWindow()).append(',');
            number(json, "failed", value.failed()).append(',');
            number(json, "uncertain", value.uncertain()).append(',');
            number(json, "admittedTerminalWithinWindow", value.admittedTerminalWithinWindow()).append(',');
            number(json, "terminalAfterWindow", value.terminalAfterWindow()).append(',');
            number(json, "retired", value.retired()).append(',');
            number(json, "retirementFailure", value.retirementFailure()).append(',');
            number(json, "providerSubmitNanos", value.providerSubmitNanos()).append(',');
            number(json, "lastCompletionNanos", value.lastCompletionNanos()).append(',');
            number(json, "measurementDeadlineNanos", value.measurementDeadlineNanos()).append(',');
            number(json, "backlogAtWindowClose", value.backlogAtWindowClose()).append(',');
            summary(json, "endToEndLatency", value.endToEndLatency()).append(',');
            summary(json, "queueLatency", value.queueLatency());
            return json.append('}');
        }

        private StringBuilder appendRuntime(StringBuilder json) {
            json.append("\"runtime\":");
            SigningExecutionRuntime.Metrics value = latestRuntime;
            if (value == null) {
                return json.append("null");
            }
            json.append('{');
            number(json, "schedulerReserved", value.schedulerReserved()).append(',');
            number(json, "running", value.running()).append(',');
            number(json, "ready", value.ready()).append(',');
            number(json, "pendingAdvisories", value.pendingAdvisories()).append(',');
            number(json, "highWaterSchedulerReserved", value.highWaterSchedulerReserved()).append(',');
            number(json, "schedulingRejected", value.schedulingRejected()).append(',');
            number(json, "callbackCoalesced", value.callbackCoalesced()).append(',');
            number(json, "callbackDropped", value.callbackDropped()).append(',');
            number(json, "callbackWake", value.callbackWake()).append(',');
            field(json, "state", value.state().name());
            return json.append('}');
        }

        private StringBuilder appendCleanup(StringBuilder json) {
            json.append("\"cleanup\":{");
            field(json, "state", cleanup.state()).append(',');
            if (cleanup.reason().isPresent()) {
                field(json, "reason", cleanup.reason().orElseThrow());
            } else {
                json.append("\"reason\":null");
            }
            return json.append('}');
        }

        private StringBuilder appendWorkflowFailureDiagnostics(StringBuilder json) {
            json.append("\"workflowFailureDiagnostics\":[");
            boolean first = true;
            for (WorkflowDiagnosticSite site : WorkflowDiagnosticSite.values()) {
                WorkflowFailureDiagnostic diagnostic = workflowFailures.get(site.ordinal());
                if (diagnostic == null) {
                    continue;
                }
                if (!first) {
                    json.append(',');
                }
                first = false;
                json.append('{');
                field(json, "site", diagnostic.site().jsonName()).append(',');
                field(json, "category", diagnostic.category()).append(',');
                if (diagnostic.type() == null) {
                    json.append("\"type\":null,");
                } else {
                    field(json, "type", diagnostic.type()).append(',');
                }
                if (diagnostic.message() == null) {
                    json.append("\"message\":null,");
                } else {
                    field(json, "message", diagnostic.message()).append(',');
                }
                if (diagnostic.stackTrace() == null) {
                    json.append("\"stackTrace\":null");
                } else {
                    field(json, "stackTrace", diagnostic.stackTrace());
                }
                json.append('}');
            }
            return json.append(']');
        }

        private StringBuilder appendFirstDeviation(StringBuilder json) {
            json.append("\"firstDeviation\":");
            FirstDeviation value = firstDeviation();
            if (value == null) {
                return json.append("null");
            }
            json.append('{');
            field(json, "category", value.category()).append(',');
            if (value.causeType() == null) {
                json.append("\"causeType\":null");
            } else {
                field(json, "causeType", value.causeType());
            }
            return json.append('}');
        }

        private StringBuilder appendFirstStoreRecoveryFailure(StringBuilder json) {
            json.append("\"firstStoreRecoveryFailure\":");
            return appendStoreRecoveryFailure(json, firstStoreRecoveryFailure.get());
        }

        private long elapsedMillis() {
            return TimeUnit.NANOSECONDS.toMillis(Math.max(0L, System.nanoTime() - startedNanos));
        }

        private void event(String event, String details) {
            OBSERVABILITY_LOGGER.log(Level.INFO, "event=" + event + ' ' + details
                    + " elapsedMillis=" + elapsedMillis());
        }

        private static String safeLogToken(String value) {
            StringBuilder token = new StringBuilder(value.length());
            for (int index = 0; index < value.length(); index++) {
                char character = value.charAt(index);
                token.append(Character.isLetterOrDigit(character) || character == '.' || character == '-'
                        ? character : '_');
            }
            return token.toString();
        }

        private static String safeReasonList(List<String> values) {
            if (values.isEmpty()) {
                return "none";
            }
            StringBuilder encoded = new StringBuilder();
            for (String value : values) {
                if (!encoded.isEmpty()) {
                    encoded.append('|');
                }
                encoded.append(safeLogToken(value));
            }
            return encoded.toString();
        }
    }

    private static StringBuilder field(StringBuilder json, String name, String value) {
        return Result.field(json, name, value);
    }

    private static StringBuilder number(StringBuilder json, String name, long value) {
        return Result.number(json, name, value);
    }

    private static StringBuilder bool(StringBuilder json, String name, boolean value) {
        return Result.bool(json, name, value);
    }

    private static StringBuilder stringArray(StringBuilder json, String name, List<String> values) {
        return Result.stringArray(json, name, values);
    }

    private static StringBuilder summary(StringBuilder json, String name,
            BoundedLatencySamples.Summary value) {
        return Result.summary(json, name, value);
    }

    record GcSnapshot(long collections, long collectionMillis, long allocatedBytes, long usedHeapBytes) {
        private static GcSnapshot capture() {
            long collections = 0L;
            long collectionMillis = 0L;
            for (GarbageCollectorMXBean collector : ManagementFactory.getGarbageCollectorMXBeans()) {
                collections += Math.max(0L, collector.getCollectionCount());
                collectionMillis += Math.max(0L, collector.getCollectionTime());
            }
            return new GcSnapshot(collections, collectionMillis, sumAllocatedBytes(),
                    ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed());
        }

        private static long sumAllocatedBytes() {
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
            if (!(threadBean instanceof com.sun.management.ThreadMXBean allocationBean)
                    || !allocationBean.isThreadAllocatedMemorySupported()) {
                return -1L;
            }
            if (!allocationBean.isThreadAllocatedMemoryEnabled()) {
                allocationBean.setThreadAllocatedMemoryEnabled(true);
            }
            long total = 0L;
            for (long value : allocationBean.getThreadAllocatedBytes(threadBean.getAllThreadIds())) {
                if (value >= 0L) {
                    total += value;
                }
            }
            return total;
        }
    }

    private static void resetPeakHeap() {
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getType() == java.lang.management.MemoryType.HEAP) {
                pool.resetPeakUsage();
            }
        }
    }

    private static long peakHeapBytes() {
        long peak = 0L;
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getType() == java.lang.management.MemoryType.HEAP && pool.getPeakUsage() != null) {
                peak = Math.addExact(peak, Math.max(0L, pool.getPeakUsage().getUsed()));
            }
        }
        return peak;
    }

    record Environment(String javaVersion, String javaVendor, String vmName, String osName, String osVersion,
            String osArchitecture, String cpuModel, int processors, long maximumHeapBytes, String garbageCollectors,
            String jvmArguments, String filesystemType, long filesystemUsableBytes, String mountPoint,
            String mountSource, String mountOptions, boolean localNvmeVerified, String localNvmeEvidence,
            String containerConstraints, String powerConstraints, String hostname) {
        private static final int MAXIMUM_REPORTED_JVM_ARGUMENTS = 64;
        private static final int MAXIMUM_REPORTED_OPTION_NAME = 96;
        private static final Set<String> SAFE_GC_ARGUMENTS = Set.of(
                "-XX:+UseG1GC", "-XX:-UseG1GC", "-XX:+UseParallelGC", "-XX:-UseParallelGC",
                "-XX:+UseSerialGC", "-XX:-UseSerialGC", "-XX:+UseZGC", "-XX:-UseZGC",
                "-XX:+UseShenandoahGC", "-XX:-UseShenandoahGC");

        private static Environment capturePreflight(Path work) throws IOException {
            Path filesystemProbe = existingAncestor(work);
            RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
            MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
            FileStore fileStore = Files.getFileStore(filesystemProbe);
            List<String> collectors = new ArrayList<>();
            for (GarbageCollectorMXBean collector : ManagementFactory.getGarbageCollectorMXBeans()) {
                collectors.add(collector.getName());
            }
            MountInfo mount = mount(work);
            StorageEvidence storage = detectStorage(mount);
            return new Environment(System.getProperty("java.version"), System.getProperty("java.vendor"),
                    runtime.getVmName(), System.getProperty("os.name"), System.getProperty("os.version"),
                    System.getProperty("os.arch"), detectCpuModel(), Runtime.getRuntime().availableProcessors(),
                    memory.getHeapMemoryUsage().getMax(), String.join(",", collectors),
                    sanitizeJvmArguments(runtime.getInputArguments()), fileStore.type(), fileStore.getUsableSpace(),
                    mount.mountPoint(), mount.source(), mount.options(), storage.verified(), storage.description(),
                    detectContainerConstraints(),
                    "unavailable: no portable power-policy measurement seam",
                    System.getenv().getOrDefault("HOSTNAME", "unknown"));
        }

        private static String sanitizeJvmArguments(List<String> arguments) {
            List<String> sanitized = new ArrayList<>(Math.min(arguments.size(), MAXIMUM_REPORTED_JVM_ARGUMENTS));
            int reported = Math.min(arguments.size(), MAXIMUM_REPORTED_JVM_ARGUMENTS);
            for (int index = 0; index < reported; index++) {
                sanitized.add(sanitizeJvmArgument(arguments.get(index)));
            }
            if (arguments.size() > MAXIMUM_REPORTED_JVM_ARGUMENTS) {
                sanitized.add("<additional-options-redacted>");
            }
            return String.join(" ", sanitized);
        }

        private static String sanitizeJvmArgument(String argument) {
            if (SAFE_GC_ARGUMENTS.contains(argument) || safeHeapArgument(argument)) {
                return argument;
            }
            if (!argument.startsWith("-")) {
                return "<argument-redacted>";
            }
            if (argument.startsWith("-Xms")) {
                return "-Xms=<redacted>";
            }
            if (argument.startsWith("-Xmx")) {
                return "-Xmx=<redacted>";
            }
            if (argument.startsWith("-Xss")) {
                return "-Xss=<redacted>";
            }
            int equals = argument.indexOf('=');
            int agentSeparator = argument.startsWith("-javaagent:") || argument.startsWith("-agentpath:")
                    || argument.startsWith("-agentlib:") || argument.startsWith("-Xlog:")
                    || argument.startsWith("-Xloggc:") || argument.startsWith("-Xbootclasspath:")
                    || argument.startsWith("-Xbootclasspath/a:") || argument.startsWith("-Xbootclasspath/p:")
                    || argument.startsWith("-splash:")
                            ? argument.indexOf(':') : -1;
            int separator = equals >= 0 && agentSeparator >= 0 ? Math.min(equals, agentSeparator)
                    : Math.max(equals, agentSeparator);
            String name = separator < 0 ? argument : argument.substring(0, separator);
            return sanitizeOptionName(name) + (separator < 0 ? "" : "=<redacted>");
        }

        private static boolean safeHeapArgument(String argument) {
            if (argument.startsWith("-Xms")) {
                return safeMemoryQuantity(argument.substring("-Xms".length()));
            }
            if (argument.startsWith("-Xmx")) {
                return safeMemoryQuantity(argument.substring("-Xmx".length()));
            }
            String[] integralPrefixes = { "-XX:InitialHeapSize=", "-XX:MaxHeapSize=" };
            for (String prefix : integralPrefixes) {
                if (argument.startsWith(prefix)) {
                    return safeUnsignedNumber(argument.substring(prefix.length()), false);
                }
            }
            String[] decimalPrefixes = { "-XX:InitialRAMPercentage=", "-XX:MinRAMPercentage=",
                    "-XX:MaxRAMPercentage=" };
            for (String prefix : decimalPrefixes) {
                if (argument.startsWith(prefix)) {
                    return safeUnsignedNumber(argument.substring(prefix.length()), true);
                }
            }
            return false;
        }

        private static boolean safeMemoryQuantity(String value) {
            if (value.isEmpty()) {
                return false;
            }
            int numericLength = value.length();
            char suffix = value.charAt(value.length() - 1);
            if (suffix == 'k' || suffix == 'K' || suffix == 'm' || suffix == 'M'
                    || suffix == 'g' || suffix == 'G' || suffix == 't' || suffix == 'T') {
                numericLength--;
            }
            return numericLength > 0 && safeUnsignedNumber(value.substring(0, numericLength), false);
        }

        private static boolean safeUnsignedNumber(String value, boolean decimal) {
            if (value.isEmpty() || value.length() > 32) {
                return false;
            }
            boolean point = false;
            for (int index = 0; index < value.length(); index++) {
                char character = value.charAt(index);
                if (character == '.' && decimal && !point) {
                    point = true;
                } else if (!Character.isDigit(character)) {
                    return false;
                }
            }
            return !".".equals(value);
        }

        private static String sanitizeOptionName(String value) {
            int length = Math.min(value.length(), MAXIMUM_REPORTED_OPTION_NAME);
            StringBuilder sanitized = new StringBuilder(length);
            for (int index = 0; index < length; index++) {
                char character = value.charAt(index);
                sanitized.append(Character.isLetterOrDigit(character) || character == '-' || character == '_'
                        || character == '.' || character == '+' || character == ':' ? character : '_');
            }
            if (sanitized.isEmpty()) {
                return "<unnamed-option>";
            }
            return sanitized.toString();
        }

        private static Path existingAncestor(Path requested) throws IOException {
            Path current = Objects.requireNonNull(requested, "requested").toAbsolutePath().normalize();
            while (current != null && !Files.exists(current)) {
                current = current.getParent();
            }
            if (current == null) {
                throw new IOException("signing benchmark preflight filesystem is unavailable");
            }
            return current;
        }

        private static String detectCpuModel() {
            Path cpuInfo = Path.of("/proc/cpuinfo");
            if (!Files.isReadable(cpuInfo)) {
                return "unavailable";
            }
            try (Stream<String> lines = Files.lines(cpuInfo, StandardCharsets.US_ASCII)) {
                return lines.filter(line -> line.startsWith("model name"))
                        .map(line -> line.substring(line.indexOf(':') + 1).trim()).findFirst().orElse("unavailable");
            } catch (IOException failure) {
                return "unavailable";
            }
        }

        private static MountInfo mount(Path work) {
            Path mountInfo = Path.of("/proc/self/mountinfo");
            if (!Files.isReadable(mountInfo)) {
                return MountInfo.UNAVAILABLE;
            }
            String normalized = work.toAbsolutePath().normalize().toString();
            MountInfo best = null;
            try {
                for (String line : Files.readAllLines(mountInfo, StandardCharsets.UTF_8)) {
                    String[] halves = line.split(" - ", 2);
                    String[] left = halves[0].split(" ");
                    String[] right = halves.length == 2 ? halves[1].split(" ") : new String[0];
                    if (left.length < 6 || right.length < 2) {
                        continue;
                    }
                    String point = left[4].replace("\\040", " ");
                    if ((normalized.equals(point) || normalized.startsWith(point.endsWith("/") ? point : point + "/"))
                            && (best == null || point.length() > best.mountPoint().length())) {
                        String options = right.length >= 3 ? left[5] + "," + right[2] : left[5];
                        best = new MountInfo(point, right[1], options);
                    }
                }
                return best == null ? MountInfo.UNAVAILABLE : best;
            } catch (IOException failure) {
                return MountInfo.UNAVAILABLE;
            }
        }

        private static String detectContainerConstraints() {
            String memory = readConstraint(Path.of("/sys/fs/cgroup/memory.max"));
            String cpu = readConstraint(Path.of("/sys/fs/cgroup/cpu.max"));
            if (memory == null && cpu == null) {
                return "unavailable: cgroup-v2 constraints are not readable";
            }
            return "memory.max=" + (memory == null ? "unavailable" : memory) + ",cpu.max="
                    + (cpu == null ? "unavailable" : cpu);
        }

        private static StorageEvidence detectStorage(MountInfo mount) {
            if (MountInfo.UNAVAILABLE.equals(mount)) {
                return StorageEvidence.unavailable("mount source is unavailable");
            }
            String sourceName;
            try {
                sourceName = Path.of(mount.source()).getFileName().toString();
            } catch (RuntimeException failure) {
                return StorageEvidence.unavailable("mount source cannot be mapped to a block device");
            }
            if (mount.source().startsWith("/dev/mapper/")) {
                sourceName = mappedDevice(sourceName);
                if (sourceName == null) {
                    return StorageEvidence.unavailable("device-mapper source is not visible in sysfs");
                }
            }
            Set<String> leaves = new HashSet<>();
            try {
                collectBlockLeaves(sourceName, leaves, new HashSet<>());
                if (leaves.isEmpty()) {
                    return StorageEvidence.unavailable("no leaf block device is discoverable");
                }
                for (String leaf : leaves) {
                    String rotational = Files.readString(rotationalPath(leaf), StandardCharsets.US_ASCII).trim();
                    String sysfsPath = Path.of("/sys/class/block", leaf).toRealPath().toString();
                    if (!leaf.startsWith("nvme") || !"0".equals(rotational) || !sysfsPath.contains("/pci")) {
                        return StorageEvidence.unavailable("non-local-NVMe or rotational leaf device: " + leaf);
                    }
                }
                List<String> sorted = new ArrayList<>(leaves);
                sorted.sort(String::compareTo);
                return new StorageEvidence(true, "verified local non-rotational NVMe leaves: "
                        + String.join(",", sorted));
            } catch (IOException failure) {
                return StorageEvidence.unavailable("block topology is incomplete or unreadable");
            }
        }

        private static Path rotationalPath(String device) throws IOException {
            Path block = Path.of("/sys/class/block", device);
            Path queueDevice = block;
            if (Files.isRegularFile(block.resolve("partition"))) {
                Path realDevice = block.toRealPath();
                queueDevice = Path.of("/sys/class/block", realDevice.getParent().getFileName().toString());
            }
            return queueDevice.resolve("queue/rotational");
        }

        private static String mappedDevice(String mapperName) {
            Path blockRoot = Path.of("/sys/class/block");
            try (Stream<Path> devices = Files.list(blockRoot)) {
                return devices.filter(path -> path.getFileName().toString().startsWith("dm-"))
                        .filter(path -> mapperName.equals(readTrimmed(path.resolve("dm/name"))))
                        .map(path -> path.getFileName().toString()).findFirst().orElse(null);
            } catch (IOException failure) {
                return null;
            }
        }

        private static String readTrimmed(Path path) {
            try {
                return Files.readString(path, StandardCharsets.US_ASCII).trim();
            } catch (IOException failure) {
                return "";
            }
        }

        private static void collectBlockLeaves(String device, Set<String> leaves, Set<String> visited)
                throws IOException {
            if (!visited.add(device)) {
                throw new IOException("cyclic block-device topology");
            }
            Path slaves = Path.of("/sys/class/block", device, "slaves");
            if (!Files.isDirectory(slaves)) {
                leaves.add(device);
                return;
            }
            List<String> children;
            try (Stream<Path> entries = Files.list(slaves)) {
                children = entries.map(path -> path.getFileName().toString()).sorted().toList();
            }
            if (children.isEmpty()) {
                leaves.add(device);
                return;
            }
            for (String child : children) {
                collectBlockLeaves(child, leaves, visited);
            }
        }

        private static String readConstraint(Path path) {
            try {
                return Files.isReadable(path) ? Files.readString(path, StandardCharsets.US_ASCII).trim() : null;
            } catch (IOException failure) {
                return null;
            }
        }

        private record MountInfo(String mountPoint, String source, String options) {
            private static final MountInfo UNAVAILABLE = new MountInfo("unavailable", "unavailable", "unavailable");
        }

        private record StorageEvidence(boolean verified, String description) {
            private static StorageEvidence unavailable(String reason) {
                return new StorageEvidence(false, "unavailable: " + reason);
            }
        }
    }

    record CleanupOutcome(String state, Optional<String> reason) {
        CleanupOutcome {
            Objects.requireNonNull(state, "state");
            reason = Objects.requireNonNull(reason, "reason");
            if (!Set.of("PENDING", "SUCCEEDED", "FAILED").contains(state)
                    || "FAILED".equals(state) != reason.isPresent()) {
                throw new IllegalArgumentException("benchmark cleanup outcome is invalid");
            }
        }

        private static CleanupOutcome pending() {
            return new CleanupOutcome("PENDING", Optional.empty());
        }

        private static CleanupOutcome success() {
            return new CleanupOutcome("SUCCEEDED", Optional.empty());
        }

        private static CleanupOutcome failure(String reason) {
            return new CleanupOutcome("FAILED", Optional.of(reason));
        }

        /* default */ AcceptanceAssessment gate(AcceptanceAssessment workloadAssessment) {
            Objects.requireNonNull(workloadAssessment, "workloadAssessment");
            return switch (state) {
                case "SUCCEEDED" -> workloadAssessment;
                case "PENDING" -> workloadAssessment.invalid("CLEANUP_PENDING");
                case "FAILED" -> workloadAssessment.invalid("CLEANUP_FAILED");
                default -> throw new IllegalStateException("benchmark cleanup outcome is invalid");
            };
        }
    }

    record PreflightAssessment(boolean proceed, boolean diagnosticOnly,
            List<String> mismatchReasons, Environment environment) {
        PreflightAssessment {
            mismatchReasons = List.copyOf(mismatchReasons);
            Objects.requireNonNull(environment, "environment");
        }

        static PreflightAssessment assess(SigningBenchmarkConfig configuration, Environment environment) {
            List<String> reasons = AcceptanceAssessment.referenceEnvironmentReasons(environment);
            boolean mismatch = !reasons.isEmpty();
            boolean override = configuration.diagnosticEnvironmentOverride();
            // Reference-environment mismatches are advisory warnings, not blockers: the
            // benchmark always proceeds and measures throughput so a figure can be
            // obtained on any host. The mismatch reasons are retained and mark the run
            // diagnostic-only, so only the approved reference environment (with no
            // override) can ever produce an evaluable acceptance anchor.
            return new PreflightAssessment(true, override || mismatch, reasons, environment);
        }
    }

    record AcceptanceAssessment(boolean evaluable, boolean targetMet, List<String> reasons) {
        private static final long APPROVED_HEAP_BYTES = 4L * 1_024L * 1_024L * 1_024L;
        private static final long APPROVED_SEED = 0x5eed_2026L;

        AcceptanceAssessment {
            reasons = List.copyOf(reasons);
        }

        static AcceptanceAssessment assess(SigningBenchmarkConfig configuration, Environment environment,
                long scheduled, long admitted, long accepted, long rejected, long completed, long completedWithinWindow,
                long failed, long uncertain, double throughput, long p99Nanos, int retainedProviderOperations) {
            List<String> reasons = new ArrayList<>();
            exact(reasons, "profile", configuration.profile(), "acceptance");
            exact(reasons, "target", configuration.targetMode(),
                    SigningBenchmarkConfig.TargetMode.NATIVE_SHARED_LEDGER);
            exact(reasons, "warmupSeconds", configuration.warmupSeconds(), 30);
            exact(reasons, "durationSeconds", configuration.durationSeconds(), 300);
            exact(reasons, "offeredRate", configuration.rate(), 1_100);
            exact(reasons, "lanes", configuration.lanes(), 16);
            exact(reasons, "cellId", configuration.cellId(), SigningBenchmarkGrid.ANCHOR_ID);
            exact(reasons, "cellMode", configuration.cellMode(), SigningBenchmarkConfig.CellMode.GRID);
            exact(reasons, "retainedPopulation", configuration.retainedPopulation(),
                    SigningBenchmarkGrid.ANCHOR_RETAINED);
            exact(reasons, "activePopulation", configuration.activePopulation(),
                    SigningBenchmarkGrid.ANCHOR_ACTIVE);
            exact(reasons, "groupSize", configuration.groupSize(), SigningBenchmarkGrid.ANCHOR_GROUP);
            exact(reasons, "residentIndexBudgetBytes", configuration.residentIndexBudgetBytes(),
                    SigningBenchmarkConfig.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
            exact(reasons, "compactionTransientBudgetBytes", configuration.compactionTransientBudgetBytes(),
                    SigningBenchmarkConfig.DEFAULT_COMPACTION_TRANSIENT_BUDGET_BYTES);
            exact(reasons, "queueCapacity", configuration.queueCapacity(), 64);
            exact(reasons, "providerMeanMillis", configuration.providerMeanMillis(), 0);
            exact(reasons, "providerJitterMillis", configuration.providerJitterMillis(), 0);
            exact(reasons, "payloadBytes", configuration.payloadBytes(), 1_024);
            exact(reasons, "sampleCapacity", configuration.sampleCapacity(), 1_000_000);
            exact(reasons, "drainSeconds", configuration.drainSeconds(), 120);
            exact(reasons, "seed", configuration.seed(), APPROVED_SEED);
            if (configuration.diagnosticEnvironmentOverride()) {
                reasons.add("diagnostic environment override enabled; result cannot satisfy acceptance");
            }
            if (configuration.cellMode() == SigningBenchmarkConfig.CellMode.NATIVE_DIAGNOSTIC) {
                reasons.add("native diagnostic mode cannot satisfy acceptance");
            }
            reasons.addAll(referenceEnvironmentReasons(environment));
            boolean evaluable = reasons.isEmpty();
            if (scheduled != 330_000L || admitted != scheduled || accepted != scheduled || rejected != 0L) {
                reasons.add("acceptance requires all 330000 arrivals to be executor-admitted and durably accepted "
                        + "with zero rejection");
            }
            if (completed != accepted || failed != 0L || uncertain != 0L) {
                reasons.add("acceptance requires every admitted operation to complete with zero failure/uncertainty");
            }
            if (completedWithinWindow < 300_000L || throughput < 1_000.0) {
                reasons.add("fixed-window completion throughput is below 1000/s");
            }
            if (p99Nanos >= TimeUnit.MILLISECONDS.toNanos(100L)) {
                reasons.add("end-to-end p99 is not below 100 ms");
            }
            if (retainedProviderOperations < 0) {
                reasons.add("indexed retained-operation verification is unavailable");
            } else if (retainedProviderOperations != 0) {
                reasons.add("provider terminal state was not fully retired");
            }
            return new AcceptanceAssessment(evaluable, evaluable && reasons.isEmpty(), reasons);
        }

        private AcceptanceAssessment invalid(String reason) {
            List<String> invalidReasons = new ArrayList<>(reasons);
            invalidReasons.add(reason);
            return new AcceptanceAssessment(false, false, invalidReasons);
        }

        private static List<String> referenceEnvironmentReasons(Environment environment) {
            List<String> reasons = new ArrayList<>();
            exact(reasons, "maximumHeapBytes", environment.maximumHeapBytes(), APPROVED_HEAP_BYTES);
            if (javaFeature(environment.javaVersion()) != 25) {
                reasons.add("approved environment mismatch: Java feature version is not 25");
            }
            if (!"amd ryzen 5 7600 6 core processor".equals(normalizeIdentity(environment.cpuModel()))) {
                reasons.add("approved environment mismatch: CPU is not AMD Ryzen 5 7600 6-Core Processor");
            }
            if (environment.processors() != 12) {
                reasons.add("approved environment mismatch: logical processor count is not 12");
            }
            String collectors = normalizeIdentity(environment.garbageCollectors());
            if (!collectors.contains("g1 young generation") || !collectors.contains("g1 concurrent gc")
                    || !collectors.contains("g1 old generation")) {
                reasons.add("approved environment mismatch: G1 collector topology is incomplete or unverifiable");
            }
            if (!"btrfs".equalsIgnoreCase(environment.filesystemType())) {
                reasons.add("approved environment mismatch: filesystem is not Btrfs");
            }
            Set<String> mountOptions = new HashSet<>(List.of(environment.mountOptions().split(",")));
            List<String> requiredOptions = List.of("noatime", "compress=zstd:3", "ssd", "discard=async");
            for (String required : requiredOptions) {
                if (!mountOptions.contains(required)) {
                    reasons.add("approved environment mismatch: mount option is missing: " + required);
                }
            }
            if (!environment.localNvmeVerified()) {
                reasons.add("approved environment mismatch: local NVMe is unverified: "
                        + environment.localNvmeEvidence());
            }
            return List.copyOf(reasons);
        }

        private static int javaFeature(String version) {
            try {
                return Runtime.Version.parse(version).feature();
            } catch (IllegalArgumentException failure) {
                return -1;
            }
        }

        private static String normalizeIdentity(String value) {
            StringBuilder normalized = new StringBuilder(value.length());
            boolean separator = false;
            for (int index = 0; index < value.length(); index++) {
                char character = Character.toLowerCase(value.charAt(index));
                if (Character.isLetterOrDigit(character)) {
                    if (separator && normalized.length() != 0) {
                        normalized.append(' ');
                    }
                    normalized.append(character);
                    separator = false;
                } else {
                    separator = true;
                }
            }
            return normalized.toString();
        }

        private static void exact(List<String> reasons, String field, Object actual, Object expected) {
            if (!Objects.equals(actual, expected)) {
                reasons.add("approved profile mismatch: " + field);
            }
        }
    }

    record ProviderMetrics(String implementation, long providerCalls, long providerNanos, long statusCalls,
            long statusNanos, long forceCount, long diagnosticWrites, long requestsCommitted,
            long writeBytes, int retainedOperations,
            int accountedEventHighWaterRecords, long wholeRunMaximumBatchSize,
            long inferredSharedLocalAtomicCommits, boolean sharedWriterEvidence,
            long groupsCommitted, long groupCommitWaitNanos, long maximumGroupCommitWaitNanos,
            long forceNanos, long maximumForceNanos, Optional<BoundedLatencySamples.Summary> forceLatency) {

        private static ProviderMetrics deterministic(DeterministicDurableSignatureWorkflow.Metrics metrics) {
            return new ProviderMetrics("deterministic-durable-diagnostic", metrics.providerCalls(),
                    metrics.providerNanos(), metrics.statusCalls(), metrics.statusNanos(), metrics.forceCount(),
                    metrics.writeCount(), 0L, metrics.writeBytes(), metrics.retainedOperations(), 0, 0L, 0L, false,
                    0L, 0L, 0L, 0L, 0L, Optional.of(metrics.forceLatency()));
        }

        private static ProviderMetrics nativeLocal(long submitNanos, long providerCalls, long acceptedOperations,
                int retainedOperations,
                int accountedEventHighWaterRecords, FilesystemPkiStore.LocalSigningWriterMetrics before,
                FilesystemPkiStore.LocalSigningWriterMetrics after) {
            return new ProviderMetrics("zeroecho-lib-local-shared-ledger", providerCalls,
                    submitNanos, 0L, 0L, delta(after.forces(), before.forces()),
                    0L,
                    delta(after.requestsCommitted(), before.requestsCommitted()),
                    delta(after.bytesAppended(), before.bytesAppended()), retainedOperations,
                    accountedEventHighWaterRecords, after.maximumBatchSize(),
                    inferNativeAtomicCommits(acceptedOperations, providerCalls), true,
                    delta(after.groupsCommitted(), before.groupsCommitted()),
                    delta(after.groupCommitWaitNanos(), before.groupCommitWaitNanos()),
                    after.maximumGroupCommitWaitNanos(), delta(after.forceNanos(), before.forceNanos()),
                    after.maximumForceNanos(), Optional.empty());
        }

        private static long delta(long after, long before) {
            if (after < before) {
                throw new IllegalStateException("native writer counter regressed");
            }
            return after - before;
        }
    }

    record IndexCapacityMetrics(BudgetMetrics steady, BudgetMetrics transientBudget,
            BudgetMetrics combined) {

        IndexCapacityMetrics {
            Objects.requireNonNull(steady, "steady");
            Objects.requireNonNull(transientBudget, "transientBudget");
            Objects.requireNonNull(combined, "combined");
            if (combined.currentReservedBytes() != Math.addExact(
                    steady.currentReservedBytes(), transientBudget.currentReservedBytes())
                    || combined.highWaterReservedBytes() != Math.addExact(
                            steady.highWaterReservedBytes(),
                            transientBudget.highWaterReservedBytes())
                    || combined.maximumBytes() != Math.addExact(
                            steady.maximumBytes(), transientBudget.maximumBytes())) {
                throw new IllegalArgumentException("combined signing index capacity metrics are inconsistent");
            }
        }

        private static IndexCapacityMetrics from(
                FilesystemPkiStore.LocalSigningIndexCapacityMetrics metrics) {
            return new IndexCapacityMetrics(
                    new BudgetMetrics(metrics.steadyCurrentReservedBytes(),
                            metrics.steadyHighWaterReservedBytes(), metrics.steadyMaximumBytes()),
                    new BudgetMetrics(metrics.transientCurrentReservedBytes(),
                            metrics.transientHighWaterReservedBytes(), metrics.transientMaximumBytes()),
                    new BudgetMetrics(metrics.combinedCurrentReservedBytes(),
                            metrics.combinedHighWaterReservedBytes(), metrics.combinedMaximumBytes()));
        }
    }

    record BudgetMetrics(long currentReservedBytes, long highWaterReservedBytes,
            long maximumBytes) {
        BudgetMetrics {
            if (currentReservedBytes < 0L || highWaterReservedBytes < currentReservedBytes
                    || maximumBytes < highWaterReservedBytes) {
                throw new IllegalArgumentException("signing index budget metrics are inconsistent");
            }
        }

        long headroomBytes() {
            return maximumBytes - currentReservedBytes;
        }
    }

    record PopulationMetrics(String mode, long plannedGenericRecords, long plannedActivePreload,
            long plannedContextCapacity, long plannedArrivals, long plannedMaximumCurrentRecords,
            long plannedDrainedCurrentRecords,
            long observedGenericRecords, long observedSignRecords, long observedOwnerRecords,
            long observedWatermarkRecords, long observedPreloadCurrentRecords, long observedDueRecords,
            long observedSharedContentOwners, long observedBenchmarkCurrentRecords,
            long accountedEventHighWaterRecords, long observedOwnerAdmissions,
            long observedOwnerRetirements, CapacityArtifact capacityArtifact) {

        private static PopulationMetrics none() {
            return new PopulationMetrics("NONE", 0L, 0L, 0L, 0L, 0L,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                    CapacityArtifact.notCaptured());
        }

        /* default */ static PopulationMetrics observed(SigningPopulationPlan.Plan plan,
                SigningPopulationFixture.Observation observation) {
            return observed(plan, observation, CapacityArtifact.notCaptured());
        }

        /* default */ static PopulationMetrics observed(SigningPopulationPlan.Plan plan,
                SigningPopulationFixture.Artifact artifact, long expectedResidentIndexBudgetBytes,
                long expectedTransientIndexBudgetBytes) {
            return observed(plan, artifact.population(), CapacityArtifact.assess(
                    plan, artifact, expectedResidentIndexBudgetBytes,
                    expectedTransientIndexBudgetBytes));
        }

        private static PopulationMetrics observed(SigningPopulationPlan.Plan plan,
                SigningPopulationFixture.Observation observation, CapacityArtifact capacityArtifact) {
            return new PopulationMetrics(plan.mode().name(), plan.genericRecords(), plan.activePreload(),
                    plan.contextCapacity(), plan.arrivals(), plan.maximumCurrentRecords(),
                    plan.drainedCurrentRecords(),
                    observation.genericRecords(), observation.signRecords(), observation.ownerRecords(),
                    observation.watermarkRecords(), observation.currentRecords(), observation.dueRecords(),
                    observation.sharedContentOwners(), observation.currentRecords(), observation.currentRecords(),
                    0L, 0L, capacityArtifact);
        }

        private PopulationMetrics withAccounting(long currentRecords, long highWaterRecords,
                long ownerAdmissions, long ownerRetirements) {
            return new PopulationMetrics(mode, plannedGenericRecords, plannedActivePreload,
                    plannedContextCapacity, plannedArrivals, plannedMaximumCurrentRecords,
                    plannedDrainedCurrentRecords, observedGenericRecords, observedSignRecords,
                    observedOwnerRecords, observedWatermarkRecords, observedPreloadCurrentRecords,
                    observedDueRecords, observedSharedContentOwners, currentRecords, highWaterRecords,
                    ownerAdmissions, ownerRetirements, capacityArtifact);
        }
    }

    /** Exact scalar capacity evidence for a quiescent retained-only population. */
    record CapacityArtifact(String state, boolean required, boolean verified, List<String> reasons,
            Optional<SigningPopulationFixture.CapacityEvidence> observation,
            Optional<SigningPopulationFixture.QuiescentJvm> jvm) {
        CapacityArtifact {
            Objects.requireNonNull(state, "state");
            reasons = List.copyOf(reasons);
            observation = Objects.requireNonNull(observation, "observation");
            jvm = Objects.requireNonNull(jvm, "jvm");
        }

        private static CapacityArtifact notCaptured() {
            return new CapacityArtifact("NOT_CAPTURED", false, false, List.of(),
                    Optional.empty(), Optional.empty());
        }

        /* default */ static CapacityArtifact assess(SigningPopulationPlan.Plan plan,
                SigningPopulationFixture.Artifact artifact,
                long expectedResidentIndexBudgetBytes,
                long expectedTransientIndexBudgetBytes) {
            if (expectedResidentIndexBudgetBytes <= 0L
                    || expectedTransientIndexBudgetBytes <= 0L) {
                throw new IllegalArgumentException("expected index budgets must be positive");
            }
            SigningPopulationFixture.CapacityEvidence value = artifact.capacity();
            if (plan.mode() != SigningPopulationPlan.Mode.RETAINED_ONLY) {
                return new CapacityArtifact("OBSERVED", false, false, List.of(),
                        Optional.of(value), Optional.of(artifact.jvm()));
            }
            List<String> reasons = new ArrayList<>();
            if (value.currentKeys() != plan.maximumCurrentRecords()) {
                reasons.add("CAPACITY_CURRENT_KEYS_MISMATCH");
            }
            if (value.dueWork() != 0 || value.dueCanonicalIdBytes() != 0L
                    || value.dueEstimatedResidentBytes() != 0L || value.dueReservedBytes() != 0L) {
                reasons.add("CAPACITY_DUE_WORK_NOT_ZERO");
            }
            if (value.ownerWork() != 0 || value.ownerCanonicalIdBytes() != 0L
                    || value.ownerEstimatedResidentBytes() != 0L || value.ownerReservedBytes() != 0L
                    || value.projectedIdentities() != 0 || value.projectionReservedBytes() != 0L) {
                reasons.add("CAPACITY_OWNER_WORK_NOT_ZERO");
            }
            if (value.retentionRecords() != 0 || value.retentionReservedBytes() != 0L) {
                reasons.add("CAPACITY_RETENTION_NOT_ZERO");
            }
            if (value.mvccLiveSnapshots() != 0 || value.canonicalKeyBytes() <= 0L
                    || value.mvccEstimatedResidentBytes() <= 0L || value.mvccReservedBytes() <= 0L) {
                reasons.add("CAPACITY_MVCC_OBSERVATION_INVALID");
            }
            if (value.registeredGenerations() <= 0
                    || value.registeredGenerations() != value.publishedGenerations()
                    || value.supersededGenerations() != 0 || value.reclaimingGenerations() != 0
                    || value.reclaimableGenerations() != 0) {
                reasons.add("CAPACITY_GENERATION_PUBLICATION_INCONSISTENT");
            }
            if (value.generationCurrentReferences() != value.currentKeys()) {
                reasons.add("CAPACITY_GENERATION_REFERENCES_MISMATCH");
            }
            if (value.generationSnapshotPins() != 0L) {
                reasons.add("CAPACITY_GENERATION_PINS_NOT_ZERO");
            }
            if (value.steadyMaximumBytes() != expectedResidentIndexBudgetBytes) {
                reasons.add("CAPACITY_STEADY_MAXIMUM_MISMATCH");
            }
            if (value.transientMaximumBytes() != expectedTransientIndexBudgetBytes) {
                reasons.add("CAPACITY_TRANSIENT_MAXIMUM_MISMATCH");
            }
            try {
                long componentReserved = Math.addExact(value.mvccReservedBytes(), value.dueReservedBytes());
                componentReserved = Math.addExact(componentReserved, value.retentionReservedBytes());
                componentReserved = Math.addExact(componentReserved, value.ownerReservedBytes());
                componentReserved = Math.addExact(componentReserved, value.projectionReservedBytes());
                if (componentReserved != value.steadyReservedBytes()) {
                    reasons.add("CAPACITY_STEADY_RESERVATION_MISMATCH");
                }
            } catch (ArithmeticException overflow) {
                reasons.add("CAPACITY_STEADY_RESERVATION_OVERFLOW");
            }
            if (value.steadyReservedBytes() < 0L
                    || value.steadyHighWaterReservedBytes() < value.steadyReservedBytes()
                    || value.steadyHighWaterReservedBytes() > value.steadyMaximumBytes()) {
                reasons.add("CAPACITY_STEADY_BUDGET_EXCEEDED");
            }
            if (value.transientReservedBytes() < 0L
                    || value.transientHighWaterReservedBytes() < value.transientReservedBytes()
                    || value.transientHighWaterReservedBytes() > value.transientMaximumBytes()) {
                reasons.add("CAPACITY_TRANSIENT_BUDGET_EXCEEDED");
            }
            try {
                if (value.combinedReservedBytes() != Math.addExact(
                        value.steadyReservedBytes(), value.transientReservedBytes())
                        || value.combinedHighWaterReservedBytes() != Math.addExact(
                                value.steadyHighWaterReservedBytes(),
                                value.transientHighWaterReservedBytes())
                        || value.combinedMaximumBytes() != Math.addExact(
                                value.steadyMaximumBytes(), value.transientMaximumBytes())) {
                    reasons.add("CAPACITY_COMBINED_ACCOUNTING_MISMATCH");
                }
            } catch (ArithmeticException overflow) {
                reasons.add("CAPACITY_COMBINED_ACCOUNTING_OVERFLOW");
            }
            boolean verified = reasons.isEmpty();
            return new CapacityArtifact(verified ? "VERIFIED" : "FAILED", true, verified,
                    reasons, Optional.of(value), Optional.of(artifact.jvm()));
        }
    }

    /** Constant-space benchmark-owned current/high-water accounting. */
    /* default */ static final class PopulationAccounting {
        private final PopulationMetrics initial;
        private final AtomicLong current;
        private final AtomicLong highWater;
        private final AtomicLong admissions = new AtomicLong();
        private final AtomicLong retirements = new AtomicLong();

        /* default */ PopulationAccounting(PopulationMetrics initial) {
            this.initial = initial;
            current = new AtomicLong(initial.observedPreloadCurrentRecords());
            highWater = new AtomicLong(initial.observedPreloadCurrentRecords());
        }

        private boolean enabled() {
            return !"NONE".equals(initial.mode());
        }

        /* default */ void ownerAdmitted() {
            if (!enabled()) return;
            admissions.incrementAndGet();
            long observed = current.addAndGet(2L);
            highWater.accumulateAndGet(observed, Math::max);
        }

        /* default */ void ownerRetired() {
            if (!enabled()) return;
            long retired = retirements.incrementAndGet();
            if (retired > admissions.get() || current.decrementAndGet() < 0L) {
                throw new IllegalStateException("native population accounting is inconsistent");
            }
        }

        /* default */ PopulationMetrics finish() {
            if (!enabled()) return initial;
            long admitted = admissions.get();
            long retired = retirements.get();
            long expected = Math.addExact(initial.observedPreloadCurrentRecords(),
                    Math.subtractExact(Math.multiplyExact(admitted, 2L), retired));
            long exactCurrent = current.get();
            long exactHighWater = highWater.get();
            if (retired > admitted || exactCurrent != expected || exactHighWater < exactCurrent) {
                throw new IllegalStateException("native population accounting is inconsistent");
            }
            if (admitted == initial.plannedArrivals() && retired == admitted
                    && exactCurrent != initial.plannedDrainedCurrentRecords()) {
                throw new IllegalStateException("native population accounting is inconsistent");
            }
            return initial.withAccounting(exactCurrent, exactHighWater, admitted, retired);
        }
    }

    static long inferNativeAtomicCommits(long acceptedOperations, long providerInvocations) {
        if (acceptedOperations < 0L || acceptedOperations != providerInvocations) {
            throw new IllegalStateException("native accepted/provider invocation invariant failed");
        }
        return acceptedOperations;
    }

    private static void verifyAccounting(SigningBenchmarkConfig configuration, long scheduled,
            boolean diagnostic, RunMetrics metrics) {
        if (configuration.targetMode() != SigningBenchmarkConfig.TargetMode.NATIVE_SHARED_LEDGER
                || configuration.cellMode() == SigningBenchmarkConfig.CellMode.SMOKE) {
            return;
        }
        long contextAdmitted = metrics.workflowContextsAdmitted.sum();
        long admitted = metrics.admitted.sum();
        long completed = metrics.completed.sum();
        List<String> reasons = new ArrayList<>();
        expectEqual(reasons, "scheduledVsAttempted", scheduled, metrics.attemptedArrivals.sum());
        expectEqual(reasons, "workflowContextCapacityAccounting", scheduled,
                contextAdmitted + metrics.contextCapacityRejected.sum());
        expectEqual(reasons, "workflowContextAdmissionAccounting", contextAdmitted,
                admitted + metrics.productionAdmissionRejected.sum() + metrics.preAcceptFailure.sum());
        expectEqual(reasons, "admittedVsAccepted", admitted, metrics.accepted.sum());
        expectEqual(reasons, "terminalAccounting", admitted,
                completed + metrics.failed.sum() + metrics.uncertain.sum());
        expectEqual(reasons, "completionWindowAccounting", completed,
                metrics.completedWithinWindow.sum() + metrics.completedAfterWindow.sum());
        if (metrics.admittedTerminalWithinWindow.sum() > metrics.admittedWithinWindow.sum()) {
            reasons.add("terminalWithinWindow actual=" + metrics.admittedTerminalWithinWindow.sum()
                    + " maximum=" + metrics.admittedWithinWindow.sum());
        }
        if (metrics.admittedTerminalWithinWindow.sum() + metrics.terminalAfterWindow.sum() > admitted) {
            reasons.add("allTerminal actual="
                    + (metrics.admittedTerminalWithinWindow.sum() + metrics.terminalAfterWindow.sum())
                    + " maximum=" + admitted);
        }
        expectEqual(reasons, "windowBacklog", metrics.backlogAtWindowClose.get(),
                metrics.admittedWithinWindow.sum() - metrics.admittedTerminalWithinWindow.sum());
        expectEqual(reasons, "retirementAccounting",
                metrics.retired.sum() + metrics.retirementFailure.sum(), completed + metrics.failed.sum());
        if (!reasons.isEmpty() && !diagnostic) {
            // On a diagnostic run the host may leave work in flight, so the final
            // counts need not balance; the measured throughput is still reported and
            // the run stays not-evaluable. An evaluable acceptance run must balance.
            throw new PhaseInvariantException("report", reasons);
        }
    }

    record Result(String profile, String targetMode, String admissionTopology,
            String cellId, String cellMode, int retainedPopulation, int activePopulation, int groupSize,
            long residentIndexBudgetBytes, long compactionTransientBudgetBytes,
            int warmupSeconds, int durationSeconds, int offeredRate, int lanes, int queueCapacity, int payloadBytes,
            int providerMeanMillis, int providerJitterMillis, int sampleCapacity, int drainSeconds, long seed,
            boolean diagnosticEnvironmentOverride, String workRoot, long scheduled, long admitted, long accepted,
            long workflowContextsAdmitted, long admittedWithinWindow,
            long rejected, long productionAdmissionRejected, long preAcceptFailure, long contextCapacityRejected,
            long completed, long retired,
            long completedWithinWindow, long completedAfterWindow, long terminalWithinWindow,
            long terminalAfterWindow, long backlogAtWindowClose, long failed, long retirementFailure,
            long uncertain, int contextCapacity, int stepWorkers, long workflowTransitionsExecuted,
            long observationAttempts, long peakResidentContexts,
            double achievedThroughput, BoundedLatencySamples.Summary endToEnd,
            BoundedLatencySamples.Summary queue, ProviderMetrics provider,
            SigningExecutionRuntime.Metrics runtime,
            long allocatedBytes, long gcCollections, long gcMillis, long usedHeapDeltaBytes,
            long baselineHeapBytes, long finalHeapBytes, long peakHeapBytes,
            PopulationMetrics population, IndexCapacityMetrics indexCapacity,
            Environment environment, PreflightAssessment preflight,
            AcceptanceAssessment workloadAcceptance, AcceptanceAssessment acceptance,
            CleanupOutcome cleanup, String generatedAt) {

        private static Result of(SigningBenchmarkConfig configuration, long scheduled, RunMetrics metrics,
                ProviderMetrics provider, SigningExecutionRuntime.Metrics runtime,
                GcSnapshot before, GcSnapshot after,
                long elapsedNanos, PreflightAssessment preflight, CleanupOutcome cleanup,
                IndexCapacityMetrics indexCapacity) {
            return of(configuration, scheduled, metrics, provider, runtime, before, after, elapsedNanos,
                    preflight, cleanup, before.usedHeapBytes(), after.usedHeapBytes(),
                    Math.max(before.usedHeapBytes(), after.usedHeapBytes()), PopulationMetrics.none(),
                    indexCapacity);
        }

        private static Result of(SigningBenchmarkConfig configuration, long scheduled, RunMetrics metrics,
                ProviderMetrics provider, SigningExecutionRuntime.Metrics runtime,
                GcSnapshot before, GcSnapshot after,
                long elapsedNanos, PreflightAssessment preflight, CleanupOutcome cleanup,
                long baselineHeapBytes, long finalHeapBytes, long peakHeapBytes,
                PopulationMetrics population, IndexCapacityMetrics indexCapacity) {
            Environment environment = preflight.environment();
            verifyAccounting(configuration, scheduled, preflight.diagnosticOnly(), metrics);
            if (provider.sharedWriterEvidence()
                    && provider.wholeRunMaximumBatchSize() > configuration.groupSize()) {
                throw new IllegalStateException("native writer exceeded configured maximum group size");
            }
            long completed = metrics.completed.sum();
            double throughput = metrics.completedWithinWindow.sum() * (double) NANOS_PER_SECOND / elapsedNanos;
            BoundedLatencySamples.Summary endToEnd = metrics.endToEndLatency.summarize();
            AcceptanceAssessment acceptance = AcceptanceAssessment.assess(configuration, environment,
                    scheduled, metrics.admitted.sum(), metrics.accepted.sum(),
                    metrics.rejected.sum(), completed, metrics.completedWithinWindow.sum(), metrics.failed.sum(),
                    metrics.uncertain.sum(), throughput, endToEnd.p99Nanos(), provider.retainedOperations());
            if (metrics.contextCapacityRejected.sum() != 0L) {
                acceptance = acceptance.invalid("HARNESS_CONTEXT_CAPACITY_EXHAUSTED");
            }
            if (provider.retainedOperations() < 0) {
                acceptance = acceptance.invalid("INDEXED_CAPACITY_STATS_UNAVAILABLE");
            }
            for (String reason : population.capacityArtifact().reasons()) {
                acceptance = acceptance.invalid(reason);
            }
            if (configuration.targetMode() == SigningBenchmarkConfig.TargetMode.NATIVE_SHARED_LEDGER
                    && (runtime.schedulerReserved() != 0 || runtime.running() != 0 || runtime.ready() != 0
                            || runtime.pendingAdvisories() != 0)) {
                acceptance = acceptance.invalid("RUNTIME_NOT_DRAINED");
            }
            long allocated = before.allocatedBytes() < 0L || after.allocatedBytes() < before.allocatedBytes() ? -1L
                    : after.allocatedBytes() - before.allocatedBytes();
            boolean multiplexerUsed = configuration.targetMode()
                    == SigningBenchmarkConfig.TargetMode.NATIVE_SHARED_LEDGER
                    && configuration.cellMode() != SigningBenchmarkConfig.CellMode.SMOKE
                    && !"RETAINED_ONLY".equals(population.mode());
            int contextCapacity = multiplexerUsed ? configuration.activePopulation() : 0;
            int stepWorkers = multiplexerUsed ? nativeConcurrency(configuration) : 0;
            long workflowTransitionsExecuted = multiplexerUsed
                    ? metrics.workflowTransitionsExecuted.sum() : 0L;
            long observationAttempts = multiplexerUsed ? metrics.observationAttempts.sum() : 0L;
            long peakResidentContexts = multiplexerUsed ? metrics.peakResidentContexts.get() : 0L;
            return new Result(configuration.profile(), configuration.targetMode().commandValue(),
                    configuration.targetMode().admissionTopology(), configuration.cellId(),
                    configuration.cellMode().commandValue(), configuration.retainedPopulation(),
                    configuration.activePopulation(), configuration.groupSize(),
                    configuration.residentIndexBudgetBytes(), configuration.compactionTransientBudgetBytes(),
                    configuration.warmupSeconds(),
                    configuration.durationSeconds(), configuration.rate(), configuration.lanes(),
                    configuration.queueCapacity(), configuration.payloadBytes(), configuration.providerMeanMillis(),
                    configuration.providerJitterMillis(), configuration.sampleCapacity(),
                    configuration.drainSeconds(), configuration.seed(), configuration.diagnosticEnvironmentOverride(),
                    configuration.workRoot().toString(), scheduled, metrics.admitted.sum(),
                    metrics.accepted.sum(), metrics.workflowContextsAdmitted.sum(),
                    metrics.admittedWithinWindow.sum(),
                    metrics.rejected.sum(), metrics.productionAdmissionRejected.sum(),
                    metrics.preAcceptFailure.sum(), metrics.contextCapacityRejected.sum(), completed,
                    metrics.retired.sum(),
                    metrics.completedWithinWindow.sum(), metrics.completedAfterWindow.sum(),
                    metrics.admittedTerminalWithinWindow.sum(), metrics.terminalAfterWindow.sum(),
                    metrics.backlogAtWindowClose.get(), metrics.failed.sum(), metrics.retirementFailure.sum(),
                    metrics.uncertain.sum(), contextCapacity, stepWorkers,
                    workflowTransitionsExecuted, observationAttempts, peakResidentContexts, throughput,
                    endToEnd, metrics.queueLatency.summarize(), provider, runtime, allocated,
                    Math.max(0L, after.collections() - before.collections()),
                    Math.max(0L, after.collectionMillis() - before.collectionMillis()),
                    after.usedHeapBytes() - before.usedHeapBytes(), baselineHeapBytes, finalHeapBytes, peakHeapBytes,
                    population, indexCapacity, environment, preflight, acceptance,
                    cleanup.gate(acceptance), cleanup,
                    Instant.now().toString());
        }

        Result withCleanup(CleanupOutcome outcome) {
            return new Result(profile, targetMode, admissionTopology, cellId, cellMode, retainedPopulation,
                    activePopulation, groupSize, residentIndexBudgetBytes, compactionTransientBudgetBytes,
                    warmupSeconds, durationSeconds, offeredRate,
                    lanes, queueCapacity, payloadBytes, providerMeanMillis, providerJitterMillis, sampleCapacity,
                    drainSeconds, seed, diagnosticEnvironmentOverride, workRoot, scheduled, admitted, accepted,
                    workflowContextsAdmitted, admittedWithinWindow,
                    rejected, productionAdmissionRejected, preAcceptFailure, contextCapacityRejected,
                    completed, retired,
                    completedWithinWindow, completedAfterWindow, terminalWithinWindow, terminalAfterWindow,
                    backlogAtWindowClose, failed, retirementFailure, uncertain, contextCapacity, stepWorkers,
                    workflowTransitionsExecuted, observationAttempts, peakResidentContexts,
                    achievedThroughput, endToEnd,
                    queue, provider, runtime, allocatedBytes, gcCollections, gcMillis, usedHeapDeltaBytes,
                    baselineHeapBytes, finalHeapBytes, peakHeapBytes, population, indexCapacity, environment,
                    preflight, workloadAcceptance, outcome.gate(workloadAcceptance), outcome, generatedAt);
        }

        String humanSummary(Path output) {
            return String.format(java.util.Locale.ROOT,
                    "Signing benchmark [%s/%s]: offered=%d/s admitted=%d accepted=%d rejected=%d completed=%d "
                            + "windowCompleted=%d backlog=%d uncertain=%d windowThroughput=%.1f/s "
                            + "p50=%.3fms p95=%.3fms p99=%.3fms max=%.3fms report=%s",
                    profile, targetMode, offeredRate, admitted, accepted, rejected, completed, completedWithinWindow,
                    backlogAtWindowClose, uncertain, achievedThroughput,
                    millis(endToEnd.p50Nanos()), millis(endToEnd.p95Nanos()), millis(endToEnd.p99Nanos()),
                    millis(endToEnd.maxNanos()), output);
        }

        String toJson() {
            StringBuilder json = new StringBuilder(4_096);
            json.append('{');
            field(json, "schema", "zeroecho-signing-performance-v5").append(',');
            field(json, "generatedAt", generatedAt).append(',');
            field(json, "profile", profile).append(',');
            json.append("\"configuration\":{");
            field(json, "target", targetMode).append(',');
            field(json, "admissionTopology", admissionTopology).append(',');
            field(json, "cellId", cellId).append(',');
            field(json, "cellMode", cellMode).append(',');
            number(json, "retainedPopulation", retainedPopulation).append(',');
            number(json, "activePopulation", activePopulation).append(',');
            number(json, "groupSize", groupSize).append(',');
            number(json, "residentIndexBudgetBytes", residentIndexBudgetBytes).append(',');
            number(json, "compactionTransientBudgetBytes", compactionTransientBudgetBytes).append(',');
            number(json, "warmupSeconds", warmupSeconds).append(',');
            number(json, "durationSeconds", durationSeconds).append(',');
            number(json, "offeredRatePerSecond", offeredRate).append(',');
            number(json, "lanes", lanes).append(',');
            number(json, "queueCapacity", queueCapacity).append(',');
            number(json, "payloadBytes", payloadBytes).append(',');
            number(json, "providerMeanMillis", providerMeanMillis).append(',');
            number(json, "providerJitterMillis", providerJitterMillis).append(',');
            number(json, "sampleCapacity", sampleCapacity).append(',');
            number(json, "drainSeconds", drainSeconds).append(',');
            number(json, "seed", seed).append(',');
            bool(json, "diagnosticEnvironmentOverride", diagnosticEnvironmentOverride).append(',');
            field(json, "workRoot", workRoot).append("},");
            json.append("\"population\":{");
            field(json, "mode", population.mode()).append(',');
            number(json, "plannedGenericRecords", population.plannedGenericRecords()).append(',');
            number(json, "plannedActivePreload", population.plannedActivePreload()).append(',');
            number(json, "plannedContextCapacity", population.plannedContextCapacity()).append(',');
            number(json, "plannedArrivals", population.plannedArrivals()).append(',');
            number(json, "plannedMaximumCurrentRecords", population.plannedMaximumCurrentRecords()).append(',');
            number(json, "plannedDrainedCurrentRecords", population.plannedDrainedCurrentRecords()).append(',');
            number(json, "observedGenericRecords", population.observedGenericRecords()).append(',');
            number(json, "observedSignRecords", population.observedSignRecords()).append(',');
            number(json, "observedOwnerRecords", population.observedOwnerRecords()).append(',');
            number(json, "observedWatermarkRecords", population.observedWatermarkRecords()).append(',');
            number(json, "observedPreloadCurrentRecords", population.observedPreloadCurrentRecords()).append(',');
            number(json, "observedDueRecords", population.observedDueRecords()).append(',');
            number(json, "observedSharedContentOwners", population.observedSharedContentOwners()).append(',');
            number(json, "observedBenchmarkCurrentRecords",
                    population.observedBenchmarkCurrentRecords()).append(',');
            number(json, "accountedEventHighWaterRecords",
                    population.accountedEventHighWaterRecords()).append(',');
            number(json, "observedOwnerAdmissions", population.observedOwnerAdmissions()).append(',');
            number(json, "observedOwnerRetirements", population.observedOwnerRetirements()).append(',');
            capacityArtifact(json, "capacityArtifact", population.capacityArtifact()).append("},");
            json.append("\"residentIndexCapacity\":{");
            budgetMetrics(json, "steady", indexCapacity.steady()).append(',');
            budgetMetrics(json, "transient", indexCapacity.transientBudget()).append(',');
            budgetMetrics(json, "combined", indexCapacity.combined()).append("},");
            json.append("\"multiplexer\":{");
            number(json, "contextCapacity", contextCapacity).append(',');
            number(json, "stepWorkers", stepWorkers).append(',');
            number(json, "workflowTransitionsExecuted", workflowTransitionsExecuted).append(',');
            number(json, "observationAttempts", observationAttempts).append(',');
            number(json, "peakResidentContexts", peakResidentContexts).append("},");
            json.append("\"outcomes\":{");
            number(json, "scheduled", scheduled).append(',');
            number(json, "workflowContextsAdmitted", workflowContextsAdmitted).append(',');
            number(json, "admitted", admitted).append(',');
            number(json, "admittedWithinWindow", admittedWithinWindow).append(',');
            number(json, "accepted", accepted).append(',');
            number(json, "rejected", rejected).append(',');
            number(json, "productionAdmissionRejected", productionAdmissionRejected).append(',');
            number(json, "preAcceptFailure", preAcceptFailure).append(',');
            number(json, "contextCapacityRejected", contextCapacityRejected).append(',');
            number(json, "completed", completed).append(',');
            number(json, "retired", retired).append(',');
            number(json, "completedWithinWindow", completedWithinWindow).append(',');
            number(json, "completedAfterWindow", completedAfterWindow).append(',');
            number(json, "terminalWithinWindow", terminalWithinWindow).append(',');
            number(json, "terminalAfterWindow", terminalAfterWindow).append(',');
            number(json, "backlogAtWindowClose", backlogAtWindowClose).append(',');
            number(json, "failed", failed).append(',');
            number(json, "retirementFailure", retirementFailure).append(',');
            number(json, "uncertain", uncertain).append(',');
            decimal(json, "achievedThroughputPerSecond", achievedThroughput).append("},");
            json.append("\"latencyMillis\":{");
            summary(json, "endToEndFromScheduledArrival", endToEnd).append(',');
            summary(json, "admissionQueue", queue).append("},");
            json.append("\"provider\":{");
            field(json, "implementation", provider.implementation()).append(',');
            number(json, "submitCalls", provider.providerCalls()).append(',');
            decimal(json, "meanSubmitMillis", averageMillis(provider.providerNanos(), provider.providerCalls()))
                    .append(',');
            number(json, "statusCalls", provider.statusCalls()).append(',');
            decimal(json, "meanStatusMillis", averageMillis(provider.statusNanos(), provider.statusCalls()))
                    .append(',');
            number(json, "durabilityForces", provider.forceCount()).append(',');
            if (provider.sharedWriterEvidence()) {
                json.append("\"diagnosticWrites\":null,");
                number(json, "requestsCommitted", provider.requestsCommitted()).append(',');
            } else {
                number(json, "diagnosticWrites", provider.diagnosticWrites()).append(',');
                json.append("\"requestsCommitted\":null,");
            }
            number(json, "bytesWritten", provider.writeBytes()).append(',');
            decimal(json, "bytesPerAcceptedSignature", ratio(provider.writeBytes(), accepted)).append(',');
            decimal(json, "forcesPerAcceptedSignature", ratio(provider.forceCount(), accepted)).append(',');
            number(json, "retainedOperations", provider.retainedOperations()).append(',');
            number(json, "accountedEventHighWaterRecords",
                    provider.accountedEventHighWaterRecords()).append(',');
            number(json, "wholeRunMaximumBatchSize", provider.wholeRunMaximumBatchSize()).append(',');
            number(json, "inferredSharedLocalAtomicCommits",
                    provider.inferredSharedLocalAtomicCommits()).append(',');
            bool(json, "sharedWriterEvidence", provider.sharedWriterEvidence()).append(',');
            if (provider.sharedWriterEvidence()) {
                number(json, "groupsCommitted", provider.groupsCommitted()).append(',');
                decimal(json, "groupCommitWaitMillis", millis(provider.groupCommitWaitNanos())).append(',');
                decimal(json, "wholeRunMaximumGroupCommitWaitMillis",
                        millis(provider.maximumGroupCommitWaitNanos()))
                        .append(',');
                decimal(json, "totalForceMillis", millis(provider.forceNanos())).append(',');
                decimal(json, "wholeRunMaximumForceMillis", millis(provider.maximumForceNanos())).append(',');
            } else {
                json.append("\"groupsCommitted\":null,\"groupCommitWaitMillis\":null,")
                        .append("\"wholeRunMaximumGroupCommitWaitMillis\":null,\"totalForceMillis\":null,")
                        .append("\"wholeRunMaximumForceMillis\":null,");
            }
            if (provider.forceLatency().isPresent()) {
                summary(json, "forceLatencyMillis", provider.forceLatency().orElseThrow());
            } else {
                json.append("\"forceLatencyMillis\":null");
            }
            json.append("},");
            json.append("\"runtime\":{");
            number(json, "schedulerReserved", runtime.schedulerReserved()).append(',');
            number(json, "running", runtime.running()).append(',');
            number(json, "ready", runtime.ready()).append(',');
            number(json, "pendingAdvisories", runtime.pendingAdvisories()).append(',');
            number(json, "wholeRunHighWaterSchedulerReserved", runtime.highWaterSchedulerReserved()).append(',');
            number(json, "schedulingRejected", runtime.schedulingRejected()).append(',');
            number(json, "callbackCoalesced", runtime.callbackCoalesced()).append(',');
            number(json, "callbackDropped", runtime.callbackDropped()).append(',');
            number(json, "callbackWake", runtime.callbackWake()).append(',');
            field(json, "measurementEndLifecycleState", runtime.state().name()).append("},");
            json.append("\"jvm\":{");
            if (allocatedBytes < 0L) {
                json.append("\"liveThreadAllocatedBytesEstimate\":null,");
            } else {
                number(json, "liveThreadAllocatedBytesEstimate", allocatedBytes).append(',');
            }
            number(json, "gcCollections", gcCollections).append(',');
            number(json, "gcMillis", gcMillis).append(',');
            number(json, "usedHeapDeltaBytes", usedHeapDeltaBytes).append(',');
            number(json, "baselineHeapBytes", baselineHeapBytes).append(',');
            number(json, "finalHeapBytes", finalHeapBytes).append(',');
            number(json, "sumOfHeapPoolPeakBytes", peakHeapBytes).append("},");
            json.append("\"environment\":{");
            field(json, "javaVersion", environment.javaVersion()).append(',');
            field(json, "javaVendor", environment.javaVendor()).append(',');
            field(json, "vmName", environment.vmName()).append(',');
            field(json, "osName", environment.osName()).append(',');
            field(json, "osVersion", environment.osVersion()).append(',');
            field(json, "osArchitecture", environment.osArchitecture()).append(',');
            field(json, "cpuModel", environment.cpuModel()).append(',');
            number(json, "processors", environment.processors()).append(',');
            number(json, "maximumHeapBytes", environment.maximumHeapBytes()).append(',');
            field(json, "garbageCollectors", environment.garbageCollectors()).append(',');
            field(json, "jvmArguments", environment.jvmArguments()).append(',');
            field(json, "filesystemType", environment.filesystemType()).append(',');
            number(json, "filesystemUsableBytes", environment.filesystemUsableBytes()).append(',');
            field(json, "mountPoint", environment.mountPoint()).append(',');
            field(json, "mountSource", environment.mountSource()).append(',');
            field(json, "mountOptions", environment.mountOptions()).append(',');
            bool(json, "localNvmeVerified", environment.localNvmeVerified()).append(',');
            field(json, "localNvmeEvidence", environment.localNvmeEvidence()).append(',');
            field(json, "containerConstraints", environment.containerConstraints()).append(',');
            field(json, "powerConstraints", environment.powerConstraints()).append(',');
            field(json, "hostname", environment.hostname()).append("},");
            json.append("\"preflight\":{");
            bool(json, "proceed", preflight.proceed()).append(',');
            bool(json, "diagnosticOnly", preflight.diagnosticOnly()).append(',');
            stringArray(json, "mismatchReasons", preflight.mismatchReasons()).append("},");
            json.append("\"acceptance\":{");
            bool(json, "evaluated", acceptance.evaluable()).append(',');
            bool(json, "targetMet", acceptance.targetMet()).append(',');
            stringArray(json, "reasons", acceptance.reasons()).append(',');
            field(json, "target", ">=1000 fixed-window completions/s and p99 <100ms at 16 lanes").append("},");
            json.append("\"cleanup\":{");
            field(json, "state", cleanup.state()).append(',');
            if (cleanup.reason().isPresent()) {
                field(json, "reason", cleanup.reason().orElseThrow());
            } else {
                json.append("\"reason\":null");
            }
            json.append("}}");
            return json.toString();
        }

        private static StringBuilder stringArray(StringBuilder json, String name, List<String> values) {
            quote(json, name).append(":[");
            for (int index = 0; index < values.size(); index++) {
                if (index != 0) {
                    json.append(',');
                }
                quote(json, values.get(index));
            }
            return json.append(']');
        }

        private static StringBuilder capacityArtifact(StringBuilder json, String name,
                CapacityArtifact artifact) {
            quote(json, name).append(":{");
            field(json, "state", artifact.state()).append(',');
            bool(json, "required", artifact.required()).append(',');
            bool(json, "verified", artifact.verified()).append(',');
            stringArray(json, "reasons", artifact.reasons()).append(',');
            if (artifact.observation().isEmpty()) {
                json.append("\"observation\":null,");
            } else {
                SigningPopulationFixture.CapacityEvidence value = artifact.observation().orElseThrow();
                json.append("\"observation\":{");
                number(json, "currentKeys", value.currentKeys()).append(',');
                number(json, "canonicalKeyBytes", value.canonicalKeyBytes()).append(',');
                number(json, "mvccLiveSnapshots", value.mvccLiveSnapshots()).append(',');
                number(json, "mvccEstimatedResidentBytes", value.mvccEstimatedResidentBytes()).append(',');
                number(json, "mvccReservedBytes", value.mvccReservedBytes()).append(',');
                number(json, "dueWork", value.dueWork()).append(',');
                number(json, "dueCanonicalIdBytes", value.dueCanonicalIdBytes()).append(',');
                number(json, "dueEstimatedResidentBytes", value.dueEstimatedResidentBytes()).append(',');
                number(json, "dueReservedBytes", value.dueReservedBytes()).append(',');
                number(json, "retentionRecords", value.retentionRecords()).append(',');
                number(json, "retentionReservedBytes", value.retentionReservedBytes()).append(',');
                number(json, "ownerWork", value.ownerWork()).append(',');
                number(json, "ownerCanonicalIdBytes", value.ownerCanonicalIdBytes()).append(',');
                number(json, "ownerEstimatedResidentBytes", value.ownerEstimatedResidentBytes()).append(',');
                number(json, "ownerReservedBytes", value.ownerReservedBytes()).append(',');
                number(json, "projectedIdentities", value.projectedIdentities()).append(',');
                number(json, "projectionReservedBytes", value.projectionReservedBytes()).append(',');
                number(json, "registeredGenerations", value.registeredGenerations()).append(',');
                number(json, "publishedGenerations", value.publishedGenerations()).append(',');
                number(json, "supersededGenerations", value.supersededGenerations()).append(',');
                number(json, "reclaimingGenerations", value.reclaimingGenerations()).append(',');
                number(json, "reclaimableGenerations", value.reclaimableGenerations()).append(',');
                number(json, "generationCurrentReferences", value.generationCurrentReferences()).append(',');
                number(json, "generationSnapshotPins", value.generationSnapshotPins()).append(',');
                number(json, "steadyReservedBytes", value.steadyReservedBytes()).append(',');
                number(json, "steadyHighWaterReservedBytes",
                        value.steadyHighWaterReservedBytes()).append(',');
                number(json, "steadyMaximumBytes", value.steadyMaximumBytes()).append(',');
                number(json, "transientReservedBytes", value.transientReservedBytes()).append(',');
                number(json, "transientHighWaterReservedBytes",
                        value.transientHighWaterReservedBytes()).append(',');
                number(json, "transientMaximumBytes", value.transientMaximumBytes()).append(',');
                number(json, "combinedReservedBytes", value.combinedReservedBytes()).append(',');
                number(json, "combinedHighWaterReservedBytes",
                        value.combinedHighWaterReservedBytes()).append(',');
                number(json, "combinedMaximumBytes", value.combinedMaximumBytes()).append("},");
            }
            if (artifact.jvm().isEmpty()) {
                json.append("\"quiescentJvm\":null");
            } else {
                SigningPopulationFixture.QuiescentJvm value = artifact.jvm().orElseThrow();
                json.append("\"quiescentJvm\":{");
                number(json, "usedHeapBytes", value.usedHeapBytes()).append(',');
                if (value.allocatedBytes() < 0L) {
                    json.append("\"liveThreadAllocatedBytesEstimate\":null,");
                } else {
                    number(json, "liveThreadAllocatedBytesEstimate", value.allocatedBytes()).append(',');
                }
                number(json, "gcCollections", value.gcCollections()).append(',');
                number(json, "gcMillis", value.gcMillis()).append('}');
            }
            return json.append('}');
        }

        private static StringBuilder budgetMetrics(StringBuilder json, String name,
                BudgetMetrics metrics) {
            quote(json, name).append(":{");
            number(json, "currentReservedBytes", metrics.currentReservedBytes()).append(',');
            number(json, "highWaterReservedBytes", metrics.highWaterReservedBytes()).append(',');
            number(json, "maximumBytes", metrics.maximumBytes()).append(',');
            return number(json, "headroomBytes", metrics.headroomBytes()).append('}');
        }

        private static StringBuilder summary(StringBuilder json, String name,
                BoundedLatencySamples.Summary summary) {
            quote(json, name).append(":{");
            number(json, "observations", summary.observations()).append(',');
            number(json, "samples", summary.samples()).append(',');
            decimal(json, "p50", millis(summary.p50Nanos())).append(',');
            decimal(json, "p95", millis(summary.p95Nanos())).append(',');
            decimal(json, "p99", millis(summary.p99Nanos())).append(',');
            return decimal(json, "max", millis(summary.maxNanos())).append('}');
        }

        private static StringBuilder field(StringBuilder json, String name, String value) {
            quote(json, name).append(':');
            return quote(json, value);
        }

        private static StringBuilder number(StringBuilder json, String name, long value) {
            quote(json, name).append(':').append(value);
            return json;
        }

        private static StringBuilder decimal(StringBuilder json, String name, double value) {
            quote(json, name).append(':').append(String.format(java.util.Locale.ROOT, "%.6f", value));
            return json;
        }

        private static StringBuilder bool(StringBuilder json, String name, boolean value) {
            quote(json, name).append(':').append(value);
            return json;
        }

        private static StringBuilder quote(StringBuilder json, String value) {
            json.append('"');
            for (int index = 0; index < value.length(); index++) {
                char character = value.charAt(index);
                switch (character) {
                    case '"' -> json.append("\\\"");
                    case '\\' -> json.append("\\\\");
                    case '\n' -> json.append("\\n");
                    case '\r' -> json.append("\\r");
                    case '\t' -> json.append("\\t");
                    default -> {
                        if (character < 0x20) {
                            json.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) character));
                        } else {
                            json.append(character);
                        }
                    }
                }
            }
            return json.append('"');
        }

        private static double millis(long nanoseconds) {
            return nanoseconds / 1_000_000.0;
        }

        private static double averageMillis(long nanoseconds, long count) {
            return count == 0L ? 0.0 : nanoseconds / 1_000_000.0 / count;
        }

        private static double ratio(long numerator, long denominator) {
            return denominator == 0L ? 0.0 : numerator / (double) denominator;
        }
    }
}
