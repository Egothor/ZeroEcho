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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.util.async.AsyncState;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.impl.fs.SigningPopulationFixture;

/** Contract coverage for benchmark scheduling, bounds, and real-path wiring. */
@SuppressWarnings({ "PMD.UnitTestContainsTooManyAsserts", "PMD.UnitTestAssertionsShouldIncludeMessage",
        "PMD.AvoidDuplicateLiterals", "PMD.AvoidInstantiatingObjectsInLoops" })
final class SigningPerformanceBenchmarkTest {

    @Test
    void storeRecoveryFailureJsonContainsFullFirstCauseChain() {
        IOException storageFailure = new IOException("injected force \"failure\"");
        IllegalStateException recoveryFailure = new IllegalStateException(
                "metadata recovery required", storageFailure);

        String json = SigningPerformanceBenchmark.storeRecoveryFailureJson(recoveryFailure);

        assertTrue(json.contains("\"type\":\"java.lang.IllegalStateException\""));
        assertTrue(json.contains("\"message\":\"metadata recovery required\""));
        assertTrue(json.contains("\"stackTrace\":\"java.lang.IllegalStateException:"));
        assertTrue(json.contains("Caused by: java.io.IOException: injected force \\\"failure\\\""));
        assertTrue(json.contains("\"causalChain\":["
                + "{\"type\":\"java.lang.IllegalStateException\","
                + "\"message\":\"metadata recovery required\"},"
                + "{\"type\":\"java.io.IOException\","
                + "\"message\":\"injected force \\\"failure\\\"\"}]"));
        assertEquals("null", SigningPerformanceBenchmark.storeRecoveryFailureJson(null));
    }

    @Test
    void smokeProfileExercisesNativeRuntimeAndProducesVersionedJson(@TempDir Path temporary) throws Exception {
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                "--profile=smoke", "--warmupSeconds=1", "--workRoot=" + temporary.resolve("work"),
                "--output=" + temporary.resolve("result.json")
        });

        SigningPerformanceBenchmark.Result result = SigningPerformanceBenchmark.run(configuration);

        assertEquals(3L, result.scheduled());
        assertEquals(3L, result.admitted());
        assertEquals(3L, result.accepted());
        assertEquals(0L, result.rejected());
        assertEquals(3L, result.completed());
        assertEquals(0L, result.uncertain());
        assertEquals("zeroecho-lib-local-shared-ledger", result.provider().implementation());
        assertEquals(6L, result.provider().forceCount());
        assertEquals(3L, result.provider().inferredSharedLocalAtomicCommits());
        assertEquals(3, result.provider().accountedEventHighWaterRecords());
        assertTrue(result.provider().wholeRunMaximumBatchSize() <= result.groupSize());
        assertEquals(0, result.provider().retainedOperations());
        assertEquals(0, result.contextCapacity());
        assertEquals(0, result.stepWorkers());
        assertEquals(0L, result.workflowTransitionsExecuted());
        assertEquals(0L, result.observationAttempts());
        assertEquals(0L, result.peakResidentContexts());
        assertEquals("SUCCEEDED", result.cleanup().state());
        assertTrue(result.toJson().contains("\"schema\":\"zeroecho-signing-performance-v5\""));
        assertTrue(result.toJson().contains("\"cellId\":\"native-smoke\""));
        assertTrue(result.toJson().contains("\"preflight\":{"));
        assertTrue(result.toJson().contains("\"sharedWriterEvidence\":true"));
        assertTrue(result.toJson().contains("\"accountedEventHighWaterRecords\":3"));
        assertFalse(result.toJson().contains("\"durablePopulationHighWater\""));
        assertEquals(1, result.runtime().highWaterSchedulerReserved());
        assertEquals(0, result.runtime().schedulerReserved());
        assertEquals("CLOSED", result.runtime().state().name());
        assertTrue(result.toJson().contains("\"target\":\"native-shared-ledger\""));
        assertTrue(result.toJson().contains(
                "\"admissionTopology\":\"production-local-shared-ledger-step-scheduler\""));
    }

    @Test
    void rejectsUnknownOrUnsafeConfiguration() {
        assertThrows(IllegalArgumentException.class,
                () -> SigningBenchmarkConfig.parse(new String[] { "--profile=diagnostic", "--bogus=true" }));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=diagnostic", "--providerMeanMillis=5", "--providerJitterMillis=6"
        }));
        assertThrows(IllegalArgumentException.class,
                () -> SigningBenchmarkConfig.parse(new String[] { "--profile=diagnostic", "--rate=0" }));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=diagnostic", "--diagnosticEnvironmentOverride=yes"
        }));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--retainedPopulation=0"
        }));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--activePopulation=100001"
        }));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--groupSize=2"
        }));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--cellId=NOT_VALID"
        }));
    }

    @Test
    void orthogonalGridHasExactStableOrderCoverageAndNoDuplicates() {
        List<SigningBenchmarkGrid.Cell> cells = SigningBenchmarkGrid.cells();

        assertEquals(11, cells.size());
        assertEquals(List.of(
                "m1000000-w100000-l16-g32",
                "m1000-w100000-l16-g32",
                "m100000-w100000-l16-g32",
                "m1000000-w10-l16-g32",
                "m1000000-w1000-l16-g32",
                "m1000000-w100000-l1-g32",
                "m1000000-w100000-l8-g32",
                "m1000000-w100000-l32-g32",
                "m1000000-w100000-l16-g1",
                "m1000000-w100000-l16-g8",
                "m1000000-w100000-l16-g64"),
                cells.stream().map(SigningBenchmarkGrid.Cell::id).toList());
        assertEquals(10L, cells.stream().filter(SigningBenchmarkGrid.Cell::supported).count());
        assertEquals(1L, cells.stream().filter(cell -> !cell.supported()).count());

        List<SigningBenchmarkGrid.Cell> incomplete = new ArrayList<>(cells);
        incomplete.removeLast();
        SigningBenchmarkGrid.ContractException failure = assertThrows(
                SigningBenchmarkGrid.ContractException.class,
                () -> SigningBenchmarkGrid.verifyDefinition(incomplete));
        assertEquals("GRID_INCOMPLETE", failure.reasonCode());
    }

    @Test
    void populationPlannerCoversEveryGridCellAndMatchesExactAnchor() {
        List<String> modes = new ArrayList<>();
        for (SigningBenchmarkGrid.Cell cell : SigningBenchmarkGrid.cells()) {
            SigningBenchmarkConfig configuration = gridConfiguration(cell);
            if (cell.supported()) {
                modes.add(SigningPopulationPlan.forCell(cell, configuration).mode().name());
            } else {
                SigningBenchmarkGrid.ContractException failure = assertThrows(
                        SigningBenchmarkGrid.ContractException.class,
                        () -> SigningPopulationPlan.forCell(cell, configuration));
                assertEquals("UNSUPPORTED_MAX_32", failure.reasonCode());
                modes.add("UNSUPPORTED");
            }
        }
        assertEquals(List.of("COMBINED_WORKLOAD", "RETAINED_ONLY", "RETAINED_ONLY",
                "COMBINED_WORKLOAD", "COMBINED_WORKLOAD", "COMBINED_WORKLOAD",
                "COMBINED_WORKLOAD", "COMBINED_WORKLOAD", "COMBINED_WORKLOAD",
                "COMBINED_WORKLOAD", "UNSUPPORTED"), modes);

        SigningBenchmarkGrid.Cell anchor = SigningBenchmarkGrid.cells().getFirst();
        SigningPopulationPlan.Plan plan = SigningPopulationPlan.forCell(anchor,
                gridConfiguration(anchor));
        assertEquals(100_000L, plan.contextCapacity());
        assertEquals(0L, plan.activePreload());
        assertEquals(363_000L, plan.arrivals());
        assertEquals(536_999L, plan.genericRecords());
        assertEquals(1_000_000L, plan.maximumCurrentRecords());
        assertEquals(900_000L, plan.drainedCurrentRecords());
    }

    @Test
    void impossiblePopulationShapeRejectsBeforeWorkRootMutation(@TempDir Path temporary) {
        Path workRoot = temporary.resolve("must-not-exist");
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--cellId=impossible-shape",
                "--retainedPopulation=1000", "--activePopulation=10", "--workRoot=" + workRoot
        });
        SigningBenchmarkGrid.Cell cell = new SigningBenchmarkGrid.Cell("impossible-shape",
                1_000, 10, 16, 32, true);

        SigningBenchmarkGrid.ContractException failure = assertThrows(
                SigningBenchmarkGrid.ContractException.class,
                () -> SigningPopulationPlan.forCell(cell, configuration));

        assertEquals("POPULATION_SHAPE_IMPOSSIBLE", failure.reasonCode());
        assertFalse(Files.exists(workRoot));
    }

    @Test
    void boundedRealPopulationReopensWithExactCountsAndSharedOwnership(@TempDir Path temporary)
            throws Exception {
        Path storeRoot = temporary.resolve("store");
        Instant now = Instant.parse("2026-08-31T10:15:30.123456789Z");
        Instant normalizedNow = Instant.ofEpochMilli(now.toEpochMilli());
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults().withSigningMaximumGroupSize(8);

        SigningPopulationFixture.Artifact artifact = SigningPopulationFixture.populate(
                storeRoot, options, now, 7L, 3L);
        SigningPopulationFixture.Observation observation = artifact.population();

        assertEquals(new SigningPopulationFixture.Observation(7L, 3L, 3L, 1L, 14L, 3L, 3L),
                observation);
        assertEquals(14, artifact.capacity().currentKeys());
        assertEquals(3, artifact.capacity().dueWork());
        assertEquals(3, artifact.capacity().ownerWork());
        assertEquals(3, artifact.capacity().projectedIdentities());
        assertTrue(artifact.capacity().steadyReservedBytes()
                <= artifact.capacity().steadyMaximumBytes());
        assertEquals(0L, artifact.capacity().transientReservedBytes());
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                storeRoot, options, Clock.fixed(normalizedNow, java.time.ZoneOffset.UTC))) {
            assertEquals(3, reopened.selectDueSignRecords(now, 10).size());
            assertTrue(reopened.selectDueSignRecords(now, 10).stream()
                    .allMatch(record -> record.state()
                            == zeroecho.pki.spi.store.SignWorkflowStore.State.INTENT));
            assertTrue(reopened.selectDueSignRecords(now, 10).stream()
                    .allMatch(record -> record.createdAt().equals(normalizedNow)));
        }
    }

    @Test
    void retainedOnlyRunReportsExactQuiescentCapacityArtifact(@TempDir Path temporary)
            throws Exception {
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--diagnosticEnvironmentOverride=true",
                "--retainedPopulation=1000", "--cellId=m1000-w100000-l16-g32",
                "--workRoot=" + temporary.resolve("work"),
                "--output=" + temporary.resolve("result.json")
        });

        SigningPerformanceBenchmark.Result result = SigningPerformanceBenchmark.run(
                configuration, unverifiedEnvironment());
        SigningPerformanceBenchmark.CapacityArtifact artifact = result.population().capacityArtifact();
        SigningPopulationFixture.CapacityEvidence capacity = artifact.observation().orElseThrow();

        assertEquals("VERIFIED", artifact.state());
        assertTrue(artifact.required());
        assertTrue(artifact.verified());
        assertTrue(artifact.reasons().isEmpty());
        assertEquals(1_000, capacity.currentKeys());
        assertEquals(0, capacity.dueWork());
        assertEquals(0, capacity.ownerWork());
        assertEquals(0, capacity.retentionRecords());
        assertEquals(0, capacity.projectedIdentities());
        assertEquals(1_000L, capacity.generationCurrentReferences());
        assertEquals(0L, capacity.generationSnapshotPins());
        assertTrue(capacity.steadyReservedBytes() <= capacity.steadyMaximumBytes());
        assertEquals(0L, capacity.transientReservedBytes());
        assertFalse(result.acceptance().evaluable());
        assertFalse(result.acceptance().targetMet());
        assertTrue(result.toJson().contains("\"capacityArtifact\":{\"state\":\"VERIFIED\""));
        assertTrue(result.toJson().contains("\"currentKeys\":1000"));
        assertTrue(result.toJson().contains("\"quiescentJvm\":{"));
    }

    @Test
    void retainedCapacityMismatchUsesStableFailClosedReason() {
        SigningPopulationPlan.Plan plan = new SigningPopulationPlan.Plan(
                SigningPopulationPlan.Mode.RETAINED_ONLY, 9L, 0L, 0L, 0L, 1L, 10L, 10L);
        SigningPopulationFixture.CapacityEvidence capacity = capacityEvidence(9, 1_000L, 0L, 1_000L);
        SigningPopulationFixture.Artifact source = new SigningPopulationFixture.Artifact(
                new SigningPopulationFixture.Observation(9L, 0L, 0L, 1L, 10L, 0L, 0L),
                capacity, new SigningPopulationFixture.QuiescentJvm(1L, -1L, 0L, 0L));

        SigningPerformanceBenchmark.CapacityArtifact artifact =
                SigningPerformanceBenchmark.CapacityArtifact.assess(plan, source,
                        SigningBenchmarkConfig.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                        SigningBenchmarkConfig.DEFAULT_COMPACTION_TRANSIENT_BUDGET_BYTES);

        assertEquals("FAILED", artifact.state());
        assertTrue(artifact.required());
        assertFalse(artifact.verified());
        assertEquals(List.of("CAPACITY_CURRENT_KEYS_MISMATCH"), artifact.reasons());
    }

    @Test
    void retainedCapacityReservationMismatchUsesStableFailClosedReason() {
        SigningPerformanceBenchmark.CapacityArtifact artifact = capacityArtifact(
                capacityEvidence(10, 1_000L, 0L, 999L));

        assertEquals("FAILED", artifact.state());
        assertEquals(List.of("CAPACITY_STEADY_RESERVATION_MISMATCH"), artifact.reasons());
    }

    @Test
    void retainedCapacityReservationOverflowUsesStableFailClosedReason() {
        SigningPerformanceBenchmark.CapacityArtifact artifact = capacityArtifact(
                capacityEvidence(10, Long.MAX_VALUE, 1L, 1_000L));

        assertEquals("FAILED", artifact.state());
        assertTrue(artifact.reasons().contains("CAPACITY_STEADY_RESERVATION_OVERFLOW"));
    }

    @Test
    void retainedCapacityArtifactAcceptsConfiguredOneGiBDiagnosticBudget() {
        long diagnosticBudget = 1024L * 1024L * 1024L;
        SigningPerformanceBenchmark.CapacityArtifact artifact = capacityArtifact(
                capacityEvidence(10, 1_000L, 0L, 1_000L, diagnosticBudget),
                diagnosticBudget);

        assertEquals("VERIFIED", artifact.state());
        assertTrue(artifact.verified());
        assertTrue(artifact.reasons().isEmpty());
        assertEquals(diagnosticBudget,
                artifact.observation().orElseThrow().steadyMaximumBytes());
    }

    @Test
    void populationAccountingReportsFinalCurrentAndDiagnosticEventHighWater() {
        SigningPopulationPlan.Plan plan = new SigningPopulationPlan.Plan(
                SigningPopulationPlan.Mode.COMBINED_WORKLOAD, 7L, 3L, 2L, 4L, 1L, 20L, 18L);
        SigningPerformanceBenchmark.PopulationMetrics initial =
                SigningPerformanceBenchmark.PopulationMetrics.observed(plan,
                        new SigningPopulationFixture.Observation(7L, 3L, 3L, 1L, 14L, 3L, 3L));
        SigningPerformanceBenchmark.PopulationAccounting accounting =
                new SigningPerformanceBenchmark.PopulationAccounting(initial);

        for (int index = 0; index < 4; index++) {
            accounting.ownerAdmitted();
            accounting.ownerRetired();
        }
        SigningPerformanceBenchmark.PopulationMetrics observed = accounting.finish();

        assertEquals(18L, observed.observedBenchmarkCurrentRecords());
        assertEquals(19L, observed.accountedEventHighWaterRecords());
        assertEquals(20L, observed.plannedMaximumCurrentRecords());
        assertEquals(18L, observed.plannedDrainedCurrentRecords());
        assertEquals(4L, observed.observedOwnerAdmissions());
        assertEquals(4L, observed.observedOwnerRetirements());
    }

    @Test
    void reorderedAccountingEventsDoNotTurnDiagnosticHighWaterIntoCapacityVerdict() {
        SigningPopulationPlan.Plan plan = new SigningPopulationPlan.Plan(
                SigningPopulationPlan.Mode.COMBINED_WORKLOAD, 7L, 3L, 2L, 4L, 1L, 20L, 18L);
        SigningPerformanceBenchmark.PopulationMetrics initial =
                SigningPerformanceBenchmark.PopulationMetrics.observed(plan,
                        new SigningPopulationFixture.Observation(7L, 3L, 3L, 1L, 14L, 3L, 3L));
        SigningPerformanceBenchmark.PopulationAccounting sequential =
                new SigningPerformanceBenchmark.PopulationAccounting(initial);
        SigningPerformanceBenchmark.PopulationAccounting reordered =
                new SigningPerformanceBenchmark.PopulationAccounting(initial);

        for (int index = 0; index < 4; index++) {
            sequential.ownerAdmitted();
            sequential.ownerRetired();
            reordered.ownerAdmitted();
        }
        for (int index = 0; index < 4; index++) {
            reordered.ownerRetired();
        }
        SigningPerformanceBenchmark.PopulationMetrics sequentialObserved = sequential.finish();
        SigningPerformanceBenchmark.PopulationMetrics reorderedObserved = reordered.finish();

        assertEquals(18L, sequentialObserved.observedBenchmarkCurrentRecords());
        assertEquals(18L, reorderedObserved.observedBenchmarkCurrentRecords());
        assertEquals(19L, sequentialObserved.accountedEventHighWaterRecords());
        assertEquals(22L, reorderedObserved.accountedEventHighWaterRecords());
        assertTrue(reorderedObserved.accountedEventHighWaterRecords()
                > reorderedObserved.plannedMaximumCurrentRecords());
    }

    @Test
    void populationAccountingFailsClosedOnOwnerRetirementMismatch() {
        SigningPopulationPlan.Plan plan = new SigningPopulationPlan.Plan(
                SigningPopulationPlan.Mode.COMBINED_WORKLOAD, 7L, 3L, 1L, 1L, 1L, 16L, 15L);
        SigningPerformanceBenchmark.PopulationAccounting accounting =
                new SigningPerformanceBenchmark.PopulationAccounting(
                        SigningPerformanceBenchmark.PopulationMetrics.observed(plan,
                                new SigningPopulationFixture.Observation(
                                        7L, 3L, 3L, 1L, 14L, 3L, 3L)));

        assertThrows(IllegalStateException.class, accounting::ownerRetired);
    }

    @Test
    void cleanupOutcomeGatesAcceptanceUntilSuccessfulCleanup() {
        SigningPerformanceBenchmark.AcceptanceAssessment passing =
                new SigningPerformanceBenchmark.AcceptanceAssessment(true, true, List.of());

        SigningPerformanceBenchmark.AcceptanceAssessment pending =
                new SigningPerformanceBenchmark.CleanupOutcome("PENDING", java.util.Optional.empty())
                        .gate(passing);
        SigningPerformanceBenchmark.AcceptanceAssessment failed =
                new SigningPerformanceBenchmark.CleanupOutcome("FAILED",
                        java.util.Optional.of("WORK_ROOT_DELETE_FAILED")).gate(passing);
        SigningPerformanceBenchmark.AcceptanceAssessment succeeded =
                new SigningPerformanceBenchmark.CleanupOutcome("SUCCEEDED", java.util.Optional.empty())
                        .gate(passing);

        assertFalse(pending.evaluable());
        assertFalse(pending.targetMet());
        assertEquals(List.of("CLEANUP_PENDING"), pending.reasons());
        assertFalse(failed.evaluable());
        assertFalse(failed.targetMet());
        assertEquals(List.of("CLEANUP_FAILED"), failed.reasons());
        assertTrue(succeeded.evaluable());
        assertTrue(succeeded.targetMet());
        assertTrue(succeeded.reasons().isEmpty());
    }

    @Test
    void unsupportedGroup64RejectsBeforePreflightOrWorkRootMutation(@TempDir Path temporary) {
        Path workRoot = temporary.resolve("must-not-exist");
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--groupSize=64",
                "--cellId=m1000000-w100000-l16-g64", "--workRoot=" + workRoot
        });

        SigningBenchmarkGrid.ContractException failure = assertThrows(
                SigningBenchmarkGrid.ContractException.class,
                () -> SigningPerformanceBenchmark.run(configuration, unverifiedEnvironment()));

        assertEquals("UNSUPPORTED_MAX_32", failure.reasonCode());
        assertEquals("signing benchmark contract rejected: code=UNSUPPORTED_MAX_32",
                failure.getMessage());
        assertFalse(Files.exists(workRoot));
    }

    @Test
    void unsafeExecutionEnvelopeRejectsBeforePreflightOrWorkRootMutation(@TempDir Path temporary) {
        List<String> unsafeOverrides = List.of(
                "--lanes=33",
                "--queueCapacity=" + Integer.MAX_VALUE,
                "--rate=1101",
                "--warmupSeconds=31",
                "--durationSeconds=301",
                "--drainSeconds=121");

        for (int index = 0; index < unsafeOverrides.size(); index++) {
            Path workRoot = temporary.resolve("unsafe-" + index);
            SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                    "--profile=diagnostic", unsafeOverrides.get(index), "--workRoot=" + workRoot
            });

            SigningBenchmarkGrid.ContractException failure = assertThrows(
                    SigningBenchmarkGrid.ContractException.class,
                    () -> SigningPerformanceBenchmark.run(configuration));

            assertEquals("EXECUTION_ENVELOPE_EXCEEDED", failure.reasonCode());
            assertFalse(Files.exists(workRoot));
        }
    }

    @Test
    void acceptanceRejectsLegacyTargetBeforePreflightOrWorkRootMutation(@TempDir Path temporary) {
        Path workRoot = temporary.resolve("must-not-exist");
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--target=legacy-filesystem-diagnostic", "--workRoot=" + workRoot
        });

        SigningBenchmarkGrid.ContractException failure = assertThrows(
                SigningBenchmarkGrid.ContractException.class,
                () -> SigningPerformanceBenchmark.run(configuration));

        assertEquals("PROFILE_TARGET_MISMATCH", failure.reasonCode());
        assertFalse(Files.exists(workRoot));
    }

    @Test
    void nonReferencePreflightWarnsButProceedsAsDiagnostic() {
        // Reference-environment mismatches are advisory warnings: the benchmark still
        // runs and measures throughput, but the result is diagnostic-only and never
        // evaluable, whether or not the diagnostic environment override is set.
        SigningBenchmarkConfig plain = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance"
        });
        SigningPerformanceBenchmark.PreflightAssessment plainPreflight =
                SigningPerformanceBenchmark.PreflightAssessment.assess(plain, unverifiedEnvironment());
        assertTrue(plainPreflight.proceed());
        assertTrue(plainPreflight.diagnosticOnly());
        assertFalse(plainPreflight.mismatchReasons().isEmpty());
        assertTrue(plainPreflight.mismatchReasons().stream().anyMatch(reason -> reason.contains("Java feature")));
        assertTrue(plainPreflight.mismatchReasons().stream().anyMatch(reason -> reason.contains("local NVMe")));

        SigningBenchmarkConfig overridden = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--diagnosticEnvironmentOverride=true"
        });
        SigningPerformanceBenchmark.PreflightAssessment overriddenPreflight =
                SigningPerformanceBenchmark.PreflightAssessment.assess(overridden, unverifiedEnvironment());
        assertTrue(overriddenPreflight.proceed());
        assertTrue(overriddenPreflight.diagnosticOnly());
        assertFalse(overriddenPreflight.mismatchReasons().isEmpty());

        SigningPerformanceBenchmark.AcceptanceAssessment diagnosticAssessment =
                idealAssessment(overridden, unverifiedEnvironment());
        assertFalse(diagnosticAssessment.evaluable());
        assertFalse(diagnosticAssessment.targetMet());
        assertTrue(diagnosticAssessment.reasons().stream().anyMatch(reason -> reason.contains("Java feature")));
        assertTrue(diagnosticAssessment.reasons().stream().anyMatch(reason -> reason.contains("local NVMe")));
    }

    @Test
    void latencyReservoirIsBoundedAndRetainsObservationCount() {
        BoundedLatencySamples samples = new BoundedLatencySamples(4, 42L);
        for (long value = 1L; value <= 100L; value++) {
            samples.add(value);
        }

        BoundedLatencySamples.Summary summary = samples.summarize();

        assertEquals(100L, summary.observations());
        assertEquals(4, summary.samples());
        assertEquals(100L, summary.maxNanos());
    }

    @Test
    void exactApprovedFingerprintCanEvaluateAnIdealFixedWindowResult(@TempDir Path temporary) {
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--workRoot=" + temporary.resolve("work")
        });

        SigningPerformanceBenchmark.AcceptanceAssessment assessment =
                SigningPerformanceBenchmark.AcceptanceAssessment.assess(configuration, approvedEnvironment(),
                        330_000L, 330_000L, 330_000L, 0L, 330_000L, 300_001L, 0L, 0L, 1_000.003,
                        99_999_999L, 0);

        assertTrue(assessment.evaluable());
        assertTrue(assessment.targetMet());
        assertTrue(assessment.reasons().isEmpty());
        assertEquals(SigningBenchmarkGrid.ANCHOR_ID, configuration.cellId());
        assertEquals(SigningBenchmarkConfig.CellMode.GRID, configuration.cellMode());
        assertEquals(1_000_000, configuration.retainedPopulation());
        assertEquals(100_000, configuration.activePopulation());
        assertEquals(32, configuration.groupSize());
        assertEquals(512L * 1024L * 1024L, configuration.residentIndexBudgetBytes());
        assertEquals(512L * 1024L * 1024L, configuration.compactionTransientBudgetBytes());
        assertEquals(0, configuration.providerMeanMillis());
        assertEquals(0, configuration.providerJitterMillis());
    }

    @Test
    void nonDefaultResidentIndexBudgetIsDiagnosticOnlyAndFingerprintBound(@TempDir Path temporary) {
        SigningBenchmarkConfig defaults = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--workRoot=" + temporary.resolve("default")
        });
        SigningBenchmarkConfig overridden = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--residentIndexBudgetBytes=1073741824",
                "--workRoot=" + temporary.resolve("overridden")
        });

        SigningPerformanceBenchmark.AcceptanceAssessment assessment =
                idealAssessment(overridden, approvedEnvironment());
        assertFalse(assessment.evaluable());
        assertFalse(assessment.targetMet());
        assertTrue(assessment.reasons().contains(
                "approved profile mismatch: residentIndexBudgetBytes"));
        assertFalse(defaults.argumentsFingerprint().equals(overridden.argumentsFingerprint()));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--residentIndexBudgetBytes=0"
        }));
    }

    @Test
    void nonDefaultCompactionTransientBudgetIsDiagnosticOnlyAndFingerprintBound(@TempDir Path temporary) {
        String workRoot = "--workRoot=" + temporary.resolve("work");
        SigningBenchmarkConfig defaults = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", workRoot
        });
        SigningBenchmarkConfig overridden = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--compactionTransientBudgetBytes=1073741824", workRoot
        });

        SigningPerformanceBenchmark.AcceptanceAssessment assessment =
                idealAssessment(overridden, approvedEnvironment());
        assertFalse(assessment.evaluable());
        assertTrue(assessment.reasons().contains(
                "approved profile mismatch: compactionTransientBudgetBytes"));
        assertFalse(defaults.argumentsFingerprint().equals(overridden.argumentsFingerprint()));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--compactionTransientBudgetBytes=0"
        }));
        assertThrows(IllegalArgumentException.class, () -> SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--residentIndexBudgetBytes=" + Long.MAX_VALUE,
                "--compactionTransientBudgetBytes=1"
        }));
    }

    @Test
    void acceptanceOverrideAndLegacyTargetAreNeverEvaluable(@TempDir Path temporary) {
        SigningBenchmarkConfig overridden = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--rate=1200", "--workRoot=" + temporary.resolve("override")
        });
        SigningBenchmarkConfig legacy = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--target=legacy-filesystem-diagnostic",
                "--workRoot=" + temporary.resolve("legacy")
        });

        SigningPerformanceBenchmark.AcceptanceAssessment overrideAssessment =
                SigningPerformanceBenchmark.AcceptanceAssessment.assess(overridden, approvedEnvironment(),
                        360_000L, 360_000L, 360_000L, 0L, 360_000L, 300_001L, 0L, 0L, 1_000.003,
                        99_999_999L, 0);
        SigningPerformanceBenchmark.AcceptanceAssessment legacyAssessment =
                SigningPerformanceBenchmark.AcceptanceAssessment.assess(legacy, approvedEnvironment(),
                        330_000L, 330_000L, 330_000L, 0L, 330_000L, 300_001L, 0L, 0L, 1_000.003,
                        99_999_999L, 0);

        assertFalse(overrideAssessment.evaluable());
        assertFalse(overrideAssessment.targetMet());
        assertFalse(legacyAssessment.evaluable());
        assertFalse(legacyAssessment.targetMet());
    }

    @Test
    void combinedAnchorHasCheckedPlanBeforeWorkMutation(@TempDir Path temporary) {
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--workRoot=" + temporary.resolve("must-not-exist")
        });

        SigningPopulationPlan.Plan plan = SigningPopulationPlan.forCell(
                SigningBenchmarkGrid.cells().getFirst(), configuration);

        assertEquals(0L, plan.activePreload());
        assertFalse(Files.exists(configuration.workRoot()));
    }

    @Test
    void absoluteArrivalScheduleNeverDependsOnCompletionTime() {
        long start = 17L;

        assertEquals(start, SigningPerformanceBenchmark.scheduledTime(start, 0L, 3));
        assertEquals(start + 333_333_333L, SigningPerformanceBenchmark.scheduledTime(start, 1L, 3));
        assertEquals(start + 1_000_000_000L, SigningPerformanceBenchmark.scheduledTime(start, 3L, 3));
        assertEquals(start + 1_666_666_666L, SigningPerformanceBenchmark.scheduledTime(start, 5L, 3));
    }

    @Test
    void inferredNativeAtomicCommitsRequireExactAcceptedInvocationIdentity() {
        assertEquals(1L, SigningPerformanceBenchmark.inferNativeAtomicCommits(1L, 1L));
        assertEquals(2L, SigningPerformanceBenchmark.inferNativeAtomicCommits(2L, 2L));
        assertEquals(3L, SigningPerformanceBenchmark.inferNativeAtomicCommits(3L, 3L));
        assertThrows(IllegalStateException.class,
                () -> SigningPerformanceBenchmark.inferNativeAtomicCommits(2L, 1L));
    }

    @Test
    void deterministicClockAndParkSeamStopsExactlyAtAbsoluteDeadline() {
        AtomicLong now = new AtomicLong(7L);
        List<Long> parks = new ArrayList<>();

        SigningPerformanceBenchmark.parkUntil(31L, now::get, nanos -> {
            parks.add(nanos);
            now.addAndGet(nanos);
        });

        assertEquals(List.of(24L), parks);
        assertEquals(31L, now.get());
    }

    @Test
    void nativeWorkflowMultiplexerBoundsResidentContextsAndUsesDueOrder() throws Exception {
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        List<Long> executionOrder = new ArrayList<>();
        NativeWorkflowMultiplexer.WorkflowContext first =
                new NativeWorkflowMultiplexer.WorkflowContext(0L, 0L, true);
        NativeWorkflowMultiplexer.WorkflowContext later =
                new NativeWorkflowMultiplexer.WorkflowContext(1L, 0L, true);
        NativeWorkflowMultiplexer.WorkflowContext earlier =
                new NativeWorkflowMultiplexer.WorkflowContext(2L, 0L, true);

        try (NativeWorkflowMultiplexer multiplexer = new NativeWorkflowMultiplexer(3, 1, context -> {
            executionOrder.add(context.sequence());
            if (context.sequence() == 0L) {
                firstStarted.countDown();
                releaseFirst.await();
            }
            return NativeWorkflowMultiplexer.StepResult.completed();
        })) {
            assertTrue(multiplexer.trySubmit(first, 0L));
            assertTrue(firstStarted.await(5L, TimeUnit.SECONDS));
            assertTrue(multiplexer.trySubmit(later, 0L));
            assertTrue(multiplexer.trySubmit(earlier, -1L));
            assertFalse(multiplexer.trySubmit(
                    new NativeWorkflowMultiplexer.WorkflowContext(3L, 0L, true), -2L));
            assertEquals(3, multiplexer.awaitIdleOrRemaining(0L, TimeUnit.NANOSECONDS));
            assertEquals(3, multiplexer.peakResidentContexts());
            assertThrows(IllegalStateException.class, multiplexer::resetPeakResidentContextsWhenIdle);
            releaseFirst.countDown();

            assertTrue(multiplexer.awaitIdle(5L, TimeUnit.SECONDS));
            assertEquals(3, multiplexer.peakResidentContexts());
            multiplexer.resetPeakResidentContextsWhenIdle();
            assertEquals(0, multiplexer.peakResidentContexts());
            assertEquals(List.of(0L, 2L, 1L), executionOrder);
            assertEquals(NativeWorkflowMultiplexer.WorkflowState.DONE, first.state());
            assertEquals(NativeWorkflowMultiplexer.WorkflowState.DONE, earlier.state());
            assertEquals(NativeWorkflowMultiplexer.WorkflowState.DONE, later.state());
        }
    }

    @Test
    void nativeWorkflowMultiplexerRequeuesOnlyTheCompletedShortStep() throws Exception {
        AtomicLong invocations = new AtomicLong();
        List<NativeWorkflowMultiplexer.WorkflowState> observedStates = new ArrayList<>();
        NativeWorkflowMultiplexer.WorkflowContext context =
                new NativeWorkflowMultiplexer.WorkflowContext(7L, 11L, false);

        try (NativeWorkflowMultiplexer multiplexer = new NativeWorkflowMultiplexer(1, 1, current -> {
            observedStates.add(current.state());
            if (invocations.incrementAndGet() == 1L) {
                return NativeWorkflowMultiplexer.StepResult.requeue(
                        NativeWorkflowMultiplexer.WorkflowState.OBSERVE, 0L);
            }
            return NativeWorkflowMultiplexer.StepResult.completed();
        })) {
            assertTrue(multiplexer.trySubmit(context, 0L));
            assertTrue(multiplexer.awaitIdle(5L, TimeUnit.SECONDS));
        }

        assertEquals(List.of(NativeWorkflowMultiplexer.WorkflowState.SUBMIT,
                NativeWorkflowMultiplexer.WorkflowState.OBSERVE), observedStates);
        assertEquals(7L, context.sequence());
        assertEquals(11L, context.scheduledNanos());
        assertFalse(context.measured());
        assertEquals(NativeWorkflowMultiplexer.WorkflowState.DONE, context.state());
    }

    @Test
    void nativeWorkflowMultiplexerCloseInterruptsAndJoinsAnOwnedStep() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch neverReleased = new CountDownLatch(1);
        AtomicBoolean interrupted = new AtomicBoolean();
        NativeWorkflowMultiplexer.WorkflowContext context =
                new NativeWorkflowMultiplexer.WorkflowContext(9L, 0L, true);
        NativeWorkflowMultiplexer multiplexer = new NativeWorkflowMultiplexer(1, 1, current -> {
            started.countDown();
            try {
                neverReleased.await();
            } catch (InterruptedException problem) {
                interrupted.set(true);
                throw problem;
            }
            return NativeWorkflowMultiplexer.StepResult.completed();
        });
        try {
            assertTrue(multiplexer.trySubmit(context, 0L));
            assertTrue(started.await(5L, TimeUnit.SECONDS));
        } finally {
            multiplexer.close();
        }

        assertTrue(interrupted.get());
        assertEquals(NativeWorkflowMultiplexer.WorkflowState.DONE, context.state());
    }

    @Test
    void nativeWorkflowMultiplexerReportsTheFirstWorkerFailure() throws Exception {
        IllegalStateException injected = new IllegalStateException("injected step failure");
        NativeWorkflowMultiplexer multiplexer = new NativeWorkflowMultiplexer(1, 1, context -> {
            throw injected;
        });
        IllegalStateException awaitFailure;
        IllegalStateException closeFailure;
        try {
            assertTrue(multiplexer.trySubmit(
                    new NativeWorkflowMultiplexer.WorkflowContext(13L, 0L, true), 0L));
            awaitFailure = assertThrows(IllegalStateException.class,
                    () -> multiplexer.awaitIdle(5L, TimeUnit.SECONDS));
        } finally {
            closeFailure = assertThrows(IllegalStateException.class, multiplexer::close);
        }

        assertEquals(injected, awaitFailure.getCause());
        assertEquals(injected, closeFailure.getCause());
    }

    @Test
    void nativeWorkflowMultiplexerValidatesExactWorkerAndContextBounds() {
        assertThrows(IllegalArgumentException.class,
                () -> new NativeWorkflowMultiplexer(0, 1,
                        context -> NativeWorkflowMultiplexer.StepResult.completed()));
        assertThrows(IllegalArgumentException.class,
                () -> new NativeWorkflowMultiplexer(2, 0,
                        context -> NativeWorkflowMultiplexer.StepResult.completed()));
        assertThrows(IllegalArgumentException.class,
                () -> new NativeWorkflowMultiplexer(2, 3,
                        context -> NativeWorkflowMultiplexer.StepResult.completed()));
    }

    @Test
    void nativeWorkflowContextTracksStableInvocationAndOneStepSignatureOwnership() {
        NativeWorkflowMultiplexer.WorkflowContext context =
                new NativeWorkflowMultiplexer.WorkflowContext(17L, 19L, true);
        PkiId operationId = new PkiId("benchmark-operation");

        assertThrows(IllegalStateException.class, context::operationId);
        assertThrows(IllegalStateException.class, context::markSubmissionInvoked);
        context.assignOperationId(operationId);
        context.markSubmissionInvoked();
        assertEquals(operationId, context.operationId());
        assertTrue(context.submissionInvoked());
        assertThrows(IllegalStateException.class, () -> context.assignOperationId(operationId));
        assertThrows(IllegalStateException.class, context::markSubmissionInvoked);
        assertFalse(context.acceptanceConfirmed());
        context.recordAdmission(true);
        assertTrue(context.admittedWithinWindow());
        assertTrue(context.confirmAcceptance());
        assertFalse(context.confirmAcceptance());
        assertTrue(context.acceptanceConfirmed());
        assertThrows(IllegalStateException.class, context::rollbackUnconfirmedAdmission);
        assertTrue(context.recordPostAcceptFailure());
        assertFalse(context.recordPostAcceptFailure());

        byte[] expectedSignature = new byte[] { 1, 2, 3 };
        context.takeOwnershipOfExpectedSignature(expectedSignature, 23L);
        assertEquals(23L, context.terminalNanos());
        assertArrayEquals(expectedSignature, context.takeExpectedSignature());
        assertThrows(IllegalStateException.class, context::takeExpectedSignature);
    }

    @Test
    void nativeWorkflowContextRollsBackOnlyAnUnconfirmedAdmissionOnce() {
        NativeWorkflowMultiplexer.WorkflowContext context =
                new NativeWorkflowMultiplexer.WorkflowContext(29L, 31L, false);

        assertFalse(context.rollbackUnconfirmedAdmission());
        context.recordAdmission(false);
        assertFalse(context.admittedWithinWindow());
        assertTrue(context.rollbackUnconfirmedAdmission());
        assertFalse(context.rollbackUnconfirmedAdmission());
        assertFalse(context.acceptanceConfirmed());
        assertThrows(IllegalStateException.class, () -> context.recordAdmission(false));
        assertThrows(IllegalStateException.class, context::confirmAcceptance);
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 8, 32 })
    void nativeDiagnosticRunsExactAuthoritativeLifecycleAndNeverEvaluatesAcceptance(
            int groupSize, @TempDir Path temporary) throws Exception {
        SigningBenchmarkConfig configuration = SigningBenchmarkConfig.parse(new String[] {
                "--profile=native-diagnostic", "--diagnosticEnvironmentOverride=true",
                "--groupSize=" + groupSize,
                "--cellId=native-diagnostic-m1000-w10-l16-g" + groupSize,
                "--warmupSeconds=1", "--durationSeconds=1", "--rate=2", "--drainSeconds=30",
                "--workRoot=" + temporary.resolve("work-" + groupSize),
                "--output=" + temporary.resolve("result-" + groupSize + ".json")
        });

        SigningPerformanceBenchmark.Result result = SigningPerformanceBenchmark.run(
                configuration, unverifiedEnvironment());

        assertEquals(2L, result.scheduled());
        assertEquals(2L, result.workflowContextsAdmitted());
        assertEquals(2L, result.admitted());
        assertEquals(2L, result.accepted());
        assertEquals(2L, result.completed());
        assertEquals(2L, result.retired());
        assertEquals(2L, result.terminalWithinWindow());
        assertEquals(0L, result.terminalAfterWindow());
        assertEquals(2L, result.provider().providerCalls());
        assertEquals(2L, result.provider().inferredSharedLocalAtomicCommits());
        assertTrue(result.provider().sharedWriterEvidence());
        assertTrue(result.provider().wholeRunMaximumBatchSize() > 0L);
        assertTrue(result.provider().wholeRunMaximumBatchSize() <= groupSize);
        assertEquals(0L, result.rejected());
        assertEquals(0L, result.contextCapacityRejected());
        assertEquals(10, result.contextCapacity());
        assertEquals(10, result.stepWorkers());
        assertTrue(result.workflowTransitionsExecuted() >= 8L);
        assertTrue(result.observationAttempts() >= result.accepted());
        assertTrue(result.peakResidentContexts() >= 1L);
        assertTrue(result.peakResidentContexts() <= result.contextCapacity());
        assertEquals(0L, result.failed());
        assertEquals(0L, result.uncertain());
        assertFalse(result.acceptance().evaluable());
        assertFalse(result.acceptance().targetMet());
        assertTrue(result.acceptance().reasons().contains("native diagnostic mode cannot satisfy acceptance"));
        assertTrue(result.toJson().contains(
                "\"requestsCommitted\":" + result.provider().requestsCommitted()));
        assertTrue(result.toJson().contains("\"residentIndexCapacity\""));
        assertTrue(result.toJson().contains("\"steady\":{"));
        assertTrue(result.toJson().contains("\"transient\":{"));
        assertTrue(result.toJson().contains("\"combined\":{"));
        assertEquals(configuration.residentIndexBudgetBytes(),
                result.indexCapacity().steady().maximumBytes());
        assertEquals(configuration.compactionTransientBudgetBytes(),
                result.indexCapacity().transientBudget().maximumBytes());
        assertEquals(Math.addExact(configuration.residentIndexBudgetBytes(),
                configuration.compactionTransientBudgetBytes()),
                result.indexCapacity().combined().maximumBytes());
        assertTrue(result.indexCapacity().steady().currentReservedBytes()
                <= result.indexCapacity().steady().highWaterReservedBytes());
        assertFalse(result.toJson().contains("\"writes\""));
        assertEquals("SUCCEEDED", result.cleanup().state());
    }

    @Test
    void unverifiedReferenceEnvironmentAndDiagnosticOverrideFailClosed(@TempDir Path temporary) {
        SigningBenchmarkConfig unverified = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--workRoot=" + temporary.resolve("unverified")
        });
        SigningBenchmarkConfig overridden = SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--diagnosticEnvironmentOverride=true",
                "--workRoot=" + temporary.resolve("override")
        });

        SigningPerformanceBenchmark.AcceptanceAssessment environmentAssessment = idealAssessment(unverified,
                unverifiedEnvironment());
        SigningPerformanceBenchmark.AcceptanceAssessment overrideAssessment = idealAssessment(overridden,
                approvedEnvironment());

        assertFalse(environmentAssessment.evaluable());
        assertFalse(environmentAssessment.targetMet());
        assertTrue(environmentAssessment.reasons().stream().anyMatch(reason -> reason.contains("Java feature")));
        assertTrue(environmentAssessment.reasons().stream().anyMatch(reason -> reason.contains("local NVMe")));
        assertFalse(overrideAssessment.evaluable());
        assertFalse(overrideAssessment.targetMet());
        assertTrue(overrideAssessment.reasons().stream()
                .anyMatch(reason -> reason.contains("diagnostic environment override")));
    }

    @Test
    void deadlineBacklogIncludesAdmittedWorkBeforeDurableAcceptance() {
        assertEquals(80L, SigningPerformanceBenchmark.backlogAtDeadline(96L, 16L));
        assertThrows(IllegalArgumentException.class,
                () -> SigningPerformanceBenchmark.backlogAtDeadline(16L, 17L));
    }

    @Test
    void failedAuthoritativeTerminalUsesObservationTimeForDeadlineAndBacklog() {
        assertEquals(SigningPerformanceBenchmark.TerminalWindow.WITHIN,
                SigningPerformanceBenchmark.terminalWindow(AsyncState.FAILED, 99L, 100L));
        assertEquals(SigningPerformanceBenchmark.TerminalWindow.WITHIN,
                SigningPerformanceBenchmark.terminalWindow(AsyncState.FAILED, 100L, 100L));
        assertEquals(SigningPerformanceBenchmark.TerminalWindow.AFTER,
                SigningPerformanceBenchmark.terminalWindow(AsyncState.FAILED, 101L, 100L));
        assertEquals(1L, SigningPerformanceBenchmark.backlogAtDeadline(2L, 1L));
    }

    private static SigningPerformanceBenchmark.AcceptanceAssessment idealAssessment(
            SigningBenchmarkConfig configuration, SigningPerformanceBenchmark.Environment environment) {
        return SigningPerformanceBenchmark.AcceptanceAssessment.assess(configuration, environment,
                330_000L, 330_000L, 330_000L, 0L, 330_000L, 300_001L, 0L, 0L, 1_000.003,
                99_999_999L, 0);
    }

    private static SigningPerformanceBenchmark.CapacityArtifact capacityArtifact(
            SigningPopulationFixture.CapacityEvidence capacity) {
        return capacityArtifact(capacity,
                SigningBenchmarkConfig.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
    }

    private static SigningPerformanceBenchmark.CapacityArtifact capacityArtifact(
            SigningPopulationFixture.CapacityEvidence capacity, long expectedResidentIndexBudgetBytes) {
        SigningPopulationPlan.Plan plan = new SigningPopulationPlan.Plan(
                SigningPopulationPlan.Mode.RETAINED_ONLY, 9L, 0L, 0L, 0L, 1L, 10L, 10L);
        SigningPopulationFixture.Artifact source = new SigningPopulationFixture.Artifact(
                new SigningPopulationFixture.Observation(9L, 0L, 0L, 1L, 10L, 0L, 0L),
                capacity, new SigningPopulationFixture.QuiescentJvm(1L, -1L, 0L, 0L));
        return SigningPerformanceBenchmark.CapacityArtifact.assess(
                plan, source, expectedResidentIndexBudgetBytes,
                SigningBenchmarkConfig.DEFAULT_COMPACTION_TRANSIENT_BUDGET_BYTES);
    }

    private static SigningPopulationFixture.CapacityEvidence capacityEvidence(
            int currentKeys, long mvccReservedBytes, long dueReservedBytes, long steadyReservedBytes) {
        return capacityEvidence(currentKeys, mvccReservedBytes, dueReservedBytes,
                steadyReservedBytes, SigningBenchmarkConfig.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES);
    }

    private static SigningPopulationFixture.CapacityEvidence capacityEvidence(
            int currentKeys, long mvccReservedBytes, long dueReservedBytes,
            long steadyReservedBytes, long maximumBytes) {
        long transientMaximum = SigningBenchmarkConfig.DEFAULT_COMPACTION_TRANSIENT_BUDGET_BYTES;
        return new SigningPopulationFixture.CapacityEvidence(
                currentKeys, 0, currentKeys * 10L, mvccReservedBytes, mvccReservedBytes,
                0, 0L, dueReservedBytes, dueReservedBytes, 0, 0L,
                0, 0L, 0L, 0L, 0, 0L,
                1, 1, 0, 0, 0, currentKeys, 0L,
                steadyReservedBytes, steadyReservedBytes, maximumBytes,
                0L, 0L, transientMaximum,
                steadyReservedBytes, steadyReservedBytes,
                Math.addExact(maximumBytes, transientMaximum));
    }

    private static SigningBenchmarkConfig gridConfiguration(SigningBenchmarkGrid.Cell cell) {
        return SigningBenchmarkConfig.parse(new String[] {
                "--profile=acceptance", "--cellId=" + cell.id(),
                "--retainedPopulation=" + cell.retainedPopulation(),
                "--activePopulation=" + cell.activePopulation(),
                "--lanes=" + cell.lanes(), "--groupSize=" + cell.groupSize()
        });
    }

    private static SigningPerformanceBenchmark.Environment approvedEnvironment() {
        return new SigningPerformanceBenchmark.Environment("25.0.1", "Eclipse Adoptium", "OpenJDK 64-Bit VM",
                "Linux", "test", "amd64", " AMD  Ryzen-5 7600 / 6-Core Processor ", 12,
                4_294_967_296L, "G1 Young Generation,G1 Concurrent GC,G1 Old Generation", "-Xmx4g", "btrfs",
                1_000_000L, "/home", "/dev/mapper/reference", "rw,noatime,compress=zstd:3,ssd,discard=async",
                true, "verified local non-rotational NVMe leaves: nvme1n1p3", "unavailable: test",
                "unavailable: test", "test-host");
    }

    private static SigningPerformanceBenchmark.Environment unverifiedEnvironment() {
        return new SigningPerformanceBenchmark.Environment("unavailable", "unavailable", "unavailable",
                "Linux", "test", "amd64", "unavailable", 0, 4_294_967_296L, "unavailable", "-Xmx4g",
                "unavailable", 0L, "unavailable", "unavailable", "unavailable", false,
                "unavailable: block topology is incomplete", "unavailable: test", "unavailable: test",
                "test-host");
    }
}
