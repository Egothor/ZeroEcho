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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class SigningDueSelectionBenchmarkTest {

    @Test
    void fixedSelectionAxisIncludesRequired4096WithoutExecutingIt() {
        assertEquals(List.of(1, 64, 1_024, 4_096),
                SigningDueSelectionBenchmark.SELECTION_AXIS);
    }

    @Test
    void configurationIsStrictBoundedAndFingerprintIsStable(@TempDir Path temporary) {
        SigningDueSelectionBenchmark.Configuration configuration =
                SigningDueSelectionBenchmark.Configuration.parse(new String[] {
                    "--activePopulation=10", "--selectionBound=1",
                    "--subsequentInProcessSamples=4",
                    "--output=" + temporary.resolve("result.json"),
                    "--workRoot=" + temporary.resolve("work")
                });
        SigningDueSelectionBenchmark.Configuration repeated =
                SigningDueSelectionBenchmark.Configuration.parse(new String[] {
                    "--activePopulation=10", "--selectionBound=1",
                    "--subsequentInProcessSamples=4",
                    "--output=" + temporary.resolve("result.json"),
                    "--workRoot=" + temporary.resolve("work")
                });

        assertEquals(10, configuration.activePopulation());
        assertEquals(1, configuration.selectionBound());
        assertEquals(4, configuration.subsequentInProcessSamples());
        assertEquals(configuration.fingerprint(), repeated.fingerprint());
        assertEquals(64, configuration.fingerprint().length());
        assertEquals("SELECTION_BOUND_EXCEEDS_ELIGIBLE",
                rejected("--activePopulation=10", "--selectionBound=64"));
        assertEquals("SELECTION_BOUND_UNSUPPORTED",
                rejected("--activePopulation=10", "--selectionBound=2"));
        assertEquals("CONFIGURATION_INVALID",
                rejected("--activePopulation=0", "--selectionBound=1"));
        assertEquals("CONFIGURATION_INVALID",
                rejected("--activePopulation=10", "--selectionBound=1",
                        "--subsequentInProcessSamples=0"));
        assertEquals("CONFIGURATION_INVALID",
                rejected("--activePopulation=10", "--selectionBound=1",
                        "--subsequentInProcessSamples=4097"));
        assertEquals("CONFIGURATION_INVALID",
                rejected("--activePopulation=10", "--selectionBound=1", "--warmSamples=4"));
        assertEquals("CONFIGURATION_INVALID",
                rejected("--activePopulation=10", "--selectionBound=1", "--unknown=value"));
    }

    @Test
    void primitiveSubsequentSummaryUsesNearestRankPercentiles() {
        SigningDueSelectionBenchmark.SubsequentInProcessSummary summary =
                SigningDueSelectionBenchmark.SubsequentInProcessSummary.from(
                        new long[] { 100L, 1L, 80L, 2L, 60L, 3L, 40L, 4L, 20L, 5L });

        assertEquals(10, summary.count());
        assertEquals(5L, summary.p50Nanos());
        assertEquals(100L, summary.p95Nanos());
        assertEquals(100L, summary.p99Nanos());
        assertEquals(100L, summary.maxNanos());
    }

    @Test
    void schemaReportsExactConfigurationAndNoAcceptanceVerdict(@TempDir Path temporary) {
        SigningDueSelectionBenchmark.Configuration configuration =
                new SigningDueSelectionBenchmark.Configuration(10, 1, 4,
                        "0".repeat(64),
                        temporary.resolve("result.json"), temporary.resolve("work"));
        SigningDueSelectionBenchmark.Result result = new SigningDueSelectionBenchmark.Result(
                11L, new SigningDueSelectionBenchmark.SubsequentInProcessSummary(
                        4, 12L, 13L, 14L, 15L));

        String json = result.toJson(configuration);

        assertTrue(json.contains("\"schema\":\"zeroecho-signing-due-selection-v1\""));
        assertTrue(json.contains("\"activePopulationW\":10"));
        assertTrue(json.contains("\"eligibleCount\":10"));
        assertTrue(json.contains("\"selectionBoundD\":1"));
        assertTrue(json.contains("\"subsequentInProcessSamples\":4"));
        assertTrue(json.contains("\"firstInProcessNanos\":11"));
        assertTrue(json.contains("\"subsequentInProcessP50Nanos\":12"));
        assertTrue(json.contains("\"jitSteadyStateOrCacheGuarantee\":false"));
        assertTrue(json.contains("\"recordIoIncluded\":false"));
        assertTrue(json.contains("\"algorithmicWorkEvidence\":\"STATIC_COMPLEXITY_ONLY\""));
        assertTrue(json.contains("\"timeComplexity\":\"O(log W + D)\""));
        assertTrue(json.contains("\"selectionMemoryComplexity\":\"O(D)\""));
        assertFalse(json.contains("targetMet"));
        assertFalse(json.contains("threshold"));
        assertFalse(json.contains("warm"));
    }

    @Test
    void smallRealRecoveredLedgerReturnsExactDueSelection(@TempDir Path temporary)
            throws IOException {
        SigningDueSelectionBenchmark.Configuration configuration =
                new SigningDueSelectionBenchmark.Configuration(4, 1, 2,
                        "0".repeat(64),
                        temporary.resolve("result.json"), temporary.resolve("work"));

        SigningDueSelectionBenchmark.Result result = SigningDueSelectionBenchmark.run(configuration);

        assertTrue(result.firstInProcessNanos() >= 0L);
        assertEquals(2, result.subsequentInProcess().count());
        assertTrue(Files.exists(temporary.resolve("work")));
    }

    @Test
    void secondRunRejectsExistingRootBeforeMutationAndPreservesFirstArtifact(
            @TempDir Path temporary) throws IOException {
        Path workRoot = temporary.resolve("nested").resolve("work");
        SigningDueSelectionBenchmark.Configuration configuration =
                new SigningDueSelectionBenchmark.Configuration(4, 1, 1,
                        "0".repeat(64),
                        temporary.resolve("result.json"), workRoot);
        SigningDueSelectionBenchmark.run(configuration);
        Path manifest = new FsPaths(workRoot).transactionalMetadataRoot()
                .resolve(SigningLedgerRecovery.MANIFEST_FILE);
        byte[] before = Files.readAllBytes(manifest);

        SigningDueSelectionBenchmark.BenchmarkException second = assertThrows(
                SigningDueSelectionBenchmark.BenchmarkException.class,
                () -> SigningDueSelectionBenchmark.run(configuration));

        assertEquals("WORK_ROOT_NOT_FRESH", second.reasonCode());
        assertArrayEquals(before, Files.readAllBytes(manifest));
    }

    @Test
    void countMismatchAndFixtureFailureUseStableReasons(@TempDir Path temporary)
            throws IOException {
        SigningDueSelectionBenchmark.BenchmarkException mismatch = assertThrows(
                SigningDueSelectionBenchmark.BenchmarkException.class,
                () -> SigningDueSelectionBenchmark.verifyReturnedCount(4, 3));
        assertEquals("DUE_SELECTION_WRONG_COUNT", mismatch.reasonCode());

        Path regularFile = temporary.resolve("not-a-directory");
        Files.writeString(regularFile, "fixture-failure");
        SigningDueSelectionBenchmark.Configuration configuration =
                new SigningDueSelectionBenchmark.Configuration(4, 1, 1,
                        "0".repeat(64),
                        temporary.resolve("result.json"), regularFile.resolve("work"));
        SigningDueSelectionBenchmark.BenchmarkException fixture = assertThrows(
                SigningDueSelectionBenchmark.BenchmarkException.class,
                () -> SigningDueSelectionBenchmark.run(configuration));
        assertEquals("FIXTURE_RECOVERY_UNAVAILABLE_OR_INVALID", fixture.reasonCode());
    }

    private static String rejected(String... arguments) {
        SigningDueSelectionBenchmark.ContractException failure = assertThrows(
                SigningDueSelectionBenchmark.ContractException.class,
                () -> SigningDueSelectionBenchmark.Configuration.parse(arguments));
        return failure.reasonCode();
    }
}
