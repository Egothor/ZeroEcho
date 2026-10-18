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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class SigningDirectMaintenanceBenchmarkTest {

    @Test
    void strictConfigurationRejectsUnsupportedShapes(@TempDir Path temporary) {
        SigningDirectMaintenanceBenchmark.Configuration configuration =
                SigningDirectMaintenanceBenchmark.Configuration.parse(new String[] {
                    "--liveRecords=4", "--sourceGenerations=2", "--sealedSegments=1",
                    "--firstGenerationIdentity=10", "--checkpointIdentity=20",
                    "--nextActiveIdentity=21", "--output=" + temporary.resolve("result.json"),
                    "--workRoot=" + temporary.resolve("work")
                });

        assertEquals(4, configuration.liveRecords());
        assertEquals(2, configuration.sourceGenerations());
        assertEquals(1, configuration.sealedSegments());
        assertEquals(64, configuration.fingerprint().length());
        assertEquals("CONFIGURATION_INVALID", rejected(
                "--liveRecords=1", "--sourceGenerations=2", "--sealedSegments=1"));
        assertEquals("CONFIGURATION_INVALID", rejected(
                "--liveRecords=4", "--sourceGenerations=1", "--sealedSegments=1"));
        assertEquals("CONFIGURATION_INVALID", rejected(
                "--liveRecords=4", "--sourceGenerations=65", "--sealedSegments=1"));
        assertEquals("CONFIGURATION_INVALID", rejected(
                "--liveRecords=4", "--sourceGenerations=2", "--sealedSegments=0"));
        assertEquals("CONFIGURATION_INVALID", rejected(
                "--liveRecords=4", "--sourceGenerations=2", "--sealedSegments=1",
                "--checkpointIdentity=1"));
    }

    @Test
    void tinyRealMaintenanceMeasuresBoundaryAndZeroCopy(@TempDir Path temporary)
            throws IOException {
        SigningDirectMaintenanceBenchmark.Configuration configuration = configuration(
                temporary.resolve("work"), temporary.resolve("result.json"));
        LongSupplier clock = sequenceClock(100L, 150L, 220L);

        SigningDirectMaintenanceBenchmark.Result result =
                SigningDirectMaintenanceBenchmark.run(configuration, clock);

        assertEquals(50L, result.timings().rotationToBoundaryNanos());
        assertEquals(70L, result.timings().checkpointAfterBoundaryNanos());
        assertEquals(120L, result.timings().totalCompactionNanos());
        assertEquals(1, result.evidence().beforeManifest().sealedCount());
        assertEquals(0, result.evidence().afterManifest().sealedCount());
        assertTrue(result.evidence().afterManifest().checkpointName().isPresent());
        assertEquals(4, result.evidence().checkpointLiveRecords());
        assertEquals(2L, result.evidence().sourceChannelsOpened());
        assertEquals(2, result.evidence().reclaimedActions());
        assertEquals(4, result.evidence().reclaimedArtifacts());
    }

    @Test
    void schemaUsesExactTimingNamesAndTruthfulDirectScope(@TempDir Path temporary)
            throws IOException {
        SigningDirectMaintenanceBenchmark.Result result = SigningDirectMaintenanceBenchmark.run(
                configuration(temporary.resolve("work"), temporary.resolve("result.json")),
                sequenceClock(10L, 20L, 40L));

        String json = result.toJson(configuration(
                temporary.resolve("unused"), temporary.resolve("result.json")));

        assertTrue(json.contains("\"schema\":\"zeroecho-signing-direct-maintenance-v1\""));
        assertTrue(json.contains("\"rotationToBoundaryNanos\":10"));
        assertTrue(json.contains("\"checkpointAfterBoundaryNanos\":20"));
        assertTrue(json.contains("\"totalCompactionNanos\":30"));
        assertTrue(json.contains("\"directMaintenanceCharacterization\":true"));
        assertTrue(json.contains("\"automaticEngineAdmissionContentionMeasured\":false"));
        assertTrue(json.contains("\"rotationPublicationMode\":\"HARD_LINK\""));
        assertTrue(json.contains("\"zeroCopyEvidence\":\"STATIC_CODE_PATH\""));
        assertTrue(json.contains("\"timeComplexity\":\"O(L + B_live + S)\""));
        assertTrue(json.contains("\"auxiliaryMemory\":"
                + "\"O(L + B_batch + S), B_batch<=67108864 bytes, S<=64\""));
        assertFalse(json.contains("admissionPause"));
        assertFalse(json.contains("targetMet"));
        assertFalse(json.contains("threshold"));
    }

    @Test
    void existingRootFailsBeforeMutationAndPreservesArtifact(@TempDir Path temporary)
            throws IOException {
        Path workRoot = temporary.resolve("nested").resolve("work");
        SigningDirectMaintenanceBenchmark.Configuration configuration = configuration(
                workRoot, temporary.resolve("result.json"));
        SigningDirectMaintenanceBenchmark.run(configuration, sequenceClock(1L, 2L, 3L));
        Path manifest = workRoot.resolve(SigningLedgerRecovery.MANIFEST_FILE);
        byte[] before = Files.readAllBytes(manifest);

        SigningDirectMaintenanceBenchmark.BenchmarkException failure = assertThrows(
                SigningDirectMaintenanceBenchmark.BenchmarkException.class,
                () -> SigningDirectMaintenanceBenchmark.run(configuration,
                        sequenceClock(4L, 5L, 6L)));

        assertEquals("WORK_ROOT_NOT_FRESH", failure.reasonCode());
        assertArrayEquals(before, Files.readAllBytes(manifest));
    }

    @Test
    void outputInsideWorkRootIsRejectedBeforeMutation(@TempDir Path temporary) {
        Path workRoot = temporary.resolve("work");

        SigningDirectMaintenanceBenchmark.ContractException equal = assertThrows(
                SigningDirectMaintenanceBenchmark.ContractException.class,
                () -> configuration(workRoot, workRoot));
        SigningDirectMaintenanceBenchmark.ContractException child = assertThrows(
                SigningDirectMaintenanceBenchmark.ContractException.class,
                () -> configuration(workRoot, workRoot.resolve("manifest")));

        assertEquals("CONFIGURATION_INVALID", equal.reasonCode());
        assertEquals("CONFIGURATION_INVALID", child.reasonCode());
        assertFalse(Files.exists(workRoot));
    }

    @Test
    void reportRejectsSymbolicLinkAndReplacesRegularLeaf(@TempDir Path temporary)
            throws IOException {
        Path target = temporary.resolve("target.json");
        Path symbolicLink = temporary.resolve("report-link.json");
        Files.writeString(target, "preserved");
        Files.createSymbolicLink(symbolicLink, target.getFileName());

        SigningDirectMaintenanceBenchmark.BenchmarkException failure = assertThrows(
                SigningDirectMaintenanceBenchmark.BenchmarkException.class,
                () -> SigningDirectMaintenanceBenchmark.writeReport(symbolicLink, "rejected"));

        assertEquals("REPORT_OUTPUT_INVALID", failure.reasonCode());
        assertEquals("preserved", Files.readString(target));

        Path regular = temporary.resolve("regular.json");
        Files.writeString(regular, "old-longer-content");
        SigningDirectMaintenanceBenchmark.writeReport(regular, "new");
        assertEquals("new" + System.lineSeparator(), Files.readString(regular));
    }

    @Test
    void nonMonotonicOrMissingBoundaryFailsStable() {
        SigningDirectMaintenanceBenchmark.BenchmarkException nonMonotonic = assertThrows(
                SigningDirectMaintenanceBenchmark.BenchmarkException.class,
                () -> SigningDirectMaintenanceBenchmark.Timings.checked(10L, 9L, 20L, 1));
        assertEquals("EVIDENCE_MISMATCH", nonMonotonic.reasonCode());
        SigningDirectMaintenanceBenchmark.BenchmarkException missing = assertThrows(
                SigningDirectMaintenanceBenchmark.BenchmarkException.class,
                () -> SigningDirectMaintenanceBenchmark.Timings.checked(10L, 15L, 20L, 0));
        assertEquals("EVIDENCE_MISMATCH", missing.reasonCode());
    }

    private static SigningDirectMaintenanceBenchmark.Configuration configuration(
            Path workRoot, Path output) {
        return new SigningDirectMaintenanceBenchmark.Configuration(
                4, 2, 1, 10L, 20L, 21L, output, workRoot);
    }

    private static LongSupplier sequenceClock(long... values) {
        AtomicInteger index = new AtomicInteger();
        return () -> values[index.getAndIncrement()];
    }

    private static String rejected(String... arguments) {
        SigningDirectMaintenanceBenchmark.ContractException failure = assertThrows(
                SigningDirectMaintenanceBenchmark.ContractException.class,
                () -> SigningDirectMaintenanceBenchmark.Configuration.parse(arguments));
        return failure.reasonCode();
    }
}
