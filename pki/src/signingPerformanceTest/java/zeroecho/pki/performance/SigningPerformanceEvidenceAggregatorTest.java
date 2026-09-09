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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Fixed-bundle acceptance and tamper tests for the non-launching aggregator. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.UnitTestAssertionsShouldIncludeMessage"})
class SigningPerformanceEvidenceAggregatorTest {
    private static final List<Cell> CELLS = List.of(
            new Cell("grid-m1000-w100000-l16-g32.json", 1_000, 100_000, 16, 32),
            new Cell("grid-m100000-w100000-l16-g32.json", 100_000, 100_000, 16, 32),
            new Cell("grid-m1000000-w10-l16-g32.json", 1_000_000, 10, 16, 32),
            new Cell("grid-m1000000-w1000-l16-g32.json", 1_000_000, 1_000, 16, 32),
            new Cell("grid-m1000000-w100000-l1-g32.json", 1_000_000, 100_000, 1, 32),
            new Cell("grid-m1000000-w100000-l8-g32.json", 1_000_000, 100_000, 8, 32),
            new Cell("grid-m1000000-w100000-l32-g32.json", 1_000_000, 100_000, 32, 32),
            new Cell("grid-m1000000-w100000-l16-g1.json", 1_000_000, 100_000, 16, 1),
            new Cell("grid-m1000000-w100000-l16-g8.json", 1_000_000, 100_000, 16, 8));

    @TempDir
    private Path temporary;

    @Test
    void acceptsCompleteFixedEvidenceBundle() throws IOException {
        Path evidence = fixture();
        SigningPerformanceEvidenceAggregator.Verdict verdict =
                SigningPerformanceEvidenceAggregator.aggregate(evidence);

        assertTrue(verdict.passed(), () -> String.join(",", verdict.reasons()));
        org.junit.jupiter.api.Assertions.assertEquals(18, verdict.inputHashes().size(),
                "all fixed evidence hashes must be retained");
        assertTrue(verdict.worstAnchorThroughput() >= 1_000.0, "worst throughput must pass");
        assertTrue(verdict.worstAnchorP99Millis() < 100.0, "worst p99 must pass");
    }

    @Test
    void rejectsFileChangedAfterHashManifestWasWritten() throws IOException {
        Path evidence = fixture();
        Files.writeString(evidence.resolve("anchor-2.json"), " ", StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);

        SigningPerformanceEvidenceAggregator.Verdict verdict =
                SigningPerformanceEvidenceAggregator.aggregate(evidence);

        assertFalse(verdict.passed(), "tampered evidence must fail");
        assertTrue(verdict.reasons().contains("HASH_MISMATCH:anchor-2.json"),
                "verdict must identify the changed fixed input");
    }

    @Test
    void rejectsPeakResidentContextsAboveFixedCapacity() throws IOException {
        Path evidence = fixture();
        String name = "grid-m1000000-w10-l16-g32.json";
        String report = Files.readString(evidence.resolve(name), StandardCharsets.UTF_8)
                .replace("\"peakResidentContexts\":10", "\"peakResidentContexts\":11");
        write(evidence, name, report);
        writeManifest(evidence);

        SigningPerformanceEvidenceAggregator.Verdict verdict =
                SigningPerformanceEvidenceAggregator.aggregate(evidence);

        assertFalse(verdict.passed(), "impossible multiplexer metrics must fail");
        assertTrue(verdict.reasons().contains(
                "FIELD_MISMATCH:" + name + ":multiplexer.peakResidentContextsExceedsCapacity"),
                "verdict must identify a peak above fixed context capacity");
    }

    @Test
    void rejectsDueSelectionNotBoundToAnchorEvidence() throws IOException {
        Path evidence = fixture();
        String due = Files.readString(evidence.resolve("due-selection.json"), StandardCharsets.UTF_8)
                .replace(sha256(evidence.resolve("anchor-1.json")), "0".repeat(64));
        write(evidence, "due-selection.json", due);
        writeManifest(evidence);

        SigningPerformanceEvidenceAggregator.Verdict verdict =
                SigningPerformanceEvidenceAggregator.aggregate(evidence);

        assertFalse(verdict.passed(), "unbound due-selection evidence must fail");
        assertTrue(verdict.reasons().contains(
                "FIELD_MISMATCH:due-selection.json:environmentEvidenceSha256"),
                "verdict must identify the missing host-evidence binding");
    }

    @Test
    void rejectsRetainedEvidenceNotBoundToAnchorEvidence() throws IOException {
        Path evidence = fixture();
        String retained = Files.readString(evidence.resolve("retained-index-evidence.json"),
                StandardCharsets.UTF_8).replace(sha256(evidence.resolve("anchor-1.json")), "0".repeat(64));
        write(evidence, "retained-index-evidence.json", retained);
        writeManifest(evidence);

        SigningPerformanceEvidenceAggregator.Verdict verdict =
                SigningPerformanceEvidenceAggregator.aggregate(evidence);

        assertFalse(verdict.passed(), "unbound retained-index evidence must fail");
        assertTrue(verdict.reasons().contains(
                "FIELD_MISMATCH:retained-index-evidence.json:environmentEvidenceSha256"),
                "verdict must identify the missing retained-index host-evidence binding");
    }

    @Test
    void rejectsFullyRehashedJava21EvidenceBundle() throws IOException {
        Path evidence = fixture();
        for (int repetition = 1; repetition <= 3; repetition++) {
            replaceJavaVersion(evidence, "anchor-" + repetition + ".json", "21.0.11");
        }
        for (Cell cell : CELLS) {
            replaceJavaVersion(evidence, cell.file(), "21.0.11");
        }
        String anchorHash = sha256(evidence.resolve("anchor-1.json"));
        write(evidence, "due-selection.json", dueSelection(anchorHash));
        String rawHash = sha256(evidence.resolve(SigningPerformanceEvidenceAggregator.RAW_ARTIFACT));
        write(evidence, "retained-index-evidence.json", retainedEvidence(anchorHash, rawHash));
        writeManifest(evidence);

        SigningPerformanceEvidenceAggregator.Verdict verdict =
                SigningPerformanceEvidenceAggregator.aggregate(evidence);

        assertFalse(verdict.passed(), "Java 21 evidence must fail the Java 25 LTS fingerprint");
        org.junit.jupiter.api.Assertions.assertEquals(
                List.of("ENVIRONMENT_JAVA_FEATURE_MISMATCH:anchor-1.json"), verdict.reasons(),
                "a fully rebound and rehashed Java 21 bundle must fail only the Java feature gate");
    }

    private Path fixture() throws IOException {
        Path evidence = Files.createDirectory(temporary.resolve("evidence"));
        Cell anchor = new Cell("unused", 1_000_000, 100_000, 16, 32);
        for (int repetition = 1; repetition <= 3; repetition++) {
            write(evidence, "anchor-" + repetition + ".json", mainReport(anchor, true));
        }
        for (Cell cell : CELLS) {
            write(evidence, cell.file(), mainReport(cell, false));
        }
        write(evidence, "group64-rejection.json", groupRejection());
        String anchorHash = sha256(evidence.resolve("anchor-1.json"));
        write(evidence, "due-selection.json", dueSelection(anchorHash));
        write(evidence, "direct-maintenance.json", maintenance());
        write(evidence, "recovery.json", recovery());
        write(evidence, SigningPerformanceEvidenceAggregator.RAW_ARTIFACT, "raw heap evidence\n");
        String rawHash = sha256(evidence.resolve(SigningPerformanceEvidenceAggregator.RAW_ARTIFACT));
        write(evidence, "retained-index-evidence.json", retainedEvidence(anchorHash, rawHash));
        writeManifest(evidence);
        return evidence;
    }

    private static void writeManifest(Path evidence) throws IOException {
        List<String> names;
        try (Stream<Path> paths = Files.list(evidence)) {
            names = paths.map(path -> path.getFileName().toString())
                    .filter(name -> !SigningPerformanceEvidenceAggregator.HASH_MANIFEST.equals(name))
                    .sorted().toList();
        }
        StringBuilder manifest = new StringBuilder();
        for (String name : names) {
            manifest.append(sha256(evidence.resolve(name))).append("  ").append(name).append('\n');
        }
        write(evidence, SigningPerformanceEvidenceAggregator.HASH_MANIFEST, manifest.toString());
    }

    private static String mainReport(Cell cell, boolean anchor) {
        String cellId = "m" + cell.retained() + "-w" + cell.active()
                + "-l" + cell.lanes() + "-g" + cell.group();
        boolean retainedOnly = cell.retained() != 1_000_000 && cell.active() == 100_000
                && cell.lanes() == 16 && cell.group() == 32;
        int contextCapacity = retainedOnly ? 0 : cell.active();
        int stepWorkers = retainedOnly ? 0 : Math.min(cell.active(), cell.lanes() + 64);
        int operations = retainedOnly ? 0 : 330_000;
        int completionsWithinWindow = retainedOnly ? 0 : 300_001;
        double throughput = retainedOnly ? 0.0 : 1_000.003;
        return """
                {"schema":"zeroecho-signing-performance-v5","profile":"acceptance",
                "configuration":{"target":"native-shared-ledger",
                "admissionTopology":"production-local-shared-ledger-step-scheduler",
                "cellId":"%s","cellMode":"grid","retainedPopulation":%d,"activePopulation":%d,
                "groupSize":%d,"residentIndexBudgetBytes":536870912,
                "warmupSeconds":30,"durationSeconds":300,
                "offeredRatePerSecond":1100,"lanes":%d,"queueCapacity":64,"payloadBytes":1024,
                "providerMeanMillis":0,"providerJitterMillis":0,"sampleCapacity":1000000,
                "drainSeconds":120,"seed":1592598566,"diagnosticEnvironmentOverride":false},
                "multiplexer":{"contextCapacity":%d,"stepWorkers":%d,
                "workflowTransitionsExecuted":%d,"observationAttempts":%d,
                "peakResidentContexts":%d},
                "outcomes":{"scheduled":%d,"workflowContextsAdmitted":%d,"admitted":%d,
                "productionAdmissionRejected":0,"preAcceptFailure":0,"contextCapacityRejected":0,
                "accepted":%d,"rejected":0,"completed":%d,
                "completedWithinWindow":%d,"failed":0,"uncertain":0,
                "achievedThroughputPerSecond":%.3f},
                "latencyMillis":{"endToEndFromScheduledArrival":{"p99":99.999}},
                "environment":{"javaVersion":"25.0.1","javaVendor":"Eclipse Adoptium",
                "vmName":"OpenJDK 64-Bit VM","osName":"Linux","osVersion":"test",
                "osArchitecture":"amd64","cpuModel":"AMD Ryzen 5 7600","processors":12,
                "maximumHeapBytes":4294967296,"garbageCollectors":"G1","jvmArguments":"-Xmx4g",
                "filesystemType":"btrfs","filesystemUsableBytes":1000000,"mountPoint":"/pki",
                "mountSource":"/dev/nvme0n1p1","mountOptions":"rw,noatime,compress=zstd:3,ssd,discard=async",
                "localNvmeVerified":true,"localNvmeEvidence":"verified","containerConstraints":"none",
                "powerConstraints":"performance","hostname":"reference"},
                "preflight":{"proceed":true,"diagnosticOnly":false,"mismatchReasons":[]},
                "acceptance":{"evaluated":%s,"targetMet":%s,"reasons":[]},
                "cleanup":{"state":"SUCCEEDED","reason":null}}
                """.formatted(cellId, cell.retained(), cell.active(), cell.group(), cell.lanes(),
                        contextCapacity, stepWorkers, operations * 4L, operations, contextCapacity,
                        operations, operations, operations, operations, operations,
                        completionsWithinWindow, throughput, anchor, anchor);
    }

    private static String groupRejection() {
        return """
                {"schema":"zeroecho-signing-contract-rejection-v1","reasonCode":"UNSUPPORTED_MAX_32",
                "exitCode":1,"workRootCreated":false,"configuration":{"profile":"acceptance",
                "cellId":"m1000000-w100000-l16-g64","retainedPopulation":1000000,
                "activePopulation":100000,"lanes":16,"groupSize":64,
                "residentIndexBudgetBytes":536870912}}
                """;
    }

    private static String dueSelection(String anchorHash) {
        return """
                {"schema":"zeroecho-signing-due-selection-v1","configurationFingerprint":"due-config",
                "environmentEvidenceSha256":"%s","configuration":{"activePopulationW":100000,
                "eligibleCount":100000,"selectionBoundD":4096,"selectionAxisD":[1,64,1024,4096]},
                "contract":{"timeComplexity":"O(log W + D)","selectionMemoryComplexity":"O(D)",
                "diagnosticOnly":true}}
                """.formatted(anchorHash);
    }

    private static String maintenance() {
        return """
                {"schema":"zeroecho-signing-direct-maintenance-v1","configuration":{"sealedSegments":8},
                "evidence":{"rotationPublicationMode":"HARD_LINK","zeroCopyEvidence":"STATIC_CODE_PATH"},
                "contract":{"diagnosticOnly":true}}
                """;
    }

    private static String recovery() {
        return """
                {"schema":"zeroecho-signing-production-recovery-v1","mode":"RECOVER_ONLY",
                "configurationFingerprint":"recovery-config","configuration":{"retainedPopulation":1000000,
                "activePopulation":100000,"sealedSegments":4096,"suffixFrames":4096},
                "capacity":{"steadyReservedBytes":536870912},"contract":{"diagnosticOnly":true}}
                """;
    }

    private static String retainedEvidence(String anchorHash, String rawHash) {
        return """
                {"schema":"zeroecho-signing-retained-index-evidence-v1","method":"CLASS_HISTOGRAM",
                "environmentEvidenceSha256":"%s",
                "retainedIndexBytes":536870912,"rawArtifactFile":"retained-index-heap-artifact.bin",
                "rawArtifactSha256":"%s","tool":"jcmd","toolVersion":"25.0.1",
                "command":"jcmd PID GC.class_histogram","capturedOutsideLatency":true}
                """.formatted(anchorHash, rawHash);
    }

    private static void replaceJavaVersion(Path evidence, String name, String javaVersion) throws IOException {
        Path report = evidence.resolve(name);
        String source = Files.readString(report, StandardCharsets.UTF_8);
        write(evidence, name, source.replace("\"javaVersion\":\"25.0.1\"",
                "\"javaVersion\":\"" + javaVersion + "\""));
    }

    private static void write(Path root, String name, String value) throws IOException {
        Files.writeString(root.resolve(name), value, StandardCharsets.UTF_8);
    }

    private static String sha256(Path path) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private record Cell(String file, int retained, int active, int lanes, int group) {
    }
}
