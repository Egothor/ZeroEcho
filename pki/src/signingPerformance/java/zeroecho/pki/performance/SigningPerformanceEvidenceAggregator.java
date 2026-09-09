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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.TokenStreamFactory;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.core.json.JsonReadFeature;

/**
 * Verifies the fixed Increment-13 evidence bundle without launching a benchmark.
 *
 * <p>The trusted evidence directory is fixed by contract and is not enumerated.
 * JSON inputs are capped and parsed with bounded metadata; the raw heap artifact
 * is hashed as a stream. Runtime is {@code O(B)} for total evidence bytes and
 * auxiliary memory is bounded independently of the raw artifact size.</p>
 */
@SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.AvoidLiteralsInIfCondition",
        "PMD.CommentDefaultAccessModifier", "PMD.ExceptionAsFlowControl",
        "PMD.AvoidDuplicateLiterals"})
public final class SigningPerformanceEvidenceAggregator {
    static final String VERDICT_SCHEMA = "zeroecho-signing-evidence-verdict-v1";
    static final String RETAINED_SCHEMA = "zeroecho-signing-retained-index-evidence-v1";
    static final long MAXIMUM_JSON_BYTES = 1_048_576L;
    static final long MAXIMUM_RETAINED_INDEX_BYTES = 512L * 1024L * 1024L;
    static final String HASH_MANIFEST = "evidence-sha256.txt";
    static final String RAW_ARTIFACT = "retained-index-heap-artifact.bin";

    private static final int APPROVED_JAVA_FEATURE = 25;
    private static final int MAXIMUM_SCALARS = 512;
    private static final TokenStreamFactory JSON = jsonFactory();
    private static final List<String> ANCHORS = List.of("anchor-1.json", "anchor-2.json", "anchor-3.json");
    private static final Map<String, GridCell> GRID_REPORTS = gridReports();
    private static final List<String> SIDECARS = List.of(
            "group64-rejection.json", "due-selection.json", "direct-maintenance.json",
            "recovery.json", "retained-index-evidence.json", RAW_ARTIFACT);
    private static final Set<String> EXPECTED_EVIDENCE = expectedEvidence();
    private static final List<String> ENVIRONMENT_FIELDS = List.of(
            "environment.javaVersion", "environment.javaVendor", "environment.vmName",
            "environment.osName", "environment.osVersion", "environment.osArchitecture",
            "environment.cpuModel", "environment.processors", "environment.maximumHeapBytes",
            "environment.garbageCollectors", "environment.jvmArguments", "environment.filesystemType",
            "environment.mountPoint", "environment.mountSource", "environment.mountOptions",
            "environment.localNvmeVerified", "environment.localNvmeEvidence",
            "environment.containerConstraints", "environment.powerConstraints", "environment.hostname");

    private SigningPerformanceEvidenceAggregator() {
    }

    /** Aggregates a fixed evidence directory into a deterministic verdict file. */
    public static void main(String[] arguments) throws IOException {
        Configuration configuration = Configuration.parse(arguments);
        Verdict verdict = aggregate(configuration.evidenceRoot());
        writeVerdict(configuration, verdict);
        if (!verdict.passed()) {
            throw new EvidenceException("signing evidence rejected: " + String.join(",", verdict.reasons()));
        }
    }

    static Verdict aggregate(Path evidenceRoot) {
        Objects.requireNonNull(evidenceRoot, "evidenceRoot");
        Set<String> reasons = new TreeSet<>();
        Map<String, String> hashes = verifyHashManifest(evidenceRoot, reasons);
        List<Document> mainReports = new ArrayList<>(ANCHORS.size() + GRID_REPORTS.size());
        for (String name : ANCHORS) {
            Document report = readJson(evidenceRoot, name, reasons);
            mainReports.add(report);
            verifyMainReport(report, name, GridCell.anchor(), true, reasons);
        }
        for (Map.Entry<String, GridCell> entry : GRID_REPORTS.entrySet()) {
            Document report = readJson(evidenceRoot, entry.getKey(), reasons);
            mainReports.add(report);
            verifyMainReport(report, entry.getKey(), entry.getValue(), false, reasons);
        }
        verifyCommonEnvironment(mainReports, reasons);
        verifyGroupRejection(readJson(evidenceRoot, "group64-rejection.json", reasons), reasons);
        verifyDueSelection(readJson(evidenceRoot, "due-selection.json", reasons), hashes, reasons);
        verifyMaintenance(readJson(evidenceRoot, "direct-maintenance.json", reasons), reasons);
        verifyRecovery(readJson(evidenceRoot, "recovery.json", reasons), reasons);
        long retainedBytes = verifyRetainedEvidence(evidenceRoot,
                readJson(evidenceRoot, "retained-index-evidence.json", reasons), hashes, reasons);
        double worstThroughput = minimum(mainReports.subList(0, ANCHORS.size()),
                "outcomes.achievedThroughputPerSecond", reasons);
        double worstP99 = maximum(mainReports.subList(0, ANCHORS.size()),
                "latencyMillis.endToEndFromScheduledArrival.p99", reasons);
        return new Verdict(reasons.isEmpty(), List.copyOf(reasons), Map.copyOf(hashes),
                retainedBytes, worstThroughput, worstP99);
    }

    private static Map<String, String> verifyHashManifest(Path root, Set<String> reasons) {
        Map<String, String> declared = new TreeMap<>();
        Path manifest = root.resolve(HASH_MANIFEST);
        try {
            requireRegularFile(manifest, 8_192L);
            List<String> lines = Files.readAllLines(manifest, StandardCharsets.US_ASCII);
            String previous = null;
            for (String line : lines) {
                if (line.length() < 67 || line.charAt(64) != ' ' || line.charAt(65) != ' '
                        || !line.substring(0, 64).matches("[0-9a-f]{64}")) {
                    throw new EvidenceException("HASH_MANIFEST_FORMAT");
                }
                String name = line.substring(66);
                if (!EXPECTED_EVIDENCE.contains(name) || previous != null && previous.compareTo(name) >= 0
                        || declared.putIfAbsent(name, line.substring(0, 64)) != null) {
                    throw new EvidenceException("HASH_MANIFEST_CONTENT");
                }
                previous = name;
            }
            if (!declared.keySet().equals(EXPECTED_EVIDENCE)) {
                throw new EvidenceException("HASH_MANIFEST_CONTENT");
            }
            for (Map.Entry<String, String> entry : declared.entrySet()) {
                Path file = root.resolve(entry.getKey());
                requireRegularFile(file, entry.getKey().endsWith(".json") ? MAXIMUM_JSON_BYTES : Long.MAX_VALUE);
                if (!entry.getValue().equals(sha256(file))) {
                    reasons.add("HASH_MISMATCH:" + entry.getKey());
                }
            }
        } catch (IOException | EvidenceException failure) {
            reasons.add(reason("HASH_MANIFEST_INVALID", failure));
        }
        return declared;
    }

    private static Document readJson(Path root, String name, Set<String> reasons) {
        Path file = root.resolve(name);
        try {
            requireRegularFile(file, MAXIMUM_JSON_BYTES);
            Map<String, String> values = new LinkedHashMap<>();
            try (InputStream input = new BufferedInputStream(Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS));
                    JsonParser parser = JSON.createParser(input)) {
                JsonToken first = parser.nextToken();
                if (first != JsonToken.START_OBJECT) {
                    throw new EvidenceException("JSON_ROOT_INVALID");
                }
                readObject(parser, "", values, new ScalarCount());
                if (parser.nextToken() != null) {
                    throw new EvidenceException("JSON_TRAILING_DATA");
                }
            }
            return new Document(name, Map.copyOf(values));
        } catch (IOException | EvidenceException failure) {
            reasons.add(reason("JSON_INVALID:" + name, failure));
            return new Document(name, Map.of());
        }
    }

    private static void readObject(JsonParser parser, String path, Map<String, String> values,
            ScalarCount count) throws IOException {
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            if (parser.currentToken() != JsonToken.PROPERTY_NAME) {
                throw new EvidenceException("JSON_OBJECT_INVALID");
            }
            String name = parser.currentName();
            JsonToken token = parser.nextToken();
            readValue(parser, token, child(path, name), values, count);
        }
    }

    private static void readArray(JsonParser parser, String path, Map<String, String> values,
            ScalarCount count) throws IOException {
        int index = 0;
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            readValue(parser, parser.currentToken(), path + '.' + index, values, count);
            index++;
        }
        put(values, path + ".length", Integer.toString(index), count);
    }

    private static void readValue(JsonParser parser, JsonToken token, String path,
            Map<String, String> values, ScalarCount count) throws IOException {
        if (token == JsonToken.START_OBJECT) {
            readObject(parser, path, values, count);
        } else if (token == JsonToken.START_ARRAY) {
            readArray(parser, path, values, count);
        } else if (token == JsonToken.VALUE_NULL) {
            put(values, path, "null", count);
        } else if (token != null && token.isScalarValue()) {
            put(values, path, parser.getText(), count);
        } else {
            throw new EvidenceException("JSON_VALUE_INVALID");
        }
    }

    private static void put(Map<String, String> values, String path, String value, ScalarCount count) {
        if (count.increment() > MAXIMUM_SCALARS || values.putIfAbsent(path, value) != null) {
            throw new EvidenceException("JSON_METADATA_BOUND");
        }
    }

    private static void verifyMainReport(Document report, String name, GridCell cell,
            boolean anchor, Set<String> reasons) {
        report.expect("schema", "zeroecho-signing-performance-v5", reasons);
        report.expect("profile", "acceptance", reasons);
        report.expect("configuration.target", "native-shared-ledger", reasons);
        report.expect("configuration.admissionTopology", "production-local-shared-ledger-step-scheduler", reasons);
        report.expect("configuration.cellId", cell.id(), reasons);
        report.expect("configuration.cellMode", "grid", reasons);
        report.expectLong("configuration.retainedPopulation", cell.retained(), reasons);
        report.expectLong("configuration.activePopulation", cell.active(), reasons);
        report.expectLong("configuration.lanes", cell.lanes(), reasons);
        report.expectLong("configuration.groupSize", cell.group(), reasons);
        verifyFrozenConfiguration(report, reasons);
        report.expect("preflight.proceed", "true", reasons);
        report.expect("preflight.diagnosticOnly", "false", reasons);
        report.expectLong("preflight.mismatchReasons.length", 0L, reasons);
        report.expect("cleanup.state", "SUCCEEDED", reasons);
        report.expect("cleanup.reason", "null", reasons);
        report.expectLong("outcomes.rejected", 0L, reasons);
        report.expectLong("outcomes.contextCapacityRejected", 0L, reasons);
        report.expectLong("outcomes.failed", 0L, reasons);
        report.expectLong("outcomes.uncertain", 0L, reasons);
        long scheduled = report.longValue("outcomes.scheduled", reasons);
        long contextsAdmitted = report.longValue("outcomes.workflowContextsAdmitted", reasons);
        long contextCapacityRejected = report.longValue("outcomes.contextCapacityRejected", reasons);
        long admitted = report.longValue("outcomes.admitted", reasons);
        long productionAdmissionRejected = report.longValue(
                "outcomes.productionAdmissionRejected", reasons);
        long preAcceptFailure = report.longValue("outcomes.preAcceptFailure", reasons);
        if (!sumEquals(scheduled, contextsAdmitted, contextCapacityRejected)) {
            reasons.add("FIELD_MISMATCH:" + name + ":outcomes.workflowContextCapacityAccounting");
        }
        if (!sumEquals(contextsAdmitted, admitted, productionAdmissionRejected, preAcceptFailure)) {
            reasons.add("FIELD_MISMATCH:" + name + ":outcomes.workflowContextAdmissionAccounting");
        }
        boolean retainedOnly = cell.retained() != 1_000_000L && cell.active() == 100_000L
                && cell.lanes() == 16L && cell.group() == 32L;
        long expectedContextCapacity = retainedOnly ? 0L : cell.active();
        long expectedStepWorkers = retainedOnly ? 0L : Math.min(cell.active(), cell.lanes() + 64L);
        long contextCapacity = report.longValue("multiplexer.contextCapacity", reasons);
        long stepWorkers = report.longValue("multiplexer.stepWorkers", reasons);
        long transitions = report.longValue("multiplexer.workflowTransitionsExecuted", reasons);
        long observations = report.longValue("multiplexer.observationAttempts", reasons);
        long peakResident = report.longValue("multiplexer.peakResidentContexts", reasons);
        expectMetric(name, "contextCapacity", contextCapacity, expectedContextCapacity, reasons);
        expectMetric(name, "stepWorkers", stepWorkers, expectedStepWorkers, reasons);
        requireNonnegativeMetric(name, "workflowTransitionsExecuted", transitions, reasons);
        requireNonnegativeMetric(name, "observationAttempts", observations, reasons);
        requireNonnegativeMetric(name, "peakResidentContexts", peakResident, reasons);
        if (peakResident > contextCapacity) {
            reasons.add("FIELD_MISMATCH:" + name + ":multiplexer.peakResidentContextsExceedsCapacity");
        }
        long accepted = report.longValue("outcomes.accepted", reasons);
        if (retainedOnly) {
            if (transitions != 0L || observations != 0L || peakResident != 0L) {
                reasons.add("FIELD_MISMATCH:" + name + ":multiplexer.nonMultiplexerMetrics");
            }
        } else {
            if (transitions < contextsAdmitted) {
                reasons.add("FIELD_MISMATCH:" + name + ":multiplexer.workflowTransitionsExecuted");
            }
            if (observations < accepted) {
                reasons.add("FIELD_MISMATCH:" + name + ":multiplexer.observationAttempts");
            }
        }
        long completed = report.longValue("outcomes.completed", reasons);
        if (accepted != completed) {
            reasons.add("FIELD_MISMATCH:" + name + ":outcomes.completed");
        }
        if (anchor) {
            report.expect("acceptance.evaluated", "true", reasons);
            report.expect("acceptance.targetMet", "true", reasons);
            if (report.longValue("outcomes.completedWithinWindow", reasons) < 300_000L
                    || report.doubleValue("outcomes.achievedThroughputPerSecond", reasons) < 1_000.0
                    || report.doubleValue("latencyMillis.endToEndFromScheduledArrival.p99", reasons) >= 100.0) {
                reasons.add("ANCHOR_THRESHOLD_FAILED:" + name);
            }
        }
    }

    private static void expectMetric(String report, String metric, long actual, long expected,
            Set<String> reasons) {
        requireNonnegativeMetric(report, metric, actual, reasons);
        if (actual != expected) {
            reasons.add("FIELD_MISMATCH:" + report + ":multiplexer." + metric);
        }
    }

    private static void requireNonnegativeMetric(String report, String metric, long value,
            Set<String> reasons) {
        if (value < 0L) {
            reasons.add("FIELD_INVALID:" + report + ":multiplexer." + metric);
        }
    }

    private static boolean sumEquals(long expected, long... terms) {
        try {
            long actual = 0L;
            for (long term : terms) {
                actual = Math.addExact(actual, term);
            }
            return actual == expected;
        } catch (ArithmeticException overflow) {
            return false;
        }
    }

    private static void verifyFrozenConfiguration(Document report, Set<String> reasons) {
        report.expectLong("configuration.warmupSeconds", 30L, reasons);
        report.expectLong("configuration.durationSeconds", 300L, reasons);
        report.expectLong("configuration.offeredRatePerSecond", 1_100L, reasons);
        report.expectLong("configuration.queueCapacity", 64L, reasons);
        report.expectLong("configuration.residentIndexBudgetBytes",
                SigningBenchmarkConfig.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES, reasons);
        report.expectLong("configuration.providerMeanMillis", 0L, reasons);
        report.expectLong("configuration.providerJitterMillis", 0L, reasons);
        report.expectLong("configuration.payloadBytes", 1_024L, reasons);
        report.expectLong("configuration.sampleCapacity", 1_000_000L, reasons);
        report.expectLong("configuration.drainSeconds", 120L, reasons);
        report.expectLong("configuration.seed", 0x5eed_2026L, reasons);
        report.expect("configuration.diagnosticEnvironmentOverride", "false", reasons);
    }

    private static void verifyCommonEnvironment(List<Document> reports, Set<String> reasons) {
        if (reports.isEmpty()) {
            return;
        }
        Document reference = reports.getFirst();
        if (javaFeature(reference.required("environment.javaVersion", reasons)) != APPROVED_JAVA_FEATURE) {
            reasons.add("ENVIRONMENT_JAVA_FEATURE_MISMATCH:" + reference.name());
        }
        for (String field : ENVIRONMENT_FIELDS) {
            String expected = reference.required(field, reasons);
            for (int index = 1; index < reports.size(); index++) {
                Document report = reports.get(index);
                if (!expected.equals(report.required(field, reasons))) {
                    reasons.add("ENVIRONMENT_MISMATCH:" + report.name() + ':' + field);
                }
            }
        }
    }

    private static void verifyGroupRejection(Document report, Set<String> reasons) {
        report.expect("schema", SigningContractRejectionReport.SCHEMA, reasons);
        report.expect("reasonCode", "UNSUPPORTED_MAX_32", reasons);
        report.expectLong("exitCode", 1L, reasons);
        report.expect("workRootCreated", "false", reasons);
        report.expect("configuration.profile", "acceptance", reasons);
        report.expect("configuration.cellId", "m1000000-w100000-l16-g64", reasons);
        report.expectLong("configuration.retainedPopulation", 1_000_000L, reasons);
        report.expectLong("configuration.activePopulation", 100_000L, reasons);
        report.expectLong("configuration.lanes", 16L, reasons);
        report.expectLong("configuration.groupSize", 64L, reasons);
        report.expectLong("configuration.residentIndexBudgetBytes",
                SigningBenchmarkConfig.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES, reasons);
    }

    private static void verifyDueSelection(Document report, Map<String, String> hashes,
            Set<String> reasons) {
        report.expect("schema", "zeroecho-signing-due-selection-v1", reasons);
        report.requireNonblank("configurationFingerprint", reasons);
        report.expect("environmentEvidenceSha256", hashes.getOrDefault("anchor-1.json", ""), reasons);
        report.expectLong("configuration.activePopulationW", 100_000L, reasons);
        report.expectLong("configuration.eligibleCount", 100_000L, reasons);
        report.expectLong("configuration.selectionBoundD", 4_096L, reasons);
        long[] axis = {1L, 64L, 1_024L, 4_096L};
        report.expectLong("configuration.selectionAxisD.length", axis.length, reasons);
        for (int index = 0; index < axis.length; index++) {
            report.expectLong("configuration.selectionAxisD." + index, axis[index], reasons);
        }
        report.expect("contract.timeComplexity", "O(log W + D)", reasons);
        report.expect("contract.selectionMemoryComplexity", "O(D)", reasons);
        report.expect("contract.diagnosticOnly", "true", reasons);
    }

    private static void verifyMaintenance(Document report, Set<String> reasons) {
        report.expect("schema", "zeroecho-signing-direct-maintenance-v1", reasons);
        report.expectLong("configuration.sealedSegments", 8L, reasons);
        report.expect("evidence.rotationPublicationMode", "HARD_LINK", reasons);
        report.expect("evidence.zeroCopyEvidence", "STATIC_CODE_PATH", reasons);
        report.expect("contract.diagnosticOnly", "true", reasons);
    }

    private static void verifyRecovery(Document report, Set<String> reasons) {
        report.expect("schema", "zeroecho-signing-production-recovery-v1", reasons);
        report.expect("mode", "RECOVER_ONLY", reasons);
        report.requireNonblank("configurationFingerprint", reasons);
        report.expectLong("configuration.retainedPopulation", 1_000_000L, reasons);
        report.expectLong("configuration.activePopulation", 100_000L, reasons);
        report.expectLong("configuration.sealedSegments", 4_096L, reasons);
        report.expectLong("configuration.suffixFrames", 4_096L, reasons);
        long reserved = report.longValue("capacity.steadyReservedBytes", reasons);
        if (reserved < 0L || reserved > MAXIMUM_RETAINED_INDEX_BYTES) {
            reasons.add("RECOVERY_CAPACITY_EXCEEDED");
        }
        report.expect("contract.diagnosticOnly", "true", reasons);
    }

    private static long verifyRetainedEvidence(Path root, Document report, Map<String, String> hashes,
            Set<String> reasons) {
        report.expect("schema", RETAINED_SCHEMA, reasons);
        report.expect("environmentEvidenceSha256", hashes.getOrDefault("anchor-1.json", ""), reasons);
        String method = report.required("method", reasons);
        if (!Set.of("CLASS_HISTOGRAM", "HEAP_DUMP").contains(method)) {
            reasons.add("RETAINED_METHOD_INVALID");
        }
        long retained = report.longValue("retainedIndexBytes", reasons);
        if (retained < 0L || retained > MAXIMUM_RETAINED_INDEX_BYTES) {
            reasons.add("RETAINED_INDEX_CAPACITY_EXCEEDED");
        }
        report.expect("rawArtifactFile", RAW_ARTIFACT, reasons);
        report.expect("rawArtifactSha256", hashes.getOrDefault(RAW_ARTIFACT, ""), reasons);
        report.requireNonblank("tool", reasons);
        report.requireNonblank("toolVersion", reasons);
        report.requireNonblank("command", reasons);
        report.expect("capturedOutsideLatency", "true", reasons);
        try {
            requireRegularFile(root.resolve(RAW_ARTIFACT), Long.MAX_VALUE);
        } catch (IOException failure) {
            reasons.add(reason("RAW_ARTIFACT_INVALID", failure));
        }
        return retained;
    }

    private static int javaFeature(String version) {
        try {
            return Runtime.Version.parse(version).feature();
        } catch (IllegalArgumentException failure) {
            return -1;
        }
    }

    private static double minimum(List<Document> reports, String field, Set<String> reasons) {
        double value = Double.POSITIVE_INFINITY;
        for (Document report : reports) {
            value = Math.min(value, report.doubleValue(field, reasons));
        }
        return Double.isInfinite(value) ? 0.0 : value;
    }

    private static double maximum(List<Document> reports, String field, Set<String> reasons) {
        double value = 0.0;
        for (Document report : reports) {
            value = Math.max(value, report.doubleValue(field, reasons));
        }
        return value;
    }

    private static void writeVerdict(Configuration configuration, Verdict verdict) throws IOException {
        Path output = configuration.output();
        if (output.equals(configuration.evidenceRoot()) || output.startsWith(configuration.evidenceRoot())) {
            throw new EvidenceException("verdict output must be outside the evidence directory");
        }
        Path parent = output.getParent();
        if (parent == null) {
            throw new EvidenceException("verdict output has no parent");
        }
        Files.createDirectories(parent);
        if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new EvidenceException("verdict output is invalid");
        }
        Files.writeString(output, verdict.toJson() + System.lineSeparator(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS);
    }

    private static void requireRegularFile(Path path, long maximumBytes) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new EvidenceException("not a regular file");
        }
        long size = Files.size(path);
        if (size > maximumBytes) {
            throw new EvidenceException("file exceeds its size bound");
        }
    }

    private static String sha256(Path path) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
        byte[] buffer = new byte[64 * 1_024];
        try (InputStream input = new BufferedInputStream(Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS))) {
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count != 0) {
                    digest.update(buffer, 0, count);
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static TokenStreamFactory jsonFactory() {
        StreamReadConstraints constraints = StreamReadConstraints.builder().maxNestingDepth(16)
                .maxDocumentLength(MAXIMUM_JSON_BYTES).maxTokenCount(4_096).maxNumberLength(64)
                .maxStringLength(65_536).maxNameLength(128).build();
        JsonFactoryBuilder builder = JsonFactory.builder().streamReadConstraints(constraints)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .disable(StreamReadFeature.AUTO_CLOSE_SOURCE);
        for (JsonReadFeature feature : JsonReadFeature.values()) {
            builder.disable(feature);
        }
        return builder.build();
    }

    private static Set<String> expectedEvidence() {
        Set<String> names = new TreeSet<>();
        names.addAll(ANCHORS);
        names.addAll(GRID_REPORTS.keySet());
        names.addAll(SIDECARS);
        return Set.copyOf(names);
    }

    private static Map<String, GridCell> gridReports() {
        Map<String, GridCell> reports = new LinkedHashMap<>();
        add(reports, 1_000, 100_000, 16, 32);
        add(reports, 100_000, 100_000, 16, 32);
        add(reports, 1_000_000, 10, 16, 32);
        add(reports, 1_000_000, 1_000, 16, 32);
        add(reports, 1_000_000, 100_000, 1, 32);
        add(reports, 1_000_000, 100_000, 8, 32);
        add(reports, 1_000_000, 100_000, 32, 32);
        add(reports, 1_000_000, 100_000, 16, 1);
        add(reports, 1_000_000, 100_000, 16, 8);
        return Map.copyOf(reports);
    }

    private static void add(Map<String, GridCell> reports, int retained, int active, int lanes, int group) {
        GridCell cell = new GridCell(retained, active, lanes, group);
        reports.put("grid-" + cell.id() + ".json", cell);
    }

    private static String child(String path, String name) {
        return path.isEmpty() ? name : path + '.' + name;
    }

    private static String reason(String prefix, Throwable failure) {
        if (failure instanceof EvidenceException && failure.getMessage() != null) {
            return prefix + ':' + failure.getMessage();
        }
        return prefix;
    }

    record Verdict(boolean passed, List<String> reasons, Map<String, String> inputHashes,
            long retainedIndexBytes, double worstAnchorThroughput, double worstAnchorP99Millis) {
        Verdict {
            reasons = List.copyOf(reasons);
            inputHashes = Map.copyOf(inputHashes);
        }

        String toJson() {
            StringBuilder json = new StringBuilder(4_096).append('{');
            field(json, "schema", VERDICT_SCHEMA).append(',');
            bool(json, "passed", passed).append(',');
            number(json, "retainedIndexBytes", retainedIndexBytes).append(',');
            decimal(json, "worstAnchorThroughputPerSecond", worstAnchorThroughput).append(',');
            decimal(json, "worstAnchorP99Millis", worstAnchorP99Millis).append(',');
            json.append("\"reasons\":[");
            for (int index = 0; index < reasons.size(); index++) {
                if (index != 0) {
                    json.append(',');
                }
                quote(json, reasons.get(index));
            }
            json.append("],\"inputSha256\":{");
            int index = 0;
            for (Map.Entry<String, String> entry : new TreeMap<>(inputHashes).entrySet()) {
                if (index++ != 0) {
                    json.append(',');
                }
                field(json, entry.getKey(), entry.getValue());
            }
            return json.append("}}" ).toString();
        }
    }

    private record Document(String name, Map<String, String> values) {
        private String required(String field, Set<String> reasons) {
            String value = values.get(field);
            if (value == null) {
                reasons.add("FIELD_MISSING:" + name + ':' + field);
                return "";
            }
            return value;
        }

        private void requireNonblank(String field, Set<String> reasons) {
            if (required(field, reasons).isBlank()) {
                reasons.add("FIELD_INVALID:" + name + ':' + field);
            }
        }

        private void expect(String field, String expected, Set<String> reasons) {
            if (!Objects.equals(expected, required(field, reasons))) {
                reasons.add("FIELD_MISMATCH:" + name + ':' + field);
            }
        }

        private void expectLong(String field, long expected, Set<String> reasons) {
            if (longValue(field, reasons) != expected) {
                reasons.add("FIELD_MISMATCH:" + name + ':' + field);
            }
        }

        private long longValue(String field, Set<String> reasons) {
            try {
                return Long.parseLong(required(field, reasons));
            } catch (NumberFormatException failure) {
                reasons.add("FIELD_INVALID:" + name + ':' + field);
                return Long.MIN_VALUE;
            }
        }

        private double doubleValue(String field, Set<String> reasons) {
            try {
                double value = Double.parseDouble(required(field, reasons));
                if (!Double.isFinite(value)) {
                    throw new NumberFormatException("non-finite");
                }
                return value;
            } catch (NumberFormatException failure) {
                reasons.add("FIELD_INVALID:" + name + ':' + field);
                return 0.0;
            }
        }
    }

    private record GridCell(int retained, int active, int lanes, int group) {
        private static GridCell anchor() {
            return new GridCell(1_000_000, 100_000, 16, 32);
        }

        private String id() {
            return "m" + retained + "-w" + active + "-l" + lanes + "-g" + group;
        }
    }

    private record Configuration(Path evidenceRoot, Path output) {
        private Configuration {
            evidenceRoot = Objects.requireNonNull(evidenceRoot, "evidenceRoot").toAbsolutePath().normalize();
            output = Objects.requireNonNull(output, "output").toAbsolutePath().normalize();
        }

        private static Configuration parse(String[] arguments) {
            Map<String, String> values = new LinkedHashMap<>();
            for (String argument : arguments) {
                if (argument == null || !argument.startsWith("--") || argument.indexOf('=') < 3) {
                    throw new EvidenceException("arguments must use --name=value");
                }
                int separator = argument.indexOf('=');
                String name = argument.substring(2, separator);
                if (!Set.of("evidenceRoot", "output").contains(name)
                        || values.putIfAbsent(name, argument.substring(separator + 1)) != null) {
                    throw new EvidenceException("unknown or duplicate argument");
                }
            }
            if (values.size() != 2 || values.values().stream().anyMatch(String::isBlank)) {
                throw new EvidenceException("evidenceRoot and output are required");
            }
            return new Configuration(Path.of(values.get("evidenceRoot")), Path.of(values.get("output")));
        }
    }

    /** Mutable parser-local scalar counter; never escapes one JSON read. */
    private static final class ScalarCount {
        private int value;

        private int increment() {
            return ++value;
        }
    }

    /** Stable local evidence-contract failure. */
    static final class EvidenceException extends IllegalArgumentException {
        private static final long serialVersionUID = -8410798571561049500L;

        EvidenceException(String message) {
            super(message);
        }
    }

    private static StringBuilder field(StringBuilder json, String name, String value) {
        quote(json, name).append(':');
        return quote(json, value);
    }

    private static StringBuilder number(StringBuilder json, String name, long value) {
        return quote(json, name).append(':').append(value);
    }

    private static StringBuilder decimal(StringBuilder json, String name, double value) {
        return quote(json, name).append(':')
                .append(String.format(java.util.Locale.ROOT, "%.6f", value));
    }

    private static StringBuilder bool(StringBuilder json, String name, boolean value) {
        return quote(json, name).append(':').append(value);
    }

    private static StringBuilder quote(StringBuilder json, String value) {
        json.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"', '\\' -> json.append('\\').append(character);
                case '\b' -> json.append("\\b");
                case '\f' -> json.append("\\f");
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
}
