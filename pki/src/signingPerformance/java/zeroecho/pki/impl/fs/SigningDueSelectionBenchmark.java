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
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import zeroecho.pki.spi.store.MetadataStoreId;

/** Opt-in eligibility-ordered due-selection diagnostic over a production-recovered ledger. */
@SuppressWarnings({ "PMD.CommentRequired", "PMD.SystemPrintln", "PMD.UseObjectForClearerAPI" })
public final class SigningDueSelectionBenchmark {
    static final String SCHEMA = "zeroecho-signing-due-selection-v1";
    static final List<Integer> SELECTION_AXIS = List.of(1, 64, 1_024, 4_096);
    static final String CUTOFF_CLASSIFICATION = "ALL_ELIGIBLE_AT_CUTOFF";
    static final String ALGORITHMIC_EVIDENCE = "STATIC_COMPLEXITY_ONLY";
    private static final Instant CREATED_AT = Instant.parse("2026-08-30T00:00:00Z");
    private static final Instant CUTOFF = CREATED_AT.plus(Duration.ofDays(1));

    private SigningDueSelectionBenchmark() {
        // entry point
    }

    /** Populates, production-recovers, reopens, and measures one diagnostic. */
    public static void main(String[] arguments) throws Exception {
        Configuration configuration = Configuration.parse(arguments);
        Result result = run(configuration);
        String json = result.toJson(configuration);
        Path parent = configuration.output().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(configuration.output(), json + System.lineSeparator(),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
        System.out.println(json);
    }

    /* default */ static Result run(Configuration configuration) throws IOException {
        Objects.requireNonNull(configuration, "configuration");
        prepareFreshWorkRoot(configuration.workRoot());
        SigningPopulationFixture.Artifact fixture = populateAndRecover(configuration);
        if (fixture.population().dueRecords() != configuration.activePopulation()) {
            throw new BenchmarkException("FIXTURE_RECOVERY_UNAVAILABLE_OR_INVALID");
        }
        FsPaths paths = new FsPaths(configuration.workRoot());
        Path metadataRoot = paths.transactionalMetadataRoot();
        String signingNamespace = Files.readString(paths.signingNamespaceFile()).trim();
        try {
            try (SegmentedTransactionalMetadataStore metadata =
                    SegmentedTransactionalMetadataStore.open(metadataRoot,
                            new MetadataStoreId(signingNamespace),
                            SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK,
                            SigningActiveWal.Configuration.defaults(),
                            FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES,
                            FsPkiStoreOptions.DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES,
                            FilesystemStagedContentStore.readOnlyResolver(
                                    paths.stagedContentRoot(), signingNamespace))) {
                long first = sample(metadata, configuration.selectionBound());
                long[] subsequent = new long[configuration.subsequentInProcessSamples()];
                for (int index = 0; index < subsequent.length; index++) {
                    subsequent[index] = sample(metadata, configuration.selectionBound());
                }
                return new Result(first, SubsequentInProcessSummary.from(subsequent));
            }
        } catch (IOException failure) {
            throw new BenchmarkException("FIXTURE_RECOVERY_UNAVAILABLE_OR_INVALID", failure);
        }
    }

    private static void prepareFreshWorkRoot(Path workRoot) throws BenchmarkException {
        if (Files.exists(workRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new BenchmarkException("WORK_ROOT_NOT_FRESH");
        }
        Path parent = workRoot.getParent();
        if (parent == null) {
            throw new BenchmarkException("FIXTURE_RECOVERY_UNAVAILABLE_OR_INVALID");
        }
        try {
            Files.createDirectories(parent);
        } catch (IOException failure) {
            throw new BenchmarkException("FIXTURE_RECOVERY_UNAVAILABLE_OR_INVALID", failure);
        }
        try {
            Files.createDirectory(workRoot);
        } catch (FileAlreadyExistsException failure) {
            throw new BenchmarkException("WORK_ROOT_NOT_FRESH", failure);
        } catch (IOException failure) {
            throw new BenchmarkException("FIXTURE_RECOVERY_UNAVAILABLE_OR_INVALID", failure);
        }
    }

    private static SigningPopulationFixture.Artifact populateAndRecover(Configuration configuration)
            throws BenchmarkException {
        try {
            return SigningPopulationFixture.populate(configuration.workRoot(),
                    FsPkiStoreOptions.defaults(), CREATED_AT, 0L,
                    configuration.activePopulation());
        } catch (IOException | IllegalStateException failure) {
            throw new BenchmarkException("FIXTURE_RECOVERY_UNAVAILABLE_OR_INVALID", failure);
        }
    }

    private static long sample(SegmentedTransactionalMetadataStore metadata, int selectionBound)
            throws IOException {
        long started = System.nanoTime();
        List<String> selected = metadata.selectSigningDue(CUTOFF, selectionBound);
        long elapsed = Math.max(0L, System.nanoTime() - started);
        verifyReturnedCount(selectionBound, selected.size());
        return elapsed;
    }

    /* default */ static void verifyReturnedCount(int expected, int actual) throws BenchmarkException {
        if (actual != expected) {
            throw new BenchmarkException("DUE_SELECTION_WRONG_COUNT");
        }
    }

    /* default */ record Configuration(int activePopulation, int selectionBound,
            int subsequentInProcessSamples, String environmentEvidenceSha256,
            Path output, Path workRoot) {
        private static final int MAXIMUM_ACTIVE_POPULATION = 100_000;
        private static final int MAXIMUM_SUBSEQUENT_SAMPLES = 4_096;

        Configuration {
            if (activePopulation <= 0 || activePopulation > MAXIMUM_ACTIVE_POPULATION
                    || subsequentInProcessSamples <= 0
                    || subsequentInProcessSamples > MAXIMUM_SUBSEQUENT_SAMPLES) {
                throw new ContractException("CONFIGURATION_INVALID");
            }
            if (!SELECTION_AXIS.contains(selectionBound)) {
                throw new ContractException("SELECTION_BOUND_UNSUPPORTED");
            }
            if (selectionBound > activePopulation) {
                throw new ContractException("SELECTION_BOUND_EXCEEDS_ELIGIBLE");
            }
            if (environmentEvidenceSha256 == null
                    || !environmentEvidenceSha256.matches("[0-9a-f]{64}")) {
                throw new ContractException("CONFIGURATION_INVALID");
            }
            output = Objects.requireNonNull(output, "output").toAbsolutePath().normalize();
            workRoot = Objects.requireNonNull(workRoot, "workRoot").toAbsolutePath().normalize();
        }

        /* default */ static Configuration parse(String[] arguments) {
            Map<String, String> values = parseArguments(arguments);
            try {
                return new Configuration(integer(values, "activePopulation", 100_000),
                        integer(values, "selectionBound", 4_096),
                        integer(values, "subsequentInProcessSamples", 64),
                        values.getOrDefault("environmentEvidenceSha256", "0".repeat(64)),
                        Path.of(values.getOrDefault("output",
                                "build/reports/signing-performance/due-selection.json")),
                        Path.of(values.getOrDefault("workRoot",
                                "build/signing-performance/due-selection")));
            } catch (NumberFormatException failure) {
                throw new ContractException("CONFIGURATION_INVALID", failure);
            }
        }

        /* default */ String fingerprint() {
            String canonical = "schema=" + SCHEMA
                    + "|activePopulation=" + activePopulation
                    + "|eligibleCount=" + activePopulation
                    + "|cutoff=" + CUTOFF
                    + "|cutoffClassification=" + CUTOFF_CLASSIFICATION
                    + "|selectionBound=" + selectionBound
                    + "|subsequentInProcessSamples=" + subsequentInProcessSamples
                    + "|environmentEvidenceSha256=" + environmentEvidenceSha256
                    + "|recordIoIncluded=false"
                    + "|algorithmicWorkEvidence=" + ALGORITHMIC_EVIDENCE;
            return HexFormat.of().formatHex(SigningFormatSupport.sha256().digest(
                    canonical.getBytes(StandardCharsets.US_ASCII)));
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
                if (!List.of("activePopulation", "selectionBound", "subsequentInProcessSamples",
                        "environmentEvidenceSha256", "output", "workRoot").contains(name)
                        || values.putIfAbsent(name, argument.substring(separator + 1)) != null) {
                    throw new ContractException("CONFIGURATION_INVALID");
                }
            }
            return values;
        }

        private static int integer(Map<String, String> values, String name, int fallback) {
            return Integer.parseInt(values.getOrDefault(name, Integer.toString(fallback)));
        }
    }

    /* default */ record Result(long firstInProcessNanos,
            SubsequentInProcessSummary subsequentInProcess) {
        Result {
            if (firstInProcessNanos < 0L) {
                throw new IllegalArgumentException("first in-process sample must not be negative");
            }
            Objects.requireNonNull(subsequentInProcess, "subsequentInProcess");
        }

        /* default */ String toJson(Configuration configuration) {
            Objects.requireNonNull(configuration, "configuration");
            StringBuilder json = new StringBuilder(1024);
            json.append('{');
            field(json, "schema", SCHEMA).append(',');
            field(json, "configurationFingerprint", configuration.fingerprint()).append(',');
            field(json, "environmentEvidenceSha256",
                    configuration.environmentEvidenceSha256()).append(',');
            json.append("\"configuration\":{");
            number(json, "activePopulationW", configuration.activePopulation()).append(',');
            number(json, "eligibleCount", configuration.activePopulation()).append(',');
            field(json, "cutoff", CUTOFF.toString()).append(',');
            field(json, "cutoffClassification", CUTOFF_CLASSIFICATION).append(',');
            number(json, "selectionBoundD", configuration.selectionBound()).append(',');
            json.append("\"selectionAxisD\":[1,64,1024,4096],");
            number(json, "subsequentInProcessSamples",
                    configuration.subsequentInProcessSamples()).append(',');
            field(json, "output", configuration.output().toString()).append(',');
            field(json, "workRoot", configuration.workRoot().toString()).append("},");
            json.append("\"measurement\":{");
            number(json, "firstInProcessNanos", firstInProcessNanos).append(',');
            number(json, "subsequentInProcessCount", subsequentInProcess.count()).append(',');
            number(json, "subsequentInProcessP50Nanos",
                    subsequentInProcess.p50Nanos()).append(',');
            number(json, "subsequentInProcessP95Nanos",
                    subsequentInProcess.p95Nanos()).append(',');
            number(json, "subsequentInProcessP99Nanos",
                    subsequentInProcess.p99Nanos()).append(',');
            number(json, "subsequentInProcessMaxNanos",
                    subsequentInProcess.maxNanos()).append("},");
            json.append("\"contract\":{");
            json.append("\"recordIoIncluded\":false,");
            field(json, "algorithmicWorkEvidence", ALGORITHMIC_EVIDENCE).append(',');
            field(json, "timeComplexity", "O(log W + D)").append(',');
            field(json, "selectionMemoryComplexity", "O(D)").append(',');
            json.append("\"jitSteadyStateOrCacheGuarantee\":false,");
            json.append("\"diagnosticOnly\":true}");
            return json.append('}').toString();
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
                            json.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) current));
                        } else {
                            json.append(current);
                        }
                    }
                }
            }
            return json.append('"');
        }
    }

    /* default */ record SubsequentInProcessSummary(int count, long p50Nanos, long p95Nanos,
            long p99Nanos, long maxNanos) {
        SubsequentInProcessSummary {
            if (count <= 0 || p50Nanos < 0L || p95Nanos < p50Nanos
                    || p99Nanos < p95Nanos || maxNanos < p99Nanos) {
                throw new IllegalArgumentException(
                        "subsequent in-process due-selection summary is invalid");
            }
        }

        /* default */ static SubsequentInProcessSummary from(long[] samples) {
            Objects.requireNonNull(samples, "samples");
            if (samples.length == 0) {
                throw new IllegalArgumentException(
                        "subsequent in-process due-selection samples must not be empty");
            }
            long[] ordered = Arrays.copyOf(samples, samples.length);
            Arrays.sort(ordered);
            return new SubsequentInProcessSummary(ordered.length, percentile(ordered, 50),
                    percentile(ordered, 95), percentile(ordered, 99), ordered[ordered.length - 1]);
        }

        private static long percentile(long[] ordered, int percentile) {
            int index = Math.max(0, (int) Math.ceil(percentile * ordered.length / 100.0) - 1);
            return ordered[index];
        }
    }

    /* default */ static final class ContractException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        private final String reasonCode;

        private ContractException(String reasonCode) {
            super("signing due-selection benchmark rejected: code=" + reasonCode);
            this.reasonCode = reasonCode;
        }

        private ContractException(String reasonCode, Throwable cause) {
            super("signing due-selection benchmark rejected: code=" + reasonCode, cause);
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
            super("signing due-selection benchmark failed: code=" + reasonCode);
            this.reasonCode = reasonCode;
        }

        private BenchmarkException(String reasonCode, Throwable cause) {
            super("signing due-selection benchmark failed: code=" + reasonCode, cause);
            this.reasonCode = reasonCode;
        }

        /* default */ String reasonCode() {
            return reasonCode;
        }
    }
}
