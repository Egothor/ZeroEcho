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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;

/** Fixed report emitted only for the pre-work unsupported group-size boundary. */
final class SigningContractRejectionReport {
    static final String SCHEMA = "zeroecho-signing-contract-rejection-v1";

    private SigningContractRejectionReport() {
    }

    static void write(SigningBenchmarkConfig configuration, String reasonCode) throws IOException {
        Objects.requireNonNull(configuration, "configuration");
        if (!"UNSUPPORTED_MAX_32".equals(reasonCode)) {
            throw new IllegalArgumentException("unsupported signing rejection report reason");
        }
        Path output = configuration.output();
        Path workRoot = configuration.workRoot();
        if (output.equals(workRoot) || output.startsWith(workRoot)) {
            throw new IOException("signing rejection report output is invalid");
        }
        Path parent = output.getParent();
        if (parent == null) {
            throw new IOException("signing rejection report output is invalid");
        }
        Files.createDirectories(parent);
        if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("signing rejection report output is invalid");
        }
        Files.writeString(output, toJson(configuration, reasonCode) + System.lineSeparator(),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS);
    }

    static String toJson(SigningBenchmarkConfig configuration, String reasonCode) {
        StringBuilder json = new StringBuilder(1024).append('{');
        field(json, "schema", SCHEMA).append(',');
        field(json, "reasonCode", reasonCode).append(',');
        json.append("\"exitCode\":1,\"workRootCreated\":false,");
        field(json, "configurationFingerprint", configuration.argumentsFingerprint()).append(',');
        json.append("\"configuration\":{");
        field(json, "profile", configuration.profile()).append(',');
        field(json, "target", configuration.targetMode().commandValue()).append(',');
        field(json, "cellId", configuration.cellId()).append(',');
        field(json, "cellMode", configuration.cellMode().commandValue()).append(',');
        number(json, "retainedPopulation", configuration.retainedPopulation()).append(',');
        number(json, "activePopulation", configuration.activePopulation()).append(',');
        number(json, "groupSize", configuration.groupSize()).append(',');
        number(json, "residentIndexBudgetBytes", configuration.residentIndexBudgetBytes()).append(',');
        number(json, "warmupSeconds", configuration.warmupSeconds()).append(',');
        number(json, "durationSeconds", configuration.durationSeconds()).append(',');
        number(json, "rate", configuration.rate()).append(',');
        number(json, "lanes", configuration.lanes()).append(',');
        number(json, "queueCapacity", configuration.queueCapacity()).append(',');
        number(json, "providerMeanMillis", configuration.providerMeanMillis()).append(',');
        number(json, "providerJitterMillis", configuration.providerJitterMillis()).append(',');
        number(json, "payloadBytes", configuration.payloadBytes()).append(',');
        number(json, "sampleCapacity", configuration.sampleCapacity()).append(',');
        number(json, "drainSeconds", configuration.drainSeconds()).append(',');
        number(json, "seed", configuration.seed()).append(',');
        bool(json, "diagnosticEnvironmentOverride",
                configuration.diagnosticEnvironmentOverride()).append(',');
        field(json, "output", configuration.output().toString()).append(',');
        field(json, "workRoot", configuration.workRoot().toString()).append("}}");
        return json.toString();
    }

    private static StringBuilder field(StringBuilder json, String name, String value) {
        quote(json, name).append(':');
        return quote(json, value);
    }

    private static StringBuilder number(StringBuilder json, String name, long value) {
        return quote(json, name).append(':').append(value);
    }

    private static StringBuilder bool(StringBuilder json, String name, boolean value) {
        return quote(json, name).append(':').append(value);
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
