/*
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
 */
package zeroecho.pki.server;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import zeroecho.pki.api.backup.BackupLimits;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.http.StrictJson;

/**
 * Explicit, opt-in budgets for remote backup transfer. No enabled defaults exist.
 * The separate document preserves the schema and record shape of the server
 * configuration. Artifact storage must be outside the replaceable PKI root,
 * in a pre-existing, durably provisioned directory accessible only to its owner.
 *
 * <p>Workspace bytes are an admission reservation, not an operating-system disk
 * quota. Administrators must provision recovery/index headroom and filesystem
 * quotas in addition to the archive and expansion limits.</p>
 *
 * @param directory exclusively owned artifact directory
 * @param maximumArchiveBytes compressed bytes allowed in one transfer
 * @param maximumRetainedBytes total reserved compressed artifact bytes
 * @param maximumArtifacts maximum live descriptors, including incomplete uploads
 * @param maximumConcurrentJobs maximum simultaneous transfer or domain jobs
 * @param maximumWorkspaceBytes aggregate domain-workspace admission budget
 * @param lifetime lifetime measured from artifact reservation, not last access
 * @param transferTimeout maximum duration of one network transfer
 * @param browserOrigin exact origin allowed to submit browser transfer requests
 */
public record BackupTransferConfiguration(Path directory, long maximumArchiveBytes,
        long maximumRetainedBytes, int maximumArtifacts, int maximumConcurrentJobs,
        long maximumWorkspaceBytes, Duration lifetime, Duration transferTimeout,
        URI browserOrigin) {
    /** Version of the separate transfer configuration document. */
    public static final int VERSION = 1;
    private static final int CONFIGURATION_LIMIT = 16_384;
    private static final Set<String> FIELDS = Set.of("version", "directory", "maximumArchiveBytes",
            "maximumRetainedBytes", "maximumArtifacts", "maximumConcurrentJobs",
            "maximumWorkspaceBytes", "lifetimeSeconds", "transferTimeoutSeconds", "browserOrigin");

    /** Validates mandatory budgets without creating directories or opening stores. */
    public BackupTransferConfiguration {
        directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
        Objects.requireNonNull(lifetime, "lifetime");
        Objects.requireNonNull(transferTimeout, "transferTimeout");
        Objects.requireNonNull(browserOrigin, "browserOrigin");
        BackupLimits limits = BackupLimits.defaults();
        if (directory.getParent() == null || maximumArchiveBytes < 1
                || maximumArchiveBytes > limits.compressedBytes()
                || maximumRetainedBytes < maximumArchiveBytes
                || maximumArtifacts < 1 || maximumArtifacts > 4096
                || maximumConcurrentJobs < 1 || maximumConcurrentJobs > maximumArtifacts
                || maximumWorkspaceBytes < maximumArchiveBytes + 2 * limits.expandedBytes()
                || lifetime.isNegative() || lifetime.isZero() || lifetime.compareTo(Duration.ofDays(7)) > 0
                || transferTimeout.isNegative() || transferTimeout.isZero()
                || transferTimeout.compareTo(lifetime) > 0
                || transferTimeout.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("Invalid backup transfer budget");
        }
        boolean https = "https".equals(browserOrigin.getScheme());
        boolean loopbackHttp = "http".equals(browserOrigin.getScheme())
                && browserOrigin.getHost() != null
                && Set.of("127.0.0.1", "localhost", "[::1]").contains(browserOrigin.getHost()); // NOPMD AvoidUsingHardCodedIP - Loopback is an explicit trusted-proxy allowlist boundary, not a deployment endpoint.
        if (!(https || loopbackHttp) || browserOrigin.getHost() == null
                || browserOrigin.getRawUserInfo() != null || browserOrigin.getRawQuery() != null
                || browserOrigin.getRawFragment() != null || !browserOrigin.getRawPath().isEmpty()) {
            throw new IllegalArgumentException("Invalid backup browser origin");
        }
    }

    /**
     * Returns the minimum reservation for one verification or restore job.
     * Recovery/index workspace above this floor remains part of the operator's
     * provisioned filesystem headroom.
     * @return archive plus two maximum expanded trees, in bytes
     */
    public long workspaceReservationBytes() {
        return maximumArchiveBytes + 2 * BackupLimits.defaults().expandedBytes();
    }

    /**
     * Reads an explicit bounded configuration. Every field is mandatory.
     * @param path configuration file
     * @return validated immutable settings
     * @throws IOException if reading fails or the document exceeds its byte limit
     * @throws IllegalArgumentException if fields, types or budgets are invalid
     */
    public static BackupTransferConfiguration read(Path path) throws IOException {
        byte[] bytes;
        try (java.io.InputStream input = Files.newInputStream(path)) {
            bytes = input.readNBytes(CONFIGURATION_LIMIT + 1);
        }
        if (bytes.length > CONFIGURATION_LIMIT) {
            throw new IOException("Backup transfer configuration too large");
        }
        return decode(bytes);
    }

    /**
     * Parses a closed version-1 transfer configuration.
     * @param bytes bounded UTF-8 JSON
     * @return validated settings
     * @throws IllegalArgumentException if the document is invalid
     */
    public static BackupTransferConfiguration decode(byte[] bytes) {
        if (!(StrictJson.parse(bytes, CONFIGURATION_LIMIT) instanceof PkiOperationValue.ObjectValue object)
                || !object.fields().keySet().equals(FIELDS)) {
            throw new IllegalArgumentException("Invalid backup transfer configuration");
        }
        Map<String, PkiOperationValue> fields = object.fields();
        if (number(fields, "version") != VERSION) {
            throw new IllegalArgumentException("Unknown backup transfer version");
        }
        return new BackupTransferConfiguration(Path.of(text(fields, "directory")),
                number(fields, "maximumArchiveBytes"), number(fields, "maximumRetainedBytes"),
                integer(fields, "maximumArtifacts"),
                integer(fields, "maximumConcurrentJobs"),
                number(fields, "maximumWorkspaceBytes"),
                Duration.ofSeconds(number(fields, "lifetimeSeconds")),
                Duration.ofSeconds(number(fields, "transferTimeoutSeconds")),
                URI.create(text(fields, "browserOrigin")));
    }

    private static long number(Map<String, PkiOperationValue> fields, String key) {
        if (fields.get(key) instanceof PkiOperationValue.IntegerValue value) {
            return value.value();
        }
        throw new IllegalArgumentException("Invalid backup transfer numeric field");
    }

    private static int integer(Map<String, PkiOperationValue> fields, String key) {
        long value = number(fields, key);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Backup transfer integer out of range");
        }
        return (int) value;
    }

    private static String text(Map<String, PkiOperationValue> fields, String key) {
        if (fields.get(key) instanceof PkiOperationValue.Text value) {
            return value.value();
        }
        throw new IllegalArgumentException("Invalid backup transfer text field");
    }
}
