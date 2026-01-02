/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevokedRecord;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Filesystem-based reference implementation of {@link PkiStore}.
 *
 * <h2>Consistency and Atomicity Guarantees</h2>
 *
 * <p>
 * This store provides the following guarantees:
 * </p>
 *
 * <ul>
 * <li><strong>Atomic object replacement:</strong> writes of {@code current.bin}
 * are done via a write-to-temp + atomic move (best-effort {@code ATOMIC_MOVE},
 * with a documented fallback when not supported).</li>
 *
 * <li><strong>Write-once enforcement:</strong> objects stored under write-once
 * namespaces (credentials, requests, status objects, policy traces,
 * publications) are never overwritten. A second write to the same identifier
 * fails with {@link IllegalStateException}. This is intentional to surface
 * anomalous behavior for audit and incident analysis.
 *
 * <li><strong>Audit history for mutable entities:</strong> CA records,
 * profiles, and revocations are treated as "mutable but auditable": each update
 * appends an immutable history entry and then updates {@code current.bin}
 * atomically. This supports forensic reconstruction, and snapshot export ("time
 * travel") without mutating the store.</li>
 *
 * <li><strong>Deterministic behavior:</strong> filenames, ordering, and cleanup
 * semantics are deterministic. Cleanup occurs only during writes
 * ({@link FsHistoryPolicy.CleanupStrategy#ON_WRITE}).</li>
 *
 * <li><strong>Single-writer process lock:</strong> an exclusive file lock is
 * held for the lifetime of the instance. Multiple processes can be prevented
 * from concurrently modifying the same root.</li>
 * </ul>
 *
 * <h2>Security Notes</h2>
 *
 * <p>
 * This reference implementation stores objects as-is. It does not implement
 * encryption at rest. It also must not persist private key material; higher
 * layers must respect the SPI security requirements.
 * </p>
 *
 * <p>
 * Logging (JUL) never includes raw serialized bytes or sensitive payloads. Logs
 * are limited to object type, safe IDs, and file operation outcomes.
 * </p>
 */
public final class FilesystemPkiStore implements PkiStore, Closeable {

    private static final Logger LOG = Logger.getLogger(FilesystemPkiStore.class.getName());

    private static final String VERSION_V1 = "v1";

    private final FsPkiStoreOptions options;
    private final FsPaths paths;
    private final AtomicLong historySeq;

    private final FileChannel lockChannel;

    /**
     * Opens or creates a filesystem PKI store rooted at {@code root}.
     *
     * @param root    store root directory
     * @param options implementation options
     * @throws IllegalArgumentException if inputs are null
     * @throws IllegalStateException    if the store cannot be opened or locked
     */
    public FilesystemPkiStore(final Path root, final FsPkiStoreOptions options) {
        this.options = Objects.requireNonNull(options, "options");
        Objects.requireNonNull(root, "root");

        try {
            FsOperations.ensureDir(root);
            this.paths = new FsPaths(root);
            FsOperations.ensureDir(this.paths.lockFile().getParent());

            this.lockChannel = FileChannel.open(this.paths.lockFile(), StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE);
            lockChannel.lock(); // exclusive lock

            ensureVersionFile();
            this.historySeq = new AtomicLong(0L);

            LOG.log(Level.INFO, "running in {0}", root);

        } catch (IOException e) {
            throw new IllegalStateException("failed to open filesystem store at " + root, e);
        }
    }

    /**
     * Exports a snapshot of this store as of time {@code at} into
     * {@code targetRoot}.
     *
     * <p>
     * This method is an implementation-only feature. It does not modify the current
     * store; it clones a new store layout and reconstructs {@code current.bin} for
     * history-tracked entities.
     * </p>
     *
     * @param targetRoot new store root to create/populate
     * @param at         snapshot time (inclusive, "latest &lt;= at")
     * @throws IllegalArgumentException if inputs are null
     * @throws IllegalStateException    if export fails
     */
    public void exportSnapshot(final Path targetRoot, final Instant at) {
        Objects.requireNonNull(targetRoot, "targetRoot");
        Objects.requireNonNull(at, "at");
        new FsSnapshotExporter(this.options).exportSnapshot(this.paths.root(), targetRoot, at);
    }

    @Override
    public void putCa(final CaRecord record) {
        Objects.requireNonNull(record, "record");
        PkiId caId = record.caId();
        Path current = this.paths.caCurrent(caId);

        writeWithHistory(this.paths.caHistoryDir(caId), current, FsCodec.encode(record), this.options.caHistoryPolicy(),
                "CA", FsUtil.safeId(caId));
    }

    @Override
    public Optional<CaRecord> getCa(final PkiId caId) {
        Objects.requireNonNull(caId, "caId");
        Path p = this.paths.caCurrent(caId);
        return readOptional(p, CaRecord.class);
    }

    @Override
    public List<CaRecord> listCas() {
        Path casRoot = this.paths.root().resolve("cas").resolve("by-id");
        return listCurrentRecords(casRoot, CaRecord.class);
    }

    @Override
    public void putCredential(final Credential credential) {
        Objects.requireNonNull(credential, "credential");
        PkiId id = credential.credentialId();
        Path p = this.paths.credentialPath(id);
        writeOnce(p, FsCodec.encode(credential), "CREDENTIAL", FsUtil.safeId(id));
    }

    @Override
    public Optional<Credential> getCredential(final PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        return readOptional(this.paths.credentialPath(credentialId), Credential.class);
    }

    @Override
    public void putRequest(final ParsedCertificationRequest request) {
        Objects.requireNonNull(request, "request");
        PkiId id = request.requestId();
        writeOnce(this.paths.requestPath(id), FsCodec.encode(request), "REQUEST", FsUtil.safeId(id));
    }

    @Override
    public Optional<ParsedCertificationRequest> getRequest(final PkiId requestId) {
        Objects.requireNonNull(requestId, "requestId");
        return readOptional(this.paths.requestPath(requestId), ParsedCertificationRequest.class);
    }

    @Override
    public void putRevocation(final RevokedRecord record) {
        Objects.requireNonNull(record, "record");
        PkiId credId = record.credentialId();
        Path current = this.paths.revocationCurrent(credId);

        writeWithHistory(this.paths.revocationHistoryDir(credId), current, FsCodec.encode(record),
                this.options.revocationHistoryPolicy(), "REVOCATION", FsUtil.safeId(credId));
    }

    @Override
    public Optional<RevokedRecord> getRevocation(final PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        return readOptional(this.paths.revocationCurrent(credentialId), RevokedRecord.class);
    }

    @Override
    public List<RevokedRecord> listRevocations() {
        Path root = this.paths.root().resolve("revocations").resolve("by-credential");
        return listCurrentRecords(root, RevokedRecord.class);
    }

    @Override
    public void putStatusObject(final StatusObject object) {
        Objects.requireNonNull(object, "object");
        PkiId id = object.statusObjectId();
        writeOnce(this.paths.statusObjectPath(id), FsCodec.encode(object), "STATUS_OBJECT", FsUtil.safeId(id));
    }

    @Override
    public Optional<StatusObject> getStatusObject(final PkiId statusObjectId) {
        Objects.requireNonNull(statusObjectId, "statusObjectId");
        return readOptional(this.paths.statusObjectPath(statusObjectId), StatusObject.class);
    }

    @Override
    public List<StatusObject> listStatusObjects(final PkiId issuerCaId) {
        Objects.requireNonNull(issuerCaId, "issuerCaId");

        // Deterministic but coarse: scan all and filter by issuer id.
        // This is acceptable for a reference implementation; indexes can be added
        // later.
        Path byId = this.paths.root().resolve("status").resolve("by-id");
        List<StatusObject> all = listBinaryFiles(byId, StatusObject.class);
        List<StatusObject> out = new ArrayList<>();
        for (StatusObject o : all) {
            if (issuerCaId.equals(o.issuerCaId())) {
                out.add(o);
            }
        }
        return out;
    }

    @Override
    public void putPublicationRecord(final PublicationRecord record) {
        Objects.requireNonNull(record, "record");
        PkiId id = record.publicationId();
        writeOnce(this.paths.publicationPath(id), FsCodec.encode(record), "PUBLICATION", FsUtil.safeId(id));
    }

    @Override
    public List<PublicationRecord> listPublicationRecords() {
        Path byId = this.paths.root().resolve("publications").resolve("by-id");
        return listBinaryFiles(byId, PublicationRecord.class);
    }

    @Override
    public void putProfile(final CertificateProfile profile) {
        Objects.requireNonNull(profile, "profile");
        String profileId = profile.profileId();
        Path current = this.paths.profileCurrent(profileId);

        writeWithHistory(this.paths.profileHistoryDir(profileId), current, FsCodec.encode(profile),
                this.options.profileHistoryPolicy(), "PROFILE", FsUtil.safeSegment(profileId));
    }

    @Override
    public Optional<CertificateProfile> getProfile(final String profileId) {
        if (profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException("profileId must not be null/blank");
        }
        return readOptional(this.paths.profileCurrent(profileId), CertificateProfile.class);
    }

    @Override
    public List<CertificateProfile> listProfiles() {
        Path root = this.paths.root().resolve("profiles").resolve("by-id");
        return listCurrentRecords(root, CertificateProfile.class);
    }

    @Override
    public void putPolicyTrace(final PolicyTrace trace) {
        Objects.requireNonNull(trace, "trace");
        PkiId id = trace.decisionId();
        writeOnce(this.paths.policyTracePath(id), FsCodec.encode(trace), "POLICY_TRACE", FsUtil.safeId(id));
    }

    @Override
    public Optional<PolicyTrace> getPolicyTrace(final PkiId decisionId) {
        Objects.requireNonNull(decisionId, "decisionId");
        return readOptional(this.paths.policyTracePath(decisionId), PolicyTrace.class);
    }

    // -------------------------------------------------------------------------
    // Workflow continuation state (orchestration)
    // -------------------------------------------------------------------------

    @Override
    public void putWorkflowState(final WorkflowStateRecord record) {
        Objects.requireNonNull(record, "record");

        PkiId opId = record.opId();
        Path current = this.paths.workflowCurrent(opId);

        // Never log payload; writeWithHistory logs only type + safe identifiers.
        writeWithHistory(this.paths.workflowHistoryDir(opId), current, FsCodec.encode(record),
                this.options.workflowHistoryPolicy(), "WORKFLOW", FsUtil.safeId(opId));
    }

    @Override
    public Optional<WorkflowStateRecord> getWorkflowState(final PkiId opId) {
        Objects.requireNonNull(opId, "opId");
        return readOptional(this.paths.workflowCurrent(opId), WorkflowStateRecord.class);
    }

    @Override
    public void deleteWorkflowState(final PkiId opId) {
        Objects.requireNonNull(opId, "opId");
        Path current = this.paths.workflowCurrent(opId);

        try {
            Files.deleteIfExists(current);
        } catch (IOException e) {
            throw new IllegalStateException("failed to delete workflow state opId=" + FsUtil.safeId(opId), e);
        }
    }

    @Override
    public List<WorkflowStateRecord> listWorkflowStates() {
        // List by operation directory (workflows/by-op/<opId>/current.bin)
        return listCurrentRecords(this.paths.workflowRoot(), WorkflowStateRecord.class);
    }

    @Override
    public void close() throws IOException {
        synchronized (this.lockChannel) { // NOPMD
            if (this.lockChannel.isOpen()) {
                this.lockChannel.close();
            }
        }
    }

    private void ensureVersionFile() throws IOException {
        Path vf = this.paths.versionFile();
        if (!Files.exists(vf)) {
            FsOperations.writeAtomic(vf, VERSION_V1.getBytes());
            return;
        }
        String ver = Files.readString(vf).trim();
        if (!VERSION_V1.equals(ver)) {
            throw new IllegalStateException("unsupported store version: " + ver);
        }
    }

    private static <T> Optional<T> readOptional(final Path path, final Class<T> type) {
        try {
            if (!Files.exists(path)) {
                return Optional.empty();
            }
            byte[] data = FsOperations.readAll(path);
            return Optional.of(FsCodec.decode(data, type));
        } catch (IOException e) {
            throw new IllegalStateException("read failed: " + path, e);
        }
    }

    private static <T> List<T> listBinaryFiles(final Path byIdDir, final Class<T> type) {
        if (!Files.isDirectory(byIdDir)) {
            return List.of();
        }
        try {
            return Files.list(byIdDir).filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString())).map(p -> {
                        try {
                            return FsCodec.decode(FsOperations.readAll(p), type);
                        } catch (IOException e) {
                            throw new IllegalStateException("read failed: " + p, e);
                        }
                    }).toList();
        } catch (IOException e) {
            throw new IllegalStateException("list failed: " + byIdDir, e);
        }
    }

    private static <T> List<T> listCurrentRecords(final Path byIdDir, final Class<T> type) {
        if (!Files.isDirectory(byIdDir)) {
            return List.of();
        }
        try {
            List<Path> entityDirs = Files.list(byIdDir).filter(Files::isDirectory)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString())).toList();

            List<T> out = new ArrayList<>();
            for (Path entityDir : entityDirs) {
                Path current = entityDir.resolve(FsPaths.CURRENT_FILE);
                if (Files.exists(current)) {
                    out.add(FsCodec.decode(FsOperations.readAll(current), type));
                }
            }
            return out;
        } catch (IOException e) {
            throw new IllegalStateException("list current records failed: " + byIdDir, e);
        }
    }

    private static void writeOnce(final Path target, final byte[] data, final String kind, final String safeId) {
        try {
            FsOperations.ensureDir(target.getParent());
            if (Files.exists(target)) {
                throw new IllegalStateException(kind + " is write-once; already exists: " + safeId);
            }
            FsOperations.writeNew(target, data);
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "{0} stored (write-once): {1}", new Object[] { kind, safeId });
            }
        } catch (FileAlreadyExistsException e) {
            throw new IllegalStateException(kind + " is write-once; already exists: " + safeId, e);
        } catch (IOException e) {
            throw new IllegalStateException("write-once store failed: " + kind + " " + safeId, e);
        }
    }

    private void writeWithHistory(final Path historyDir, final Path currentFile, final byte[] data,
            final FsHistoryPolicy policy, final String kind, final String safeId) {

        try {
            FsOperations.ensureDir(currentFile.getParent());

            if (policy.enabled()) {
                FsOperations.ensureDir(historyDir);
                Path entry = historyDir.resolve(historyFileName(Instant.now(), this.historySeq.incrementAndGet()));
                FsOperations.writeAtomic(entry, data);

                if (policy.cleanupStrategy() == FsHistoryPolicy.CleanupStrategy.ON_WRITE) {
                    cleanupHistory(historyDir, policy.retentionWindow());
                }
            }

            FsOperations.writeAtomic(currentFile, data);
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "{0} stored/updated: {1}", new Object[] { kind, safeId });
            }

        } catch (IOException e) {
            throw new IllegalStateException("store failed: " + kind + " " + safeId, e);
        }
    }

    private static String historyFileName(final Instant now, final long seq) {
        long tsMicros = now.getEpochSecond() * 1_000_000L + (now.getNano() / 1_000);
        return tsMicros + "-" + seq + ".bin";
    }

    private static void cleanupHistory(final Path historyDir, final Optional<Duration> retentionWindow) {
        if (retentionWindow.isEmpty()) {
            return;
        }
        Duration window = retentionWindow.get();
        Instant cutoff = Instant.now().minus(window);

        try {
            Files.list(historyDir).filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString())).forEach(p -> {
                        String name = p.getFileName().toString();
                        int dash = name.indexOf('-');
                        if (dash <= 0) {
                            return;
                        }
                        String tsPart = name.substring(0, dash);
                        try {
                            long tsMicros = Long.parseLong(tsPart);
                            Instant entryTime = Instant.ofEpochSecond(tsMicros / 1_000_000L,
                                    (tsMicros % 1_000_000L) * 1_000L); // NOPMD
                            if (entryTime.isBefore(cutoff)) {
                                Files.deleteIfExists(p);
                            }
                        } catch (NumberFormatException | IOException ignored) {
                            // deterministic best-effort; never fail a write due to cleanup
                        }
                    });
        } catch (IOException ignored) {
            // deterministic best-effort
        }
    }
}
