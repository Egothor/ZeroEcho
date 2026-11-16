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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.backup.BackupSource;

/**
 * Realm-owned durable transfer spool. Callers authorize each action before using
 * this repository; ownership checks here supplement, never replace, authorization.
 * Metadata operations are serialized. File bodies use one 64 KiB buffer per job.
 * Retained metadata is O(configured artifact count); transfers take O(bytes) time.
 * A failed durable publication fences this instance until restart.
 */
final class BackupArtifactRepository implements AutoCloseable { // NOPMD CyclomaticComplexity - One spool owner guards artifacts, leases, budgets and recovery; individual methods remain checked.
    private static final String PROCESS_LOCK_FILE = "process.lock";
    private static final int MINIMUM_METADATA_BYTES = 40;
    private static final String ARCHIVE_SUFFIX = ".zip";


    private static final int MAGIC = 0x5a454241;
    private static final int VERSION = 1;
    private static final int METADATA_LIMIT = 16_384;
    private final BackupTransferConfiguration configuration;
    private final String realm;
    private final Clock clock;
    private final SecureRandom random;
    private final Observer observer;
    private final Map<String, Descriptor> artifacts = new HashMap<>();
    private final Map<String, Lease> leases = new HashMap<>();
    private final FileChannel lockChannel;
    private final FileLock processLock;
    private boolean closed;
    private boolean fenced;
    private long reservedBytes;
    private long workspaceBytes;
    private int preparationJobs;
    /**
     * Durable publication boundaries exposed to deterministic fault injection.
     */
    /* default */ enum Phase {
        /**
         * The temporary metadata file has been forced to durable storage.
         */
        METADATA_FORCED,
        /**
         * The metadata file has been atomically published under its retained name.
         */
        METADATA_RENAMED,
        /**
         * The spool directory has been forced after a metadata or file change.
         */
        DIRECTORY_FORCED,
        /**
         * Artifact deletion is about to begin.
         */
        BEFORE_DELETE
    }
    /**
     * Receives durable publication boundaries without changing their ordering.
     */
    /* default */ @FunctionalInterface interface Observer {
        /**
         * Observes one boundary.
         * @param phase completed or imminent persistence boundary
         * @throws IOException when an injected failure interrupts publication
         */
        void at(Phase phase) throws IOException;
    }
    /**
     * Direction in which an artifact crosses the server boundary.
     */
    /* default */ enum Purpose {
        /**
         * Archive bytes are uploaded into the server restore spool.
         */
        IMPORT,
        /**
         * Archive bytes are prepared for download from the server.
         */
        EXPORT
    }
    /**
     * Persisted lifecycle states of a transfer and its restore workflow.
     */
    /* default */ enum State {
        /**
         * Archive capacity is reserved but bytes have not been received.
         */
        RESERVED,
        /**
         * Archive bytes are being received and verified.
         */
        RECEIVING,
        /**
         * The complete archive is retained and ready for manifest verification.
         */
        READY,
        /**
         * The retained archive is being verified by the domain backup service.
         */
        VERIFYING,
        /**
         * The archive manifest has been verified.
         */
        VERIFIED,
        /**
         * A domain restore attempt has started and its result is not yet reconciled.
         */
        RESTORING,
        /**
         * Restore state is staged but not yet activated.
         */
        STAGED,
        /**
         * The restore has been activated successfully.
         */
        ACTIVATED,
        /**
         * The restore was rejected without an unresolved outcome.
         */
        REJECTED,
        /**
         * The archive transfer failed.
         */
        FAILED,
        /**
         * The restore outcome requires authoritative reconciliation.
         */
        UNCERTAIN,
        /**
         * The resolved workflow was acknowledged and can be cleaned up.
         */
        CONSUMED
    }

    /**
     * Durable artifact identity, ownership, byte commitment and restore lifecycle snapshot.
     *
     * @param handle opaque 64-character lowercase hexadecimal transfer handle
     * @param owner principal that owns the transfer
     * @param realm realm in which the transfer was reserved
     * @param purpose import or export direction
     * @param backupId domain backup identity
     * @param length expected archive size in bytes; positive
     * @param sha256 lowercase hexadecimal SHA-256 of the archive
     * @param manifest verified manifest commitment, or empty before verification
     * @param expiresAt absolute artifact expiry
     * @param state retained transfer or restore state
     * @param archiveRetained whether archive bytes remain owned by this repository
     * @param restoreId current canonical restore UUID, or empty before restore
     * @param previousRestoreId prior canonical restore UUID, or empty if none
     */
    /* default */ record Descriptor(String handle, String owner, String realm, Purpose purpose,
            PkiId backupId, long length, String sha256, String manifest,
            Instant expiresAt, State state, boolean archiveRetained, String restoreId, String previousRestoreId) {
        /**
         * Validates descriptor syntax before metadata can be persisted.
         *
         * @param handle opaque transfer handle
         * @param owner owning principal
         * @param realm owning realm
         * @param purpose transfer direction
         * @param backupId source backup identity
         * @param length positive archive size in bytes
         * @param sha256 archive SHA-256 commitment
         * @param manifest manifest SHA-256 commitment, or empty
         * @param expiresAt absolute artifact expiry
         * @param state persisted lifecycle state
         * @param archiveRetained whether archive bytes remain retained
         * @param restoreId current restore UUID, or empty
         * @param previousRestoreId preceding restore UUID, or empty
         * @throws IllegalArgumentException if a coordinate, commitment, length or restore identity is invalid
         * @throws NullPointerException if the manifest is null
         */
        Descriptor {
            if (!token(handle) || !bounded(owner) || !bounded(realm) || backupId == null
                    || !bounded(backupId.value()) || length < 1 || !digest(sha256)
                    || !(manifest.isEmpty() || digest(manifest)) || purpose == null
                    || expiresAt == null || state == null || restoreId == null
                    || !optionalUuid(restoreId) || !optionalUuid(previousRestoreId)
                    || !restoreId.isEmpty() && restoreId.equals(previousRestoreId)) {
                throw new IllegalArgumentException("Invalid backup artifact descriptor");
            }
        }
        /**
         * Copies this descriptor with a new workflow state and manifest commitment.
         *
         * @param next replacement lifecycle state
         * @param commitment replacement manifest SHA-256, or empty before verification
         * @return validated replacement retaining archive and restore coordinates
         * @throws IllegalArgumentException if the replacement state or commitment is invalid
         * @throws NullPointerException if the commitment is null
         */
        /* default */ Descriptor state(State next, String commitment) {
            return new Descriptor(handle, owner, realm, purpose, backupId, length, sha256,
                    commitment, expiresAt, next, archiveRetained, restoreId, previousRestoreId);
        }
        /**
         * Copies metadata after archive bytes have been removed.
         *
         * @return replacement with {@code archiveRetained} set to false
         */
        /* default */ Descriptor withoutArchive() {
            return new Descriptor(handle, owner, realm, purpose, backupId, length, sha256,
                    manifest, expiresAt, state, false, restoreId, previousRestoreId);
        }
        /**
         * Binds a restore attempt to the artifact without discarding the previous attempt identity.
         *
         * @param expected canonical UUID of the new restore attempt
         * @param prior prior canonical restore UUID, or empty
         * @return replacement in {@link State#RESTORING}
         * @throws IllegalArgumentException if either UUID is invalid or the identities are equal
         */
        /* default */ Descriptor restoring(String expected, String prior) {
            return new Descriptor(handle, owner, realm, purpose, backupId, length, sha256,
                    manifest, expiresAt, State.RESTORING, archiveRetained, expected, prior);
        }
        /**
         * {@inheritDoc}
         */
        @Override public String toString() { return "BackupArtifactDescriptor[redacted]"; }
    }
    private static boolean optionalUuid(String value) {
        if (value == null) {
            return false;
        }
        if (value.isEmpty()) {
            return true;
        }
        try { return java.util.UUID.fromString(value).toString().equals(value); }
        catch (IllegalArgumentException invalid) { return false; }
    }

    // Snapshots persisted restore states under the artifact-map monitor.
    /**
     * Snapshots restores that still need authoritative result reconciliation.
     *
     * @return immutable list of staged or uncertain restore descriptors
     * @throws IOException if the repository is closed or fenced
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized java.util.List<Descriptor> unresolvedRestores() throws IOException {
        requireOpen();
        return artifacts.values().stream().filter(value -> value.state() == State.UNCERTAIN
                || value.state() == State.STAGED).toList();
    }

    // Keeps descriptor rejection, durable publication and retained-byte accounting atomic.
    /**
     * Durably rejects the exact unresolved descriptor when no transfer work is active.
     *
     * @param expected unchanged retained descriptor to reject
     * @throws IOException if the repository is unavailable, the snapshot is stale,
     *         work is active or durable publication fails
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized void rejectUnpublished(Descriptor expected) throws IOException {
        requireOpen();
        if (!expected.equals(artifacts.get(expected.handle())) || !leases.isEmpty() || preparationJobs != 0) {
            throw new IOException("BACKUP_RESTORE_OUTCOME_UNCERTAIN");
        }
        Descriptor rejected = expected.state(State.REJECTED, expected.manifest());
        publish(rejected);
        artifacts.put(rejected.handle(), rejected);
    }

    /**
     * Opens and exclusively locks a private durable artifact spool, recovering retained workflows.
     *
     * @param configuration spool location and storage/concurrency budgets
     * @param realm owning bounded realm identity
     * @param clock source of absolute expiry times
     * @param random source of opaque transfer-handle entropy
     * @throws IOException if the directory is not private, is already locked or cannot be recovered
     * @throws IllegalArgumentException if the realm identity is invalid
     */
    /* default */ BackupArtifactRepository(BackupTransferConfiguration configuration, String realm,
            Clock clock, SecureRandom random) throws IOException {
        this(configuration, realm, clock, random, phase -> { });
    }

    /**
     * Opens a durable artifact spool with a deterministic persistence observer.
     *
     * @param configuration spool location and storage/concurrency budgets
     * @param realm owning bounded realm identity
     * @param clock source of absolute expiry times
     * @param random source of opaque transfer-handle entropy
     * @param observer observer of publication and deletion boundaries
     * @throws IOException if the directory cannot be exclusively opened or recovered
     * @throws IllegalArgumentException if the realm identity is invalid
     */
    /* default */ BackupArtifactRepository(BackupTransferConfiguration configuration, String realm,
            Clock clock, SecureRandom random, Observer observer) throws IOException {
        this.configuration = configuration;
        this.realm = realm;
        this.clock = clock;
        this.random = random;
        this.observer = observer;
        if (!bounded(realm)) {
            throw new IllegalArgumentException("Invalid backup realm");
        }
        requirePrivateDirectory(configuration.directory());
        lockChannel = FileChannel.open(path(PROCESS_LOCK_FILE), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock acquired = null; // NOPMD CloseResource - Ownership transfers to processLock; constructor failure and repository close release it.
        try {
            acquired = lockChannel.tryLock();
            if (acquired == null) {
                throw new IOException("Backup artifact directory is already in use");
            }
            processLock = acquired;
            recover();
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            try (lockChannel) {
                if (acquired != null) {
                    acquired.close();
                }
            }
            throw failure;
        }
    }

    // Keeps capacity checks, artifact publication and reserved-byte accounting atomic.
    /**
     * Reserves archive capacity and publishes a new owner-bound transfer descriptor.
     *
     * <p>Expired artifacts are cleaned before budget checks. No archive bytes are received.</p>
     *
     * @param owner principal owning the transfer
     * @param purpose import or export direction
     * @param backupId source backup identity
     * @param length expected archive size in bytes
     * @param sha256 expected lowercase hexadecimal archive SHA-256
     * @return durably reserved descriptor with an unpredictable handle
     * @throws IOException if capacity is exhausted or cleanup/publication fails
     * @throws IllegalArgumentException if descriptor inputs are invalid
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized Descriptor reserve(String owner, Purpose purpose, PkiId backupId,
            long length, String sha256) throws IOException {
        requireOpen();
        cleanup();
        if (length < 1 || length > configuration.maximumArchiveBytes()
                || artifacts.size() >= configuration.maximumArtifacts()
                || length > configuration.maximumRetainedBytes() - reservedBytes) {
            throw new IOException("BACKUP_ARTIFACT_BUDGET_EXCEEDED");
        }
        byte[] entropy = new byte[32];
        String handle;
        do {
            random.nextBytes(entropy);
            handle = HexFormat.of().formatHex(entropy);
        } while (artifacts.containsKey(handle));
        Descriptor descriptor = new Descriptor(handle, owner, realm, purpose, backupId, length, sha256,
                "", clock.instant().plus(configuration.lifetime()), State.RESERVED, true, "", "");
        publish(descriptor);
        artifacts.put(handle, descriptor);
        reservedBytes += length;
        return descriptor;
    }

    // Reads ownership, expiry and artifact state under the same monitor as cleanup.
    /**
     * Finds a live owner-bound artifact whose archive remains retained.
     *
     * @param owner principal that must own the transfer
     * @param handle opaque artifact handle
     * @return retained, unexpired artifact descriptor
     * @throws IOException if the repository or artifact is unavailable, expired or owned by another principal
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized Descriptor inspect(String owner, String handle) throws IOException {
        Descriptor descriptor = workflow(owner, handle);
        if (!clock.instant().isBefore(descriptor.expiresAt()) || !descriptor.archiveRetained()) {
            throw new IOException("BACKUP_ARTIFACT_UNAVAILABLE");
        }
        return descriptor;
    }

    // Reads workflow ownership and terminal state under the same monitor as transitions.
    /**
     * Finds retained workflow metadata independently of archive expiry.
     *
     * @param owner principal that must own the transfer
     * @param handle opaque artifact handle
     * @return unconsumed workflow descriptor belonging to this realm and owner
     * @throws IOException if the repository is unavailable or no matching unconsumed workflow exists
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized Descriptor workflow(String owner, String handle) throws IOException {
        requireOpen();
        Descriptor descriptor = artifacts.get(handle);
        if (!token(handle) || descriptor == null || !descriptor.owner().equals(owner)
                || !descriptor.realm().equals(realm)
                || descriptor.state() == State.CONSUMED) {
            throw new IOException("BACKUP_ARTIFACT_UNAVAILABLE");
        }
        return descriptor;
    }

    /**
     * Receives and verifies an archive under an exclusive artifact lease.
     *
     * <p>The caller retains ownership of the input and must close it, including on deadline expiry.</p>
     *
     * @param owner principal owning the reserved artifact
     * @param handle reserved artifact handle
     * @param input archive stream; not closed by this method
     * @throws IOException if the artifact cannot be leased, the size/hash differs,
     *         transfer is interrupted or durable publication fails
     */
    /* default */ void receive(String owner, String handle, InputStream input) throws IOException {
        try (Lease lease = source(owner, handle, State.RESERVED, false)) {
            receive(lease, input);
        }
    }

    /**
     * Streams a leased archive into the spool and publishes it only after size/hash verification.
     *
     * <p>The lease transitions through receiving to ready; an I/O failure marks it failed
     * unless durable publication has fenced the repository.</p>
     *
     * @param lease active exclusive lease; remains owned by the caller
     * @param input archive stream; remains owned by the caller
     * @throws IOException if reading, persistence or commitment verification fails, or transfer is interrupted
     */
    /* default */ void receive(Lease lease, InputStream input) throws IOException {
        Descriptor descriptor = lease.descriptor();
        String handle = descriptor.handle();
        lease.transition(State.RECEIVING, "");
        try {
            MessageDigest hash = hash();
            long count = 0;
            byte[] buffer = new byte[65_536];
            try (FileChannel output = FileChannel.open(path(handle + ".part"),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                int size;
                while ((size = input.read(buffer)) != -1) {
                    if (Thread.currentThread().isInterrupted()) { // NOPMD DoNotUseThreads - Observes caller cancellation while owning a bounded lease; this standalone component creates no thread.
                        throw new IOException("BACKUP_TRANSFER_CANCELLED");
                    }
                    if (size > descriptor.length() - count) {
                        throw new IOException("BACKUP_ARCHIVE_SIZE_MISMATCH");
                    }
                    hash.update(buffer, 0, size);
                    ByteBuffer bytes = ByteBuffer.wrap(buffer, 0, size);
                    while (bytes.hasRemaining()) {
                        output.write(bytes);
                    }
                    count += size;
                }
                if (count != descriptor.length()
                        || !HexFormat.of().formatHex(hash.digest()).equals(descriptor.sha256())) {
                    throw new IOException("BACKUP_ARCHIVE_COMMITMENT_MISMATCH");
                }
                output.force(true);
            }
            Files.move(path(handle + ".part"), path(handle + ARCHIVE_SUFFIX), StandardCopyOption.ATOMIC_MOVE);
            forceDirectory();
            lease.transition(State.READY, "");
        } catch (IOException failure) { // NOPMD ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            boolean interrupted = Thread.interrupted(); // NOPMD DoNotUseThreads - Observes caller cancellation while owning a bounded lease; this standalone component creates no thread.
            try {
                synchronized (this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
                    if (!fenced) {
                        lease.transition(State.FAILED, "");
                    }
                }
            } finally {
                if (interrupted) {
                    Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Restores caller cancellation after interruption; this standalone component creates no thread.
                }
            }
            throw failure;
        }
    }

    // Atomically acquires an artifact lease and its workspace reservation.
    /**
     * Acquires an exclusive artifact lease and optionally reserves restore workspace.
     *
     * @param owner principal owning the artifact
     * @param handle live artifact handle
     * @param expected required current artifact state
     * @param workspace whether to reserve the configured workspace budget
     * @return lease that the caller must close
     * @throws IOException if the artifact is unavailable, state differs or concurrency/workspace budgets are
     *         exhausted
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized Lease source(String owner, String handle, State expected, boolean workspace) throws IOException {
        Descriptor descriptor = inspect(owner, handle);
        long reservation = configuration.workspaceReservationBytes();
        if (descriptor.state() != expected || leases.containsKey(handle)) {
            throw new IOException("BACKUP_ARTIFACT_STATE");
        }
        if (leases.size() + preparationJobs >= configuration.maximumConcurrentJobs()
                || workspace && reservation > configuration.maximumWorkspaceBytes() - workspaceBytes) {
            throw new IOException("BACKUP_TRANSFER_BUSY");
        }
        Lease lease = new Lease(descriptor, workspace);
        leases.put(handle, lease);
        if (workspace) {
            workspaceBytes += reservation;
        }
        return lease;
    }

    // Reserves the bounded preparation-job slot and workspace before handing off ownership.
    /**
     * Reserves one preparation slot and its configured workspace budget.
     *
     * @return preparation owner that must be closed or handed off to an artifact lease
     * @throws IOException if the repository is unavailable or concurrency/workspace budgets are exhausted
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized PreparationJob prepare() throws IOException {
        requireOpen();
        long reservation = configuration.workspaceReservationBytes();
        if (leases.size() + preparationJobs >= configuration.maximumConcurrentJobs()
                || reservation > configuration.maximumWorkspaceBytes() - workspaceBytes) {
            throw new IOException("BACKUP_TRANSFER_BUSY");
        }
        preparationJobs++;
        workspaceBytes += reservation;
        return new PreparationJob();
    }

    // Serializes restore-result reconciliation with artifact state publication.
    /**
     * Reconciles a retained restore workflow with an exact authoritative domain result.
     *
     * @param owner principal owning the workflow
     * @param handle retained artifact handle
     * @param identity observed restore identity and status
     * @return current descriptor, or durably updated descriptor when the restore coordinates match
     * @throws IOException if the workflow is unavailable or updated metadata cannot be persisted
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized Descriptor reconcile(String owner, String handle,
            zeroecho.pki.api.backup.RestoreIdentity identity) throws IOException {
        Descriptor current = workflow(owner, handle);
        if (!restoreWorkflow(current.state()) || leases.containsKey(handle)) {
            return current;
        }
        if (!current.backupId().equals(identity.sourceBackupId())
                || !current.manifest().equals(identity.manifestSha256())
                || !current.restoreId().equals(identity.status().restoreId().value())) {
            return current;
        }
        State state = switch (identity.status().state()) {
            case STAGED -> State.STAGED;
            case ACTIVATED -> State.ACTIVATED;
            case FAILED -> State.REJECTED;
            case UNCERTAIN -> State.UNCERTAIN;
        };
        Descriptor next = current.state(state, current.manifest());
        publish(next);
        artifacts.put(handle, next);
        return next;
    }

    // Serializes workflow acknowledgement with cleanup and retained-byte release.
    /**
     * Acknowledges a resolved restore workflow and releases its retained archive through cleanup.
     *
     * @param owner principal owning the workflow
     * @param handle artifact whose workflow is activated or rejected
     * @throws IOException if the workflow is unresolved, leased, unavailable or cannot be durably consumed
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized void acknowledge(String owner, String handle) throws IOException {
        Descriptor current = workflow(owner, handle);
        if (leases.containsKey(handle) || current.state() != State.ACTIVATED && current.state() != State.REJECTED) {
            throw new IOException("BACKUP_RESTORE_OUTCOME_UNRESOLVED");
        }
        Descriptor consumed = current.state(State.CONSUMED, current.manifest());
        publish(consumed);
        artifacts.put(handle, consumed);
        cleanup();
    }

    private void release(String handle, boolean workspace) {
        if (leases.remove(handle) != null && workspace) {
            workspaceBytes -= configuration.workspaceReservationBytes();
        }
        notifyAll();
    }

    // Protects artifact/lease maps and retained-byte accounting during durable cleanup.
    /**
     * Removes eligible expired/consumed artifacts and releases retained-byte reservations.
     *
     * <p>Unresolved restore metadata survives expiry; only its archive is removed. The
     * caller's interrupt status is preserved across durable cleanup.</p>
     *
     * @throws IOException if the repository is unavailable or metadata/file deletion fails
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized void cleanup() throws IOException {
        boolean interrupted = Thread.interrupted(); // NOPMD DoNotUseThreads - Temporarily masks caller interruption to finish durable cleanup; creates no thread.
        try { cleanupDurably(); }
        finally { if (interrupted) {
            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Restores the caller's original interrupt after durable cleanup; creates no thread.
        } }
    }

    private void cleanupDurably() throws IOException {
        requireOpen();
        for (Descriptor descriptor : artifacts.values().toArray(Descriptor[]::new)) {
            if (!leases.containsKey(descriptor.handle()) && restoreWorkflow(descriptor.state())
                    && !clock.instant().isBefore(descriptor.expiresAt())) {
                Files.deleteIfExists(path(descriptor.handle() + ARCHIVE_SUFFIX));
                forceDirectory();
                if (descriptor.archiveRetained()) {
                    Descriptor metadata = descriptor.withoutArchive();
                    publish(metadata);
                    artifacts.put(metadata.handle(), metadata);
                    reservedBytes -= descriptor.length();
                }
                continue;
            }
            if (!leases.containsKey(descriptor.handle())
                    && (!clock.instant().isBefore(descriptor.expiresAt())
                        || descriptor.state() == State.CONSUMED || descriptor.state() == State.FAILED)) {
                publish(descriptor.state(State.CONSUMED, descriptor.manifest()));
                artifacts.put(descriptor.handle(), descriptor.state(State.CONSUMED, descriptor.manifest()));
                deleteFiles(descriptor.handle());
                artifacts.remove(descriptor.handle());
                if (descriptor.archiveRetained()) {
                    reservedBytes -= descriptor.length();
                }
            }
        }
    }

    private void recover() throws IOException {
        recoverDescriptors();
        for (Descriptor descriptor : artifacts.values().toArray(Descriptor[]::new)) {
            recoverDescriptor(descriptor);
        }
        cleanup();
        discardIncompleteFiles();
        forceDirectory();
    }

    private void recoverDescriptors() throws IOException {
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(configuration.directory())) {
            for (Path entry : entries) {
                String name = entry.getFileName().toString();
                if (!Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("Invalid backup artifact directory entry");
                }
                if (PROCESS_LOCK_FILE.equals(name)) {
                    continue;
                }
                if (!name.matches("[0-9a-f]{64}\\.(meta|tmp|part|zip)")) {
                    throw new IOException("Unexpected backup artifact directory entry");
                }
                if (!name.endsWith(".meta")) {
                    continue;
                }
                Descriptor descriptor = read(entry);
                if (!name.equals(descriptor.handle() + ".meta") || !realm.equals(descriptor.realm())
                        || descriptor.length() > configuration.maximumArchiveBytes()
                        || artifacts.size() >= configuration.maximumArtifacts()
                        || descriptor.archiveRetained() && descriptor.length() > configuration.maximumRetainedBytes() - reservedBytes) {
                    throw new IOException("Incompatible backup artifact metadata");
                }
                artifacts.put(descriptor.handle(), descriptor);
                if (descriptor.archiveRetained()) {
                    reservedBytes += descriptor.length();
                }
            }
        }
    }

    private void recoverDescriptor(Descriptor original) throws IOException {
        Descriptor descriptor = original;
        State recovered = switch (descriptor.state()) {
            case RESERVED, RECEIVING -> State.FAILED;
            case VERIFYING -> State.READY;
            case RESTORING -> State.UNCERTAIN;
            default -> descriptor.state();
        };
        if (recovered != descriptor.state()) {
            descriptor = descriptor.state(recovered, descriptor.manifest());
            publish(descriptor);
            artifacts.put(descriptor.handle(), descriptor);
        }
        if (descriptor.archiveRetained() && recovered != State.FAILED && recovered != State.CONSUMED
                && !(restoreWorkflow(recovered) && !clock.instant().isBefore(descriptor.expiresAt()))
                && (!Files.isRegularFile(path(descriptor.handle() + ARCHIVE_SUFFIX))
                    || Files.size(path(descriptor.handle() + ARCHIVE_SUFFIX)) != descriptor.length())) {
            throw new IOException("Incomplete backup artifact");
        }
    }

    private void discardIncompleteFiles() throws IOException {
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(configuration.directory())) {
            for (Path entry : entries) {
                String name = entry.getFileName().toString();
                if (PROCESS_LOCK_FILE.equals(name)) {
                    continue;
                }
                String handle = name.substring(0, 64);
                if (name.endsWith(".tmp") || name.endsWith(".part") || !artifacts.containsKey(handle)) {
                    Files.delete(entry);
                }
            }
        }
    }

    private void publish(Descriptor descriptor) throws IOException {
        byte[] bytes = encode(descriptor);
        Path temporary = path(descriptor.handle() + ".tmp");
        try {
            try (FileChannel output = FileChannel.open(temporary, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    output.write(buffer);
                }
                output.force(true);
                observer.at(Phase.METADATA_FORCED);
            }
            Files.move(temporary, path(descriptor.handle() + ".meta"),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            observer.at(Phase.METADATA_RENAMED);
            forceDirectory();
        } catch (IOException failure) {
            fenced = true;
            throw new IOException("BACKUP_ARTIFACT_OUTCOME_UNCERTAIN", failure);
        }
    }

    private byte[] encode(Descriptor descriptor) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(MAGIC);
            output.writeInt(VERSION);
            output.writeUTF(descriptor.handle());
            output.writeUTF(descriptor.owner());
            output.writeUTF(descriptor.realm());
            output.writeUTF(descriptor.purpose().name());
            output.writeUTF(descriptor.backupId().value());
            output.writeLong(descriptor.length());
            output.writeUTF(descriptor.sha256());
            output.writeUTF(descriptor.manifest());
            output.writeLong(descriptor.expiresAt().getEpochSecond());
            output.writeUTF(descriptor.state().name());
            output.writeBoolean(descriptor.archiveRetained());
            output.writeUTF(descriptor.restoreId());
            output.writeUTF(descriptor.previousRestoreId());
        }
        byte[] payload = bytes.toByteArray();
        bytes.write(hash().digest(payload));
        return bytes.toByteArray();
    }

    /**
     * Computes a commitment to the complete persisted descriptor encoding.
     *
     * @param descriptor validated artifact metadata
     * @return lowercase hexadecimal SHA-256 including the encoding's integrity trailer
     * @throws IOException if metadata cannot be encoded
     */
    /* default */ String commitment(Descriptor descriptor) throws IOException {
        return HexFormat.of().formatHex(hash().digest(encode(descriptor)));
    }

    private Descriptor read(Path file) throws IOException {
        byte[] bytes;
        try (InputStream input = Files.newInputStream(file)) { bytes = input.readNBytes(METADATA_LIMIT + 1); }
        if (bytes.length > METADATA_LIMIT) {
            throw new IOException("Oversized backup artifact descriptor");
        }
        if (bytes.length < MINIMUM_METADATA_BYTES) {
            throw new IOException("Truncated backup artifact descriptor");
        }
        byte[] payload = java.util.Arrays.copyOf(bytes, bytes.length - 32);
        if (!MessageDigest.isEqual(hash().digest(payload), java.util.Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length))) {
            throw new IOException("Corrupt backup artifact descriptor");
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION) {
                throw new IOException("Unsupported backup artifact descriptor");
            }
            Descriptor descriptor = new Descriptor(input.readUTF(), input.readUTF(), input.readUTF(),
                    Purpose.valueOf(input.readUTF()), new PkiId(input.readUTF()), input.readLong(),
                    input.readUTF(), input.readUTF(), Instant.ofEpochSecond(input.readLong()),
                    State.valueOf(input.readUTF()), input.readBoolean(), input.readUTF(), input.readUTF());
            if (input.read() != -1) {
                throw new IOException("Trailing backup artifact metadata");
            }
            return descriptor;
        } catch (IllegalArgumentException failure) {
            throw new IOException("Invalid backup artifact descriptor", failure);
        }
    }

    private void deleteFiles(String handle) throws IOException {
        observer.at(Phase.BEFORE_DELETE);
        Files.deleteIfExists(path(handle + ".part"));
        Files.deleteIfExists(path(handle + ARCHIVE_SUFFIX));
        Files.deleteIfExists(path(handle + ".tmp"));
        forceDirectory();
        Files.deleteIfExists(path(handle + ".meta"));
        forceDirectory();
    }

    private Path path(String name) { return configuration.directory().resolve(name); }
    private static void requirePrivateDirectory(Path directory) throws IOException {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Pre-existing private backup artifact directory required");
        }
        PosixFileAttributeView posix = Files.getFileAttributeView(directory,
                PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            for (PosixFilePermission permission : posix.readAttributes().permissions()) {
                if (!permission.name().startsWith("OWNER_")) {
                    throw new IOException("Backup artifact directory must be owner-only");
                }
            }
            return;
        }
        AclFileAttributeView acl = Files.getFileAttributeView(directory,
                AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl == null) {
            throw new IOException("Private backup artifact storage is unsupported");
        }
        for (AclEntry entry : acl.getAcl()) {
            if (entry.type() == AclEntryType.ALLOW && !entry.principal().equals(acl.getOwner())) {
                throw new IOException("Backup artifact directory must be owner-only");
            }
        }
    }
    private void forceDirectory() throws IOException {
        try (FileChannel directory = FileChannel.open(configuration.directory(), StandardOpenOption.READ)) {
            directory.force(true);
        }
        observer.at(Phase.DIRECTORY_FORCED);
    }
    private void requireOpen() throws IOException {
        if (closed || fenced) {
            throw new IOException("BACKUP_ARTIFACT_REPOSITORY_UNAVAILABLE");
        }
    }
    private static boolean token(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
    private static boolean digest(String value) { return token(value); }
    private static boolean restoreWorkflow(State state) {
        return state == State.RESTORING || state == State.STAGED || state == State.UNCERTAIN
                || state == State.ACTIVATED || state == State.REJECTED;
    }
    private static boolean bounded(String value) { return value != null && !value.isBlank() && value.length() <= 1024; }
    private static MessageDigest hash() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }

    // Serializes close with active leases and wait/notify draining before releasing the process lock.
    /**
     * Releases the exclusive spool lock only after preparation jobs and artifact leases have drained.
     *
     * <p>This method does not wait for active jobs. After they finish, an external owner
     * may retry. The repository is marked closed before process-lock/channel closure;
     * a later call does not repeat a failed underlying close attempt.</p>
     *
     * @throws IOException if preparation jobs or leases remain active, or the process lock/channel fails to close
     */
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    @Override public synchronized void close() throws IOException {
        if (closed) {
            return;
        }
        if (!leases.isEmpty() || preparationJobs != 0) {
            throw new IOException("Backup artifact jobs are still active");
        }
        closed = true;
        try (lockChannel) {
            processLock.close();
        }
    }

    /**
     * Holds bounded workspace before an export has acquired its archive identity.
     */
    /* default */ final class PreparationJob implements AutoCloseable {
        private boolean released;
        private PreparationJob() { }
        /**
         * Transfers this preparation reservation into an exclusive reserved-artifact lease.
         *
         * @param owner principal owning the artifact
         * @param handle reserved artifact handle
         * @return lease that now owns the workspace reservation and must be closed
         * @throws IOException if this job is closed or the artifact cannot be leased
         */
        /* default */ Lease handoff(String owner, String handle) throws IOException {
            synchronized (BackupArtifactRepository.this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
                if (released) {
                    throw new IOException("Backup preparation job is closed");
                }
                preparationJobs--;
                workspaceBytes -= configuration.workspaceReservationBytes();
                try {
                    Lease lease = source(owner, handle, State.RESERVED, true);
                    released = true;
                    return lease;
                } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
                    preparationJobs++;
                    workspaceBytes += configuration.workspaceReservationBytes();
                    throw failure;
                }
            }
        }
        /**
         * {@inheritDoc}
         */
        @Override public void close() {
            synchronized (BackupArtifactRepository.this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
                if (!released) {
                    released = true;
                    preparationJobs--;
                    workspaceBytes -= configuration.workspaceReservationBytes();
                }
            }
        }
    }

    /**
     * Pins repository-owned bytes; closing releases only this borrowed view.
     */
    /* default */ final class Lease implements BackupSource {
        private final Descriptor descriptor;
        private final boolean workspace;
        private final Set<InputStream> streams = new HashSet<>();
        private boolean released;
        private Lease(Descriptor descriptor, boolean workspace) {
            this.descriptor = descriptor;
            this.workspace = workspace;
        }
        /**
         * Returns the immutable descriptor snapshot captured when this lease was acquired.
         *
         * @return acquisition-time metadata, which does not track later transitions
         */
        /* default */ Descriptor descriptor() { return descriptor; }
        /**
         * Durably begins the sole unresolved restore attempt for this repository.
         *
         * @param restoreId canonical UUID of the new restore attempt
         * @param previousRestoreId prior canonical UUID, or empty
         * @throws IOException if the lease is closed, the artifact is not verified,
         *         another restore is unresolved or publication fails
         * @throws IllegalArgumentException if restore identifiers are malformed or equal
         */
        /* default */ void beginRestore(String restoreId, String previousRestoreId) throws IOException {
            synchronized (BackupArtifactRepository.this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
                requireOpen();
                if (!java.util.UUID.fromString(restoreId).toString().equals(restoreId)) {
                    throw new IllegalArgumentException("Restore identifier must be a canonical UUID");
                }
                if (leases.get(descriptor.handle()) != this) { // NOPMD CompareObjectsWithEquals - Only the exact registered lease instance may mutate this artifact.
                    throw new IOException("Backup artifact lease is closed");
                }
                Descriptor current = artifacts.get(descriptor.handle());
                if (current.state() != State.VERIFIED || current.manifest().isEmpty()) {
                    throw new IOException("BACKUP_ARTIFACT_STATE");
                }
                for (Descriptor other : artifacts.values()) {
                    if (other.state() == State.RESTORING || other.state() == State.STAGED || other.state() == State.UNCERTAIN) {
                        throw new IOException("BACKUP_RESTORE_OUTCOME_UNRESOLVED");
                    }
                }
                Descriptor next = current.restoring(restoreId, previousRestoreId);
                publish(next);
                artifacts.put(next.handle(), next);
            }
        }
        /**
         * Publishes replacement workflow state through this exact active lease.
         *
         * @param next replacement lifecycle state
         * @param manifest manifest SHA-256 commitment, or empty before verification
         * @throws IOException if the lease/repository is unavailable or durable publication fails
         * @throws IllegalArgumentException if replacement descriptor values are invalid
         */
        /* default */ void transition(State next, String manifest) throws IOException {
            synchronized (BackupArtifactRepository.this) { // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
                requireOpen();
                if (leases.get(descriptor.handle()) != this) { // NOPMD CompareObjectsWithEquals - Only the exact registered lease instance may mutate this artifact.
                    throw new IOException("Backup artifact lease is closed");
                }
                Descriptor replacement = artifacts.get(descriptor.handle()).state(next, manifest);
                publish(replacement);
                artifacts.put(replacement.handle(), replacement);
            }
        }
        /**
         * {@inheritDoc}
         */
        @Override public PkiId backupId() { return descriptor.backupId(); }
        /**
         * {@inheritDoc}
         */
        @Override public long contentLength() { return descriptor.length(); }
        /**
         * {@inheritDoc}
         */
        @Override public String sha256() { return descriptor.sha256(); }
        // Serializes the lease's closed state and tracked-stream registration.
        /**
         * {@inheritDoc}
         */
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized InputStream openStream() throws IOException {
            if (released) {
                throw new IOException("Backup source is closed");
            }
            InputStream input = Files.newInputStream(path(descriptor.handle() + ARCHIVE_SUFFIX));
            streams.add(input);
            return input;
        }
        // Drains this lease's tracked streams before releasing its artifact and workspace reservations.
        /**
         * Closes every stream opened through this lease before releasing its artifact/workspace reservation.
         *
         * <p>Stream failures are combined with suppressed exceptions. The reservation remains
         * owned until all stream closes succeed, allowing a later close attempt to retry.</p>
         *
         * @throws IOException if any tracked source stream fails to close
         */
        @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
        @Override public synchronized void close() throws IOException {
            if (released) {
                return;
            }
            IOException failure = null;
            for (InputStream stream : streams) { // NOPMD CloseResource - Every tracked stream is explicitly closed; failures are aggregated before lease release.
                try { stream.close(); }
                catch (IOException problem) {
                    if (failure == null) {
                        failure = problem;
                    }
                    else {
                        failure.addSuppressed(problem);
                    }
                }
            }
            if (failure != null) {
                throw failure;
            }
            released = true;
            synchronized (BackupArtifactRepository.this) { release(descriptor.handle(), workspace); } // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
        }
    }
}
