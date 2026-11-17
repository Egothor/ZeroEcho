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
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Optional;
import java.util.UUID;
import zeroecho.pki.api.BackupService;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.backup.BackupPreparation;
import zeroecho.pki.api.backup.BackupRequest;
import zeroecho.pki.api.backup.BackupSource;
import zeroecho.pki.api.backup.RestoreIdentity;
import zeroecho.pki.api.backup.RestoreStatus;

/**
 * Authorized transfer workflow orchestration. Domain archive validation and
 * activation remain in BackupService. Every call requires prior gateway policy
 * enforcement; the repository additionally checks immutable ownership/identity.
 * Domain jobs retain their leases until they actually return, even after a
 * transport timeout. No network timeout implies that restoration failed.
 */
final class BackupTransferService implements AutoCloseable {
    private final BackupService backup;
    private final BackupArtifactRepository repository;
    private final RestorePreflight preflight;
    /**
     * Checks whether a cold restore may be staged in the current server state.
     */
    /* default */ @FunctionalInterface interface RestorePreflight {
        /**
         * Checks that the server can safely stage a restore without mutating domain state.
         *
         * @throws IOException if runtime prerequisites do not permit safe staging
         */
        void check() throws IOException;
    }

    /**
     * Composes backup transfer ownership and reconciles unresolved retained restores on open.
     *
     * @param backup authoritative domain backup/restore service
     * @param repository realm-owned durable artifact spool
     * @param preflight runtime prerequisite check performed before restore staging
     * @throws NullPointerException if a collaborator is null
     * @throws IOException if cold-start restore reconciliation or spool cleanup fails
     */
    /* default */ BackupTransferService(BackupService backup, BackupArtifactRepository repository, RestorePreflight preflight) throws IOException {
        this.backup = java.util.Objects.requireNonNull(backup);
        this.repository = java.util.Objects.requireNonNull(repository);
        this.preflight = java.util.Objects.requireNonNull(preflight);
        reconcileColdStart();
    }

    private void reconcileColdStart() throws IOException {
        for (BackupArtifactRepository.Descriptor descriptor : repository.unresolvedRestores()) {
            reconcileRestore(descriptor);
        }
        repository.cleanup();
    }

    private void reconcileRestore(BackupArtifactRepository.Descriptor descriptor) throws IOException {
        Optional<RestoreIdentity> latest = backup.latestRestoreIdentity();
        String current = latest.map(value -> value.status().restoreId().value()).orElse("");
        if (current.equals(descriptor.previousRestoreId())) {
            Optional<PkiId> prior = current.isEmpty() ? Optional.empty() : Optional.of(new PkiId(current));
            backup.discardUnpublishedRestore(new PkiId(descriptor.restoreId()), prior, descriptor.manifest());
            repository.rejectUnpublished(descriptor);
        } else if (latest.isPresent()) {
            repository.reconcile(descriptor.owner(), descriptor.handle(), latest.orElseThrow());
        }
    }

    /**
     * Reserves an owner-bound import artifact before receiving any archive bytes.
     *
     * @param owner authenticated principal owning the transfer
     * @param backupId expected source backup identity
     * @param length expected archive size, in bytes
     * @param archiveSha256 expected lowercase hexadecimal archive SHA-256
     * @return durably reserved import descriptor
     * @throws IOException if capacity is exhausted or durable reservation fails
     */
    /* default */ BackupArtifactRepository.Descriptor reserveUpload(String owner, PkiId backupId,
            long length, String archiveSha256) throws IOException {
        return repository.reserve(owner, BackupArtifactRepository.Purpose.IMPORT, backupId, length, archiveSha256);
    }

    /**
     * Resolves an owner-bound, unexpired artifact with retained archive bytes.
     *
     * @param owner authenticated principal owning the artifact
     * @param handle opaque transfer handle
     * @return exact current artifact descriptor
     * @throws IOException if the artifact is unavailable, expired or owned by another principal
     */
    /* default */ BackupArtifactRepository.Descriptor bind(String owner, String handle) throws IOException {
        return repository.inspect(owner, handle);
    }

    /**
     * Resolves the exact artifact/workflow snapshot required by a backup command.
     *
     * @param owner authenticated principal owning the transfer
     * @param command command selecting the artifact and required lifecycle view
     * @return workflow metadata for status/acknowledgement, otherwise a live artifact descriptor
     * @throws IOException if the required artifact or workflow is unavailable
     */
    /* default */ BackupArtifactRepository.Descriptor bind(String owner, ServerControlOperation.BackupArtifactCommand command)
            throws IOException {
        return command.action() == ServerControlOperation.BackupArtifactCommand.Action.STATUS
                || command.action() == ServerControlOperation.BackupArtifactCommand.Action.ACKNOWLEDGE
                ? repository.workflow(owner, command.artifactHandle()) : bind(owner, command.artifactHandle());
    }

    /**
     * Commits the exact descriptor used for operation approval and execution binding.
     *
     * @param descriptor selected immutable artifact snapshot
     * @return lowercase hexadecimal descriptor SHA-256
     * @throws IOException if descriptor encoding fails
     */
    /* default */ String commitment(BackupArtifactRepository.Descriptor descriptor) throws IOException {
        return repository.commitment(descriptor);
    }

    // Source and verification close before the lease releases its byte budget; pre-handoff failures close the source once.
    /**
     * Creates a verified domain backup and durably spools it as an owner-bound export artifact.
     *
     * <p>All domain sources and verification resources close before the artifact lease
     * releases its byte budget. The returned handle has not yet been consumed by download.</p>
     *
     * @param owner authenticated principal owning the export
     * @param request authorized domain backup request
     * @return live ready-to-download artifact descriptor
     * @throws IOException if capacity, backup preparation, copying, verification or publication fails
     */
    /* default */ @SuppressWarnings("PMD.UseTryWithResources")
    /* default */ BackupArtifactRepository.Descriptor export(String owner, BackupRequest request) throws IOException {
        try (BackupArtifactRepository.PreparationJob job = repository.prepare()) {
            BackupSource source = backup.createBackupSource(request);
            boolean sourceOwnedByLease = false;
            try {
                BackupArtifactRepository.Descriptor descriptor = repository.reserve(owner,
                        BackupArtifactRepository.Purpose.EXPORT, source.backupId(), source.contentLength(), source.sha256());
                try (BackupArtifactRepository.Lease lease = job.handoff(owner, descriptor.handle())) {
                    sourceOwnedByLease = true;
                    // Pin the source's retained-byte reservation through verification
                    // and close both domain resources before releasing the lease.
                    try (source; BackupPreparation verified = backup.prepareBackup(source);
                            InputStream input = source.openStream()) {
                        repository.receive(lease, input);
                        lease.transition(BackupArtifactRepository.State.READY, verified.manifestSha256());
                    } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
                        lease.transition(BackupArtifactRepository.State.FAILED, "");
                        throw failure;
                    }
                }
                return repository.inspect(owner, descriptor.handle());
            } finally {
                if (!sourceOwnedByLease) {
                    source.close();
                }
            }
        }
    }

    /**
     * Receives the exact reserved import artifact and verifies its archive size and SHA-256.
     *
     * @param owner authenticated principal owning the import
     * @param expected exact previously bound import descriptor
     * @param input caller-owned archive stream; remains open
     * @throws IOException if purpose, identity or state changed, capacity is unavailable,
     *         input fails or the archive commitment differs
     */
    /* default */ void upload(String owner, BackupArtifactRepository.Descriptor expected, InputStream input) throws IOException {
        requirePurpose(expected, BackupArtifactRepository.Purpose.IMPORT);
        try (BackupArtifactRepository.Lease lease = repository.source(owner, expected.handle(),
                BackupArtifactRepository.State.RESERVED, false)) {
            requireIdentity(lease, expected);
            repository.receive(lease, input);
        }
    }

    /**
     * Consumes an export handle and copies its archive to an already opened destination.
     *
     * @param owner authenticated principal owning the export
     * @param expected exact previously bound ready export descriptor
     * @param output transport-owned destination; flushed but not closed
     * @throws IOException if identity/state differs, copying is interrupted or I/O/cleanup fails
     */
    /* default */ void download(String owner, BackupArtifactRepository.Descriptor expected, OutputStream output) throws IOException {
        download(owner, expected, length -> output);
    }

    /**
     * Opens the response body only after the artifact length has been validated.
     */
    /* default */ @FunctionalInterface interface DownloadOutput {
        /**
         * Opens the destination owned by the surrounding transport lifecycle.
         * @param length validated artifact length in bytes
         * @return destination stream
         * @throws IOException if the destination cannot be opened
         */
        OutputStream open(long length) throws IOException;
    }

    /**
     * Durably consumes an export before opening the destination or releasing archive bytes.
     *
     * <p>An interrupted download requires a new authorized export. This handle cannot be
     * replayed. The surrounding transport owns and closes the destination stream.</p>
     *
     * @param owner authenticated principal owning the export
     * @param expected exact previously bound ready export descriptor
     * @param destination opens the destination after validated content length is known
     * @throws IOException if identity/state differs, copying is interrupted or I/O/cleanup fails
     */
    /* default */ void download(String owner, BackupArtifactRepository.Descriptor expected, DownloadOutput destination) throws IOException {
        requirePurpose(expected, BackupArtifactRepository.Purpose.EXPORT);
        try (BackupArtifactRepository.Lease lease = repository.source(owner, expected.handle(),
                BackupArtifactRepository.State.READY, false)) {
            requireIdentity(lease, expected);
            // Consume durably before releasing any bytes. An interrupted download
            // requires a new authorized export, never replay of this transfer token.
            lease.transition(BackupArtifactRepository.State.CONSUMED, expected.manifest());
            OutputStream output = destination.open(expected.length()); // NOPMD CloseResource - Transport owns and closes the destination stream after the transfer response completes.
            try (InputStream input = lease.openStream()) {
                byte[] buffer = new byte[65_536];
                int length;
                while ((length = input.read(buffer)) != -1) {
                    if (Thread.currentThread().isInterrupted()) { // NOPMD DoNotUseThreads - Observes caller cancellation while owning a bounded lease; this standalone component creates no thread.
                        throw new IOException("BACKUP_TRANSFER_CANCELLED");
                    }
                    output.write(buffer, 0, length);
                }
                output.flush();
            }
        } finally {
            repository.cleanup();
        }
    }

    /**
     * Verifies a ready import through the domain backup service under a workspace lease.
     *
     * @param owner authenticated principal owning the import
     * @param expected exact previously bound ready import descriptor
     * @return descriptor retaining the verified manifest commitment
     * @throws IOException if identity/state differs, workspace is unavailable,
     *         verification fails or the verified backup identity differs
     */
    /* default */ BackupArtifactRepository.Descriptor verify(String owner,
            BackupArtifactRepository.Descriptor expected) throws IOException {
        requirePurpose(expected, BackupArtifactRepository.Purpose.IMPORT);
        try (BackupArtifactRepository.Lease lease = repository.source(owner, expected.handle(),
                BackupArtifactRepository.State.READY, true)) {
            requireIdentity(lease, expected);
            lease.transition(BackupArtifactRepository.State.VERIFYING, "");
            try (BackupPreparation preparation = backup.prepareBackup(lease)) {
                if (!preparation.backupId().equals(expected.backupId())) {
                    throw new IOException("BACKUP_IDENTITY_MISMATCH");
                }
                lease.transition(BackupArtifactRepository.State.VERIFIED, preparation.manifestSha256());
            } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
                lease.transition(BackupArtifactRepository.State.FAILED, "");
                throw failure;
            }
        }
        return repository.inspect(owner, expected.handle());
    }

    /**
     * Stages a verified import after runtime preflight and binds a unique domain restore identity.
     *
     * <p>Definite rejection is returned as retained rejected metadata. An ambiguous failure
     * is retained as uncertain and must be reconciled before another restore.</p>
     *
     * @param owner authenticated principal owning the import
     * @param expected exact previously bound verified import descriptor
     * @return staged or definitely rejected restore-workflow descriptor
     * @throws IOException if prerequisites, identity/state, workspace, staging or publication fails
     */
    /* default */ BackupArtifactRepository.Descriptor restore(String owner,
            BackupArtifactRepository.Descriptor expected) throws IOException {
        requirePurpose(expected, BackupArtifactRepository.Purpose.IMPORT);
        preflight.check();
        try (BackupArtifactRepository.Lease lease = repository.source(owner, expected.handle(),
                BackupArtifactRepository.State.VERIFIED, true)) {
            requireIdentity(lease, expected);
            PkiId restoreId = new PkiId(UUID.randomUUID().toString());
            String previous = backup.latestRestoreIdentity().map(value -> value.status().restoreId().value()).orElse("");
            lease.beginRestore(restoreId.value(), previous);
            try {
                RestoreStatus status = backup.stageRestore(lease, restoreId);
                if (!status.restoreId().equals(restoreId) || status.state() != RestoreStatus.State.STAGED) {
                    throw new IOException("BACKUP_RESTORE_OUTCOME_UNCERTAIN");
                }
                lease.transition(BackupArtifactRepository.State.STAGED, expected.manifest());
            } catch (zeroecho.pki.api.backup.RestoreRejectedException rejection) {
                lease.transition(BackupArtifactRepository.State.REJECTED, expected.manifest());
                return repository.workflow(owner, expected.handle());
            } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
                lease.transition(BackupArtifactRepository.State.UNCERTAIN, expected.manifest());
                throw failure;
            }
        }
        return repository.workflow(owner, expected.handle());
    }

    /**
     * Reconciles retained workflow metadata with the latest authoritative restore result.
     *
     * @param owner authenticated principal owning the workflow
     * @param workflowId opaque retained artifact/workflow handle
     * @return reconciled workflow descriptor
     * @throws IOException if the workflow is unavailable, reconciliation or cleanup fails
     */
    /* default */ BackupArtifactRepository.Descriptor status(String owner, String workflowId) throws IOException {
        BackupArtifactRepository.Descriptor descriptor = repository.workflow(owner, workflowId);
        Optional<RestoreIdentity> identity = backup.latestRestoreIdentity();
        if (identity.isPresent()) {
            descriptor = repository.reconcile(owner, workflowId, identity.orElseThrow());
        }
        repository.cleanup();
        return descriptor;
    }

    /**
     * Reconciles and acknowledges a resolved restore workflow so retained resources can be cleaned.
     *
     * @param owner authenticated principal owning the workflow
     * @param workflowId opaque retained artifact/workflow handle
     * @throws IOException if the outcome remains unresolved or reconciliation/consumption fails
     */
    /* default */ void acknowledge(String owner, String workflowId) throws IOException {
        status(owner, workflowId);
        repository.acknowledge(owner, workflowId);
    }

    private static void requireIdentity(BackupArtifactRepository.Lease lease,
            BackupArtifactRepository.Descriptor expected) throws IOException {
        if (!lease.descriptor().equals(expected)) {
            throw new IOException("BACKUP_ARTIFACT_IDENTITY_CHANGED");
        }
    }

    private static void requirePurpose(BackupArtifactRepository.Descriptor descriptor,
            BackupArtifactRepository.Purpose purpose) throws IOException {
        if (descriptor.purpose() != purpose) {
            throw new IOException("BACKUP_ARTIFACT_PURPOSE");
        }
    }

    /**
     * Closes the owned durable transfer repository after all transfer jobs and leases have drained.
     *
     * @throws IOException if repository work remains active or spool-lock/channel closure fails
     */
    @Override public void close() throws IOException { repository.close(); }
}
