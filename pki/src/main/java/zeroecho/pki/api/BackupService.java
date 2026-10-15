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
package zeroecho.pki.api;

import zeroecho.pki.api.backup.BackupArtifact;
import zeroecho.pki.api.backup.BackupRequest;
import zeroecho.pki.api.backup.BackupVerificationReport;
import zeroecho.pki.api.backup.RestoreReport;
import zeroecho.pki.api.backup.RestoreRequest;

/**
 * Backup/restore operations for PKI state.
 *
 * <p>
 * Backups must not implicitly include private keys. Private keys are referenced
 * via {@link KeyRef} and may be managed by separate components.
 * </p>
 */
public interface BackupService {

    /**
     * Discards an unpublished restore attempt after cold coordinator recovery.
     * The current restore identifier must still equal {@code previousRestoreId};
     * a published or uncertain attempt must never be discarded. Implementations
     * remove only the exact unreferenced staging data and matching role marker,
     * durably and idempotently. Callers invoke this before admitting new work.
     * @param restoreId fresh canonical UUID assigned to the unpublished attempt
     * @param previousRestoreId authoritative identifier observed before that attempt
     * @param manifestSha256 expected lowercase SHA-256 manifest digest
     * @throws java.io.IOException if identity, markers, or durable cleanup cannot be established
     * @throws UnsupportedOperationException if this recovery capability is unsupported
     */
    default void discardUnpublishedRestore(PkiId restoreId, java.util.Optional<PkiId> previousRestoreId,
            String manifestSha256) throws java.io.IOException {
        throw new UnsupportedOperationException("Unpublished restore cleanup is unsupported");
    }
    /**
     * Returns the authoritative source identity of the latest restore outcome.
     * The default does not claim support for transport-level crash reconciliation.
     * @return exact source and outcome, or empty if unavailable
     * @throws java.io.IOException if the coordinator cannot be read safely
     */
    default java.util.Optional<zeroecho.pki.api.backup.RestoreIdentity> latestRestoreIdentity()
            throws java.io.IOException {
        return java.util.Optional.empty();
    }

    /**
     * Durably stages a verified local replacement for activation on the next store open.
     * Live safety authority must not regress. The caller retains ownership of the source.
     * @param source bounded archive source
     * @return staged status; never an activation acknowledgement
     * @throws java.io.IOException if preparation or durable publication fails
     * @throws UnsupportedOperationException if local staging is unsupported
     */
    default zeroecho.pki.api.backup.RestoreStatus stageRestore(
            zeroecho.pki.api.backup.BackupSource source) throws java.io.IOException {
        throw new UnsupportedOperationException("Local restore staging is unsupported");
    }

    /**
     * Stages a restore with a caller-persisted correlation identifier.
     * The identifier must be a fresh canonical UUID and must never be reused,
     * including after an uncertain result. This is not a retry API: reconcile
     * through {@link #latestRestoreIdentity()} after interrupted acknowledgement.
     * The source remains caller-owned and activation requires a subsequent open.
     * Existing implementations must opt in to exact-identity staging.
     *
     * @param source bounded archive source
     * @param restoreId fresh canonical UUID persisted before dispatch
     * @return staged status containing exactly the supplied identifier
     * @throws java.io.IOException if verification or durable publication fails
     * @throws IllegalArgumentException if the identifier is not a canonical UUID
     * @throws UnsupportedOperationException if exact-identity staging is unsupported
     */
    default zeroecho.pki.api.backup.RestoreStatus stageRestore(
            zeroecho.pki.api.backup.BackupSource source, PkiId restoreId)
            throws java.io.IOException {
        throw new UnsupportedOperationException("Exact-identity restore staging is unsupported");
    }


    /**
     * Returns the latest local restore status without attempting activation.
     * An uncertain publication requires cold reconciliation, not resubmission.
     * @return latest status, or empty when none exists
     * @throws java.io.IOException if the coordinator record is unreadable or corrupt
     */
    default java.util.Optional<zeroecho.pki.api.backup.RestoreStatus> latestRestoreStatus() throws java.io.IOException {
        return java.util.Optional.empty();
    }

    /**
     * Creates a bounded file-backed backup. The caller owns and closes the result.
     * Existing implementations must opt in; the default never buffers a legacy archive.
     * @param request backup request
     * @return owned repeatable source
     * @throws UnsupportedOperationException if streaming backup is unsupported
     * @throws java.io.IOException if backup creation or cleanup fails
     */
    default zeroecho.pki.api.backup.BackupSource createBackupSource(
            BackupRequest request) throws java.io.IOException {
        throw new UnsupportedOperationException("Streaming backup is unsupported");
    }

    /**
     * Checks an untrusted streaming archive after bounded file-backed ingestion.
     * The source remains caller-owned; only streams opened by verification are closed.
     * @param source untrusted input and its claimed commitment
     * @return integrity and offline-recovery report, not proof of authenticity
     * @throws UnsupportedOperationException if streaming verification is unsupported
     */
    default BackupVerificationReport verifyBackupSource(
            zeroecho.pki.api.backup.BackupSource source) {
        throw new UnsupportedOperationException("Streaming verification is unsupported");
    }

    /**
     * Prepares verified staging without activating it or changing the live store.
     * @param source caller-owned input
     * @return caller-owned verified candidate
     * @throws java.io.IOException if verification, staging or cleanup fails
     * @throws UnsupportedOperationException if preparation is unsupported
     */
    default zeroecho.pki.api.backup.BackupPreparation prepareBackup(
            zeroecho.pki.api.backup.BackupSource source) throws java.io.IOException {
        throw new UnsupportedOperationException("Backup preparation is unsupported");
    }



    /**
     * Creates a backup of PKI state.
     *
     * @param request backup request
     * @return backup artifact
     * @throws IllegalArgumentException if {@code request} is invalid
     * @throws PkiException             if backup creation fails
     */
    BackupArtifact createBackup(BackupRequest request);

    /**
     * Restores PKI state from a backup artifact.
     * The built-in service rejects this legacy entry point without invoking a
     * legacy store override. Use {@link #stageRestore} for explicit local staging.
     *
     * @param request restore request
     * @return restore report
     * @throws IllegalArgumentException if {@code request} is invalid
     * @throws PkiException             if restore fails
     * @throws UnsupportedOperationException if safe restoration is unavailable
     */
    RestoreReport restoreBackup(RestoreRequest request);

    /**
     * Verifies a backup artifact for structural validity and integrity.
     *
     * @param artifact backup artifact
     * @return verification report
     * @throws IllegalArgumentException if {@code artifact} is null
     * @throws PkiException             if verification fails due to IO/backend
     *                                  errors
     */
    BackupVerificationReport verifyBackup(BackupArtifact artifact);
}
