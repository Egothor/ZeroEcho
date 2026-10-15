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
package zeroecho.pki.application;

import java.util.Objects;

import zeroecho.pki.api.BackupService;
import zeroecho.pki.api.backup.BackupArtifact;
import zeroecho.pki.api.backup.BackupRequest;
import zeroecho.pki.api.backup.BackupVerificationReport;
import zeroecho.pki.api.backup.RestoreReport;
import zeroecho.pki.api.backup.RestoreRequest;
import zeroecho.pki.spi.store.PkiStore;

/**
 * {@link BackupService} adapter that delegates to a {@link PkiStore} that supports backup.
 *
 * <p>This class is internal to the application layer and must only be instantiated when
 * {@link PkiStore#supportsBackup()} returns {@code true}.</p>
 */
final class StoreBackedBackupService implements BackupService {

    private final PkiStore store;

    /**
     * Creates a store-backed backup service.
     *
     * @param store store that reports {@link PkiStore#supportsBackup()} as {@code true}
     * @throws NullPointerException if {@code store} is {@code null}
     */
    /* default */ StoreBackedBackupService(PkiStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.RestoreStatus stageRestore(zeroecho.pki.api.backup.BackupSource source)
            throws java.io.IOException {
        return store.stageRestore(source);
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.RestoreStatus stageRestore(zeroecho.pki.api.backup.BackupSource source,
            zeroecho.pki.api.PkiId restoreId) throws java.io.IOException {
        return store.stageRestore(source, restoreId);
    }

    /** {@inheritDoc} */
    @Override
    public java.util.Optional<zeroecho.pki.api.backup.RestoreStatus> latestRestoreStatus() throws java.io.IOException {
        return store.latestRestoreStatus();
    }

    /** {@inheritDoc} */
    @Override
    public void discardUnpublishedRestore(zeroecho.pki.api.PkiId restoreId,
            java.util.Optional<zeroecho.pki.api.PkiId> previousRestoreId,
            String manifestSha256) throws java.io.IOException {
        store.discardUnpublishedRestore(restoreId, previousRestoreId, manifestSha256);
    }

    /** {@inheritDoc} */
    @Override
    public java.util.Optional<zeroecho.pki.api.backup.RestoreIdentity> latestRestoreIdentity()
            throws java.io.IOException {
        return store.latestRestoreIdentity();
    }

    /**
     * Delegates to {@link PkiStore#createBackup}.
     *
     * @param request backup request
     * @return backup artifact
     */
    @Override
    public BackupArtifact createBackup(BackupRequest request) {
        return store.createBackup(request);
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.BackupSource createBackupSource(BackupRequest request) throws java.io.IOException {
        return store.createBackupSource(request);
    }

    /** {@inheritDoc} */
    @Override
    public BackupVerificationReport verifyBackupSource(zeroecho.pki.api.backup.BackupSource source) {
        return store.verifyBackupSource(source);
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.BackupPreparation prepareBackup(zeroecho.pki.api.backup.BackupSource source)
            throws java.io.IOException {
        return store.prepareBackup(source);
    }

    /**
     * Rejects the legacy service entry point without invoking an old store implementation.
     * Local callers opt in through {@link #stageRestore} and inspect {@link #latestRestoreStatus()}.
     *
     * @param request restore request
     * @return never returns normally
     * @throws UnsupportedOperationException always, because this legacy entry point is unavailable
     */
    @Override
    public RestoreReport restoreBackup(RestoreRequest request) {
        Objects.requireNonNull(request, "request");
        throw new UnsupportedOperationException("Use the local staged restore API");
    }

    /**
     * Delegates to {@link PkiStore#verifyBackup}.
     *
     * @param artifact backup artifact
     * @return verification report
     */
    @Override
    public BackupVerificationReport verifyBackup(BackupArtifact artifact) {
        return store.verifyBackup(artifact);
    }
}
