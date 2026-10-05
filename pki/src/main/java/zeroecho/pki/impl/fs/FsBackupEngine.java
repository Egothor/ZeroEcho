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
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.HexFormat;
import java.util.Objects;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.backup.BackupLimits;
import zeroecho.pki.api.backup.BackupPreparation;
import zeroecho.pki.api.backup.BackupSource;

/** Owns bounded backup ingestion, extraction and verification before restore staging. */
final class FsBackupEngine {
    private FsBackupEngine() { }

    /* default */ static BackupPreparation prepare(Path work, BackupSource source, BackupLimits limits,
            FsPkiStoreOptions options, Clock clock) throws IOException {
        Objects.requireNonNull(source, "source");
        Path owned = Files.createTempDirectory(work, ".verification-");
        Path candidate = owned.resolve("candidate");
        Path checking = owned.resolve("checking");
        boolean transferred = false;
        try {
            Path archive = owned.resolve("input.zip");
            ingest(source, archive, limits);
            FsBackupArchive.Manifest manifest = FsBackupArchive.extract(
                    archive, candidate, source.backupId(), limits);
            FsBackupArchive.extract(archive, checking, source.backupId(), limits);
            try (FilesystemPkiStore recovered = FilesystemPkiStore.openRestoreBorrowed(checking, options, clock, limits)) {
                recovered.validateBackupDomainFiles();
            } catch (RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
                throw new IOException("BACKUP_STORE_INVALID", failure);
            }
            FsBackupFiles.deleteTree(checking);
            Files.delete(archive);
            FsBackupFiles.forceTree(candidate);
            BackupPreparation result = new Prepared(owned, candidate, manifest.id(), manifest.digest());
            transferred = true;
            return result;
        } finally {
            if (!transferred) { FsBackupFiles.deleteTree(owned); }
        }
    }

    private static void ingest(BackupSource source, Path target, BackupLimits limits) throws IOException {
        long length = source.contentLength();
        String expected = source.sha256();
        if (length < 0 || length > limits.compressedBytes() || expected == null
                || !expected.matches("[0-9a-f]{64}") || source.backupId() == null) {
            throw FsBackupFiles.invalid("BACKUP_SOURCE_COMMITMENT");
        }
        MessageDigest digest = FsBackupFiles.digest();
        long copied = 0;
        byte[] buffer = new byte[FsBackupFiles.BUFFER_BYTES];
        try (InputStream input = source.openStream();
                OutputStream output = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW)) {
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count <= 0 || count > length - copied || count > limits.compressedBytes() - copied) {
                    throw FsBackupFiles.invalid("BACKUP_COMPRESSED_LIMIT");
                }
                output.write(buffer, 0, count);
                digest.update(buffer, 0, count);
                copied += count;
            }
        }
        if (copied != length || !MessageDigest.isEqual(digest.digest(), HexFormat.of().parseHex(expected))) {
            throw FsBackupFiles.invalid("BACKUP_SOURCE_COMMITMENT");
        }
    }

    /** Owns verified temporary files until their preparation handle is closed. */
    private static final class Prepared implements BackupPreparation {
        private final java.util.concurrent.locks.ReentrantLock lifecycle = new java.util.concurrent.locks.ReentrantLock();
        private final Path owned;
        private final Path candidate;
        private final PkiId id;
        private final String digest;
        private boolean closed;
        /* default */ Prepared(Path owned, Path candidate, PkiId id, String digest) {
            this.owned = owned;
            this.candidate = candidate;
            this.id = id;
            this.digest = digest;
        }
        @Override public PkiId backupId() { return id; }
        @Override public String manifestSha256() { return digest; }
        @Override public Path directory() {
            lifecycle.lock();
            try {
                if (closed) { throw new IllegalStateException("BACKUP_PREPARATION_CLOSED"); }
                return candidate;
            } finally {
                lifecycle.unlock();
            }
        }
        @Override public void close() throws IOException {
            lifecycle.lock();
            try {
                if (closed) { return; }
                FsBackupFiles.deleteTree(owned);
                closed = true;
            } finally {
                lifecycle.unlock();
            }
        }
    }
}
