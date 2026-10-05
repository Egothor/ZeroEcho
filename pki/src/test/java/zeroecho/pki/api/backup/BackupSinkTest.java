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
package zeroecho.pki.api.backup;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.PkiId;

class BackupSinkTest {
    @TempDir Path directory;

    @Test void repeatsInputAndTransfersDeleteOwnership() throws Exception {
        byte[] data = new byte[] { 1, 2, 3, 4 };
        BackupSource source;
        try (BackupSink sink = BackupSink.create(directory, new PkiId("test"), BackupLimits.defaults())) {
            sink.outputStream().write(data);
            source = sink.complete();
        }
        try (source) {
            assertEquals(4, source.contentLength());
            assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)), source.sha256());
            for (int pass = 0; pass < 2; pass++) {
                try (InputStream input = source.openStream()) { assertArrayEquals(data, input.readAllBytes()); }
            }
        }
        source.close();
        assertThrows(IOException.class, source::openStream);
        assertEmpty();
    }

    @Test void refusesExcessBeforeWritingAndCannotCompleteFailedSink() throws Exception {
        BackupLimits limits = new BackupLimits(4, 4, 4, 2, 8, 4, 1, 4, 4);
        try (BackupSink sink = BackupSink.create(directory, new PkiId("test"), limits)) {
            sink.outputStream().write(new byte[4]);
            assertThrows(IOException.class, () -> sink.outputStream().write(1));
            assertThrows(IOException.class, sink::complete);
        }
        assertEmpty();
    }

    @Test void abortsPartialInputAndRejectsNonAtomicPublication() throws Exception {
        try (BackupSink sink = new FileBackupSink(directory, new PkiId("test"), BackupLimits.defaults(),
                new FileBackupSink.Operations() {
                    @Override public void publish(Path from, Path to) throws IOException {
                        throw new AtomicMoveNotSupportedException("test", "test", "injected");
                    }
                })) {
            sink.outputStream().write(1);
            assertThrows(IOException.class, sink::complete);
        }
        assertEmpty();
    }

    @Test void reportsCleanupFailureAndAllowsRetry() throws Exception {
        boolean[] fail = { true };
        BackupSink sink = new FileBackupSink(directory, new PkiId("test"), BackupLimits.defaults(),
                new FileBackupSink.Operations() {
                    @Override public void delete(Path file) throws IOException {
                        if (fail[0]) throw new IOException("injected");
                        Files.deleteIfExists(file);
                    }
                });
        sink.outputStream().write(1);
        assertEquals("BACKUP_CLEANUP_FAILED", assertThrows(IOException.class, sink::close).getMessage());
        fail[0] = false;
        sink.close();
        assertEmpty();
    }

    @Test void publicationForceFailureLeavesNoConsumableArtifact() throws Exception {
        try (BackupSink sink = new FileBackupSink(directory, new PkiId("test"), BackupLimits.defaults(),
                new FileBackupSink.Operations() {
                    @Override public void forceDirectory(Path ignored) throws IOException {
                        throw new IOException("injected");
                    }
                })) {
            sink.outputStream().write(1);
            assertThrows(IOException.class, sink::complete);
        }
        assertEmpty();
    }

    private void assertEmpty() throws IOException {
        try (java.util.stream.Stream<Path> paths = Files.list(directory)) { assertTrue(paths.findAny().isEmpty()); }
    }

    @Test void partialOutputFailureCannotPublish() throws Exception {
        try (BackupSink sink = new FileBackupSink(directory, new PkiId("partial"), BackupLimits.defaults(),
                new FileBackupSink.Operations() {
                    @Override public java.io.OutputStream open(Path file) throws IOException {
                        java.io.OutputStream delegate = Files.newOutputStream(file);
                        return new java.io.FilterOutputStream(delegate) {
                            @Override public void write(byte[] bytes, int offset, int count) throws IOException {
                                if (count > 0) out.write(bytes[offset]);
                                throw new IOException("injected partial write");
                            }
                        };
                    }
                })) {
            assertThrows(IOException.class, () -> sink.outputStream().write(new byte[] { 1, 2 }));
            assertThrows(IOException.class, sink::complete);
        }
        assertEmpty();
    }
}
