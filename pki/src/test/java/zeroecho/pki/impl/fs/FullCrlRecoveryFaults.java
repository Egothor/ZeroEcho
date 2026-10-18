/* *****************************************************************************
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
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.time.Clock;
import java.util.OptionalLong;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;

/** Test-only access to the filesystem store's existing cleanup fault boundary. */
public final class FullCrlRecoveryFaults {
    private FullCrlRecoveryFaults() { }

    /** Opens a store that fails physical cleanup after durable signing retirement. */
    public static FilesystemPkiStore failRetirement(Path root, Clock clock) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock,
                FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE,
                reference -> { throw new IOException("Simulated cleanup failure"); });
    }

    /** Removes both sides of a status publication to simulate lost metadata. */
    public static void removeStatus(FilesystemPkiStore store, StatusObject status) throws IOException {
        mutate(store, new MetadataKey("io.zeroecho.pki.status-object-record", status.statusObjectId().value()), null);
        mutate(store, new MetadataKey("io.zeroecho.pki.status-object-owner", status.statusObjectId().value()), null);
    }

    /** Replaces status metadata while retaining its valid content and ownership. */
    public static void replaceStatus(FilesystemPkiStore store, StatusObject status) throws IOException {
        mutate(store, new MetadataKey("io.zeroecho.pki.status-object-record", status.statusObjectId().value()),
                FsCodec.encode(FsCodec.STATUS_OBJECT, status));
    }

    private static void mutate(FilesystemPkiStore store, MetadataKey key, byte[] bytes) throws IOException {
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                MetadataSnapshot.Record record = snapshot.get(key).orElseThrow();
                MetadataTransaction transaction = store.metadataStore().beginTransaction()) {
            if (bytes == null) {
                transaction.delete(key, record.recordRevision());
            } else {
                try (RepeatableContent content = new RepeatableContent() {
                    @Override public InputStream openStream() { return new ByteArrayInputStream(bytes); }
                    @Override public OptionalLong length() { return OptionalLong.of(bytes.length); }
                    @Override public String contentId() { return "test-corrupt-status"; }
                    @Override public void close() { }
                }) {
                    transaction.replace(key, record.recordRevision(), content, CancellationSignal.NONE);
                }
            }
            if (transaction.commit().outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                throw new AssertionError("Test corruption was not persisted");
            }
        }
    }
}
