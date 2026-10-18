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

/** Test-only access to existing commit-boundary fault hooks. */
public final class StatusScheduleFaults {
    private StatusScheduleFaults() { }
    public static void acceptance(String point, Runnable action) {
        FilesystemPkiStore.installSignAcceptanceCommitFault(FilesystemPkiStore.SignAcceptanceCommitFault.valueOf(point));
        try { action.run(); } finally { FilesystemPkiStore.clearSignAcceptanceCommitFault(); }
    }
    public static void effect(String point, Runnable action) {
        FilesystemPkiStore.installStatusCommitFault(FilesystemPkiStore.StatusCommitFaultPoint.valueOf(point));
        try { action.run(); } finally { FilesystemPkiStore.clearStatusCommitFault(); }
    }

    public static void corrupt(FilesystemPkiStore store, zeroecho.pki.api.schedule.StatusScheduleState state,
            String corruption) throws Exception {
        zeroecho.pki.spi.store.MetadataKey head = FsStatusSchedules.key(state.configuration().caId(), state.configuration().statusType());
        zeroecho.pki.spi.store.MetadataKey receipt = FsStatusSchedules.receiptKey(state.execution().orElseThrow().signingOperationId().orElseThrow());
        zeroecho.pki.spi.store.MetadataKey key = corruption.equals("missing-head") ? head : receipt;
        try (zeroecho.pki.spi.store.MetadataSnapshot snapshot = store.metadataStore().snapshot();
                zeroecho.pki.spi.store.MetadataTransaction transaction = store.metadataStore().beginTransaction();
                zeroecho.pki.spi.store.MetadataSnapshot.Record old = snapshot.get(key).orElseThrow()) {
            if (corruption.startsWith("missing-")) transaction.delete(key, old.recordRevision());
            else {
                byte[] bytes;
                try (java.io.InputStream input = old.openStream()) { bytes = input.readAllBytes(); }
                if (corruption.equals("future")) bytes[3] = 2;
                if (corruption.equals("trailing")) bytes = java.util.Arrays.copyOf(bytes, bytes.length + 1);
                try (zeroecho.core.io.ImmutableByteContent content = new zeroecho.core.io.ImmutableByteContent(bytes)) {
                    if (corruption.equals("wrong-operation")) transaction.create(FsStatusSchedules.receiptKey(new zeroecho.pki.api.PkiId("other")), content, zeroecho.core.io.CancellationSignal.NONE);
                    else transaction.replace(key, old.recordRevision(), content, zeroecho.core.io.CancellationSignal.NONE);
                }
            }
            org.junit.jupiter.api.Assertions.assertEquals(zeroecho.pki.spi.store.MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
        }
    }
}
