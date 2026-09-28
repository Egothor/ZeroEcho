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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static zeroecho.pki.impl.core.continuation.FullCrlRecoveryIntegrationTest.accept;
import static zeroecho.pki.impl.core.continuation.FullCrlRecoveryIntegrationTest.publishing;
import static zeroecho.pki.impl.core.continuation.FullCrlRecoveryIntegrationTest.smallFixture;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.NOW;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.open;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.registerCa;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.semantic;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.sign;

import java.nio.ByteBuffer;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.Fixture;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FullCrlRecoveryFaults;
import zeroecho.pki.spi.store.DomainContinuationStore;

class FullCrlCorruptionIntegrationTest {
    @Test void missingOrTruncatedLiveTbsFailsAtItsOwningBoundary(@TempDir Path root) throws Exception {
        for (boolean publish : new boolean[] {false, true}) {
            for (boolean missing : new boolean[] {false, true}) {
                Path source = root.resolve("live-" + publish + "-" + missing);
                DurableContentReference tbs;
                try (FilesystemPkiStore store = open(source)) {
                    Fixture fixture = smallFixture(store);
                    PkiId operation = accept(store, fixture);
                    tbs = fixture.prepared().tbsContent();
                    if (publish) {
                        sign(store, operation, fixture.signature());
                        publishing(store, operation);
                    }
                }
                Path content = contentPath(source, tbs);
                if (missing) { Files.delete(content); }
                else { try (FileChannel channel = FileChannel.open(content, StandardOpenOption.WRITE)) { channel.truncate(1); } }
                if (missing) {
                    assertReopenFails(source);
                } else {
                    try (FilesystemPkiStore store = open(source)) {
                        assertThrows(IOException.class, () -> store.stagedContent().openContent(tbs));
                    }
                }
                assertEquals(!missing, Files.exists(content));
            }
        }
    }

    @Test void malformedCompletedIdentityFailsRecovery(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Fixture fixture = smallFixture(store);
            PkiId operation = complete(store, fixture);
            DomainContinuationStore.Record domain = store.getDomainContinuation(operation).orElseThrow();
            EncodedObject malformed = new EncodedObject(Encoding.BINARY, ("crl:" + "A".repeat(64))
                    .getBytes(StandardCharsets.US_ASCII));
            store.transitionDomainContinuation(operation, domain.revision(), DomainContinuationStore.State.COMPLETED,
                    Optional.of(malformed), Optional.of("COMPLETED")).orElseThrow();
        }
        assertReopenFails(root);
    }

    @Test void missingOrMismatchingCompletedPublicationFailsOrdinaryReopen(@TempDir Path root) throws Exception {
        for (boolean missing : new boolean[] {false, true}) {
            Path source = root.resolve("completed-" + missing);
            try (FilesystemPkiStore store = open(source)) {
                Fixture fixture = smallFixture(store);
                PkiId operation = complete(store, fixture);
                DomainContinuationStore.Record domain = store.getDomainContinuation(operation).orElseThrow();
                StatusObject status = store.getStatusObject(FullCrlSigningCommand.resultId(domain.result().orElseThrow())).orElseThrow();
                if (missing) {
                    FullCrlRecoveryFaults.removeStatus(store, status);
                } else {
                    FullCrlRecoveryFaults.replaceStatus(store, new StatusObject(status.statusObjectId(), status.formatId(),
                            status.issuerCaId(), status.type(), status.thisUpdate().plusSeconds(1), status.nextUpdate(),
                            status.content(), status.attributes()));
                }
                assertThrows(RuntimeException.class, () -> semantic(store, fixture.algorithm(), 1).find(operation));
            }
            assertReopenFails(source);
        }
    }

    @Test void damagedPublishedContentRejectsLookupExportAndReopen(@TempDir Path root) throws Exception {
        for (boolean truncate : new boolean[] {false, true}) {
            Path source = root.resolve("published-" + truncate);
            Path exported = root.resolve("exported-" + truncate);
            try (FilesystemPkiStore store = open(source)) {
                Fixture fixture = smallFixture(store);
                registerCa(store, fixture);
                PkiId operation = complete(store, fixture);
                DomainContinuationStore.Record domain = store.getDomainContinuation(operation).orElseThrow();
                PkiId statusId = FullCrlSigningCommand.resultId(domain.result().orElseThrow());
                StatusObject status = store.getStatusObject(statusId).orElseThrow();
                try (FileChannel channel = FileChannel.open(contentPath(source, status.content()), StandardOpenOption.WRITE)) {
                    if (truncate) { channel.truncate(1); }
                    else { channel.write(ByteBuffer.wrap(new byte[] {0})); }
                }
                assertThrows(IllegalStateException.class, () -> store.getStatusObject(statusId));
                assertThrows(IllegalStateException.class, () -> store.exportSnapshot(exported, NOW.plusSeconds(1)));
                assertFalse(Files.exists(exported));
            }
            assertReopenFails(source);
        }
    }

    private static PkiId complete(FilesystemPkiStore store, Fixture fixture) {
        PkiId operation = accept(store, fixture);
        sign(store, operation, fixture.signature());
        new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
        return operation;
    }

    private static Path contentPath(Path root, DurableContentReference reference) {
        return root.resolve("staged-content").resolve(reference.contentId() + ".content");
    }

    private static void assertReopenFails(Path source) {
        assertThrows(IllegalStateException.class, () -> {
            try (FilesystemPkiStore ignored = open(source)) { }
        });
    }
}
