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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.impl.core.continuation.FullCrlRecoveryIntegrationTest.accept;
import static zeroecho.pki.impl.core.continuation.FullCrlRecoveryIntegrationTest.publishing;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.CA;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.fixture;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.open;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.registerCa;
import static zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.sign;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.impl.core.continuation.FullCrlStreamingPublicationTest.Fixture;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.spi.store.DomainContinuationStore;

class FullCrlSnapshotIntegrationTest {
    @Test void deltaPublicationPrefixReplaysAfterReopenAndSnapshotWithoutResigningOrReselecting(@TempDir Path root) throws Exception {
        Path source = root.resolve("source");
        Path snapshot = root.resolve("snapshot");
        PkiId operation;
        PkiId baseId;
        PkiId generation;
        String commandCommitment;
        String digest;
        long length;
        try (FilesystemPkiStore store = open(source)) {
            Fixture fixture = fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0, true);
            baseId = fixture.prepared().base().orElseThrow().statusObjectId();
            generation = fixture.prepared().issuerGenerationId();
            assertEquals(BigInteger.ONE, store.reserveCrlNumber(generation));
            assertEquals(BigInteger.TWO, store.reserveCrlNumber(generation));
            operation = accept(store, fixture);
            sign(store, operation, fixture.signature());
            publishing(store, operation);
            commandCommitment = store.getDomainContinuation(operation).orElseThrow().commandCommitment();
            digest = DomainContinuationPublisher.sha256(fixture.outer());
            length = fixture.outer().length;
            DomainContinuationPublisher.installPublicationFault(point -> { throw new SimulatedCrash(); });
            try {
                assertThrows(SimulatedCrash.class, () -> new SigningOuterTerminalDriver(store)
                        .advance(store.getSignWorkflow(operation).orElseThrow()));
            } finally { DomainContinuationPublisher.clearPublicationFault(); }
            assertEquals(DomainContinuationStore.State.PUBLISHING, store.getDomainContinuation(operation).orElseThrow().state());
            assertEquals(2, store.listStatusObjects(CA).size());
            store.exportSnapshot(snapshot, Instant.MAX);
        }
        for (Path path : java.util.List.of(source, snapshot)) {
            try (FilesystemPkiStore store = open(path)) {
                DomainContinuationStore.Record retained = store.getDomainContinuation(operation).orElseThrow();
                assertEquals(commandCommitment, retained.commandCommitment());
                DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(retained.command());
                assertEquals("GENERATE_DELTA_CRL", command.operation());
                assertEquals(baseId.value(), command.field(31));
                assertEquals(command.field(20), command.field(33));
                assertEquals(command.field(21), command.field(34));
                assertEquals(command.field(22), command.field(35));
                zeroecho.pki.spi.store.PkiStore publicationOnly = (zeroecho.pki.spi.store.PkiStore) java.lang.reflect.Proxy.newProxyInstance(
                        zeroecho.pki.spi.store.PkiStore.class.getClassLoader(), new Class<?>[] {zeroecho.pki.spi.store.PkiStore.class},
                        (proxy, method, arguments) -> {
                            if (java.util.Set.of("listStatusObjects", "requireRevocationPrefix", "openRevocationSnapshot")
                                    .contains(method.getName())) {
                                throw new AssertionError("Retained delta publication must not reselect or recapture: " + method.getName());
                            }
                            try { return method.invoke(store, arguments); }
                            catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                        });
                new SigningOuterTerminalDriver(publicationOnly).advance(store.getSignWorkflow(operation).orElseThrow());
                StatusObject completed = completedStatus(store, operation, digest);
                assertEquals(zeroecho.pki.api.status.StatusObjectType.DELTA_CRL, completed.type());
                assertContent(store, completed.content(), length, digest);
                assertEquals(FullCrlSnapshotProvenance.from(command), FullCrlSnapshotProvenance.decode(completed.attributes()));
                assertEquals(2, store.listStatusObjects(CA).size());
                assertEquals(BigInteger.valueOf(3), store.reserveCrlNumber(generation));
                new SigningOuterTerminalDriver(publicationOnly).advance(store.getSignWorkflow(operation).orElseThrow());
                assertEquals(commandCommitment, store.getDomainContinuation(operation).orElseThrow().commandCommitment());
            }
        }
    }

    @Test void snapshotRestoreAndReexportPreserveEveryLiveAndCompletedCut(@TempDir Path root) throws Exception {
        for (SnapshotCut cut : SnapshotCut.values()) {
            Path source = root.resolve(cut.name());
            Path snapshot = root.resolve(cut.name() + "-snapshot");
            Path reexport = root.resolve(cut.name() + "-reexport");
            PkiId operation;
            PkiId generation;
            EncodedObject signature;
            String expectedDigest;
            long expectedLength;
            DurableContentReference sourceIssuer;
            DurableContentReference sourceStatus = null;
            DurableContentReference sourceTbs;
            try (FilesystemPkiStore store = open(source)) {
                Fixture fixture = fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                        cut == SnapshotCut.COMPLETED ? 55_000 : 2);
                registerCa(store, fixture);
                generation = fixture.prepared().issuerGenerationId();
                assertEquals(BigInteger.ONE, store.reserveCrlNumber(generation));
                operation = accept(store, fixture);
                signature = fixture.signature();
                expectedLength = fixture.outer().length;
                expectedDigest = DomainContinuationPublisher.sha256(fixture.outer());
                sourceIssuer = fixture.prepared().issuerContent();
                sourceTbs = fixture.prepared().tbsContent();
                if (cut != SnapshotCut.SIGNING) {
                    sign(store, operation, signature);
                    publishing(store, operation);
                }
                if (cut == SnapshotCut.PUBLISHED) {
                    DomainContinuationPublisher.installPublicationFault(point -> { throw new SimulatedCrash(); });
                    try {
                        assertThrows(SimulatedCrash.class, () -> new SigningOuterTerminalDriver(store)
                                .advance(store.getSignWorkflow(operation).orElseThrow()));
                    } finally {
                        DomainContinuationPublisher.clearPublicationFault();
                    }
                } else if (cut == SnapshotCut.COMPLETED) {
                    new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
                    assertTrue(expectedLength > 1_048_576);
                    assertThrows(Exception.class, () -> store.stagedContent().openContent(sourceTbs));
                }
                if (cut == SnapshotCut.PUBLISHED || cut == SnapshotCut.COMPLETED) {
                    sourceStatus = store.listStatusObjects(CA).getFirst().content();
                }
                // Export the latest history: CA history uses wall time, independently of the fixture clock.
                store.exportSnapshot(snapshot, Instant.MAX);
            }
            DurableContentReference restoredStatus;
            try (FilesystemPkiStore store = open(snapshot)) {
                assertEquals(BigInteger.TWO, store.reserveCrlNumber(generation));
                DurableContentReference issuer = store.getCredential(store.getIssuerGeneration(generation)
                        .orElseThrow().credentialId()).orElseThrow().content();
                assertNotEquals(sourceIssuer.contentId(), issuer.contentId());
                assertEquals(sourceIssuer.sha256(), issuer.sha256());
                DomainContinuationStore.Record restored = store.getDomainContinuation(operation).orElseThrow();
                assertEquals(cut == SnapshotCut.SIGNING ? DomainContinuationStore.State.SIGNING
                        : cut == SnapshotCut.COMPLETED ? DomainContinuationStore.State.COMPLETED
                        : DomainContinuationStore.State.PUBLISHING, restored.state());
                if (cut != SnapshotCut.COMPLETED) {
                    assertContent(store, restored.signingContent().orElseThrow(), sourceTbs.length(), sourceTbs.sha256());
                }
                if (cut == SnapshotCut.SIGNING) { sign(store, operation, signature); }
                new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
                StatusObject status = completedStatus(store, operation, expectedDigest);
                restoredStatus = status.content();
                if (sourceStatus != null) { assertNotEquals(sourceStatus.contentId(), restoredStatus.contentId()); }
                assertContent(store, restoredStatus, expectedLength, expectedDigest);
                assertEquals(1, store.listStatusObjects(CA).size());
                store.exportSnapshot(reexport, Instant.MAX);
            }
            try (FilesystemPkiStore store = open(reexport)) {
                assertEquals(BigInteger.valueOf(3), store.reserveCrlNumber(generation));
                StatusObject status = completedStatus(store, operation, expectedDigest);
                assertNotEquals(restoredStatus.contentId(), status.content().contentId());
                assertContent(store, status.content(), expectedLength, expectedDigest);
                assertEquals(1, store.listStatusObjects(CA).size());
            }
        }
    }

    static StatusObject completedStatus(FilesystemPkiStore store, PkiId operation, String digest) {
        DomainContinuationStore.Record domain = store.getDomainContinuation(operation).orElseThrow();
        assertEquals(DomainContinuationStore.State.COMPLETED, domain.state());
        assertEquals(68, domain.result().orElseThrow().bytes().length);
        FullCrlSigningCommand.requireCompleted(store, domain);
        PkiId id = FullCrlSigningCommand.resultId(domain.result().orElseThrow());
        assertEquals("crl:" + digest, id.value());
        return store.getStatusObject(id).orElseThrow();
    }

    static void assertContent(FilesystemPkiStore store, DurableContentReference reference, long expectedLength,
            String expectedDigest) throws Exception {
        assertEquals(expectedLength, reference.length());
        assertEquals(expectedDigest, reference.sha256());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long length = 0;
        byte[] chunk = new byte[16 * 1024];
        try (RepeatableContent content = store.stagedContent().openContent(reference); InputStream input = content.openStream()) {
            int count;
            while ((count = input.read(chunk)) != -1) {
                digest.update(chunk, 0, count);
                length += count;
            }
        }
        assertEquals(expectedLength, length);
        assertEquals(expectedDigest, HexFormat.of().formatHex(digest.digest()));
    }

    private enum SnapshotCut { SIGNING, PUBLISHING, PUBLISHED, COMPLETED }
    private static final class SimulatedCrash extends RuntimeException { private static final long serialVersionUID = 1L; }
}
