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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.SemanticIssuanceFixture;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.Credential;
import zeroecho.core.io.CancellationSignal;

class FilesystemCrlScopeRecoveryTest {
    @Test void missingCounterOrOwnerFailsReopenWithoutReconstruction(@TempDir Path root) throws Exception {
        CrlScopeOwner owner = unreferencedOwner();
        for (boolean removeOwner : new boolean[] {false, true}) {
            Path directory = root.resolve(Boolean.toString(removeOwner));
            try (FilesystemPkiStore store = open(directory)) {
                FilesystemSignScopeAcceptanceTest.reservations(store).claim(owner);
                remove(store, removeOwner ? CrlScopeMetadataCodec.key(owner)
                        : CrlScopeMetadataCodec.counterKey(owner.scope()));
            }
            assertThrows(IllegalStateException.class, () -> new FilesystemPkiStore(directory,
                    FsPkiStoreOptions.defaults().withInitialCrlNumber(BigInteger.valueOf(900))));
        }
    }

    @Test void malformedWrongScopeAndLegacyCountersFailReopen(@TempDir Path root) throws Exception {
        CrlScopeOwner owner = unreferencedOwner();
        byte[] encoded = CrlScopeMetadataCodec.encode(new CrlScopeCounter(owner.scope().digest(), BigInteger.ONE));
        byte[] legacy = encoded.clone();
        ByteBuffer.wrap(legacy).putInt(4, 0);
        byte[] wrongScope = encoded.clone();
        wrongScope[12] ^= 1;
        byte[] outOfRange = CrlScopeMetadataCodec.encode(new CrlScopeCounter(owner.scope().digest(),
                CrlScopeCounter.EXHAUSTED));
        outOfRange[outOfRange.length - 1] = 1;
        List<byte[]> invalid = List.of(new byte[] {1}, legacy, wrongScope,
                Arrays.copyOf(encoded, encoded.length - 1), Arrays.copyOf(encoded, encoded.length + 1), outOfRange);
        for (int index = 0; index < invalid.size(); index++) {
            Path directory = root.resolve(Integer.toString(index));
            try (FilesystemPkiStore store = open(directory)) {
                FilesystemSignScopeAcceptanceTest.reservations(store).claim(owner);
                replace(store, CrlScopeMetadataCodec.counterKey(owner.scope()), invalid.get(index));
            }
            assertThrows(IllegalStateException.class, () -> open(directory));
        }
    }

    @Test void counterUnderWrongKeyFailsEvenWithAnotherValidPair(@TempDir Path root) throws Exception {
        CrlScopeOwner owner = unreferencedOwner();
        CrlScopeCounter counter = new CrlScopeCounter(owner.scope().digest(), BigInteger.ONE);
        try (FilesystemPkiStore store = open(root)) {
            FilesystemSignScopeAcceptanceTest.reservations(store).claim(owner);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, store.metadataStore().directCommit(List.of(
                    new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.CREATE,
                            new MetadataKey("io.zeroecho.pki.crl-scope-counter", "01".repeat(32)), -1,
                            CrlScopeMetadataCodec.encode(counter)))).outcome());
        }
        assertThrows(IllegalStateException.class, () -> open(root));
    }

    @Test void invalidPairSnapshotPublishesNeitherTargetNorPartialRoot(@TempDir Path root) throws Exception {
        CrlScopeOwner owner = unreferencedOwner();
        for (int kind = 0; kind < 3; kind++) {
            Path directory = root.resolve("source-" + kind);
            Path target = root.resolve("snapshot-" + kind);
            try (FilesystemPkiStore store = open(directory)) {
                FilesystemSignScopeAcceptanceTest.reservations(store).claim(owner);
                if (kind == 0) {
                    remove(store, CrlScopeMetadataCodec.counterKey(owner.scope()));
                } else if (kind == 1) {
                    remove(store, CrlScopeMetadataCodec.key(owner));
                } else {
                    replace(store, CrlScopeMetadataCodec.counterKey(owner.scope()), new byte[] {1});
                }
                assertThrows(IllegalStateException.class, () -> store.exportSnapshot(target, Instant.now()));
                assertFalse(Files.exists(target));
            }
            try (java.util.stream.Stream<Path> siblings = Files.list(root)) {
                assertFalse(siblings.anyMatch(path -> path.getFileName().toString().startsWith(".zeroecho-snapshot-")));
            }
        }
    }

    @Test void coherentDifferentKeyRootClaimsCannotReplaceRetainedCandidateScope(@TempDir Path root) throws Exception {
        Instant now = Instant.parse("2026-09-20T00:00:00Z");
        try (FilesystemPkiStore store = openAt(root, now)) {
            SignWorkflowStore.AcceptanceCommand command = FilesystemSignScopeAcceptanceTest.rootCommand(store, 9);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            CrlScope original = FilesystemSignScopeAcceptanceTest.candidateScope(command, store);
            CrlScopeOwner owner = FilesystemSignScopeAcceptanceTest.reservations(store).findOwner(original).orElseThrow();
            ScopeSerialReservation reservation = FilesystemSignScopeAcceptanceTest.reservations(store)
                    .findReservation(original, BigInteger.valueOf(9)).orElseThrow();
            java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            CrlScope replacement = CrlScope.of(new javax.security.auth.x500.X500Principal(original.canonicalIssuerName()).getEncoded(),
                    generator.generateKeyPair().getPublic().getEncoded());
            remove(store, CrlScopeMetadataCodec.key(reservation));
            remove(store, CrlScopeMetadataCodec.key(owner));
            remove(store, CrlScopeMetadataCodec.counterKey(original));
            FilesystemSignScopeAcceptanceTest.reservations(store).claim(new CrlScopeOwner(replacement, owner.authorityId()),
                    new ScopeSerialReservation(replacement, reservation.serial(), reservation.issuanceOwner()));
            assertEquals(SignWorkflowStore.State.INTENT, store.getSignWorkflow(command.operationId()).orElseThrow().state());
        }
        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> openAt(root, now));
        assertEquals("Root signing scope differs from its retained accepted candidate", failure.getMessage());
    }

    @Test void terminalOperationsReopenWithoutTbsAndPurgeKeepsClaimsThroughTwoSnapshots(@TempDir Path root)
            throws Exception {
        for (boolean expire : new boolean[] {false, true}) {
            Path directory = root.resolve(Boolean.toString(expire));
            Instant now = Instant.parse("2026-09-20T00:00:00Z");
            SignWorkflowStore.AcceptanceCommand command;
            CrlScope scope;
            try (FilesystemPkiStore store = openAt(directory, now)) {
                command = FilesystemSignScopeAcceptanceTest.rootCommand(store, 9);
                scope = FilesystemSignScopeAcceptanceTest.candidateScope(command, store);
                store.acceptSign(command);
                if (!expire) {
                    SignWorkflowStore.Workflow claimed = store.claimSignStep(command.operationId(), 0, Duration.ofSeconds(10)).orElseThrow();
                    SignWorkflowStore.Workflow failed = store.transitionSign(command.operationId(), claimed.revision(), claimed.fence(),
                            SignWorkflowStore.State.FAILED, Optional.of("DENIED"), Optional.empty(), Optional.empty()).orElseThrow();
                    DomainContinuationStore.Record domain = store.getDomainContinuation(command.operationId()).orElseThrow();
                    store.transitionDomainContinuation(command.operationId(), domain.revision(), DomainContinuationStore.State.FAILED,
                            Optional.empty(), Optional.of("FAILED")).orElseThrow();
                    store.retireSign(command.operationId(), failed.revision(), failed.fence()).orElseThrow();
                    assertThrows(java.io.IOException.class, () -> store.stagedContent().openContent(command.candidate()));
                }
            }
            try (FilesystemPkiStore store = openAt(directory, now.plusSeconds(61))) {
                assertEquals(expire ? SignWorkflowStore.State.EXPIRED : SignWorkflowStore.State.RETIRED,
                        store.getSignWorkflow(command.operationId()).orElseThrow().state());
                assertThrows(java.io.IOException.class, () -> store.stagedContent().openContent(command.candidate()));
            }
            Instant purgeTime = now.plus(FsPkiStoreOptions.defaults().signingOperationHorizon()).plusSeconds(1);
            Path snapshot = root.resolve("snapshot-" + expire);
            Path secondSnapshot = root.resolve("snapshot2-" + expire);
            try (FilesystemPkiStore store = openAt(directory, purgeTime)) {
                assertEquals(1, store.purgeExpiredSignRecords());
                assertTrue(store.getSignWorkflow(command.operationId()).isEmpty());
                store.exportSnapshot(snapshot, purgeTime);
            }
            try (FilesystemPkiStore store = openAt(snapshot, purgeTime)) {
                assertTrue(store.getSignWorkflow(command.operationId()).isEmpty());
                assertTrue(FilesystemSignScopeAcceptanceTest.reservations(store).findReservation(scope, BigInteger.valueOf(9)).isPresent());
                store.exportSnapshot(secondSnapshot, purgeTime);
            }
            try (FilesystemPkiStore store = openAt(secondSnapshot, purgeTime)) {
                assertTrue(FilesystemSignScopeAcceptanceTest.reservations(store).findReservation(scope, BigInteger.valueOf(9)).isPresent());
            }
        }
    }

    @Test void missingSerialAndIssuanceProjectionsAreRebuilt(@TempDir Path root) throws Exception {
        PkiId id;
        try (FilesystemPkiStore store = open(root)) {
            id = leaf(store).credentialId();
            removeNamespace(store, "io.zeroecho.pki.credential-serial-index");
            removeNamespace(store, FilesystemPkiStore.ISSUANCE_EVIDENCE_NAMESPACE);
        }
        try (FilesystemPkiStore store = open(root)) {
            assertEquals(id, store.getCredentialByIssuerAndSerial(SemanticIssuanceFixture.issuerId(1),
                    BigInteger.valueOf(42)).orElseThrow().credentialId());
            try (MetadataEvidenceLog.Reader reader = new MetadataEvidenceLog(store.metadataStore(),
                    FilesystemPkiStore.ISSUANCE_EVIDENCE_NAMESPACE).openReader(-1)) {
                assertTrue(reader.next(CancellationSignal.NONE));
                assertEquals(id, reader.current().objectId());
                assertEquals(1, reader.highWatermark());
            }
        }
    }

    @Test void contradictoryEvidenceMarkerAndSerialProjectionFailClosed(@TempDir Path root) throws Exception {
        for (boolean evidence : new boolean[] {true, false}) {
            Path directory = root.resolve(Boolean.toString(evidence));
            try (FilesystemPkiStore store = open(directory)) {
                leaf(store);
                if (evidence) {
                    remove(store, new MetadataKey(FilesystemPkiStore.ISSUANCE_EVIDENCE_NAMESPACE, "e:0000000000000000000"));
                } else {
                    store.metadataStore().directCommit(List.of(new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.CREATE,
                            new MetadataKey("io.zeroecho.pki.credential-serial-index", "invalid"), -1, new byte[] {1})));
                }
            }
            assertThrows(IllegalStateException.class, () -> open(directory));
        }
    }

    @Test void acceptedUnpublishedRootRequiresBothPermanentRows(@TempDir Path root) throws Exception {
        for (boolean owner : new boolean[] {false, true}) {
            Path directory = root.resolve(Boolean.toString(owner));
            try (FilesystemPkiStore store = open(directory)) {
                SignWorkflowStore.AcceptanceCommand command = FilesystemSignScopeAcceptanceTest.rootCommand(store, 9);
                assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
                CrlScope scope = FilesystemSignScopeAcceptanceTest.candidateScope(command, store);
                remove(store, owner ? CrlScopeMetadataCodec.ownerKey(scope)
                        : CrlScopeMetadataCodec.reservationKey(scope, BigInteger.valueOf(9)));
            }
            assertThrows(IllegalStateException.class, () -> open(directory));
        }
    }

    @Test void publishedImportRequiresExactReservation(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            zeroecho.pki.api.credential.Credential credential = SemanticIssuanceFixture.issuer(store, 1);
            CrlScope scope = FilesystemSignScopeAcceptanceTest.scope(store, credential);
            remove(store, CrlScopeMetadataCodec.reservationKey(scope, new BigInteger(credential.serialOrUniqueId())));
        }
        assertThrows(IllegalStateException.class, () -> open(root));
    }

    @Test void acceptedIssuanceRequiresReservationAndReopensWithoutGenerationEnumeration(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            store.acceptSign(FilesystemSignScopeAcceptanceTest.command(store, 1, 42, -1, "", null));
            SemanticIssuanceFixture.issuer(store, 2);
        }
        FilesystemPkiStore.startIssuerGenerationReadCounting();
        try (FilesystemPkiStore store = open(root)) {
            assertEquals(1, store.listSignWorkflows().size());
            assertEquals(0, FilesystemPkiStore.issuerGenerationReadCounts()[1]);
            CrlScope scope = FilesystemSignScopeAcceptanceTest.scope(store, SemanticIssuanceFixture.issuer(store, 1));
            remove(store, CrlScopeMetadataCodec.reservationKey(scope, BigInteger.valueOf(42)));
        } finally { FilesystemPkiStore.stopIssuerGenerationReadCounting(); }
        assertThrows(IllegalStateException.class, () -> open(root));
    }

    @Test void malformedUnreferencedAuthorityFailsAtOpen(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            store.metadataStore().directCommit(List.of(new SigningTransactionPayloadCodec.Mutation(
                    SigningTransactionPayloadCodec.MutationKind.CREATE,
                    new MetadataKey("io.zeroecho.pki.crl-scope-owner", "invalid"), -1, new byte[] {1})));
        }
        assertThrows(IllegalStateException.class, () -> open(root));
    }

    @Test void validUnpublishedRootReopensWithoutCompletedCa(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED,
                    store.acceptSign(FilesystemSignScopeAcceptanceTest.rootCommand(store, 9)));
        }
        try (FilesystemPkiStore store = open(root)) {
            assertTrue(store.listCas().isEmpty());
            assertEquals(1, store.listSignWorkflows().size());
        }
    }

    static void remove(FilesystemPkiStore store, MetadataKey key) throws Exception {
        long revision;
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
            revision = record.recordRevision();
        }
        store.metadataStore().directCommit(List.of(new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.DELETE, key, revision, null)));
    }

    private static void replace(FilesystemPkiStore store, MetadataKey key, byte[] encoded) throws Exception {
        long revision;
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
            revision = record.recordRevision();
        }
        assertEquals(MetadataCommitResult.Outcome.COMMITTED, store.metadataStore().directCommit(List.of(
                new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.REPLACE,
                        key, revision, encoded))).outcome());
    }

    private static CrlScopeOwner unreferencedOwner() {
        CrlScope scope = CrlScope.of(new javax.security.auth.x500.X500Principal("CN=CounterRecovery").getEncoded(),
                HexFormat.of().parseHex("302a300506032b6570032100" + "01".repeat(32)));
        return new CrlScopeOwner(scope, new PkiId("counter-recovery"));
    }

    private static void removeNamespace(FilesystemPkiStore store, String namespace) throws Exception {
        List<MetadataKey> keys = new ArrayList<>();
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) { keys.add(record.key()); }
            }
        }
        for (MetadataKey key : keys) { remove(store, key); }
    }

    private static Credential leaf(FilesystemPkiStore store) throws Exception {
        SemanticIssuanceFixture.issuer(store, 1);
        byte[] der = SemanticIssuanceFixture.certificate("CN=Leaf", BigInteger.valueOf(42),
                SemanticIssuanceFixture.BEFORE, SemanticIssuanceFixture.AFTER).getEncoded();
        Credential credential = new Credential(new PkiId("leaf"), new zeroecho.pki.api.FormatId("x509"),
                new zeroecho.pki.api.IssuerRef(SemanticIssuanceFixture.AUTHORITY, SemanticIssuanceFixture.issuerId(1),
                        SemanticIssuanceFixture.path(1).pathId()), new zeroecho.pki.api.SubjectRef("CN=Leaf"),
                new zeroecho.pki.api.Validity(SemanticIssuanceFixture.BEFORE, SemanticIssuanceFixture.AFTER), "42",
                new PkiId("public-key"), new zeroecho.pki.api.credential.EndEntityProfileBinding(
                        new zeroecho.pki.api.profile.CertificateProfileRef("profile", 1, new byte[32])),
                zeroecho.pki.api.credential.CredentialStatus.ISSUED, PkiTestRuntime.stageCredential(store, der),
                new zeroecho.pki.impl.core.attr.SimpleAttributeSet());
        store.putCredential(credential);
        return credential;
    }

    private static FilesystemPkiStore openAt(Path root, Instant now) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), Clock.fixed(now, ZoneOffset.UTC));
    }

    private static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()); }
}
