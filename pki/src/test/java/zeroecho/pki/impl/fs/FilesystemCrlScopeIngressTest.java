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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.api.content.DurableContentOwner;

class FilesystemCrlScopeIngressTest {
    private static final Instant BEFORE = Instant.parse("2025-01-01T00:00:00Z");
    private static final Instant AFTER = Instant.parse("2030-01-01T00:00:00Z");
    private static final PkiId AUTHORITY = new PkiId("ca:scope");
    private static final CertificateProfileRef PROFILE = new CertificateProfileRef("scope", 1, new byte[32]);
    private static KeyPair rootKey;
    private static KeyPair subjectKey;

    @BeforeAll static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        rootKey = generator.generateKeyPair();
        subjectKey = generator.generateKeyPair();
    }

    @Test void sameScopeRolloverKeepsPermanentSerialUniquenessAndExactReplay(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Authority first = root(store, AUTHORITY, 1);
            Authority second = root(store, AUTHORITY, 2);
            Credential issued = leaf(store, first, "first", 42);
            store.putCredential(issued);
            store.putCredential(issued);
            Credential conflict = leaf(store, second, "different", 42);
            assertThrows(IllegalStateException.class, () -> store.putCredential(conflict));
            assertFalse(store.getCredential(conflict.credentialId()).isPresent());
            assertEquals(issued.credentialId(), store.getCredentialByIssuerAndSerial(first.generation().issuerId(),
                    BigInteger.valueOf(42)).orElseThrow().credentialId());
            assertTrue(store.getCredentialByIssuerAndSerial(second.generation().issuerId(), BigInteger.valueOf(42)).isEmpty());
        }
    }

    @Test void scopeCannotBeClaimedByAnotherLogicalAuthority(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            root(store, AUTHORITY, 1);
            assertThrows(IllegalStateException.class, () -> root(store, new PkiId("ca:other"), 2));
        }
    }

    @Test void unresolvedIssuerAndChangedMetadataCannotBypassIngress(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Authority authority = root(store, AUTHORITY, 1);
            Credential leaf = leaf(store, authority, "leaf", 9);
            Credential unresolved = copy(leaf, new IssuerRef(AUTHORITY), "9");
            assertThrows(IllegalStateException.class, () -> store.putCredential(unresolved));
            assertThrows(IllegalStateException.class, () -> store.putCredential(copy(leaf, leaf.issuerRef(), "10")));
            assertFalse(store.getCredential(leaf.credentialId()).isPresent());
            store.putCredential(leaf);
        }
    }

    @Test void intermediateSerialBelongsToParentAndSubjectScopeToChild(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Authority parent = root(store, AUTHORITY, 1);
            PkiId childId = new PkiId("ca:child");
            X509CertificateHolder childCertificate = certificate(rootKey, parent.certificate().getSubject(), subjectKey,
                    "CN=Child", 17);
            Credential child = credential(store, "child", childCertificate,
                    new IssuerRef(AUTHORITY, parent.generation().issuerId(), parent.path().pathId()), true);
            store.putCredential(child);
            IssuerGeneration generation = generation(childId, child);
            store.putIssuerGeneration(generation);
            IssuerChainPath path = IssuerChainPath.create(childId, generation.issuerId(),
                    List.of(child.credentialId(), parent.credential().credentialId()));
            store.putIssuerChainPath(path);
            assertEquals(child.credentialId(), store.getCredentialByIssuerAndSerial(parent.generation().issuerId(),
                    BigInteger.valueOf(17)).orElseThrow().credentialId());
            assertTrue(store.getCredentialByIssuerAndSerial(generation.issuerId(), BigInteger.valueOf(17)).isEmpty());
            Credential childLeaf = credential(store, "child-leaf", certificate(subjectKey, childCertificate.getSubject(),
                    rootKey, "CN=Child Leaf", 17), new IssuerRef(childId, generation.issuerId(), path.pathId()), false);
            store.putCredential(childLeaf);
            assertEquals(childLeaf.credentialId(), store.getCredentialByIssuerAndSerial(generation.issuerId(),
                    BigInteger.valueOf(17)).orElseThrow().credentialId());
            assertThrows(IllegalStateException.class, () -> store.putIssuerGeneration(generation(new PkiId("ca:thief"), child)));
        }
    }

    @Test void concurrentDirectImportsHaveOneSerialWinner(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root); java.util.concurrent.ExecutorService workers = Executors.newFixedThreadPool(2)) {
            Authority authority = root(store, AUTHORITY, 1);
            Credential first = leaf(store, authority, "race-a", 88);
            Credential second = leaf(store, authority, "race-b", 88);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Boolean>> results = new ArrayList<>();
            for (Credential candidate : List.of(first, second)) {
                results.add(workers.submit(() -> {
                    start.await();
                    try { store.putCredential(candidate); return true; }
                    catch (IllegalStateException conflict) { return false; }
                }));
            }
            start.countDown();
            int winners = 0;
            for (Future<Boolean> result : results) { if (result.get()) { winners++; } }
            assertEquals(1, winners);
            assertEquals(1, (store.getCredential(first.credentialId()).isPresent() ? 1 : 0)
                    + (store.getCredential(second.credentialId()).isPresent() ? 1 : 0));
        }
    }

    @Test void snapshotRestoreUsesTheSameIssuerAndSerialIngress(@TempDir Path root) throws Exception {
        Path snapshot = root.resolve("snapshot");
        Authority authority;
        Credential original;
        try (FilesystemPkiStore store = open(root.resolve("source"))) {
            authority = root(store, AUTHORITY, 1);
            original = leaf(store, authority, "snapshot-leaf", 42);
            store.putCredential(original);
            store.exportSnapshot(snapshot, Instant.now());
        }
        try (FilesystemPkiStore restored = open(snapshot)) {
            assertTrue(restored.getCredential(original.credentialId()).isPresent());
            Credential duplicate = leaf(restored, authority, "changed-snapshot-leaf", 42);
            assertThrows(IllegalStateException.class, () -> restored.putCredential(duplicate));
            assertFalse(restored.getCredential(duplicate.credentialId()).isPresent());
        }
    }

    @Test void committedReservationSurvivesPublicationInterruptionAndUnknownCommit(@TempDir Path root) throws Exception {
        for (FilesystemPkiStore.CredentialReservationFault fault : List.of(
                FilesystemPkiStore.CredentialReservationFault.BEFORE_CREDENTIAL,
                FilesystemPkiStore.CredentialReservationFault.COMMIT_AS_UNKNOWN)) {
            Path directory = root.resolve(fault.name());
            Credential original;
            Authority authority;
            try (FilesystemPkiStore store = open(directory)) {
                authority = root(store, AUTHORITY, 1);
                original = leaf(store, authority, "reserved", 90);
                FilesystemPkiStore.installCredentialReservationFault(fault);
                try {
                    assertThrows(RuntimeException.class, () -> store.putCredential(original));
                    if (fault == FilesystemPkiStore.CredentialReservationFault.COMMIT_AS_UNKNOWN) {
                        assertThrows(PkiException.class, () -> store.getCredential(original.credentialId()));
                    } else {
                        assertFalse(store.getCredential(original.credentialId()).isPresent());
                    }
                } finally { FilesystemPkiStore.clearCredentialReservationFault(); }
            }
            try (FilesystemPkiStore reopened = open(directory)) {
                assertFalse(reopened.getCredential(original.credentialId()).isPresent());
                Credential conflicting = leaf(reopened, authority, "conflict", 90);
                assertThrows(IllegalStateException.class, () -> reopened.putCredential(conflicting));
                Credential retry = leaf(reopened, authority, "reserved", 90);
                reopened.putCredential(retry);
                assertTrue(reopened.getCredential(retry.credentialId()).isPresent());
            }
        }
    }

    @Test void snapshotKeepsUnpublishedAndPostAtReservationsWithoutHistoricalCa(@TempDir Path root) throws Exception {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        FsPkiStoreOptions options = new FsPkiStoreOptions(defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), false, defaults.signingOperationHorizon(),
                defaults.signingIdPermittedSkew(), defaults.signingMaximumGroupSize(), defaults.signingResidentIndexBudgetBytes(),
                defaults.signingCompactionTransientBudgetBytes(), defaults.initialCrlNumber(), false);
        Path snapshot = root.resolve("historical");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("source"), options)) {
            Authority authority = rootWithoutCaRecord(store, AUTHORITY, 1);
            assertTrue(store.getCa(AUTHORITY).isEmpty());
            Credential unpublished = leaf(store, authority, "unpublished", 73);
            FilesystemPkiStore.installCredentialReservationFault(FilesystemPkiStore.CredentialReservationFault.BEFORE_CREDENTIAL);
            try { assertThrows(IllegalStateException.class, () -> store.putCredential(unpublished)); }
            finally { FilesystemPkiStore.clearCredentialReservationFault(); }
            store.exportSnapshot(snapshot, Instant.EPOCH);
        }
        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshot, options)) {
            assertTrue(restored.getCa(AUTHORITY).isEmpty());
            assertThrows(IllegalStateException.class, () -> root(restored, new PkiId("ca:other"), 2));
            Authority issuer = root(restored, AUTHORITY, 1);
            Credential conflicting = leaf(restored, issuer, "changed-unpublished", 73);
            assertThrows(IllegalStateException.class, () -> restored.putCredential(conflicting));
            Credential exact = leaf(restored, issuer, "unpublished", 73);
            restored.putCredential(exact);
            restored.exportSnapshot(root.resolve("second"), Instant.now());
        }
        try (FilesystemPkiStore second = new FilesystemPkiStore(root.resolve("second"), options)) {
            assertTrue(second.getCredential(new PkiId("unpublished")).isPresent());
        }
    }

    @Test void snapshotRestoresIntermediateAndSameScopeGenerations(@TempDir Path root) throws Exception {
        Path snapshot = root.resolve("snapshot");
        PkiId childLeafId;
        try (FilesystemPkiStore store = open(root.resolve("source"))) {
            Authority parent = root(store, AUTHORITY, 1);
            root(store, AUTHORITY, 2);
            PkiId childAuthority = new PkiId("ca:snapshot-child");
            X509CertificateHolder certificate = certificate(rootKey, parent.certificate().getSubject(), subjectKey,
                    "CN=Snapshot Child", 9);
            Credential child = credential(store, "snapshot-child", certificate,
                    new IssuerRef(AUTHORITY, parent.generation().issuerId(), parent.path().pathId()), true);
            store.putCredential(child);
            IssuerGeneration generation = generation(childAuthority, child);
            store.putIssuerGeneration(generation);
            IssuerChainPath path = IssuerChainPath.create(childAuthority, generation.issuerId(),
                    List.of(child.credentialId(), parent.credential().credentialId()));
            store.putIssuerChainPath(path);
            store.putCa(new CaRecord(childAuthority, CaKind.INTERMEDIATE, CaState.ACTIVE, generation.signingKeyRef(),
                    child.subjectRef(), List.of(generation.issuerId()), generation.issuerId(), path.pathId()));
            Credential leaf = credential(store, "snapshot-child-leaf", certificate(subjectKey, certificate.getSubject(), rootKey,
                    "CN=Snapshot Child Leaf", 9), new IssuerRef(childAuthority, generation.issuerId(), path.pathId()), false);
            childLeafId = leaf.credentialId();
            store.putCredential(leaf);
            store.exportSnapshot(snapshot, Instant.now());
        }
        try (FilesystemPkiStore restored = open(snapshot)) {
            assertTrue(restored.getCredential(childLeafId).isPresent());
            assertEquals(2, restored.listIssuerGenerations(AUTHORITY).size());
            assertEquals(2, restored.listCas().size());
        }
    }

    @Test void conflictingImportedSnapshotAuthorityAbortsWithoutTarget(@TempDir Path root) throws Exception {
        Path snapshot = root.resolve("snapshot");
        try (FilesystemPkiStore store = open(root.resolve("source"))) {
            Authority authority = root(store, AUTHORITY, 1);
            FilesystemPkiStore.SnapshotCredentialAuthority proof = store.credentialSnapshotAuthority(authority.credential()).orElseThrow();
            ScopeSerialReservation conflict = new ScopeSerialReservation(proof.reservation().scope(), proof.reservation().serial(),
                    new ScopeSerialReservation.ImportedCertificateOwner("ff".repeat(32)));
            zeroecho.pki.spi.store.MetadataKey key = CrlScopeMetadataCodec.key(conflict);
            long revision;
            try (zeroecho.pki.spi.store.MetadataSnapshot metadata = store.metadataStore().snapshot();
                    zeroecho.pki.spi.store.MetadataSnapshot.Record record = metadata.get(key).orElseThrow()) {
                revision = record.recordRevision();
            }
            store.metadataStore().directCommit(List.of(new SigningTransactionPayloadCodec.Mutation(
                    SigningTransactionPayloadCodec.MutationKind.REPLACE, key, revision, CrlScopeMetadataCodec.encode(conflict))));
            byte[] credentialBefore = FsCodec.encode(FsCodec.CREDENTIAL,
                    store.getCredential(authority.credential().credentialId()).orElseThrow());
            CaRecord caBefore = store.getCa(AUTHORITY).orElseThrow();
            assertThrows(IllegalStateException.class, () -> store.exportSnapshot(snapshot, Instant.now()));
            assertFalse(java.nio.file.Files.exists(snapshot));
            assertArrayEquals(credentialBefore, FsCodec.encode(FsCodec.CREDENTIAL,
                    store.getCredential(authority.credential().credentialId()).orElseThrow()));
            assertEquals(caBefore, store.getCa(AUTHORITY).orElseThrow());
            assertEquals(conflict, new CrlScopeReservationStore(store.metadataStore(), BigInteger.ONE, ignored -> { })
                    .findReservation(conflict.scope(), conflict.serial()).orElseThrow());
        }
    }

    @Test void issuerPathAcceptsOriginalAndAlternateParentGeneration(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Authority original = rootWithoutCaRecord(store, AUTHORITY, 1);
            Authority alternate = rootWithoutCaRecord(store, AUTHORITY, 2);
            Authority child = pathChild(store, original);
            store.putIssuerChainPath(child.path());
            IssuerChainPath alternatePath = selectedParentPath(child, alternate.credential());
            store.putIssuerChainPath(alternatePath);
            assertEquals(child.path(), store.getIssuerChainPath(child.path().pathId()).orElseThrow());
            assertEquals(alternatePath, store.getIssuerChainPath(alternatePath.pathId()).orElseThrow());
        }
    }

    @Test void issuerPathRejectsMissingParentGenerationWrongAuthorityNameAndSignature(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Authority original = rootWithoutCaRecord(store, AUTHORITY, 1);
            Authority child = pathChild(store, original);
            Credential missing = candidateParent(store, "missing", AUTHORITY, rootKey, "CN=Scope Root", 3, false);
            Credential wrongAuthority = candidateParent(store, "wrong-authority", new PkiId("ca:unrelated"),
                    rootKey, "CN=Other Authority", 1, true);
            Credential wrongName = candidateParent(store, "wrong-name", AUTHORITY, rootKey, "CN=Wrong Name", 1, true);
            Credential wrongSignature = candidateParent(store, "wrong-signature", AUTHORITY, subjectKey, "CN=Scope Root", 1, true);
            for (Credential invalidParent : List.of(missing, wrongAuthority, wrongName, wrongSignature)) {
                IssuerChainPath invalid = selectedParentPath(child, invalidParent);
                assertThrows(IllegalStateException.class, () -> store.putIssuerChainPath(invalid));
                assertTrue(store.getIssuerChainPath(invalid.pathId()).isEmpty());
            }
        }
    }

    @Test void issuerGenerationReadsForTwoCertificateIngressDoNotScaleWithPopulation(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Authority parent = rootWithoutCaRecord(store, AUTHORITY, 1);
            Authority child = pathChild(store, parent);
            store.putIssuerChainPath(child.path());
            Credential unrelated = new Credential(new PkiId("unrelated-generation-fixture"), new FormatId("generation-test-binary"),
                    parent.credential().issuerRef(), new SubjectRef("unrelated"), new Validity(BEFORE, AFTER), "1",
                    new PkiId("key:unrelated"), new CaProfileBinding(PROFILE), CredentialStatus.ISSUED,
                    PkiTestRuntime.stageCredential(store, new byte[] {1, 2}), new SimpleAttributeSet());
            store.putCredential(unrelated);
            int populated = 0;
            long baseline = -1;
            for (int population : new int[] {10, 100, 1000}) {
                while (populated < population) {
                    store.putIssuerGeneration(generation(new PkiId("ca:population:" + populated++), unrelated));
                }
                Credential leaf = credential(store, "population-leaf-" + population,
                        certificate(subjectKey, child.certificate().getSubject(), rootKey, "CN=Population Leaf", population),
                        new IssuerRef(child.generation().authorityId(), child.generation().issuerId(), child.path().pathId()), false);
                FilesystemPkiStore.startIssuerGenerationReadCounting();
                try {
                    store.putCredential(leaf);
                    long[] counts = FilesystemPkiStore.issuerGenerationReadCounts();
                    assertEquals(0L, counts[1], "issuer-generation enumeration at population " + population);
                    assertTrue(counts[0] > 0 && counts[0] <= 8, "bounded two-certificate point reads");
                    if (baseline < 0) { baseline = counts[0]; }
                    assertEquals(baseline, counts[0], "identical point reads at population " + population);
                } finally { FilesystemPkiStore.stopIssuerGenerationReadCounting(); }
            }
        }
    }

    @Test void metadataForceFailureRequiresRecoveryBeforeExactReplay(@TempDir Path root) throws Exception {
        Credential leaf;
        CredentialCommitOperations operations = new CredentialCommitOperations(true, false);
        try (FilesystemPkiStore store = open(root, operations)) {
            Authority authority = rootWithoutCaRecord(store, AUTHORITY, 1);
            leaf = leaf(store, authority, "handoff-force", 80);
            reserveBeforeCredential(store, leaf);
            operations.armed.set(true);
            assertThrows(PkiException.class, () -> store.putCredential(leaf));
            assertEquals(0, operations.entered.getCount(), "fault must reach the metadata commit force");
            PkiException retry = assertThrows(PkiException.class, () -> store.putCredential(leaf));
            assertEquals(zeroecho.pki.api.PkiFailureReason.STORE_DURABILITY_UNCONFIRMED, retry.failureReason().orElseThrow());
            assertTrue(Files.exists(root.resolve("staged-content").resolve(leaf.content().contentId() + ".content")));
            assertThrows(SigningActiveWal.RecoveryRequiredException.class, store::close);
        }
        try (FilesystemPkiStore reopened = open(root)) {
            assertEquals(leaf.credentialId(), reopened.getCredentialByIssuerAndSerial(leaf.issuerRef().issuerId(),
                    new BigInteger(leaf.serialOrUniqueId())).orElseThrow().credentialId());
            assertEquals(Set.of(DurableContentOwner.credentialRecord(leaf.credentialId())),
                    reopened.stagedContent().contentOwners(leaf.content()));
            reopened.putCredential(leaf);
        }
    }

    @Test void metadataCommitLostBeforeForceRestoresNeitherRecordNorOwner(@TempDir Path root) throws Exception {
        Credential leaf;
        Authority authority;
        CredentialCommitOperations operations = new CredentialCommitOperations(false, false);
        try (FilesystemPkiStore store = open(root, operations)) {
            authority = rootWithoutCaRecord(store, AUTHORITY, 1);
            leaf = leaf(store, authority, "handoff-reopen-force", 81);
            reserveBeforeCredential(store, leaf);
            operations.armed.set(true);
            assertThrows(PkiException.class, () -> store.putCredential(leaf));
            assertEquals(0, operations.entered.getCount());
            assertThrows(SigningActiveWal.RecoveryRequiredException.class, store::close);
        }
        try (FilesystemPkiStore reopened = open(root)) {
            assertTrue(reopened.getCredential(leaf.credentialId()).isEmpty());
            try (MetadataSnapshot snapshot = reopened.metadataStore().snapshot()) {
                assertTrue(snapshot.get(AuthorityMetadataCodec.ownerSetKey(leaf.content().contentId())).isEmpty());
            }
            assertThrows(IOException.class, () -> reopened.stagedContent().openContent(leaf.content()));
            Credential retry = leaf(reopened, authority, "handoff-reopen-force", 81);
            reopened.putCredential(retry);
            assertTrue(reopened.getCredential(retry.credentialId()).isPresent());
        }
    }

    @Test void metadataConcurrentExactReplayCannotPassUnconfirmedPublisher(@TempDir Path root) throws Exception {
        CredentialCommitOperations operations = new CredentialCommitOperations(true, true);
        try (FilesystemPkiStore store = open(root, operations); java.util.concurrent.ExecutorService workers = Executors.newFixedThreadPool(2)) {
            Authority authority = rootWithoutCaRecord(store, AUTHORITY, 1);
            Credential leaf = leaf(store, authority, "handoff-queued", 82);
            reserveBeforeCredential(store, leaf);
            operations.armed.set(true);
            CountDownLatch retryStarted = new CountDownLatch(1);
            java.util.concurrent.atomic.AtomicReference<Thread> retryThread = new java.util.concurrent.atomic.AtomicReference<>();
            Future<PkiException> first = workers.submit(() -> assertThrows(PkiException.class, () -> store.putCredential(leaf)));
            try {
                assertTrue(operations.entered.await(10, TimeUnit.SECONDS));
                assertTrue(store.getCredential(leaf.credentialId()).isEmpty());
                assertTrue(store.stagedContent().contentOwners(leaf.content()).isEmpty());
                Future<PkiException> retry = workers.submit(() -> {
                    retryThread.set(Thread.currentThread());
                    retryStarted.countDown();
                    return assertThrows(PkiException.class, () -> store.putCredential(leaf));
                });
                assertTrue(retryStarted.await(10, TimeUnit.SECONDS));
                awaitCredentialLock(retryThread.get());
                assertFalse(retry.isDone());
                operations.release.countDown();
                assertEquals(zeroecho.pki.api.PkiFailureReason.STORE_DURABILITY_UNCONFIRMED,
                        first.get(10, TimeUnit.SECONDS).failureReason().orElseThrow());
                assertEquals(zeroecho.pki.api.PkiFailureReason.STORE_DURABILITY_UNCONFIRMED,
                        retry.get(10, TimeUnit.SECONDS).failureReason().orElseThrow());
            } finally { operations.release.countDown(); }
            assertThrows(SigningActiveWal.RecoveryRequiredException.class, store::close);
        }
    }

    @Test void handoffConfirmedReplayFinishesSerialIndexAndIssuanceEvidence(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Authority authority = rootWithoutCaRecord(store, AUTHORITY, 1);
            Credential leaf = leaf(store, authority, "handoff-index", 83);
            FilesystemPkiStore.installCredentialReservationFault(FilesystemPkiStore.CredentialReservationFault.BEFORE_SERIAL_INDEX);
            try { assertThrows(IllegalStateException.class, () -> store.putCredential(leaf)); }
            finally { FilesystemPkiStore.clearCredentialReservationFault(); }
            assertTrue(store.getCredential(leaf.credentialId()).isPresent());
            assertFalse(java.nio.file.Files.exists(handoffIntent(root, leaf)));
            assertTrue(store.getCredentialByIssuerAndSerial(leaf.issuerRef().issuerId(), BigInteger.valueOf(83)).isEmpty());
            try (zeroecho.pki.spi.store.AuditEvidenceFeed feed = store.openIssuanceEvidenceFeed(-1)) {
                assertEquals(0, feed.highWatermark());
            }
            store.putCredential(leaf);
            assertEquals(leaf.credentialId(), store.getCredentialByIssuerAndSerial(leaf.issuerRef().issuerId(),
                    BigInteger.valueOf(83)).orElseThrow().credentialId());
            store.putCredential(leaf);
            try (zeroecho.pki.spi.store.AuditEvidenceFeed feed = store.openIssuanceEvidenceFeed(-1)) {
                assertEquals(1, feed.highWatermark());
            }
        }
    }

    @Test void handoffCommittedReplayRejectsChangedMetadataAndCertificate(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Authority authority = rootWithoutCaRecord(store, AUTHORITY, 1);
            Credential leaf = leaf(store, authority, "handoff-immutable", 84);
            store.putCredential(leaf);
            Credential metadata = new Credential(leaf.credentialId(), leaf.formatId(), leaf.issuerRef(), new SubjectRef("CN=Changed"),
                    leaf.validity(), leaf.serialOrUniqueId(), leaf.publicKeyId(), leaf.profileBinding(), leaf.status(),
                    leaf.content(), leaf.attributes());
            assertThrows(IllegalStateException.class, () -> store.putCredential(metadata));
            Credential changed = credential(store, leaf.credentialId().value(),
                    certificate(rootKey, authority.certificate().getSubject(), subjectKey, "CN=Changed", 84), leaf.issuerRef(), false);
            assertThrows(IllegalStateException.class, () -> store.putCredential(changed));
            assertEquals(leaf.content().sha256(), store.getCredential(leaf.credentialId()).orElseThrow().content().sha256());
        }
    }

    @Test void publishedCredentialSerialIndexReadIoFencesUntilReopen(@TempDir Path root) throws Exception {
        assertPostPublicationIoRecovery(root, FilesystemPkiStore.CredentialReservationFault.SERIAL_INDEX_READ_IO);
    }

    @Test void publishedCredentialSerialIndexWriteIoFencesUntilReopen(@TempDir Path root) throws Exception {
        assertPostPublicationIoRecovery(root, FilesystemPkiStore.CredentialReservationFault.SERIAL_INDEX_WRITE_IO);
    }

    @Test void publishedCredentialIssuanceEvidenceIoFencesUntilReopen(@TempDir Path root) throws Exception {
        assertPostPublicationIoRecovery(root, FilesystemPkiStore.CredentialReservationFault.ISSUANCE_EVIDENCE_IO);
    }

    private static void assertPostPublicationIoRecovery(Path root, FilesystemPkiStore.CredentialReservationFault fault)
            throws Exception {
        Credential leaf;
        Authority authority;
        try (FilesystemPkiStore store = open(root)) {
            authority = rootWithoutCaRecord(store, AUTHORITY, 1);
            leaf = leaf(store, authority, "post-publication-io", 85);
            FilesystemPkiStore.installCredentialReservationFault(fault);
            try {
                PkiException failure = assertThrows(PkiException.class, () -> store.putCredential(leaf));
                assertEquals(zeroecho.pki.api.PkiFailureReason.STORE_DURABILITY_UNCONFIRMED, failure.failureReason().orElseThrow());
            } finally { FilesystemPkiStore.clearCredentialReservationFault(); }
            try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                    MetadataSnapshot.Record record = snapshot.get(AuthorityMetadataCodec.credentialKey(leaf.credentialId())).orElseThrow();
                    MetadataSnapshot.Record owners = snapshot.get(AuthorityMetadataCodec.ownerSetKey(leaf.content().contentId())).orElseThrow()) {
                assertArrayEquals(FsCodec.encode(FsCodec.CREDENTIAL, leaf),
                        CredentialMetadataAuthority.read(record, AuthorityMetadataCodec.MAX_VALUE_BYTES));
                assertEquals(Set.of(DurableContentOwner.credentialRecord(leaf.credentialId())),
                        CredentialMetadataAuthority.decodeOwners(owners.key(), CredentialMetadataAuthority.read(owners, 1024)));
            }
            assertFalse(java.nio.file.Files.exists(handoffIntent(root, leaf)));
            assertThrows(PkiException.class, () -> store.getCredential(leaf.credentialId()));
            assertThrows(PkiException.class, () -> store.putCredential(leaf));
            assertThrows(PkiException.class, () -> store.getCredentialByIssuerAndSerial(leaf.issuerRef().issuerId(), BigInteger.valueOf(85)));
            assertThrows(PkiException.class, () -> store.getIssuerGeneration(leaf.issuerRef().issuerId()));
            assertThrows(PkiException.class, store::listCas);
        }
        try (FilesystemPkiStore reopened = open(root)) {
            Credential restored = reopened.getCredentialByIssuerAndSerial(leaf.issuerRef().issuerId(),
                    BigInteger.valueOf(85)).orElseThrow();
            assertEquals(leaf.credentialId(), restored.credentialId());
            assertEquals(leaf.content().sha256(), restored.content().sha256());
            FilesystemPkiStore.SnapshotCredentialAuthority proof = reopened.credentialSnapshotAuthority(restored).orElseThrow();
            assertEquals(AUTHORITY, proof.scopeOwner().authorityId());
            assertEquals(new ScopeSerialReservation.ImportedCertificateOwner(leaf.content().sha256()),
                    proof.reservation().issuanceOwner());
            assertEquals(BigInteger.valueOf(85), proof.reservation().serial());
            reopened.putCredential(leaf);
            Credential conflicting = leaf(reopened, authority, "post-publication-conflict", 85);
            assertThrows(IllegalStateException.class, () -> reopened.putCredential(conflicting));
            try (zeroecho.pki.spi.store.AuditEvidenceFeed feed = reopened.openIssuanceEvidenceFeed(-1)) {
                assertEquals(1, feed.highWatermark());
            }
        }
    }

    private static Path handoffIntent(Path root, Credential credential) {
        return root.resolve("credential-handoffs").resolve(CredentialContentTransaction.intentFileName(credential.credentialId()));
    }

    private static Authority pathChild(FilesystemPkiStore store, Authority parent) throws Exception {
        X509CertificateHolder certificate = certificate(rootKey, parent.certificate().getSubject(), subjectKey, "CN=Path Child", 17);
        Credential credential = credential(store, "path-child", certificate,
                new IssuerRef(AUTHORITY, parent.generation().issuerId(), parent.path().pathId()), true);
        store.putCredential(credential);
        IssuerGeneration generation = generation(new PkiId("ca:path-child"), credential);
        store.putIssuerGeneration(generation);
        IssuerChainPath path = IssuerChainPath.create(generation.authorityId(), generation.issuerId(),
                List.of(credential.credentialId(), parent.credential().credentialId()));
        return new Authority(credential, generation, path, certificate);
    }

    private static IssuerChainPath selectedParentPath(Authority child, Credential parent) {
        return IssuerChainPath.create(child.generation().authorityId(), child.generation().issuerId(),
                List.of(child.credential().credentialId(), parent.credentialId()));
    }

    private static Credential candidateParent(FilesystemPkiStore store, String id, PkiId authority,
            KeyPair key, String name, int serial, boolean publishGeneration) throws Exception {
        PkiId credentialId = new PkiId(id);
        PkiId issuerId = IssuerGeneration.idFor(authority, credentialId);
        IssuerChainPath path = IssuerChainPath.create(authority, issuerId, List.of(credentialId));
        Credential credential = credential(store, id, certificate(key, new X500Name(name), key, name, serial),
                new IssuerRef(authority, issuerId, path.pathId()), true);
        store.putCredential(credential);
        if (publishGeneration) { store.putIssuerGeneration(generation(authority, credential)); }
        return credential;
    }

    private static FilesystemPkiStore open(Path root, CredentialCommitOperations operations) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), Clock.systemUTC(),
                SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, operations);
    }

    private static void reserveBeforeCredential(FilesystemPkiStore store, Credential credential) {
        FilesystemPkiStore.installCredentialReservationFault(FilesystemPkiStore.CredentialReservationFault.BEFORE_CREDENTIAL);
        try { assertThrows(IllegalStateException.class, () -> store.putCredential(credential)); }
        finally { FilesystemPkiStore.clearCredentialReservationFault(); }
    }

    private static void awaitCredentialLock(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        do {
            for (StackTraceElement frame : thread.getStackTrace()) {
                if (frame.getClassName().equals(FilesystemPkiStore.class.getName())
                        && frame.getMethodName().equals("acquireCredentialStateLock")
                        && thread.getState() == Thread.State.WAITING) {
                    return;
                }
            }
            java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
        } while (System.nanoTime() < deadline);
        throw new AssertionError("Exact replay did not reach the held credential lock");
    }

    /** Existing WAL seam, armed only after the credential's serial reservation. */
    private static final class CredentialCommitOperations implements SigningActiveWal.Operations {
        private final AtomicBoolean armed = new AtomicBoolean();
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release;
        private final boolean durableBeforeFailure;
        private int armedForces = 2;

        private CredentialCommitOperations(boolean durableBeforeFailure, boolean block) {
            this.durableBeforeFailure = durableBeforeFailure;
            release = new CountDownLatch(block ? 1 : 0);
        }

        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) { return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            return wrap(FileChannel.open(path, Set.of(StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)));
        }
        @Override public void forceDirectory(Path directory) throws IOException { SigningFormatSupport.forceDirectory(directory); }

        private SigningActiveWal.WalChannel wrap(FileChannel channel) throws IOException {
            long initialLength = channel.size();
            return new SigningActiveWal.WalChannel() {
                private long durableLength = initialLength;
                @Override public int read(ByteBuffer target) throws IOException { return channel.read(target); }
                @Override public int write(ByteBuffer source) throws IOException { return channel.write(source); }
                @Override public long position() throws IOException { return channel.position(); }
                @Override public SigningActiveWal.WalChannel position(long value) throws IOException { channel.position(value); return this; }
                @Override public long size() throws IOException { return channel.size(); }
                @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException { channel.truncate(size); return this; }
                @Override public boolean isOpen() { return channel.isOpen(); }
                @Override public void close() throws IOException { channel.close(); }
                @Override public void force(boolean metadata) throws IOException {
                    // The first force issues the transaction; the second commits its mutations.
                    if (armed.get() && --armedForces == 0 && armed.compareAndSet(true, false)) {
                        entered.countDown();
                        try {
                            if (!release.await(10, TimeUnit.SECONDS)) { throw new IOException("Controlled commit release timed out"); }
                        } catch (InterruptedException failure) {
                            Thread.currentThread().interrupt();
                            throw new IOException("Controlled commit interrupted", failure);
                        }
                        if (!durableBeforeFailure) { channel.truncate(durableLength); }
                        channel.force(metadata);
                        throw new IOException("Injected credential metadata force failure");
                    }
                    channel.force(metadata);
                    durableLength = channel.size();
                }
            };
        }
    }

    private static Authority root(FilesystemPkiStore store, PkiId authorityId, int serial) throws Exception {
        Authority authority = rootWithoutCaRecord(store, authorityId, serial);
        List<PkiId> generations = new ArrayList<>(store.getCa(authorityId).map(CaRecord::issuerIds).orElse(List.of()));
        generations.add(authority.generation().issuerId());
        store.putCa(new CaRecord(authorityId, CaKind.ROOT, CaState.ACTIVE, authority.generation().signingKeyRef(),
                authority.credential().subjectRef(), generations, authority.generation().issuerId(), authority.path().pathId()));
        return authority;
    }

    private static Authority rootWithoutCaRecord(FilesystemPkiStore store, PkiId authorityId, int serial) throws Exception {
        X509CertificateHolder certificate = certificate(rootKey, new X500Name("CN=Scope Root"), rootKey, "CN=Scope Root", serial);
        PkiId id = new PkiId("root:" + authorityId.value() + ":" + serial);
        PkiId issuerId = IssuerGeneration.idFor(authorityId, id);
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId, List.of(id));
        Credential credential = credential(store, id.value(), certificate, new IssuerRef(authorityId, issuerId, path.pathId()), true);
        store.putCredential(credential);
        IssuerGeneration generation = generation(authorityId, credential);
        store.putIssuerGeneration(generation);
        store.putIssuerChainPath(path);
        return new Authority(credential, generation, path, certificate);
    }

    private static IssuerGeneration generation(PkiId authority, Credential credential) {
        return new IssuerGeneration(IssuerGeneration.idFor(authority, credential.credentialId()), authority, credential.credentialId(),
                new KeyRef("key:test"), IssuerGenerationState.ACTIVE, "00".repeat(32), "00".repeat(32));
    }

    private static Credential leaf(FilesystemPkiStore store, Authority authority, String name, int serial) throws Exception {
        return credential(store, name, certificate(rootKey, authority.certificate().getSubject(), subjectKey, "CN=" + name, serial),
                new IssuerRef(authority.generation().authorityId(), authority.generation().issuerId(), authority.path().pathId()), false);
    }

    private static Credential credential(FilesystemPkiStore store, String id, X509CertificateHolder certificate,
            IssuerRef issuer, boolean ca) throws Exception {
        return new Credential(new PkiId(id), new FormatId("x509"), issuer, new SubjectRef(certificate.getSubject().toString()),
                new Validity(BEFORE, AFTER), certificate.getSerialNumber().toString(), new PkiId("key:public"),
                ca ? new CaProfileBinding(PROFILE) : new EndEntityProfileBinding(PROFILE), CredentialStatus.ISSUED,
                PkiTestRuntime.stageCredential(store, certificate.getEncoded()), new SimpleAttributeSet());
    }

    private static Credential copy(Credential value, IssuerRef issuer, String serial) {
        return new Credential(value.credentialId(), value.formatId(), issuer, value.subjectRef(), value.validity(), serial,
                value.publicKeyId(), value.profileBinding(), value.status(), value.content(), value.attributes());
    }

    private static X509CertificateHolder certificate(KeyPair signer, X500Name issuer, KeyPair subject, String name, int serial)
            throws Exception {
        return new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(serial), Date.from(BEFORE), Date.from(AFTER),
                new X500Name(name), subject.getPublic()).build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate()));
    }

    private static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()); }

    private record Authority(Credential credential, IssuerGeneration generation, IssuerChainPath path,
            X509CertificateHolder certificate) { }
}
