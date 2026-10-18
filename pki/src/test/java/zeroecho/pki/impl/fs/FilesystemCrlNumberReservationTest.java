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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

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
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.testkit.PkiTestRuntime;

class FilesystemCrlNumberReservationTest {
    private static final Instant BEFORE = Instant.parse("2025-01-01T00:00:00Z");
    private static final Instant AFTER = Instant.parse("2030-01-01T00:00:00Z");
    private static KeyPair key;

    @BeforeAll static void key() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
    }

    @Test void defaultsCustomAndZeroNumbersAreDurablyConsumed(@TempDir Path root) throws Exception {
        for (BigInteger initial : List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(400))) {
            Path directory = root.resolve(initial.toString());
            PkiId generation;
            try (FilesystemPkiStore store = new FilesystemPkiStore(directory,
                    FsPkiStoreOptions.defaults().withInitialCrlNumber(initial))) {
                generation = issuer(store, "Root", 1).generation().issuerId();
                assertEquals(initial, store.reserveCrlNumber(generation));
                assertEquals(initial.add(BigInteger.ONE), store.reserveCrlNumber(generation));
            }
            try (FilesystemPkiStore reopened = new FilesystemPkiStore(directory, FsPkiStoreOptions.defaults())) {
                assertEquals(initial.add(BigInteger.TWO), reopened.reserveCrlNumber(generation));
            }
        }
    }

    @Test void sameScopeRolloverAndReplayPreserveSequenceWhileDistinctScopesAreIndependent(@TempDir Path root)
            throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            Issuer first = issuer(store, "First", 1);
            assertEquals(BigInteger.ONE, store.reserveCrlNumber(first.generation().issuerId()));
            Issuer rollover = issuer(store, "First", 2);
            assertEquals(first.scope(), rollover.scope());
            assertThrows(IllegalStateException.class, () -> store.putIssuerGeneration(first.generation()));
            store.putCredential(first.credential());
            assertEquals(BigInteger.TWO, store.reserveCrlNumber(rollover.generation().issuerId()));
            Issuer distinct = issuer(store, "Second", 1);
            assertEquals(BigInteger.ONE, store.reserveCrlNumber(distinct.generation().issuerId()));
            FilesystemPkiStore.startIssuerGenerationReadCounting();
            try {
                assertEquals(BigInteger.valueOf(3), store.reserveCrlNumber(first.generation().issuerId()));
                long[] reads = FilesystemPkiStore.issuerGenerationReadCounts();
                assertEquals(1, reads[0]);
                assertEquals(0, reads[1]);
            } finally { FilesystemPkiStore.stopIssuerGenerationReadCounting(); }
        }
    }

    @Test void reopenedUnissuedReservationIsNotReusedAndChangedInitialOnlyAffectsNewScopes(@TempDir Path root)
            throws Exception {
        Issuer original;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            original = issuer(store, "Existing", 1);
            assertEquals(BigInteger.ONE, store.reserveCrlNumber(original.generation().issuerId()));
            // No status object is produced: the durable reservation alone consumes the number.
        }
        FsPkiStoreOptions changed = FsPkiStoreOptions.defaults().withInitialCrlNumber(BigInteger.valueOf(500));
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, changed)) {
            assertEquals(BigInteger.TWO, counter(store, original.scope()).counter().nextNumber());
            Issuer rollover = issuer(store, "Existing", 2);
            assertEquals(BigInteger.TWO, store.reserveCrlNumber(rollover.generation().issuerId()));
            Issuer distinct = issuer(store, "New", 1);
            assertEquals(BigInteger.valueOf(500), store.reserveCrlNumber(distinct.generation().issuerId()));
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertEquals(BigInteger.valueOf(3), store.reserveCrlNumber(original.generation().issuerId()));
        }
    }

    @Test void snapshotsAndHistoricalReexportsPreserveCurrentCounterHighWater(@TempDir Path root) throws Exception {
        Path current = root.resolve("current");
        Path historical = root.resolve("historical");
        Path second = root.resolve("second");
        Issuer original;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("source"), FsPkiStoreOptions.defaults())) {
            original = issuer(store, "Snapshot", 1);
            assertEquals(BigInteger.ONE, store.reserveCrlNumber(original.generation().issuerId()));
            assertEquals(BigInteger.TWO, store.reserveCrlNumber(original.generation().issuerId()));
            store.exportSnapshot(current, Instant.now());
            store.exportSnapshot(historical, Instant.EPOCH);
            assertEquals(BigInteger.valueOf(3), counter(store, original.scope()).counter().nextNumber());
        }
        FsPkiStoreOptions changed = FsPkiStoreOptions.defaults().withInitialCrlNumber(BigInteger.valueOf(900));
        try (FilesystemPkiStore store = new FilesystemPkiStore(current, changed)) {
            restoreSnapshotGeneration(store, original.generation());
            assertEquals(BigInteger.valueOf(3), store.reserveCrlNumber(original.generation().issuerId()));
            store.exportSnapshot(second, Instant.EPOCH);
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(historical, changed)) {
            restoreSnapshotGeneration(store, original.generation());
            assertEquals(BigInteger.valueOf(3), store.reserveCrlNumber(original.generation().issuerId()));
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(second, FsPkiStoreOptions.defaults())) {
            restoreSnapshotGeneration(store, original.generation());
            assertEquals(BigInteger.valueOf(4), store.reserveCrlNumber(original.generation().issuerId()));
        }
    }

    private static void restoreSnapshotGeneration(FilesystemPkiStore store, IssuerGeneration generation) {
        // This fixture has no CaRecord, so snapshots intentionally omit its generation.
        if (store.getIssuerGeneration(generation.issuerId()).isEmpty()) {
            store.putIssuerGeneration(generation);
        }
    }

    @Test void concurrentAllocationsAreUniqueAndContiguous(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                ExecutorService workers = Executors.newFixedThreadPool(8)) {
            PkiId generation = issuer(store, "Concurrent", 1).generation().issuerId();
            CountDownLatch start = new CountDownLatch(1);
            List<Future<BigInteger>> results = new ArrayList<>();
            for (int index = 0; index < 8; index++) {
                results.add(workers.submit(() -> {
                    start.await();
                    return store.reserveCrlNumber(generation);
                }));
            }
            start.countDown();
            Set<BigInteger> numbers = new HashSet<>();
            for (Future<BigInteger> result : results) { numbers.add(result.get(20, TimeUnit.SECONDS)); }
            Set<BigInteger> expected = new HashSet<>();
            for (int value = 1; value <= 8; value++) { expected.add(BigInteger.valueOf(value)); }
            assertEquals(expected, numbers);
            assertEquals(BigInteger.valueOf(9), store.reserveCrlNumber(generation));
        }
    }

    @Test void maximumIssuedNumberTransitionsOnceToExhaustion(@TempDir Path root) throws Exception {
        BigInteger maximum = CrlScopeCounter.EXHAUSTED.subtract(BigInteger.ONE);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root,
                FsPkiStoreOptions.defaults().withInitialCrlNumber(maximum))) {
            Issuer issuer = issuer(store, "Last", 1);
            assertEquals(maximum, store.reserveCrlNumber(issuer.generation().issuerId()));
            CounterSnapshot exhausted = counter(store, issuer.scope());
            assertEquals(CrlScopeCounter.EXHAUSTED, exhausted.counter().nextNumber());
            assertThrows(IllegalStateException.class, () -> store.reserveCrlNumber(issuer.generation().issuerId()));
            assertEquals(exhausted, counter(store, issuer.scope()));
        }
    }

    @Test void missingGenerationAndWrongScopeOwnerDoNotAllocate(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertThrows(IllegalStateException.class, () -> store.reserveCrlNumber(new PkiId("missing")));
            Issuer issuer = issuer(store, "Owner", 1);
            CounterSnapshot before = counter(store, issuer.scope());
            CrlScopeOwner wrong = new CrlScopeOwner(issuer.scope(), new PkiId("wrong-authority"));
            MetadataKey ownerKey = CrlScopeMetadataCodec.key(wrong);
            long revision;
            try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                    MetadataSnapshot.Record record = snapshot.get(ownerKey).orElseThrow()) {
                revision = record.recordRevision();
            }
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, store.metadataStore().directCommit(List.of(
                    new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.REPLACE,
                            ownerKey, revision, CrlScopeMetadataCodec.encode(wrong)))).outcome());
            assertThrows(CrlScopeReservationStore.ConflictException.class,
                    () -> store.reserveCrlNumber(issuer.generation().issuerId()));
            assertEquals(before, counter(store, issuer.scope()));
        }
    }

    @Test void definitePrecommitFailureLeavesNumberReusable(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            PkiId generation = issuer(store, "Definite", 1).generation().issuerId();
            CrlScopeReservationStore.installCounterCommitFault(
                    CrlScopeReservationStore.CounterCommitFault.BEFORE_COMMIT_FAILURE);
            try { assertThrows(IllegalStateException.class, () -> store.reserveCrlNumber(generation)); }
            finally { CrlScopeReservationStore.clearCounterCommitFault(); }
            assertEquals(BigInteger.ONE, store.reserveCrlNumber(generation));
        }
    }

    @Test void metadataCapacityRejectionDoesNotFenceStoreOrConsumeNumber(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            Issuer issuer = issuer(store, "Capacity", 1);
            CounterSnapshot before = counter(store, issuer.scope());
            List<MetadataTransaction> held = new ArrayList<>();
            try {
                for (int index = 0; index < 256; index++) {
                    held.add(store.metadataStore().beginTransaction());
                }
                PkiException failure = assertThrows(PkiException.class,
                        () -> store.reserveCrlNumber(issuer.generation().issuerId()));
                assertEquals("Signing metadata operation rejected: code=SIGNING_METADATA_CAPACITY_UNAVAILABLE",
                        failure.getMessage());
                assertTrue(failure.failureReason().isEmpty());
                assertTrue(failure.getCause() instanceof MetadataStoreException);
                assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED,
                        ((MetadataStoreException) failure.getCause()).category());
                store.signingNow();
                assertEquals(before, counter(store, issuer.scope()));
            } finally {
                for (MetadataTransaction transaction : held) { transaction.close(); }
            }
            assertEquals(BigInteger.ONE, store.reserveCrlNumber(issuer.generation().issuerId()));
        }
    }

    @Test void unknownCommitPrefixesReturnNoNumberFenceAndRecoverSameOrAdvancedAuthority(@TempDir Path root)
            throws Exception {
        for (CrlScopeReservationStore.CounterCommitFault fault : List.of(
                CrlScopeReservationStore.CounterCommitFault.BEFORE_COMMIT_AS_UNKNOWN,
                CrlScopeReservationStore.CounterCommitFault.AFTER_COMMIT_AS_UNKNOWN)) {
            Path directory = root.resolve(fault.name());
            PkiId generation;
            try (FilesystemPkiStore store = new FilesystemPkiStore(directory, FsPkiStoreOptions.defaults())) {
                generation = issuer(store, "Unknown", 1).generation().issuerId();
                CrlScopeReservationStore.installCounterCommitFault(fault);
                try {
                    PkiException failure = assertThrows(PkiException.class, () -> store.reserveCrlNumber(generation));
                    assertEquals(Optional.of(PkiFailureReason.STORE_DURABILITY_UNCONFIRMED), failure.failureReason());
                } finally { CrlScopeReservationStore.clearCounterCommitFault(); }
                assertThrows(PkiException.class, () -> store.reserveCrlNumber(generation));
                assertThrows(PkiException.class, store::signingNow);
            }
            try (FilesystemPkiStore reopened = new FilesystemPkiStore(directory, FsPkiStoreOptions.defaults())) {
                BigInteger expected = fault == CrlScopeReservationStore.CounterCommitFault.AFTER_COMMIT_AS_UNKNOWN
                        ? BigInteger.TWO : BigInteger.ONE;
                assertEquals(expected, reopened.reserveCrlNumber(generation));
            }
        }
    }

    private static CounterSnapshot counter(FilesystemPkiStore store, CrlScope scope) throws Exception {
        MetadataKey key = CrlScopeMetadataCodec.counterKey(scope);
        try (MetadataSnapshot snapshot = store.metadataStore().snapshot();
                MetadataSnapshot.Record record = snapshot.get(key).orElseThrow();
                java.io.InputStream input = record.openStream()) {
            return new CounterSnapshot(CrlScopeMetadataCodec.decodeCounter(key, input.readAllBytes()), record.recordRevision());
        }
    }

    private static Issuer issuer(FilesystemPkiStore store, String label, int serial) throws Exception {
        PkiId authority = new PkiId("authority:" + label);
        PkiId credentialId = new PkiId("root:" + label + ":" + serial);
        PkiId generationId = IssuerGeneration.idFor(authority, credentialId);
        IssuerChainPath path = IssuerChainPath.create(authority, generationId, List.of(credentialId));
        X500Name name = new X500Name("CN=" + label);
        X509CertificateHolder certificate = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(serial),
                Date.from(BEFORE), Date.from(AFTER), name, key.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate()));
        Credential credential = new Credential(credentialId, new FormatId("x509"),
                new IssuerRef(authority, generationId, path.pathId()), new SubjectRef(name.toString()),
                new Validity(BEFORE, AFTER), Integer.toString(serial), new PkiId("key:public"),
                new CaProfileBinding(new CertificateProfileRef("profile", 1, new byte[32])), CredentialStatus.ISSUED,
                PkiTestRuntime.stageCredential(store, certificate.getEncoded()), new SimpleAttributeSet());
        store.putCredential(credential);
        IssuerGeneration generation = new IssuerGeneration(generationId, authority, credentialId, new KeyRef("key:test"),
                IssuerGenerationState.ACTIVE, "1".repeat(64), "1".repeat(64));
        store.putIssuerGeneration(generation);
        store.putIssuerChainPath(path);
        return new Issuer(generation, credential, CrlScope.of(name.getEncoded(), key.getPublic().getEncoded()));
    }

    private record Issuer(IssuerGeneration generation, Credential credential, CrlScope scope) { }
    private record CounterSnapshot(CrlScopeCounter counter, long revision) { }
}
