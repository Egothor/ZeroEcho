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

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialSearchQuery;

final class CredentialSearchIndexTest {
    private static FsPkiStoreOptions enabled() {
        return FsPkiStoreOptions.defaults().withCredentialSearch(
                Optional.of(new FsPkiStoreOptions.CredentialSearch(1024, 5000, 1048576)));
    }

    @Test void disabledDoesNotOpenDatabaseAndNeverFallsBack(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertFalse(store.credentialSearchAvailable());
            Credential credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "serial", "profile");
            store.putCredential(credential);
            assertThrows(IllegalStateException.class, () -> store.searchCredentials(query(credential),
                    Optional.empty(), 1, value -> true, CancellationSignal.NONE));
            assertFalse(Files.exists(root.resolve("credential-search")));
        }
    }

    @Test void publishedRowsFiltersAuthorizationAndRebuildAreAuthoritative(@TempDir Path root) throws Exception {
        Credential credential;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, enabled())) {
            assertTrue(store.credentialSearchAvailable());
            credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "Serial_'%_literal", "profile");
            store.putCredential(credential);
            assertEquals(List.of(store.getCredential(credential.credentialId()).orElseThrow()), store.searchCredentials(query(credential), Optional.empty(), 1,
                    value -> true, CancellationSignal.NONE));
            assertEquals(List.of(), store.searchCredentials(query(credential), Optional.empty(), 1,
                    value -> false, CancellationSignal.NONE));
            CredentialSearchQuery literal = new CredentialSearchQuery(credential.issuerRef().caId(),
                    Optional.empty(), Optional.of("' OR 1=1 --"), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty());
            assertEquals(List.of(), store.searchCredentials(literal, Optional.empty(), 1,
                    value -> true, CancellationSignal.NONE));
            assertEquals(List.of(), store.searchCredentials(query(credential), Optional.of(credential.credentialId().value()), 1,
                    value -> true, CancellationSignal.NONE));
            assertThrows(IllegalStateException.class, () -> store.searchCredentials(query(credential),
                    Optional.empty(), 1, value -> true, () -> true));
        }
        // A stale derivative missing the credential must not produce a false negative after restart.
        try (Connection database = new org.h2.Driver().connect("jdbc:h2:file:"
                + root.resolve("credential-search/index").toAbsolutePath(), new java.util.Properties());
                Statement statement = database.createStatement()) {
            statement.executeUpdate("DELETE FROM credentials");
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, enabled())) {
            assertEquals(List.of(reopened.getCredential(credential.credentialId()).orElseThrow()), reopened.searchCredentials(query(credential), Optional.empty(), 1,
                    value -> true, CancellationSignal.NONE));
        }
    }

    private static CredentialSearchQuery query(Credential credential) {
        return new CredentialSearchQuery(credential.issuerRef().caId(), Optional.of("CN=SUBJ"),
                Optional.of("serial"), Optional.of("CRED-"), Optional.of("ISSUED"),
                Optional.of("profile"), Optional.empty());
    }

    @Test void derivativeFailureKeepsPrimaryCommittedAndCorruptionRebuilds(@TempDir Path root) throws Exception {
        Credential credential;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, enabled())) {
            credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "serial", "profile");
            CredentialSearchIndex.failPublicationForTest(true);
            try { store.putCredential(credential); }
            finally { CredentialSearchIndex.failPublicationForTest(false); }
            assertTrue(store.getCredential(credential.credentialId()).isPresent());
            assertFalse(store.credentialSearchAvailable());
            assertThrows(IllegalStateException.class, () -> store.searchCredentials(query(credential),
                    Optional.empty(), 1, value -> true, CancellationSignal.NONE));
        }
        Files.write(root.resolve("credential-search/index.mv.db"), new byte[] {1, 2, 3});
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, enabled())) {
            assertEquals(credential.credentialId(), store.searchCredentials(query(credential), Optional.empty(), 1,
                    value -> true, CancellationSignal.NONE).getFirst().credentialId());
        }
    }

    @Test void closeWaitsForAdmittedSearchWithoutLockInversion(@TempDir Path root) throws Exception {
        FilesystemPkiStore store = new FilesystemPkiStore(root, enabled());
        Credential credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "serial", "profile");
        store.putCredential(credential);
        java.util.concurrent.CountDownLatch authorized = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch proceed = new java.util.concurrent.CountDownLatch(1);
        try (java.util.concurrent.ExecutorService workers = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            java.util.concurrent.Future<List<Credential>> search = workers.submit(() -> store.searchCredentials(query(credential),
                    Optional.empty(), 1, value -> { authorized.countDown(); await(proceed); return true; }, CancellationSignal.NONE));
            assertTrue(authorized.await(2, java.util.concurrent.TimeUnit.SECONDS));
            java.util.concurrent.CountDownLatch closing = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Future<?> close = workers.submit(() -> { closing.countDown(); store.close(); return null; });
            assertTrue(closing.await(2, java.util.concurrent.TimeUnit.SECONDS));
            proceed.countDown();
            assertEquals(1, search.get(2, java.util.concurrent.TimeUnit.SECONDS).size());
            close.get(2, java.util.concurrent.TimeUnit.SECONDS);
        } finally { proceed.countDown(); store.close(); }
    }

    @Test void visibilityWaitUsesWholeCallDeadlineAndReturnsNoPartialPage(@TempDir Path root) throws Exception {
        FsPkiStoreOptions options = enabled().withCredentialSearch(
                Optional.of(new FsPkiStoreOptions.CredentialSearch(1024, 100, 1048576)));
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options);
                java.util.concurrent.ExecutorService workers = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            Credential credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "serial", "profile");
            store.putCredential(credential);
            java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.CountDownLatch proceed = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Future<?> first = workers.submit(() -> assertThrows(IllegalStateException.class,
                    () -> store.searchCredentials(query(credential), Optional.empty(), 1,
                            value -> { entered.countDown(); await(proceed); return true; }, CancellationSignal.NONE)));
            try {
                assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS));
                java.util.concurrent.Future<?> second = workers.submit(() -> assertThrows(IllegalStateException.class,
                        () -> store.searchCredentials(query(credential), Optional.empty(), 1, value -> true, CancellationSignal.NONE)));
                second.get(2, java.util.concurrent.TimeUnit.SECONDS);
            } finally { proceed.countDown(); }
            first.get(2, java.util.concurrent.TimeUnit.SECONDS);
            assertTrue(store.credentialSearchAvailable());
        }
    }

    private static void await(java.util.concurrent.CountDownLatch latch) {
        try { assertTrue(latch.await(3, java.util.concurrent.TimeUnit.SECONDS)); }
        catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError(failure); }
    }

    @Test void exactTypedSansComeFromIssuedDerAndSurviveRestart(@TempDir Path root) throws Exception {
        Credential credential;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, enabled())) {
            credential = certificate(store);
            store.putCredential(credential);
            assertSans(store, credential);
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, enabled())) { assertSans(store, credential); }
    }

    private static void assertSans(FilesystemPkiStore store, Credential credential) {
        for (zeroecho.pki.api.request.SubjectAlternativeName name : List.of(
                new zeroecho.pki.api.request.SubjectAlternativeName.DnsName("API.EXAMPLE.TEST"),
                new zeroecho.pki.api.request.SubjectAlternativeName.IpAddress(java.net.InetAddress.ofLiteral("2001:db8::1").getAddress()),
                new zeroecho.pki.api.request.SubjectAlternativeName.UriName("https://api.example.test/path"),
                new zeroecho.pki.api.request.SubjectAlternativeName.Rfc822Name("User@EXAMPLE.TEST"))) {
            CredentialSearchQuery query = new CredentialSearchQuery(credential.issuerRef().caId(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(name));
            assertEquals(credential.credentialId(), store.searchCredentials(query, Optional.empty(), 1,
                    value -> true, CancellationSignal.NONE).getFirst().credentialId());
            assertTrue(store.searchCredentials(query, Optional.empty(), 1, value -> false, CancellationSignal.NONE).isEmpty());
        }
        for (zeroecho.pki.api.request.SubjectAlternativeName name : List.of(
                new zeroecho.pki.api.request.SubjectAlternativeName.DnsName("example.test"),
                new zeroecho.pki.api.request.SubjectAlternativeName.Rfc822Name("user@example.test"),
                new zeroecho.pki.api.request.SubjectAlternativeName.UriName("https://api.example.test/Path"))) {
            CredentialSearchQuery query = new CredentialSearchQuery(credential.issuerRef().caId(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(name));
            assertTrue(store.searchCredentials(query, Optional.empty(), 1, value -> true, CancellationSignal.NONE).isEmpty());
        }
    }

    private static Credential certificate(FilesystemPkiStore store) throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.KeyPair key = generator.generateKeyPair();
        org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=Search Root");
        org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                subject, java.math.BigInteger.ONE, java.util.Date.from(java.time.Instant.parse("2025-01-01T00:00:00Z")),
                java.util.Date.from(java.time.Instant.parse("2030-01-01T00:00:00Z")), subject, key.getPublic());
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName[] {
                    new org.bouncycastle.asn1.x509.GeneralName(2, "api.example.test"),
                    new org.bouncycastle.asn1.x509.GeneralName(2, "api.example.test"),
                    new org.bouncycastle.asn1.x509.GeneralName(7, "2001:db8::1"),
                    new org.bouncycastle.asn1.x509.GeneralName(6, "https://api.example.test/path"),
                    new org.bouncycastle.asn1.x509.GeneralName(1, "User@example.test") }));
        byte[] encoded = builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA")
                .build(key.getPrivate())).getEncoded();
        zeroecho.pki.api.PkiId id = new zeroecho.pki.api.PkiId("search-root");
        zeroecho.pki.api.PkiId authority = new zeroecho.pki.api.PkiId("search-authority");
        zeroecho.pki.api.PkiId issuer = zeroecho.pki.api.ca.IssuerGeneration.idFor(authority, id);
        zeroecho.pki.api.PkiId path = zeroecho.pki.api.ca.IssuerChainPath.create(authority, issuer, List.of(id)).pathId();
        return new Credential(id, new zeroecho.pki.api.FormatId("x509"), new zeroecho.pki.api.IssuerRef(authority, issuer, path),
                new zeroecho.pki.api.SubjectRef("CN=Search Root"), new zeroecho.pki.api.Validity(
                        java.time.Instant.parse("2025-01-01T00:00:00Z"), java.time.Instant.parse("2030-01-01T00:00:00Z")),
                "1", new zeroecho.pki.api.PkiId("search-key"), new zeroecho.pki.api.credential.CaProfileBinding(
                        new zeroecho.pki.api.profile.CertificateProfileRef("profile", 1, new byte[32])),
                zeroecho.pki.api.credential.CredentialStatus.ISSUED,
                zeroecho.pki.testkit.PkiTestRuntime.stageCredential(store, encoded), new zeroecho.pki.impl.core.attr.SimpleAttributeSet());
    }

    @Test void sparseAuthorizationContinuesAcrossSqlBatchesInIdOrder(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, enabled())) {
            Credential base = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "serial", "profile");
            for (int index = 0; index < 130; index++) {
                store.putCredential(new Credential(new zeroecho.pki.api.PkiId("cred-" + String.format("%03d", index)),
                        base.formatId(), base.issuerRef(), base.subjectRef(), base.validity(), base.serialOrUniqueId(),
                        base.publicKeyId(), base.profileBinding(), base.status(), base.content(), base.attributes()));
            }
            java.util.function.Predicate<Credential> visible = value -> Integer.parseInt(value.credentialId().value().substring(5)) % 64 == 0;
            assertEquals(List.of("cred-000", "cred-064", "cred-128"), store.searchCredentials(query(base), Optional.empty(),
                    3, visible, CancellationSignal.NONE).stream().map(value -> value.credentialId().value()).toList());
            assertEquals(List.of("cred-128"), store.searchCredentials(query(base), Optional.of("cred-064"),
                    3, visible, CancellationSignal.NONE).stream().map(value -> value.credentialId().value()).toList());
        }
    }

    @Test void deniedSanCandidateNeverInvokesCertificateReader(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            Credential credential = certificate(store);
            store.putCredential(credential);
            java.util.concurrent.atomic.AtomicInteger reads = new java.util.concurrent.atomic.AtomicInteger();
            try (CredentialSearchIndex index = new CredentialSearchIndex(root, enabled().credentialSearch().orElseThrow(), value -> {
                reads.incrementAndGet(); return store.certificateHolder(value);
            })) {
                index.rebuild(new CredentialMetadataAuthority(store.metadataStore(), store.stagedContent()));
                reads.set(0);
                CredentialSearchQuery query = new CredentialSearchQuery(credential.issuerRef().caId(), Optional.empty(),
                        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                        Optional.of(new zeroecho.pki.api.request.SubjectAlternativeName.DnsName("api.example.test")));
                assertTrue(index.search(query, Optional.empty(), 1, store::getCredential, value -> false,
                        CancellationSignal.NONE, System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5)).isEmpty());
                assertEquals(0, reads.get());
            }
        }
    }

    @Test void logicalSnapshotExcludesDerivedDatabaseAndRestoredStoreRebuilds(@TempDir Path temporary) throws Exception {
        Path source = temporary.resolve("source");
        Path snapshot = temporary.resolve("snapshot");
        Credential credential;
        try (FilesystemPkiStore store = new FilesystemPkiStore(source, enabled())) {
            credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "serial", "profile");
            store.putCredential(credential);
            store.exportSnapshot(snapshot, java.time.Instant.parse("2026-01-01T00:00:00Z"));
        }
        assertFalse(Files.exists(snapshot.resolve("credential-search")));
        try (FilesystemPkiStore store = new FilesystemPkiStore(snapshot, enabled())) {
            assertEquals(credential.credentialId(), store.searchCredentials(query(credential), Optional.empty(), 1,
                    value -> true, CancellationSignal.NONE).getFirst().credentialId());
        }
    }

    @Test void indexedStoreStagesColdRestoreAndRejectsUnknownDerivativeChildren(@TempDir Path root) throws Exception {
        Credential credential;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, enabled())) {
            credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "serial", "profile");
            store.putCredential(credential);
            Path unknown = root.resolve("credential-search/external-authority.bin");
            Files.write(unknown, new byte[] {1});
            assertThrows(java.io.IOException.class, () -> FsRestoreInventory.validate(root, zeroecho.pki.api.backup.BackupLimits.defaults()));
            Files.delete(unknown);
            try (zeroecho.pki.api.backup.BackupSource backup = store.createBackupSource(new zeroecho.pki.api.backup.BackupRequest(
                    "search-restore", new zeroecho.pki.impl.core.attr.SimpleAttributeSet()))) {
                assertEquals(zeroecho.pki.api.backup.RestoreStatus.State.STAGED, store.stageRestore(backup).state());
            }
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, enabled())) {
            assertEquals(zeroecho.pki.api.backup.RestoreStatus.State.ACTIVATED, store.latestRestoreStatus().orElseThrow().state());
            assertEquals(credential.credentialId(), store.searchCredentials(query(credential), Optional.empty(), 1,
                    value -> true, CancellationSignal.NONE).getFirst().credentialId());
        }
    }

    @Test void authoritativeDisagreementFencesInsteadOfReturningIncompleteSuccess(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            Credential original = certificate(store);
            store.putCredential(original);
            try (CredentialSearchIndex index = new CredentialSearchIndex(root, enabled().credentialSearch().orElseThrow(), store::certificateHolder)) {
                index.rebuild(new CredentialMetadataAuthority(store.metadataStore(), store.stagedContent()));
                CredentialSearchQuery query = new CredentialSearchQuery(original.issuerRef().caId(), Optional.empty(),
                        Optional.empty(), Optional.empty(), Optional.of("ISSUED"), Optional.empty(), Optional.empty());
                Credential changed = new Credential(original.credentialId(), original.formatId(), original.issuerRef(), original.subjectRef(),
                        original.validity(), original.serialOrUniqueId(), original.publicKeyId(), original.profileBinding(),
                        zeroecho.pki.api.credential.CredentialStatus.REVOKED, original.content(), original.attributes());
                assertThrows(IllegalStateException.class, () -> index.search(query, Optional.empty(), 2,
                        id -> Optional.of(changed), value -> true, CancellationSignal.NONE,
                        System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5)));
                assertFalse(index.available());
            }
            try (CredentialSearchIndex index = new CredentialSearchIndex(root, enabled().credentialSearch().orElseThrow(), store::certificateHolder)) {
                index.rebuild(new CredentialMetadataAuthority(store.metadataStore(), store.stagedContent()));
                assertTrue(index.available());
            }
        }
    }

    @Test void certificateBoundIsCheckedBeforeReadingAndTypedFilterRejectsMalformedInput(@TempDir Path root) throws Exception {
        for (String malformed : List.of("", "api.example.test", "DNS_NAME:", "OTHER:api.example.test", "IP_ADDRESS:hostname",
                "IP_ADDRESS:fe80::1%lo", "URI:urn:example", "RFC822_NAME:missing-at", "DNS_NAME:bad name")) {
            assertThrows(IllegalArgumentException.class, () -> CredentialSearchQuery.parseSanFilter(malformed));
        }
        assertEquals(new zeroecho.pki.api.request.SubjectAlternativeName.DnsName("api.example.test"),
                CredentialSearchQuery.parseSanFilter("DNS_NAME:API.EXAMPLE.TEST"));
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            store.putCredential(certificate(store));
            java.util.concurrent.atomic.AtomicInteger reads = new java.util.concurrent.atomic.AtomicInteger();
            try (CredentialSearchIndex index = new CredentialSearchIndex(root,
                    new FsPkiStoreOptions.CredentialSearch(1024, 5000, 1), value -> {
                        reads.incrementAndGet(); return store.certificateHolder(value);
                    })) {
                assertThrows(java.io.IOException.class, () -> index.rebuild(
                        new CredentialMetadataAuthority(store.metadataStore(), store.stagedContent())));
                assertEquals(0, reads.get());
                assertFalse(index.available());
            }
        }
    }
}
