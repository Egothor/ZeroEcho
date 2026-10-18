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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.LinkedHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.backup.BackupArtifact;
import zeroecho.pki.api.backup.BackupLimits;
import zeroecho.pki.api.backup.BackupPreparation;
import zeroecho.pki.api.backup.BackupRequest;
import zeroecho.pki.api.backup.BackupSource;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

class FilesystemBackupTest {
    @Test void historicalUnsupportedAlternativeProfilesRemainReadableAndBackedUp() throws Exception {
        try (FilesystemPkiStore store = open("legacy-alt")) {
            for (String id : List.of("intermediate-ca", "server-tls")) {
                zeroecho.pki.api.profile.CertificateProfileDefinition base =
                        zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog.load(getClass().getClassLoader()).stream()
                                .filter(value -> value.definition().profileId().equals(id)).findFirst().orElseThrow().definition();
                for (long version : List.of(1L, 2L)) {
                    zeroecho.pki.api.profile.CertificateProfileDefinition historical = new zeroecho.pki.api.profile.CertificateProfileDefinition(
                            base.certificateType(), base.profileId(), version, base.formatId(), base.displayName(), base.maximumValidity(),
                            base.approvalRequirement(), base.subjectPolicy(), base.certificatePolicy(), base.algorithmBindingPolicy(),
                            base.confirmationPolicy(), new zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature(
                                    zeroecho.core.alg.BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm(), "legacy-alt"));
                    zeroecho.pki.testkit.RootCreationFixture.install(store, historical);
                }
                store.activateProfile(id, 1);
            }
        }
        try (FilesystemPkiStore store = open("legacy-alt")) {
            for (String id : List.of("intermediate-ca", "server-tls")) {
                assertEquals(2, store.listProfileVersions(id).size());
                assertEquals(1L, store.requireActiveProfile(id).reference().profileVersion());
                assertThrows(IllegalArgumentException.class,
                        () -> store.requireActiveProfile(id).definition().requireSupportedIssuance());
                if (id.equals("server-tls")) {
                    assertThrows(IllegalArgumentException.class, () -> store.requireActiveProfile(id).profile());
                }
                zeroecho.pki.impl.core.DefaultProfileService service = new zeroecho.pki.impl.core.DefaultProfileService(
                        store, CLOCK, new zeroecho.pki.impl.audit.InMemoryAuditSink());
                assertThrows(RuntimeException.class, () -> service.importProfile(store.getProfileVersion(id, 1).orElseThrow().canonicalJson()));
                assertThrows(RuntimeException.class, () -> service.activateProfile(id, 2));
            }
            try (BackupSource source = store.createBackupSource(request())) {
                assertTrue(store.verifyBackupSource(source).valid());
                try (BackupPreparation prepared = store.prepareBackup(source);
                        FilesystemPkiStore recovered = new FilesystemPkiStore(prepared.directory(), FsPkiStoreOptions.defaults(), CLOCK)) {
                    assertEquals(2, recovered.listProfileVersions("server-tls").size());
                    assertEquals(1L, recovered.requireActiveProfile("intermediate-ca").reference().profileVersion());
                }
            }
        }
    }
    @TempDir Path temporary;
    private static final Instant NOW = Instant.parse("2026-10-04T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final PkiId FIXTURE_ID = new PkiId("backup-fixture");

    private FilesystemPkiStore open(String name) {
        return new FilesystemPkiStore(temporary.resolve(name), FsPkiStoreOptions.defaults(), CLOCK);
    }
    private static BackupRequest request() {
        return new BackupRequest("test", FilesystemPkiStoreTest.TestObjects.emptyAttributes());
    }

    @Test void logicalSnapshotPreservesRecordsRevocationsAndFileTimesAcrossReopen() throws Exception {
        try (FilesystemPkiStore store = open("source")) {
            Credential credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "41", "profile");
            store.putCredential(credential);
            store.transitionRevocation(new RevocationCommand.Hold(credential.credentialId(),
                    FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);
            PolicyTrace trace = new PolicyTrace(new PkiId("decision"), List.of());
            store.putPolicyTrace(trace);
            Path policy = temporary.resolve("source/policy/by-decision/decision.bin");
            Files.setLastModifiedTime(policy, java.nio.file.attribute.FileTime.from(NOW.minusSeconds(70)));
            Files.createDirectories(temporary.resolve("source/keyring"));
            Files.writeString(temporary.resolve("source/keyring/private.key"), "excluded key store fixture");
            try (BackupSource source = store.createBackupSource(request())) {
                assertTrue(store.verifyBackupSource(source).valid());
                assertTrue(store.verifyBackupSource(source).valid());
                try (BackupPreparation prepared = store.prepareBackup(source)) {
                    assertFalse(Files.exists(prepared.directory().resolve("keyring")));
                    assertEquals(NOW.minusSeconds(70), Files.getLastModifiedTime(
                            prepared.directory().resolve("policy/by-decision/decision.bin")).toInstant());
                    try (FilesystemPkiStore recovered = new FilesystemPkiStore(
                            prepared.directory(), FsPkiStoreOptions.defaults(), CLOCK)) {
                        assertEquals(store.getCredential(credential.credentialId()).orElseThrow(),
                                recovered.getCredential(credential.credentialId()).orElseThrow());
                        assertTrue(recovered.getRevocation(credential.credentialId()).isPresent());
                        assertEquals(trace, recovered.getPolicyTrace(trace.decisionId()).orElseThrow());
                        recovered.transitionRevocation(new RevocationCommand.Unhold(credential.credentialId(),
                                FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW.plusSeconds(1));
                    }
                }
            }
            assertTrue(store.getCredential(credential.credentialId()).isPresent());
            assertWorkEmpty("source");
        }
    }

    @Test void freshCheckpointPreservesSigningCasCrlCountersAndRetainedOutcomes() throws Exception {
        try (FilesystemPkiStore store = open("coordinates")) {
            CaRecord ca = FilesystemPkiStoreTest.TestObjects.minimalCaRecord(store, "backup-ca", CaState.ACTIVE);
            store.putCa(ca);
            java.math.BigInteger consumed = store.reserveCrlNumber(ca.currentIssuanceIssuerId());
            String namespace = store.signingNamespace() + ".backup-test";
            PkiId operation = SigningSubmissionId.create(namespace, NOW, new java.security.SecureRandom()).id();
            SignWorkflowStore.AcceptanceCommand command = new SignWorkflowStore.AcceptanceCommand(
                    operation, namespace, new SigningProvider.ConfigurationCommitment(new byte[32]),
                    new AccessContext(new Principal("TEST", "backup"), new Purpose("SIGN"), Optional.empty(), Optional.empty()),
                    new KeyRef("backup-key"), ca.caId(), "SHA256withRSA", Encoding.BINARY, NOW, NOW.plusSeconds(60),
                    PkiTestRuntime.operationReference(store.stagedContent(), Encoding.BINARY, new byte[] {1, 2, 3}),
                    Optional.empty(), SignWorkflowStore.Mode.NORMAL, Optional.empty());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
            SignWorkflowStore.Workflow claim = store.claimSignStep(operation, 0, Duration.ofSeconds(10)).orElseThrow();
            MetadataCommitResult retained;
            try (MetadataTransaction transaction = store.metadataStore().beginTransaction();
                    RepeatableContent content = new RepeatableContent() {
                        @Override public InputStream openStream() { return new ByteArrayInputStream(new byte[] {7}); }
                        @Override public OptionalLong length() { return OptionalLong.of(1); }
                        @Override public String contentId() { return "backup-outcome"; }
                        @Override public void close() { }
                    }) {
                // Leave room for the engine's outcome and watermark mutations.
                for (int index = 0; index < 30; index++) {
                    transaction.create(new MetadataKey("io.zeroecho.test", "retained-" + index), content, CancellationSignal.NONE);
                }
                retained = transaction.commit();
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, retained.outcome());
            }
            try (BackupSource source = store.createBackupSource(request());
                    BackupPreparation prepared = store.prepareBackup(source);
                    FilesystemPkiStore recovered = new FilesystemPkiStore(prepared.directory(), FsPkiStoreOptions.defaults(), CLOCK)) {
                assertEquals(retained, recovered.metadataStore().resolve(retained.transactionId()));
                try (MetadataSnapshot snapshot = recovered.metadataStore().snapshot()) {
                    for (int index = 0; index < 30; index++) {
                        try (MetadataSnapshot.Record record = snapshot.get(
                                new MetadataKey("io.zeroecho.test", "retained-" + index)).orElseThrow()) {
                            assertEquals(retained.committedRevision().orElseThrow(), record.recordRevision());
                            try (InputStream input = record.openStream()) {
                                assertArrayEquals(new byte[] {7}, input.readAllBytes());
                            }
                        }
                    }
                }
                try (MetadataTransaction transaction = recovered.metadataStore().beginTransaction()) {
                    transaction.delete(new MetadataKey("io.zeroecho.test", "retained-0"), retained.committedRevision().orElseThrow());
                    assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
                }
                assertEquals(consumed.add(java.math.BigInteger.ONE), recovered.reserveCrlNumber(ca.currentIssuanceIssuerId()));
                SignWorkflowStore.Workflow restored = recovered.getSignWorkflow(operation).orElseThrow();
                assertEquals(claim.revision(), restored.revision());
                assertEquals(claim.fence(), restored.fence());
                assertTrue(recovered.transitionSign(operation, restored.revision() - 1, restored.fence(),
                        SignWorkflowStore.State.FAILED, Optional.of("DENIED"), Optional.empty(), Optional.empty()).isEmpty());
                assertEquals(SignWorkflowStore.State.FAILED, recovered.transitionSign(operation,
                        restored.revision(), restored.fence(), SignWorkflowStore.State.FAILED,
                        Optional.of("DENIED"), Optional.empty(), Optional.empty()).orElseThrow().state());
                assertEquals(claim.state(), store.getSignWorkflow(operation).orElseThrow().state());
            }
            BackupArtifact artifact = store.createBackup(request());
            assertTrue(store.verifyBackupSource(source(zip(unzip(artifact.payload().bytes())), artifact.backupId())).valid());
        }
    }

    @Test void primaryArtifactExceedsFourMiBWithoutReadingArchiveIntoArray() throws Exception {
        try (FilesystemPkiStore store = open("large")) {
            Credential template = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "42", "profile");
            DurableContentReference reference;
            try (ContentSink sink = store.stagedContent().beginContent(Encoding.DER, DurableContentReference.Lifecycle.PERSISTED)) {
                byte[] buffer = new byte[64 * 1024];
                new java.util.Random(17).nextBytes(buffer);
                for (int index = 0; index < 96; index++) sink.outputStream().write(buffer);
                reference = sink.complete();
            }
            Credential large = new Credential(template.credentialId(), template.formatId(), template.issuerRef(),
                    template.subjectRef(), template.validity(), template.serialOrUniqueId(), template.publicKeyId(),
                    template.profileBinding(), template.status(), reference, template.attributes());
            store.putCredential(large);
            try (BackupSource source = store.createBackupSource(request())) {
                assertTrue(source.contentLength() > 4L * 1024 * 1024);
                try (InputStream input = source.openStream()) {
                    assertEquals(source.contentLength(), input.transferTo(OutputStream.nullOutputStream()));
                }
                assertTrue(store.verifyBackupSource(source).valid());
            }
            assertEquals("BACKUP_LEGACY_LIMIT", assertThrows(IllegalStateException.class,
                    () -> store.createBackup(request())).getMessage());
            assertTrue(store.getCredential(large.credentialId()).isPresent());
            assertWorkEmpty("large");
        }
    }

    @Test void rejectsTraversalAbsoluteAliasesAndOnlyVersionBeforeExtraction() throws Exception {
        try (FilesystemPkiStore store = open("paths")) {
            Path outside = temporary.resolve("sentinel");
            Files.writeString(outside, "unchanged");
            for (String path : List.of("../sentinel", "/sentinel", "C:/sentinel", "C:sentinel",
                    "a\\b", "a//b", "a/./b", "a/../b", "VERSION/", "CON", "a./b", "a /b")) {
                byte[] zip = zip(Map.of(path, new byte[] { 1 }));
                assertFalse(store.verifyBackupSource(source(zip, FIXTURE_ID)).valid(), path);
                assertEquals("unchanged", Files.readString(outside));
                assertWorkEmpty("paths");
            }
            assertFalse(store.verifyBackupSource(source(zip(Map.of("VERSION", "v18".getBytes())), FIXTURE_ID)).valid());
        }
    }

    @Test void rejectsCentralLocalForgeryLinksDuplicatesAndTruncation() throws Exception {
        try (FilesystemPkiStore store = open("structure")) {
            BackupArtifact artifact = store.createBackup(request());
            byte[] valid = artifact.payload().bytes();
            int central = signature(valid, 0x02014b50);
            for (Consumer<byte[]> mutation : List.<Consumer<byte[]>>of(
                    bytes -> put16(bytes, central + 4, 0x314),
                    bytes -> { put16(bytes, central + 4, 0x314); put32(bytes, central + 38, 0xa1ff0000L); },
                    bytes -> put16(bytes, central + 10, 99),
                    bytes -> put16(bytes, central + 8, 1),
                    bytes -> put32(bytes, central + 24, 0xffffffffL),
                    bytes -> put32(bytes, central + 42, 1),
                    bytes -> bytes[30] ^= 1,
                    bytes -> put32(bytes, central + 20, 0x7fffffffL),
                    bytes -> put32(bytes, central + 16, 7),
                    bytes -> put16(bytes, central + 30, 1))) {
                byte[] malformed = valid.clone();
                mutation.accept(malformed);
                // A Unix creator with regular mode zero is supported, so give that case a special mode.
                if ((malformed[central + 5] & 255) == 3 && Arrays.equals(
                        Arrays.copyOfRange(malformed, central + 38, central + 42), new byte[4])) {
                    put32(malformed, central + 38, 0x20000000L);
                }
                assertFalse(store.verifyBackupSource(source(malformed, artifact.backupId())).valid());
                assertWorkEmpty("structure");
            }
            for (int length : new int[] { 0, 3, valid.length - 1, valid.length - 22 }) {
                assertFalse(store.verifyBackupSource(source(Arrays.copyOf(valid, length), artifact.backupId())).valid());
            }
            LinkedHashMap<String, byte[]> duplicate = new LinkedHashMap<>();
            duplicate.put("VERSION", new byte[] { 1 });
            duplicate.put("VERSIOX", new byte[] { 2 });
            byte[] duplicateZip = zip(duplicate);
            replaceAscii(duplicateZip, "VERSIOX", "VERSION");
            Path duplicateFile = temporary.resolve("duplicate.zip");
            Files.write(duplicateFile, duplicateZip);
            assertThrows(IOException.class, () -> FsBackupArchive.directory(duplicateFile, BackupLimits.defaults()));
        }
    }

    @Test void rejectsRecommittedCorruptionMissingStateAndMisboundDomainRecords() throws Exception {
        try (FilesystemPkiStore store = open("semantic")) {
            store.putPolicyTrace(new PolicyTrace(new PkiId("correct"), List.of()));
            try (BackupSource original = store.createBackupSource(request())) {
                for (int scenario = 0; scenario < 5; scenario++) {
                    try (BackupPreparation prepared = store.prepareBackup(original)) {
                        Path root = prepared.directory();
                        if (scenario == 0) Files.delete(root.resolve("metadata/FORMAT"));
                        if (scenario == 1) Files.writeString(root.resolve("metadata/FORMAT"), "broken");
                        if (scenario == 2) Files.move(root.resolve("policy/by-decision/correct.bin"),
                                root.resolve("policy/by-decision/wrong.bin"));
                        if (scenario == 3) Files.writeString(root.resolve("VERSION"), "v17");
                        if (scenario == 4) Files.write(root.resolve("policy/by-decision/correct.bin"), new byte[] { 1 });
                        try (BackupSource malformed = FsBackupArchive.write(root, temporary,
                                original.backupId(), NOW, BackupLimits.defaults())) {
                            assertFalse(store.verifyBackupSource(malformed).valid(), "scenario " + scenario);
                        }
                    }
                }
            }
            assertWorkEmpty("semantic");
        }
    }

    @Test void detectsManifestDigestLengthVersionsAndNoncanonicalInstant() throws Exception {
        try (FilesystemPkiStore store = open("manifest")) {
            BackupArtifact artifact = store.createBackup(request());
            Map<String, byte[]> entries = unzip(artifact.payload().bytes());
            byte[] manifest = entries.get(FsBackupFiles.MANIFEST);
            int versionOffset = 2 + ByteBuffer.wrap(manifest).getShort();
            int storeOffset = versionOffset + 4;
            int idOffset = storeOffset + 2 + unsignedShort(manifest, storeOffset);
            int instantOffset = idOffset + 2 + unsignedShort(manifest, idOffset);
            for (Consumer<byte[]> mutation : List.<Consumer<byte[]>>of(
                    bytes -> ByteBuffer.wrap(bytes).putInt(versionOffset, 2),
                    bytes -> ByteBuffer.wrap(bytes).putInt(instantOffset + 8, -1),
                    bytes -> ByteBuffer.wrap(bytes).putInt(instantOffset + 8, 1_000_000_000),
                    bytes -> bytes[bytes.length - 9] ^= 1)) {
                Map<String, byte[]> changed = new LinkedHashMap<>(entries);
                byte[] malformed = manifest.clone();
                mutation.accept(malformed);
                changed.put(FsBackupFiles.MANIFEST, malformed);
                assertFalse(store.verifyBackupSource(source(zip(changed), artifact.backupId())).valid());
            }
            Map<String, byte[]> wrongPayload = new LinkedHashMap<>(entries);
            wrongPayload.put("SIGNING_NAMESPACE", "0".repeat(32).getBytes());
            assertFalse(store.verifyBackupSource(source(zip(wrongPayload), artifact.backupId())).valid());
            assertWorkEmpty("manifest");
        }
    }

    @Test void boundedIngestionRejectsLyingLengthDigestPartialIoAndEntryBudgets() throws Exception {
        try (FilesystemPkiStore store = open("bounds")) {
            BackupArtifact artifact = store.createBackup(request());
            byte[] valid = artifact.payload().bytes();
            BackupSource truthful = source(valid, artifact.backupId());
            BackupSource liar = new BackupSource() {
                @Override public PkiId backupId() { return truthful.backupId(); }
                @Override public long contentLength() { return 1; }
                @Override public String sha256() { return truthful.sha256(); }
                @Override public InputStream openStream() { return new ByteArrayInputStream(valid); }
                @Override public void close() { }
            };
            assertFalse(store.verifyBackupSource(liar).valid());
            BackupSource broken = new BackupSource() {
                @Override public PkiId backupId() { return truthful.backupId(); }
                @Override public long contentLength() { return valid.length; }
                @Override public String sha256() { return "0".repeat(64); }
                @Override public InputStream openStream() {
                    return new InputStream() {
                        private boolean first = true;
                        @Override public int read() throws IOException {
                            if (first) { first = false; return 80; }
                            throw new IOException("private/path/not-for-reporting");
                        }
                    };
                }
                @Override public void close() { }
            };
            assertEquals(List.of("BACKUP_INVALID"), store.verifyBackupSource(broken).issues());
            assertWorkEmpty("bounds");
            BackupLimits defaults = BackupLimits.defaults();
            BackupLimits small = new BackupLimits(defaults.compressedBytes(), defaults.expandedBytes(),
                    defaults.entryBytes(), 2, defaults.pathBytes(), defaults.manifestBytes(),
                    defaults.compressionRatio(), defaults.legacyBytes(), defaults.recordBytes());
            Path archive = temporary.resolve("bounds.zip");
            Files.write(archive, valid);
            assertThrows(IOException.class, () -> FsBackupArchive.directory(archive, small));
        }
    }

    @Test void failedForceAndCleanupAreExplicitAndSourceRemainsUsable() throws Exception {
        try (FilesystemPkiStore store = open("failures")) {
            FsBackupFiles.OBSERVER.set((phase, path) -> {
                if (phase == FsBackupFiles.Phase.FORCE) throw new IOException("injected");
            });
            try { assertThrows(IOException.class, () -> store.createBackupSource(request())); }
            finally { FsBackupFiles.OBSERVER.remove(); }
            assertWorkEmpty("failures");
            try (BackupSource source = store.createBackupSource(request())) {
                BackupPreparation preparation = store.prepareBackup(source);
                FsBackupFiles.OBSERVER.set((phase, path) -> {
                    if (phase == FsBackupFiles.Phase.DELETE) throw new IOException("injected");
                });
                try {
                    assertEquals("BACKUP_CLEANUP_FAILED",
                            assertThrows(IOException.class, preparation::close).getMessage());
                } finally { FsBackupFiles.OBSERVER.remove(); }
                assertTrue(Files.isDirectory(preparation.directory()));
                preparation.close();
            }
            store.putPolicyTrace(new PolicyTrace(new PkiId("still-usable"), List.of()));
            assertWorkEmpty("failures");
        }
    }

    @Test void rejectsActualExpansionBeyondForgedSizeAndEnforcesConfiguredLimits() throws Exception {
        try (FilesystemPkiStore store = open("limits")) {
            byte[] bomb = zip(Map.of(FsBackupFiles.MANIFEST, new byte[8192]));
            int central = signature(bomb, 0x02014b50);
            int descriptor = signature(bomb, 0x08074b50);
            put32(bomb, central + 24, 1);
            put32(bomb, descriptor + 12, 1);
            assertEquals(List.of("BACKUP_EXPANSION"), store.verifyBackupSource(source(bomb, FIXTURE_ID)).issues());
            byte[] expanded = zip(Map.of(FsBackupFiles.MANIFEST, new byte[8192]));
            Path archive = temporary.resolve("ratio.zip");
            Files.write(archive, expanded);
            BackupLimits defaults = BackupLimits.defaults();
            BackupLimits ratio = new BackupLimits(defaults.compressedBytes(), defaults.expandedBytes(),
                    defaults.entryBytes(), defaults.entryCount(), defaults.pathBytes(), defaults.manifestBytes(),
                    2, defaults.legacyBytes(), defaults.recordBytes());
            assertThrows(IOException.class, () -> FsBackupArchive.directory(archive, ratio));
            BackupLimits entry = new BackupLimits(100_000, 100_000, 100, 100, 1024, 100, 1000, 10, 100);
            assertThrows(IOException.class, () -> FsBackupArchive.directory(archive, entry));
            BackupLimits path = new BackupLimits(100_000, 100_000, 10_000, 100, 4, 100, 1000, 10, 100);
            assertThrows(IOException.class, () -> FsBackupArchive.directory(archive, path));
            BackupLimits manifest = new BackupLimits(100_000, 100_000, 10_000, 100, 1024, 100, 1000, 10, 100);
            assertEquals("BACKUP_MANIFEST_LIMIT", assertThrows(IOException.class,
                    () -> FsBackupArchive.extract(archive, temporary.resolve("unwritten"), FIXTURE_ID, manifest)).getMessage());
            assertFalse(Files.exists(temporary.resolve("unwritten")));
            assertThrows(IllegalArgumentException.class, () -> new BackupLimits(Long.MAX_VALUE,
                    Long.MAX_VALUE, Long.MAX_VALUE, Integer.MAX_VALUE, 1024, 100, 1, 1, 1));
            assertWorkEmpty("limits");
        }
    }

    @Test void closeRejectsNewAdmissionAndWaitsForAnAdmittedSnapshot() throws Exception {
        FilesystemPkiStore store = open("closing");
        CountDownLatch frozen = new CountDownLatch(1), release = new CountDownLatch(1);
        CompletableFuture<BackupSource> result = new CompletableFuture<>();
        Thread producer = Thread.ofPlatform().start(() -> {
            FsBackupFiles.OBSERVER.set((phase, path) -> {
                if (phase == FsBackupFiles.Phase.FROZEN) {
                    frozen.countDown();
                    try { if (!release.await(10, TimeUnit.SECONDS)) throw new IOException("timeout"); }
                    catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new IOException(failure); }
                }
            });
            try { result.complete(store.createBackupSource(request())); }
            catch (Throwable failure) { result.completeExceptionally(failure); }
            finally { FsBackupFiles.OBSERVER.remove(); }
        });
        assertTrue(frozen.await(10, TimeUnit.SECONDS));
        CompletableFuture<Void> closed = new CompletableFuture<>();
        Thread closer = Thread.ofPlatform().start(() -> {
            try { store.close(); closed.complete(null); }
            catch (Throwable failure) { closed.completeExceptionally(failure); }
        });
        try {
            awaitBarrierQueue(store, closer);
            assertThrows(IllegalStateException.class, () -> store.putPolicyTrace(new PolicyTrace(new PkiId("late"), List.of())));
            assertFalse(closed.isDone());
        } finally { release.countDown(); }
        closed.get(10, TimeUnit.SECONDS);
        try (BackupSource source = result.get(10, TimeUnit.SECONDS)) {
            assertTrue(source.contentLength() > 0);
        }
        producer.join(10000);
        closer.join(10000);
        store.close();
        assertWorkEmpty("closing");
    }

    @Test void freezeBlocksWholeRevocationAndEscapedSinkPublication() throws Exception {
        try (FilesystemPkiStore store = open("concurrency")) {
            Credential credential = FilesystemPkiStoreTest.TestObjects.minimalCredential(store, "43", "profile");
            store.putCredential(credential);
            ContentSink sink = store.stagedContent().beginContent(Encoding.BINARY, DurableContentReference.Lifecycle.PERSISTED);
            sink.outputStream().write(new byte[] { 3, 4, 5 });
            CountDownLatch frozen = new CountDownLatch(1), release = new CountDownLatch(1);
            CompletableFuture<BackupSource> backup = new CompletableFuture<>();
            Thread producer = Thread.ofPlatform().start(() -> {
                FsBackupFiles.OBSERVER.set((phase, path) -> {
                    if (phase == FsBackupFiles.Phase.FROZEN) {
                        frozen.countDown();
                        try { if (!release.await(10, TimeUnit.SECONDS)) throw new IOException("test timeout"); }
                        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new IOException(interrupted); }
                    }
                });
                try { backup.complete(store.createBackupSource(request())); }
                catch (Throwable failure) { backup.completeExceptionally(failure); }
                finally { FsBackupFiles.OBSERVER.remove(); }
            });
            assertTrue(frozen.await(10, TimeUnit.SECONDS));
            CompletableFuture<Void> revoked = new CompletableFuture<>();
            Thread mutation = Thread.ofPlatform().start(() -> {
                try {
                    store.transitionRevocation(new RevocationCommand.Hold(credential.credentialId(),
                            FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);
                    revoked.complete(null);
                } catch (Throwable failure) { revoked.completeExceptionally(failure); }
            });
            CompletableFuture<DurableContentReference> published = new CompletableFuture<>();
            Thread completer = Thread.ofPlatform().start(() -> {
                try { published.complete(sink.complete()); }
                catch (Throwable failure) { published.completeExceptionally(failure); }
            });
            try {
                awaitBarrierQueue(store, mutation);
                awaitBarrierQueue(store, completer);
                assertFalse(revoked.isDone());
                assertFalse(published.isDone());
            } finally { release.countDown(); }
            revoked.get(10, TimeUnit.SECONDS);
            assertNotNull(published.get(10, TimeUnit.SECONDS));
            try (BackupSource source = backup.get(10, TimeUnit.SECONDS);
                    BackupPreparation prepared = store.prepareBackup(source);
                    FilesystemPkiStore recovered = new FilesystemPkiStore(prepared.directory(), FsPkiStoreOptions.defaults(), CLOCK)) {
                assertTrue(recovered.getCredential(credential.credentialId()).isPresent());
                assertTrue(recovered.getRevocation(credential.credentialId()).isEmpty());
            }
            sink.close();
            producer.join(10000);
            mutation.join(10000);
            completer.join(10000);
            assertTrue(store.getRevocation(credential.credentialId()).isPresent());
        }
    }

    private static void awaitBarrierQueue(FilesystemPkiStore store, Thread thread) throws Exception {
        java.lang.reflect.Field barrierField = FilesystemPkiStore.class.getDeclaredField("mutationBarrier");
        barrierField.setAccessible(true);
        Object barrier = barrierField.get(store);
        java.lang.reflect.Field lockField = StoreMutationBarrier.class.getDeclaredField("lock");
        lockField.setAccessible(true);
        java.util.concurrent.locks.ReentrantReadWriteLock lock =
                (java.util.concurrent.locks.ReentrantReadWriteLock) lockField.get(barrier);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!lock.hasQueuedThread(thread) && System.nanoTime() < deadline) Thread.onSpinWait();
        assertTrue(lock.hasQueuedThread(thread), "operation must queue behind the held snapshot barrier");
    }

    private void assertWorkEmpty(String root) throws IOException {
        Path work = temporary.resolve(root).resolve(".backup-work");
        if (!Files.exists(work)) return;
        try (java.util.stream.Stream<Path> files = Files.list(work)) { assertTrue(files.findAny().isEmpty()); }
    }
    private static BackupSource source(byte[] bytes, PkiId id) {
        String digest = HexFormat.of().formatHex(FsBackupFiles.digest().digest(bytes));
        return new BackupSource() {
            @Override public PkiId backupId() { return id; }
            @Override public long contentLength() { return bytes.length; }
            @Override public String sha256() { return digest; }
            @Override public InputStream openStream() { return new ByteArrayInputStream(bytes); }
            @Override public void close() { }
        };
    }
    private static byte[] zip(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return bytes.toByteArray();
    }
    private static Map<String, byte[]> unzip(byte[] bytes) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) entries.put(entry.getName(), zip.readAllBytes());
        }
        return entries;
    }
    private static int signature(byte[] bytes, int signature) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        for (int offset = 0; offset <= bytes.length - 4; offset++) if (buffer.getInt(offset) == signature) return offset;
        throw new AssertionError("signature missing");
    }
    private static void put16(byte[] bytes, int offset, int value) {
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putShort(offset, (short) value);
    }
    private static void put32(byte[] bytes, int offset, long value) {
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(offset, (int) value);
    }
    private static int unsignedShort(byte[] bytes, int offset) {
        return Short.toUnsignedInt(ByteBuffer.wrap(bytes).getShort(offset));
    }
    private static void replaceAscii(byte[] bytes, String before, String after) {
        byte[] pattern = before.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] replacement = after.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        for (int offset = 0; offset <= bytes.length - pattern.length; offset++) {
            if (Arrays.equals(bytes, offset, offset + pattern.length, pattern, 0, pattern.length)) {
                System.arraycopy(replacement, 0, bytes, offset, replacement.length);
            }
        }
    }
}
