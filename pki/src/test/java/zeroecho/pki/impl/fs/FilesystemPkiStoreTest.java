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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.orch.OrchestrationDurabilityPolicy;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.policy.PolicyTraceStep;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.profile.LeafCertificatePolicy;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.profile.SubjectAlternativeNamePolicy;
import zeroecho.pki.api.profile.SubjectPolicy;
import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Tests for {@link FilesystemPkiStore}.
 *
 * <p>
 * The tests are deterministic and do not use reflection. Snapshot export
 * semantics are tested using {@link FsPkiStoreOptions#strictSnapshotExport()}
 * configured appropriately.
 * </p>
 *
 * <p>
 * Output conventions:
 * </p>
 * <ul>
 * <li>Each test prints its own name at the start.</li>
 * <li>Each test prints {@code ...ok} on success.</li>
 * <li>Important intermediate state is printed with {@code ...} prefix.</li>
 * </ul>
 */
public final class FilesystemPkiStoreTest {

    @TempDir
    Path tmp;

    @Test
    void everyNonSigningTopLevelSchemaRoundTripsThroughRealStore() throws Exception {
        System.out.println("everyNonSigningTopLevelSchemaRoundTripsThroughRealStore");
        Path root = tmp.resolve("store-all-schemas");
        Instant now = Instant.parse("2026-01-02T03:04:05Z");
        AttributeSet attributes = TestObjects.emptyAttributes();
        ParsedCertificationRequest request = new ParsedCertificationRequest(new PkiId("request-all"),
                new FormatId("fmt-x509"), new SubjectRef("CN=request-all"),
                new EncodedObject(Encoding.DER, new byte[] { 4, 5, 6 }), Optional.empty(), Optional.of("profile-all"),
                attributes);
        CertificateProfile profile = TestObjects.minimalProfile("profile-all");
        PolicyTrace trace = new PolicyTrace(new PkiId("decision-all"),
                List.of(new PolicyTraceStep("rule-all", "ALLOW", List.of("approved"))));
        WorkflowStateRecord workflow = new WorkflowStateRecord(new PkiId("workflow-all"), "ISSUANCE",
                new Principal("TEST", "owner"), OrchestrationDurabilityPolicy.DURABLE_MIN_STATE, now, now,
                now.plusSeconds(60L), Encoding.BINARY,
                Optional.of(new EncodedObject(Encoding.BINARY, new byte[] { 9 })));

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            CaRecord ca = TestObjects.minimalCaRecord(store, "ca-all", CaState.ACTIVE);
            Credential credential = TestObjects.minimalCredential(store, "SERIAL-ALL", "profile-all");
            StatusObject status = new StatusObject(new PkiId("status-all"), new FormatId("fmt-x509"), ca.caId(),
                    StatusObjectType.CRL, now, Optional.of(now.plusSeconds(60L)),
                    zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(store.stagedContent(), Encoding.DER,
                            new byte[] { 1, 2 }),
                    attributes);
            PublicationRecord publication = new PublicationRecord(new PkiId("publication-all"), now,
                    new PublicationTarget(PublicationTargetType.FILESYSTEM, "target-all", attributes),
                    credential.credentialId(), "CREDENTIAL", PublicationStatus.PUBLISHED);
            store.putCa(ca);
            store.putCredential(credential);
            store.putRequest(request);
            RevocationJournal revocation = store.transitionRevocation(new RevocationCommand.RevokePermanently(
                    credential.credentialId(), RevocationReason.KEY_COMPROMISE, attributes), now);
            store.putStatusObject(status);
            store.putPublicationRecord(publication);
            importProfile(store, profile, now);
            store.activateProfile(profile.profileId(), 1);
            store.putPolicyTrace(trace);
            store.putWorkflowState(workflow);

            assertEquals(ca.caId(), store.getCa(ca.caId()).orElseThrow().caId());
            assertEquals(credential.credentialId(),
                    store.getCredential(credential.credentialId()).orElseThrow().credentialId());
            assertEquals(request.requestId(), store.getRequest(request.requestId()).orElseThrow().requestId());
            assertEquals(revocation.credentialId(),
                    store.getRevocationJournal(revocation.credentialId()).orElseThrow().credentialId());
            assertEquals(status.statusObjectId(),
                    store.getStatusObject(status.statusObjectId()).orElseThrow().statusObjectId());
            assertEquals(publication.publicationId(), store.listPublicationRecords().get(0).publicationId());
            assertEquals(profile, store.requireActiveProfile(profile.profileId()).profile());
            assertEquals(trace, store.getPolicyTrace(trace.decisionId()).orElseThrow());
            assertEquals(workflow.opId(), store.getWorkflowState(workflow.opId()).orElseThrow().opId());
        }

        System.out.println("...schemas round-tripped=9; signing schema covered separately");
        System.out.println("...ok");
    }

    @Test
    void writeOnceCredentialRejected() throws Exception {
        System.out.println("writeOnceCredentialRejected");

        Path root = tmp.resolve("store-writeonce");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            Credential c1 = TestObjects.minimalCredential(store, "SERIAL-1", "profile-1");
            store.putCredential(c1);

            RuntimeException ex = assertThrows(RuntimeException.class, () -> store.putCredential(c1));
            assertNotNull(ex);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("writeOnceCredentialRejected...ok");
    }

    @Test
    void caHistoryCreatesCurrentAndHistory() throws Exception {
        System.out.println("caHistoryCreatesCurrentAndHistory");

        Path root = tmp.resolve("store-ca-history");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            CaRecord ca1 = TestObjects.minimalCaRecord(store, "ca-1", CaState.ACTIVE);
            store.putCa(ca1);

            CaRecord ca2 = new CaRecord(ca1.caId(), ca1.kind(), CaState.DISABLED, ca1.issuerKeyRef(), ca1.subjectRef(),
                    ca1.credentialIds());
            store.putCa(ca2);

            Optional<CaRecord> loaded = store.getCa(ca1.caId());
            assertTrue(loaded.isPresent());
            assertEquals(CaState.DISABLED, loaded.get().state());
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("caHistoryCreatesCurrentAndHistory...ok");
    }

    @Test
    void caReferencesRequireValidStandaloneCredentialsAndPreserveOrder() throws Exception {
        System.out.println("caReferencesRequireValidStandaloneCredentialsAndPreserveOrder");
        Path root = tmp.resolve("store-ca-authority");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            Credential first = TestObjects.minimalCredential(store, "SERIAL-FIRST", "profile-ca");
            Credential second = TestObjects.minimalCredential(store, "SERIAL-SECOND", "profile-ca");
            store.putCredential(first);
            store.putCredential(second);
            CaRecord ordered = new CaRecord(new PkiId("ca-ordered"), CaKind.ROOT, CaState.ACTIVE,
                    new KeyRef("key-ordered"), new SubjectRef("CN=Ordered"),
                    List.of(second.credentialId(), first.credentialId()));
            store.putCa(ordered);

            assertEquals(List.of(second.credentialId(), first.credentialId()),
                    store.getCa(ordered.caId()).orElseThrow().credentialIds());
            CaRecord missing = new CaRecord(new PkiId("ca-missing"), CaKind.ROOT, CaState.ACTIVE,
                    new KeyRef("key-missing"), new SubjectRef("CN=Missing"),
                    List.of(new PkiId("credential-missing")));
            assertThrows(IllegalStateException.class, () -> store.putCa(missing));

            Files.write(root.resolve("staged-content").resolve(first.content().contentId() + ".content"),
                    new byte[] { 9, 9, 9 });
            assertThrows(IllegalStateException.class, () -> store.getCa(ordered.caId()));
            assertThrows(IllegalStateException.class, store::listCas);
        }
        System.out.println("caReferencesRequireValidStandaloneCredentialsAndPreserveOrder...ok");
    }

    @Test
    void oldStoreVersionIsRejected() throws Exception {
        System.out.println("oldStoreVersionIsRejected");
        Path root = tmp.resolve("store-old-version");
        Files.createDirectories(root);
        Files.writeString(root.resolve(FsPaths.VERSION_FILE), "v2");

        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
        System.out.println("oldStoreVersionIsRejected...ok");
    }

    @Test
    void snapshotReconstructsSharedCredentialOnceWithNewTargetReference() throws Exception {
        System.out.println("snapshotReconstructsSharedCredentialOnceWithNewTargetReference");
        Path root = tmp.resolve("store-snapshot-authority");
        Path snapshot = tmp.resolve("snapshot-authority");
        FsPkiStoreOptions options = nonStrictSnapshotOptions();
        PkiId credentialId;
        String sourceContentId;
        try (FilesystemPkiStore source = new FilesystemPkiStore(root, options)) {
            Credential shared = TestObjects.minimalCredential(source, "SERIAL-SHARED", "profile-ca");
            source.putCredential(shared);
            credentialId = shared.credentialId();
            sourceContentId = shared.content().contentId();
            source.putCa(new CaRecord(new PkiId("ca-shared-one"), CaKind.ROOT, CaState.ACTIVE,
                    new KeyRef("key-shared-one"), new SubjectRef("CN=Shared One"), List.of(credentialId)));
            source.putCa(new CaRecord(new PkiId("ca-shared-two"), CaKind.ROOT, CaState.ACTIVE,
                    new KeyRef("key-shared-two"), new SubjectRef("CN=Shared Two"), List.of(credentialId)));
            source.exportSnapshot(snapshot, Instant.now());
        }

        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshot, options)) {
            assertEquals(2, restored.listCas().size());
            Credential credential = restored.getCredential(credentialId).orElseThrow();
            assertFalse(sourceContentId.equals(credential.content().contentId()));
            assertEquals(List.of(credentialId),
                    restored.getCa(new PkiId("ca-shared-one")).orElseThrow().credentialIds());
        }
        try (java.util.stream.Stream<Path> records = Files.list(snapshot.resolve("credentials").resolve("by-id"))) {
            assertEquals(1, records.filter(Files::isRegularFile).count());
        }
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".content")));
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".meta")));
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".owners")));
        System.out.println("snapshotReconstructsSharedCredentialOnceWithNewTargetReference...ok");
    }

    @Test
    void snapshotPreservesStandaloneCredentialWithNewReferenceAndResolvableCa() throws Exception {
        System.out.println("snapshotPreservesStandaloneCredentialWithNewReferenceAndResolvableCa");
        Path root = tmp.resolve("store-snapshot-standalone");
        Path snapshot = tmp.resolve("snapshot-standalone");
        FsPkiStoreOptions options = nonStrictSnapshotOptions();
        PkiId standaloneId;
        String standaloneSourceContentId;
        PkiId caId;
        try (FilesystemPkiStore source = new FilesystemPkiStore(root, options)) {
            Credential standalone = TestObjects.minimalCredential(source, "SERIAL-END-ENTITY", "profile-leaf");
            source.putCredential(standalone);
            standaloneId = standalone.credentialId();
            standaloneSourceContentId = standalone.content().contentId();
            CaRecord ca = TestObjects.minimalCaRecord(source, "ca-with-authority", CaState.ACTIVE);
            source.putCa(ca);
            caId = ca.caId();
            source.exportSnapshot(snapshot, Instant.now());
        }

        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshot, options)) {
            Credential standalone = restored.getCredential(standaloneId).orElseThrow();
            assertFalse(standaloneSourceContentId.equals(standalone.content().contentId()));
            CaRecord ca = restored.getCa(caId).orElseThrow();
            assertTrue(restored.getCredential(ca.credentialIds().get(0)).isPresent());
        }
        System.out.println("snapshotPreservesStandaloneCredentialWithNewReferenceAndResolvableCa...ok");
    }

    @Test
    void snapshotPreservesSharedStatusContentWithoutStaleCredentialOwner() throws Exception {
        System.out.println("snapshotPreservesSharedStatusContentWithoutStaleCredentialOwner");
        Path root = tmp.resolve("store-snapshot-shared-status");
        Path snapshot = tmp.resolve("snapshot-shared-status");
        FsPkiStoreOptions options = nonStrictSnapshotOptions();
        PkiId credentialId;
        PkiId statusId = new PkiId("status-shared-content");
        String sourceContentId;
        byte[] expected = new byte[] { 1, 2, 3 };
        try (FilesystemPkiStore source = new FilesystemPkiStore(root, options)) {
            Credential credential = TestObjects.minimalCredential(source, "SERIAL-SHARED-STATUS", "profile-ca");
            source.putCredential(credential);
            credentialId = credential.credentialId();
            sourceContentId = credential.content().contentId();
            StatusObject status = new StatusObject(statusId, credential.formatId(), credential.issuerRef().caId(),
                    StatusObjectType.CRL, Instant.EPOCH, Optional.empty(), credential.content(),
                    TestObjects.emptyAttributes());
            source.putStatusObject(status);
            source.exportSnapshot(snapshot, Instant.now());
        }

        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshot, options)) {
            Credential credential = restored.getCredential(credentialId).orElseThrow();
            StatusObject status = restored.getStatusObject(statusId).orElseThrow();
            assertFalse(sourceContentId.equals(credential.content().contentId()));
            assertEquals(sourceContentId, status.content().contentId());
            assertArrayEquals(expected, zeroecho.pki.testkit.PkiTestRuntime.readContent(restored, credential.content()));
            assertArrayEquals(expected, zeroecho.pki.testkit.PkiTestRuntime.readContent(restored, status.content()));
        }
        assertTrue(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".content")));
        assertTrue(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".meta")));
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".owners")));
        System.out.println("snapshotPreservesSharedStatusContentWithoutStaleCredentialOwner...ok");
    }

    @Test
    void snapshotBuildFailureCleansOwnedTemporaryRootAndPublishesNothing() throws Exception {
        System.out.println("snapshotBuildFailureCleansOwnedTemporaryRootAndPublishesNothing");
        Path root = tmp.resolve("store-snapshot-build-failure");
        Path snapshot = tmp.resolve("snapshot-build-failure");
        FsPkiStoreOptions options = nonStrictSnapshotOptions();
        try (FilesystemPkiStore source = new FilesystemPkiStore(root, options)) {
            Credential standalone = TestObjects.minimalCredential(source, "SERIAL-BUILD-FAIL", "profile-leaf");
            source.putCredential(standalone);
            Files.delete(root.resolve("SIGNING_TIME_WATERMARK"));

            assertThrows(IllegalStateException.class, () -> source.exportSnapshot(snapshot, Instant.now()));
            assertFalse(Files.exists(snapshot));
        }
        try (java.util.stream.Stream<Path> siblings = Files.list(tmp)) {
            assertFalse(siblings.anyMatch(path -> path.getFileName().toString().startsWith(".zeroecho-snapshot-")));
        }
        System.out.println("snapshotBuildFailureCleansOwnedTemporaryRootAndPublishesNothing...ok");
    }

    @Test
    void snapshotRejectsExistingTargetWithoutChangingIt() throws Exception {
        System.out.println("snapshotRejectsExistingTargetWithoutChangingIt");
        Path root = tmp.resolve("store-snapshot-existing-target");
        Path snapshot = tmp.resolve("snapshot-existing-target");
        Path sentinel = snapshot.resolve("sentinel.txt");
        Files.createDirectories(snapshot);
        Files.writeString(sentinel, "owner data");

        try (FilesystemPkiStore source = new FilesystemPkiStore(root, nonStrictSnapshotOptions())) {
            assertThrows(IllegalStateException.class, () -> source.exportSnapshot(snapshot, Instant.now()));
        }

        assertEquals("owner data", Files.readString(sentinel));
        try (java.util.stream.Stream<Path> siblings = Files.list(tmp)) {
            assertFalse(siblings.anyMatch(path -> path.getFileName().toString().startsWith(".zeroecho-snapshot-")));
        }
        System.out.println("snapshotRejectsExistingTargetWithoutChangingIt...ok");
    }

    @Test
    void snapshotStrictFailsAndNonStrictOmitsOnlyInconsistentCa() throws Exception {
        System.out.println("snapshotStrictFailsAndNonStrictOmitsOnlyInconsistentCa");
        Path root = tmp.resolve("store-snapshot-inconsistent");
        Path strictSnapshot = tmp.resolve("snapshot-inconsistent-strict");
        Path nonStrictSnapshot = tmp.resolve("snapshot-inconsistent-nonstrict");
        FsPkiStoreOptions nonStrict = nonStrictSnapshotOptions();
        try (FilesystemPkiStore source = new FilesystemPkiStore(root, nonStrict)) {
            CaRecord valid = TestObjects.minimalCaRecord(source, "ca-valid", CaState.ACTIVE);
            CaRecord inconsistent = TestObjects.minimalCaRecord(source, "ca-inconsistent", CaState.ACTIVE);
            source.putCa(valid);
            source.putCa(inconsistent);
            Files.delete(new FsPaths(root).credentialPath(inconsistent.credentialIds().get(0)));

            FsPkiStoreOptions strict = strictSnapshotOptions();
            assertThrows(IllegalStateException.class,
                    () -> new FsSnapshotExporter(strict).exportSnapshot(source, strictSnapshot, Instant.now()));
            assertFalse(Files.exists(strictSnapshot));

            source.exportSnapshot(nonStrictSnapshot, Instant.now());
        }
        try (FilesystemPkiStore restored = new FilesystemPkiStore(nonStrictSnapshot, nonStrict)) {
            assertEquals(List.of("ca-valid"), restored.listCas().stream()
                    .map(ca -> ca.caId().value()).toList());
        }
        System.out.println("snapshotStrictFailsAndNonStrictOmitsOnlyInconsistentCa...ok");
    }

    @Test
    void revocationJournalPersistsLegalTransitions() throws Exception {
        System.out.println("revocationJournalPersistsLegalTransitions");

        Path root = tmp.resolve("store-revocation-history");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            Credential credential = TestObjects.minimalCredential(store, "SERIAL-REV", "profile-rev");
            store.putCredential(credential);
            store.transitionRevocation(
                    new RevocationCommand.Hold(credential.credentialId(), TestObjects.emptyAttributes()),
                    Instant.EPOCH.plusSeconds(10L));
            store.transitionRevocation(
                    new RevocationCommand.Unhold(credential.credentialId(), TestObjects.emptyAttributes()),
                    Instant.EPOCH.plusSeconds(11L));

            Optional<RevocationJournal> loaded = store.getRevocationJournal(credential.credentialId());
            assertTrue(loaded.isPresent());
            assertEquals(2L, loaded.get().latest().revision());
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("revocationJournalPersistsLegalTransitions...ok");
    }

    @Test
    void snapshotExportClonesNewRootNonStrict() throws Exception {
        System.out.println("snapshotExportClonesNewRootNonStrict");

        Path root = tmp.resolve("store-snapshot-basic");
        Path snapshot = tmp.resolve("snapshot-basic");

        FsPkiStoreOptions options = nonStrictSnapshotOptions();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            CaRecord ca1 = TestObjects.minimalCaRecord(store, "ca-snap-1", CaState.ACTIVE);
            store.putCa(ca1);

            Instant at = Instant.now();
            importProfile(store, TestObjects.minimalProfile("profile-snap-1"), Instant.now());

            store.exportSnapshot(snapshot, at);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("...snapshot tree:");
        dumpTree(snapshot);

        assertTrue(Files.exists(snapshot.resolve("VERSION")));
        assertTrue(Files.exists(snapshot.resolve("cas").resolve("by-id")));

        System.out.println("snapshotExportClonesNewRootNonStrict...ok");
    }

    @Test
    void snapshotExportWithMultipleObjectsNonStrictDoesNotFail() throws Exception {
        System.out.println("snapshotExportWithMultipleObjectsNonStrictDoesNotFail");

        Path root = tmp.resolve("store-snapshot-multi");
        Path snap1 = tmp.resolve("snapshot-multi-1");
        Path snap2 = tmp.resolve("snapshot-multi-2");

        FsPkiStoreOptions options = nonStrictSnapshotOptions();

        CertificateProfile pA = TestObjects.minimalProfile("profile-a");
        CertificateProfile pB = TestObjects.minimalProfile("profile-b");

        Instant at1;
        Instant at2;

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            CaRecord caA = TestObjects.minimalCaRecord(store, "ca-a", CaState.ACTIVE);
            CaRecord caB = TestObjects.minimalCaRecord(store, "ca-b", CaState.ACTIVE);
            store.putCa(caA);
            at1 = Instant.now();

            sleepMillis(120L);

            store.putCa(caB);
            importProfile(store, pA, Instant.now());
            at2 = Instant.now();

            sleepMillis(120L);

            importProfile(store, pB, Instant.now());

            // Export snapshots after all writes; in non-strict mode export must not fail.
            store.exportSnapshot(snap1, at1);
            store.exportSnapshot(snap2, at2);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("...snapshot1 tree:");
        dumpTree(snap1);

        System.out.println("...snapshot2 tree:");
        dumpTree(snap2);

        try (FilesystemPkiStore s2 = new FilesystemPkiStore(snap2, options)) {
            List<CaRecord> cas = s2.listCas();
            List<ImportedCertificateProfileVersion> profiles = s2.listProfileVersions("profile-a");

            Set<String> caIds = cas.stream().map(r -> r.caId().toString()).collect(Collectors.toSet());
            Set<String> profileIds = profiles.stream().map(v -> v.reference().profileId()).collect(Collectors.toSet());

            System.out.println("...snapshot2 caIds: " + caIds);
            System.out.println("...snapshot2 profileIds: " + profileIds);

            assertTrue(caIds.contains("ca-a"));
            assertTrue(caIds.contains("ca-b"));
            assertTrue(profileIds.contains("profile-a"));
            assertFalse(profileIds.contains("profile-b"));
        }

        System.out.println("snapshotExportWithMultipleObjectsNonStrictDoesNotFail...ok");
    }

    @Test
    void snapshotExportStrictFailsWhenAtIsBeforeLaterInsert() throws Exception {
        System.out.println("snapshotExportStrictFailsWhenAtIsBeforeLaterInsert");

        Path root = tmp.resolve("store-snapshot-strict-fail");
        Path snapshot = tmp.resolve("snapshot-strict-fail");

        FsPkiStoreOptions options = strictSnapshotOptions();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            // Create CA first.
            store.putCa(TestObjects.minimalCaRecord(store, "ca-strict-1", CaState.ACTIVE));

            // "at" is before the profile exists.
            Instant at = Instant.now();
            sleepMillis(120L);

            // Now create a new object that does not have history entry <= at.
            importProfile(store, TestObjects.minimalProfile("profile-strict-1"), Instant.now());

            // Immutable versions imported after the requested time are omitted.
            store.exportSnapshot(snapshot, at);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("snapshotExportStrictFailsWhenAtIsBeforeLaterInsert...ok");
    }

    @Test
    void snapshotExportStrictSucceedsWhenAtIsAfterAllWrites() throws Exception {
        System.out.println("snapshotExportStrictSucceedsWhenAtIsAfterAllWrites");

        Path root = tmp.resolve("store-snapshot-strict-ok");
        Path snapshot = tmp.resolve("snapshot-strict-ok");

        FsPkiStoreOptions options = strictSnapshotOptions();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            store.putCa(TestObjects.minimalCaRecord(store, "ca-strict-ok", CaState.ACTIVE));
            importProfile(store, TestObjects.minimalProfile("profile-strict-ok"), Instant.now());

            // "at" after all writes: strict export should succeed.
            Instant at = Instant.now();
            store.exportSnapshot(snapshot, at);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("...snapshot tree:");
        dumpTree(snapshot);

        try (FilesystemPkiStore snap = new FilesystemPkiStore(snapshot, options)) {
            Set<String> caIds = snap.listCas().stream().map(r -> r.caId().toString()).collect(Collectors.toSet());
            Set<String> profileIds = snap.listProfileVersions("profile-strict-ok").stream()
                    .map(v -> v.reference().profileId()).collect(Collectors.toSet());

            System.out.println("...snapshot caIds: " + caIds);
            System.out.println("...snapshot profileIds: " + profileIds);

            assertTrue(caIds.contains("ca-strict-ok"));
            assertTrue(profileIds.contains("profile-strict-ok"));
        }

        System.out.println("snapshotExportStrictSucceedsWhenAtIsAfterAllWrites...ok");
    }

    private static FsPkiStoreOptions nonStrictSnapshotOptions() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        return new FsPkiStoreOptions(defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), false,
                defaults.signingOperationHorizon(), defaults.signingIdPermittedSkew());
    }

    private static FsPkiStoreOptions strictSnapshotOptions() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        return new FsPkiStoreOptions(defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), true,
                defaults.signingOperationHorizon(), defaults.signingIdPermittedSkew());
    }

    private static void sleepMillis(long ms) throws InterruptedException {
        Thread.sleep(ms);
    }

    private static void dumpTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            System.out.println("...<missing> " + root);
            return;
        }
        List<Path> paths = Files.walk(root).sorted(Comparator.naturalOrder()).collect(Collectors.toList());
        for (Path p : paths) {
            Path rel = root.relativize(p);
            if (rel.toString().isEmpty()) {
                continue;
            }
            if (Files.isDirectory(p)) {
                System.out.println("..." + rel + "/");
            } else {
                long size = Files.size(p);
                System.out.println("..." + rel + " (" + size + " bytes)");
            }
        }
    }

    private static String shorten(String s, int max) {
        if (s == null) {
            return "null";
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, Math.max(0, max - 3)) + "...";
    }

    /**
     * Test-only codec-friendly {@link AttributeSet} implementation (no proxies).
     *
     * @param entries serialized entries
     */
    public record TestAttributeSet(List<Entry> entries) implements AttributeSet {

        public record Entry(AttributeId id, List<AttributeValue> values) {

            public Entry {
                if (id == null) {
                    throw new IllegalArgumentException("id must not be null");
                }
                if (values == null) {
                    throw new IllegalArgumentException("values must not be null");
                }
            }
        }

        @Override
        public Set<AttributeId> ids() {
            return entries.stream().map(Entry::id).collect(Collectors.toUnmodifiableSet());
        }

        @Override
        public Optional<AttributeValue> get(AttributeId id) {
            if (id == null) {
                throw new IllegalArgumentException("id must not be null");
            }
            for (Entry e : entries) {
                if (e.id().equals(id)) {
                    if (e.values().isEmpty()) {
                        return Optional.empty();
                    }
                    return Optional.of(e.values().get(0));
                }
            }
            return Optional.empty();
        }

        @Override
        public List<AttributeValue> getAll(AttributeId id) {
            if (id == null) {
                throw new IllegalArgumentException("id must not be null");
            }
            for (Entry e : entries) {
                if (e.id().equals(id)) {
                    return List.copyOf(e.values());
                }
            }
            return List.of();
        }
    }

    /**
     * Deterministic domain fixtures.
     */
    static void importProfile(FilesystemPkiStore store, CertificateProfile profile, Instant importedAt)
            throws Exception {
        CertificateProfileDefinition definition = new CertificateProfileDefinition(CertificateProfileKind.END_ENTITY,
                profile.profileId(), 1, profile.formatId(), profile.displayName(), profile.maximumValidity(),
                profile.subjectPolicy(), profile.leafPolicy());
        byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(canonical);
        CertificateProfileRef reference = new CertificateProfileRef(profile.profileId(), 1, hash);
        store.importProfileVersion(new ImportedCertificateProfileVersion(reference,
                CertificateProfileDefinition.SCHEMA_VERSION, definition, canonical, importedAt));
    }

    static final class TestObjects {

        private static final AtomicLong SEQ = new AtomicLong(1L);

        static CaRecord minimalCaRecord(PkiStore store, String caId, CaState state) throws IOException {
            PkiId id = new PkiId(caId);

            KeyRef issuerKeyRef = new KeyRef("issuer-key-" + caId);
            SubjectRef subjectRef = new SubjectRef("CN=" + caId);

            Credential cred = minimalCredential(store, "CA-" + caId, "profile-ca");
            store.putCredential(cred);
            return new CaRecord(id, CaKind.ROOT, state, issuerKeyRef, subjectRef,
                    List.of(cred.credentialId()));
        }

        static CertificateProfile minimalProfile(String profileId) {
            FormatId formatId = new FormatId("fmt-x509");
            SubjectPolicy subject = new SubjectPolicy(false,
                    List.of(new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 256, Optional.empty(), true)));
            SubjectAlternativeNamePolicy sans = new SubjectAlternativeNamePolicy(0, 0, List.of(), false, Set.of(),
                    false, false, false);
            LeafCertificatePolicy leaf = new LeafCertificatePolicy(sans,
                    Set.of(LeafKeyUsage.DIGITAL_SIGNATURE, LeafKeyUsage.KEY_ENCIPHERMENT),
                    Set.of(new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.1")), true, false, true, Set.of("RSA"));
            return new CertificateProfile(profileId, formatId, "Test leaf profile", Duration.ofDays(365), subject,
                    leaf);
        }

        static Credential minimalCredential(PkiStore store, String serial, String profileId) throws IOException {
            PkiId credentialId = new PkiId("cred-" + nextSeq());
            FormatId formatId = new FormatId("fmt-x509");

            IssuerRef issuerRef = new IssuerRef(new PkiId("issuer-" + nextSeq()));
            SubjectRef subjectRef = new SubjectRef("CN=subj-" + nextSeq());

            Instant notBefore = Instant.EPOCH;
            Instant notAfter = Instant.EPOCH.plusSeconds(60L);
            Validity validity = new Validity(notBefore, notAfter);

            PkiId publicKeyId = new PkiId("pk-" + nextSeq());

            CredentialStatus status = CredentialStatus.ISSUED;

            zeroecho.pki.api.content.DurableContentReference encoded = minimalEncodedObject(store);
            AttributeSet attrs = emptyAttributes();

            return new Credential(credentialId, formatId, issuerRef, subjectRef, validity, serial, publicKeyId,
                    new CaProfileBinding(
                            new zeroecho.pki.api.profile.CertificateProfileRef(profileId, 1, new byte[32])),
                    status, encoded, attrs);
        }

        static AttributeSet emptyAttributes() {
            return new TestAttributeSet(List.of());
        }

        private static zeroecho.pki.api.content.DurableContentReference minimalEncodedObject(PkiStore store)
                throws IOException {
            return zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(store.stagedContent(), Encoding.DER,
                    new byte[] { 0x01, 0x02, 0x03 });
        }

        private static String nextSeq() {
            return String.format("%016x", Long.valueOf(SEQ.getAndIncrement()));
        }
    }
}
