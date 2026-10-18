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
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
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
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
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
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
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

    @Test
    void smallLegalSigningWalConfigurationIsReusedAcrossReopen(@TempDir Path root) throws Exception {
        int maximumBatchBytes = SigningWalFrameCodec.BATCH_MARKER_BYTES
                + SigningWalFrameCodec.MAX_FRAME_BYTES;
        long maximumSegmentBytes = SigningWalContainerCodec.HEADER_BYTES
                + (long) maximumBatchBytes;
        SigningActiveWal.Configuration configuration = new SigningActiveWal.Configuration(
                4, 1, 0L, 4L * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                maximumBatchBytes, maximumSegmentBytes);
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore created = new FilesystemPkiStore(
                root, options, Clock.systemUTC(), 8, null, configuration)) {
            assertEquals(configuration.queueCapacity(),
                    created.localSigningWriterSnapshot().queueCapacity());
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, options, Clock.systemUTC(), 8, null, configuration)) {
            assertEquals(configuration.queueCapacity(),
                    reopened.localSigningWriterSnapshot().queueCapacity());
        }
    }

    @Test
    void localSigningIndexCapacityMetricsUseConfiguredBudgetAcrossReopen(@TempDir Path root) throws Exception {
        long configured = 768L * 1024L * 1024L;
        long transientConfigured = 640L * 1024L * 1024L;
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults()
                .withSigningResidentIndexBudgetBytes(configured)
                .withSigningCompactionTransientBudgetBytes(transientConfigured);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            FilesystemPkiStore.LocalSigningIndexCapacityMetrics metrics =
                    store.localSigningIndexCapacityMetrics();
            assertCapacityMetrics(metrics, configured, transientConfigured);
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, options)) {
            FilesystemPkiStore.LocalSigningIndexCapacityMetrics metrics =
                    reopened.localSigningIndexCapacityMetrics();
            assertCapacityMetrics(metrics, configured, transientConfigured);
        }
    }

    private static void assertCapacityMetrics(
            FilesystemPkiStore.LocalSigningIndexCapacityMetrics metrics,
            long steadyMaximum, long transientMaximum) {
        assertEquals(steadyMaximum, metrics.steadyMaximumBytes());
        assertEquals(transientMaximum, metrics.transientMaximumBytes());
        assertEquals(Math.addExact(steadyMaximum, transientMaximum),
                metrics.combinedMaximumBytes());
        assertTrue(metrics.steadyCurrentReservedBytes()
                <= metrics.steadyHighWaterReservedBytes());
        assertTrue(metrics.steadyHighWaterReservedBytes() <= metrics.steadyMaximumBytes());
        assertTrue(metrics.transientCurrentReservedBytes()
                <= metrics.transientHighWaterReservedBytes());
        assertTrue(metrics.transientHighWaterReservedBytes()
                <= metrics.transientMaximumBytes());
        assertEquals(Math.addExact(metrics.steadyCurrentReservedBytes(),
                metrics.transientCurrentReservedBytes()), metrics.combinedCurrentReservedBytes());
        assertEquals(Math.addExact(metrics.steadyHighWaterReservedBytes(),
                metrics.transientHighWaterReservedBytes()),
                metrics.combinedHighWaterReservedBytes());
    }

    @Test
    void signingMaximumGroupSizeHasStableValidatedCopyContract() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        assertEquals(32, defaults.signingMaximumGroupSize());
        for (int supported : List.of(1, 2, 8, 32)) {
            FsPkiStoreOptions configured = defaults.withSigningMaximumGroupSize(supported);
            assertEquals(supported, configured.signingMaximumGroupSize());
            assertEquals(defaults.caHistoryPolicy(), configured.caHistoryPolicy());
            assertEquals(defaults.profileHistoryPolicy(), configured.profileHistoryPolicy());
            assertEquals(defaults.revocationHistoryPolicy(), configured.revocationHistoryPolicy());
            assertEquals(defaults.workflowHistoryPolicy(), configured.workflowHistoryPolicy());
            assertEquals(defaults.strictSnapshotExport(), configured.strictSnapshotExport());
            assertEquals(defaults.signingOperationHorizon(), configured.signingOperationHorizon());
            assertEquals(defaults.signingIdPermittedSkew(), configured.signingIdPermittedSkew());
        }
        assertThrows(IllegalArgumentException.class,
                () -> defaults.withSigningMaximumGroupSize(0));
        assertThrows(IllegalArgumentException.class,
                () -> defaults.withSigningMaximumGroupSize(33));
    }

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
            PublicationRecord publication = new PublicationRecord(new PkiId("publication-all"),
                    PublicationSourceType.CREDENTIAL, credential.credentialId(), credential.content(),
                    new PublicationTarget(PublicationTargetType.FILESYSTEM, "target-all"),
                    PublicationStatus.PENDING, 0L, Optional.empty(), now, now, Optional.empty(), Optional.empty());
            store.putCa(ca);
            store.putCredential(credential);
            store.putRequest(request);
            RevocationRecord revocation = store.transitionRevocation(new RevocationCommand.RevokePermanently(
                    credential.credentialId(), RevocationReason.KEY_COMPROMISE, attributes), now);
            store.putStatusObject(status);
            store.createPublicationRecord(publication);
            importProfile(store, profile, now);
            store.activateProfile(profile.profileId(), 1);
            store.putPolicyTrace(trace);
            store.putWorkflowState(workflow);

            assertEquals(ca.caId(), store.getCa(ca.caId()).orElseThrow().caId());
            assertEquals(credential.credentialId(),
                    store.getCredential(credential.credentialId()).orElseThrow().credentialId());
            assertEquals(request.requestId(), store.getRequest(request.requestId()).orElseThrow().requestId());
            assertEquals(revocation.credentialId(),
                    store.getRevocation(revocation.credentialId()).orElseThrow().credentialId());
            assertEquals(status.statusObjectId(),
                    store.getStatusObject(status.statusObjectId()).orElseThrow().statusObjectId());
            assertEquals(publication.publicationId(),
                    store.getPublicationRecord(publication.publicationId()).orElseThrow().publicationId());
            assertEquals(profile, store.requireActiveProfile(profile.profileId()).profile());
            assertEquals(trace, store.getPolicyTrace(trace.decisionId()).orElseThrow());
            assertEquals(workflow.opId(), store.getWorkflowState(workflow.opId()).orElseThrow().opId());
        }

        System.out.println("...schemas round-tripped=9; signing schema covered separately");
        System.out.println("...ok");
    }

    @Test
    void statusAuthorityIsAtomicDurableWriteOnceAndProtectsContent() throws Exception {
        System.out.println("statusAuthorityIsAtomicDurableWriteOnceAndProtectsContent");
        Path root = tmp.resolve("store-status-authority");
        PkiId firstId = new PkiId("crl:status-authority-one");
        PkiId secondId = new PkiId("crl:status-authority-two");
        DurableContentReference firstReference;
        StatusObject firstStatus;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            firstReference = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(store.stagedContent(), Encoding.DER,
                    new byte[] { 1, 2, 3 });
            firstStatus = new StatusObject(firstId, new FormatId("fmt-x509"), new PkiId("ca-status"),
                    StatusObjectType.CRL, Instant.EPOCH, Optional.empty(), firstReference,
                    TestObjects.emptyAttributes());
            store.putStatusObject(firstStatus);
            assertThrows(IllegalStateException.class, () -> store.putStatusObject(firstStatus));
            assertThrows(IOException.class, () -> store.stagedContent().retireUnownedContent(firstReference));

            DurableContentReference conflictingReference = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                    store.stagedContent(), Encoding.DER, new byte[] { 7, 8, 9 });
            StatusObject conflicting = new StatusObject(firstId, new FormatId("fmt-x509"),
                    new PkiId("ca-status"), StatusObjectType.CRL, Instant.EPOCH.plusSeconds(2L), Optional.empty(),
                    conflictingReference, TestObjects.emptyAttributes());
            assertThrows(IllegalStateException.class, () -> store.putStatusObject(conflicting));
            assertEquals(firstReference, store.getStatusObject(firstId).orElseThrow().content());
            store.stagedContent().retireUnownedContent(conflictingReference);

            DurableContentReference secondReference = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                    store.stagedContent(), Encoding.DER, new byte[] { 4, 5, 6 });
            store.putStatusObject(new StatusObject(secondId, new FormatId("fmt-x509"), new PkiId("ca-status"),
                    StatusObjectType.CRL, Instant.EPOCH.plusSeconds(1L), Optional.empty(), secondReference,
                    TestObjects.emptyAttributes()));
            assertEquals(2, store.listStatusObjects(new PkiId("ca-status")).size());
            try (zeroecho.pki.api.publication.PublicationCursor cursor = store.openPublicationRecords()) {
                assertTrue(cursor.next(CancellationSignal.NONE).isEmpty());
            }
            assertFalse(Files.exists(root.resolve("staged-content").resolve(firstReference.contentId() + ".owners")));
        }

        PkiId legacyId = new PkiId("crl:legacy-distinct");
        StatusObject legacy = new StatusObject(legacyId, firstStatus.formatId(), firstStatus.issuerCaId(),
                firstStatus.type(), firstStatus.thisUpdate(), firstStatus.nextUpdate(), firstReference,
                firstStatus.attributes());
        Path obsolete = root.resolve("status").resolve("by-id").resolve(FsUtil.safeId(legacyId) + ".bin");
        Files.createDirectories(obsolete.getParent());
        Files.write(obsolete, FsCodec.encode(FsCodec.STATUS_OBJECT, legacy));
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertEquals(firstId, reopened.getStatusObject(firstId).orElseThrow().statusObjectId());
            assertEquals(secondId, reopened.getStatusObject(secondId).orElseThrow().statusObjectId());
            assertTrue(reopened.getStatusObject(legacyId).isEmpty());
            assertEquals(2, reopened.listStatusObjects(new PkiId("ca-status")).size());
            assertThrows(IOException.class, () -> reopened.stagedContent().retireUnownedContent(firstReference));
        }
        System.out.println("...statusRecords=2");
        System.out.println("statusAuthorityIsAtomicDurableWriteOnceAndProtectsContent...ok");
    }

    @Test
    void statusRecoveryRejectsRecordOwnerAsymmetry() throws Exception {
        System.out.println("statusRecoveryRejectsRecordOwnerAsymmetry");
        Path missingOwnerRoot = tmp.resolve("store-status-missing-owner");
        PkiId missingOwnerId = persistFixtureStatus(missingOwnerRoot, "missing-owner").statusObjectId();
        deleteMetadataRecord(missingOwnerRoot,
                new MetadataKey("io.zeroecho.pki.status-object-owner", missingOwnerId.value()));
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(missingOwnerRoot, FsPkiStoreOptions.defaults()));

        Path orphanOwnerRoot = tmp.resolve("store-status-orphan-owner");
        PkiId orphanOwnerId = persistFixtureStatus(orphanOwnerRoot, "orphan-owner").statusObjectId();
        deleteMetadataRecord(orphanOwnerRoot,
                new MetadataKey("io.zeroecho.pki.status-object-record", orphanOwnerId.value()));
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(orphanOwnerRoot, FsPkiStoreOptions.defaults()));
        System.out.println("...rejected=missing-owner,orphan-owner");
        System.out.println("statusRecoveryRejectsRecordOwnerAsymmetry...ok");
    }

    @Test
    void statusRecoveryRejectsMalformedOrMismatchedMetadata() throws Exception {
        System.out.println("statusRecoveryRejectsMalformedOrMismatchedMetadata");
        Path wrongIdentityRoot = tmp.resolve("store-status-wrong-owner-id");
        StatusObject wrongIdentity = persistFixtureStatus(wrongIdentityRoot, "wrong-owner-id");
        replaceMetadataRecord(wrongIdentityRoot,
                new MetadataKey("io.zeroecho.pki.status-object-owner", wrongIdentity.statusObjectId().value()),
                encodeStatusOwner("crl:different", wrongIdentity.content()));
        assertStoreOpenFails(wrongIdentityRoot);

        Path wrongReferenceRoot = tmp.resolve("store-status-wrong-owner-reference");
        StatusObject wrongReference;
        DurableContentReference alternate;
        try (FilesystemPkiStore store = new FilesystemPkiStore(wrongReferenceRoot, FsPkiStoreOptions.defaults())) {
            DurableContentReference original = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                    store.stagedContent(), Encoding.DER, new byte[] { 1 });
            wrongReference = new StatusObject(new PkiId("crl:wrong-owner-reference"), new FormatId("fmt-x509"),
                    new PkiId("ca-status"), StatusObjectType.CRL, Instant.EPOCH, Optional.empty(), original,
                    TestObjects.emptyAttributes());
            store.putStatusObject(wrongReference);
            alternate = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(store.stagedContent(), Encoding.DER,
                    new byte[] { 2 });
        }
        replaceMetadataRecord(wrongReferenceRoot,
                new MetadataKey("io.zeroecho.pki.status-object-owner", wrongReference.statusObjectId().value()),
                encodeStatusOwner(wrongReference.statusObjectId().value(), alternate));
        assertStoreOpenFails(wrongReferenceRoot);

        Path malformedRecordRoot = tmp.resolve("store-status-malformed-record");
        StatusObject malformedRecord = persistFixtureStatus(malformedRecordRoot, "malformed-record");
        replaceMetadataRecord(malformedRecordRoot,
                new MetadataKey("io.zeroecho.pki.status-object-record", malformedRecord.statusObjectId().value()),
                new byte[] { 1, 2, 3 });
        assertStoreOpenFails(malformedRecordRoot);

        Path malformedOwnerRoot = tmp.resolve("store-status-malformed-owner");
        StatusObject malformedOwner = persistFixtureStatus(malformedOwnerRoot, "malformed-owner");
        replaceMetadataRecord(malformedOwnerRoot,
                new MetadataKey("io.zeroecho.pki.status-object-owner", malformedOwner.statusObjectId().value()),
                new byte[] { 4, 5, 6 });
        assertStoreOpenFails(malformedOwnerRoot);
        System.out.println("...rejected=identity,reference,record,owner");
        System.out.println("statusRecoveryRejectsMalformedOrMismatchedMetadata...ok");
    }

    @Test
    void statusRecoveryRejectsMissingOrCorruptContentAndSidecarRepair() throws Exception {
        System.out.println("statusRecoveryRejectsMissingOrCorruptContentAndSidecarRepair");
        Path missingMetadataRoot = tmp.resolve("store-status-missing-meta");
        StatusObject missingMetadata = persistFixtureStatus(missingMetadataRoot, "missing-meta");
        Files.delete(missingMetadataRoot.resolve("staged-content")
                .resolve(missingMetadata.content().contentId() + ".meta"));
        assertStoreOpenFails(missingMetadataRoot);

        Path missingContentRoot = tmp.resolve("store-status-missing-content");
        StatusObject missingContent = persistFixtureStatus(missingContentRoot, "missing-content");
        Files.delete(missingContentRoot.resolve("staged-content")
                .resolve(missingContent.content().contentId() + ".content"));
        assertStoreOpenFails(missingContentRoot);

        Path corruptContentRoot = tmp.resolve("store-status-corrupt-content");
        StatusObject corruptContent = persistFixtureStatus(corruptContentRoot, "corrupt-content");
        Files.write(corruptContentRoot.resolve("staged-content")
                .resolve(corruptContent.content().contentId() + ".content"),
                new byte[Math.toIntExact(corruptContent.content().length())]);
        assertStoreOpenFails(corruptContentRoot);

        Path sidecarRoot = tmp.resolve("store-status-sidecar-repair");
        StatusObject sidecar = persistFixtureStatus(sidecarRoot, "sidecar-repair");
        deleteMetadataRecord(sidecarRoot,
                new MetadataKey("io.zeroecho.pki.status-object-owner", sidecar.statusObjectId().value()));
        writeStatusSidecar(sidecarRoot, sidecar);
        assertStoreOpenFails(sidecarRoot);
        System.out.println("...rejected=missing-meta,missing-content,corrupt-content,sidecar-repair");
        System.out.println("statusRecoveryRejectsMissingOrCorruptContentAndSidecarRepair...ok");
    }

    @Test
    void statusCommitFaultsPreserveAtomicityAndUnknownRecovery() throws Exception {
        System.out.println("statusCommitFaultsPreserveAtomicityAndUnknownRecovery");
        Path beforeCommitRoot = tmp.resolve("store-status-before-commit-failure");
        try (FilesystemPkiStore store = new FilesystemPkiStore(beforeCommitRoot, FsPkiStoreOptions.defaults())) {
            DurableContentReference reference = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                    store.stagedContent(), Encoding.DER, new byte[] { 3, 4 });
            StatusObject status = new StatusObject(new PkiId("crl:before-commit"), new FormatId("fmt-x509"),
                    new PkiId("ca-status"), StatusObjectType.CRL, Instant.EPOCH, Optional.empty(), reference,
                    TestObjects.emptyAttributes());
            FilesystemPkiStore.installStatusCommitFault(
                    FilesystemPkiStore.StatusCommitFaultPoint.BEFORE_COMMIT);
            try {
                assertThrows(IllegalStateException.class, () -> store.putStatusObject(status));
            } finally {
                FilesystemPkiStore.clearStatusCommitFault();
            }
            assertTrue(store.getStatusObject(status.statusObjectId()).isEmpty());
            store.stagedContent().retireUnownedContent(reference);
            assertThrows(IOException.class, () -> store.stagedContent().openContent(reference));
        }

        Path unknownRoot = tmp.resolve("store-status-after-commit-unknown");
        PkiId unknownId = new PkiId("crl:after-commit-unknown");
        DurableContentReference committedReference;
        try (FilesystemPkiStore store = new FilesystemPkiStore(unknownRoot, FsPkiStoreOptions.defaults())) {
            committedReference = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(store.stagedContent(),
                    Encoding.DER, new byte[] { 5, 6 });
            StatusObject status = new StatusObject(unknownId, new FormatId("fmt-x509"),
                    new PkiId("ca-status"), StatusObjectType.CRL, Instant.EPOCH, Optional.empty(),
                    committedReference, TestObjects.emptyAttributes());
            FilesystemPkiStore.installStatusCommitFault(
                    FilesystemPkiStore.StatusCommitFaultPoint.AFTER_COMMIT_AS_UNKNOWN);
            try {
                PkiException unknown = assertThrows(PkiException.class, () -> store.putStatusObject(status));
                assertTrue(unknown.getMessage().contains("STORE_DURABILITY_UNCONFIRMED"));
            } finally {
                FilesystemPkiStore.clearStatusCommitFault();
            }
            assertThrows(PkiException.class, () -> store.getStatusObject(unknownId));
            assertThrows(IOException.class, () -> store.stagedContent().retireUnownedContent(committedReference));
        } finally {
            FilesystemPkiStore.clearStatusCommitFault();
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(unknownRoot, FsPkiStoreOptions.defaults())) {
            assertEquals(committedReference,
                    reopened.getStatusObject(unknownId).orElseThrow().content());
        }
        System.out.println("...faults=before-commit,after-commit-unknown");
        System.out.println("statusCommitFaultsPreserveAtomicityAndUnknownRecovery...ok");
    }

    private StatusObject persistFixtureStatus(Path root, String suffix) throws Exception {
        PkiId statusId = new PkiId("crl:" + suffix);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            DurableContentReference reference = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                    store.stagedContent(), Encoding.DER, suffix.getBytes(StandardCharsets.US_ASCII));
            StatusObject status = new StatusObject(statusId, new FormatId("fmt-x509"), new PkiId("ca-status"),
                    StatusObjectType.CRL, Instant.EPOCH, Optional.empty(), reference, TestObjects.emptyAttributes());
            store.putStatusObject(status);
            return status;
        }
    }

    private static void deleteMetadataRecord(Path root, MetadataKey key) throws Exception {
        FsPaths paths = new FsPaths(root);
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.open(
                paths.transactionalMetadataRoot())) {
            long revision;
            try (MetadataSnapshot snapshot = metadata.snapshot();
                    MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
                revision = record.recordRevision();
            }
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                transaction.delete(key, revision);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
        }
    }

    private static void replaceMetadataRecord(Path root, MetadataKey key, byte[] value) throws Exception {
        FsPaths paths = new FsPaths(root);
        try (SegmentedTransactionalMetadataStore metadata = SegmentedTransactionalMetadataStore.open(
                paths.transactionalMetadataRoot())) {
            long revision;
            try (MetadataSnapshot snapshot = metadata.snapshot();
                    MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
                revision = record.recordRevision();
            }
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                transaction.replace(key, revision, byteContent(value), CancellationSignal.NONE);
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
        }
    }

    private static RepeatableContent byteContent(byte[] value) {
        byte[] immutable = value.clone();
        return new RepeatableContent() {
            @Override
            public InputStream openStream() {
                return new ByteArrayInputStream(immutable);
            }

            @Override
            public OptionalLong length() {
                return OptionalLong.of(immutable.length);
            }

            @Override
            public String contentId() {
                return "test-status-metadata";
            }

            @Override
            public void close() {
                // Immutable in-memory test content owns no external resource.
            }
        };
    }

    private static byte[] encodeStatusOwner(String ownerId, DurableContentReference reference) {
        byte[][] fields = {
                DurableContentOwner.Category.STATUS_OBJECT_RECORD.name().getBytes(StandardCharsets.US_ASCII),
                ownerId.getBytes(StandardCharsets.UTF_8), reference.storeId().getBytes(StandardCharsets.UTF_8),
                reference.contentId().getBytes(StandardCharsets.UTF_8),
                reference.encoding().name().getBytes(StandardCharsets.US_ASCII),
                reference.sha256().getBytes(StandardCharsets.US_ASCII),
                reference.lifecycle().name().getBytes(StandardCharsets.US_ASCII)
        };
        int size = Integer.BYTES + Long.BYTES;
        for (byte[] field : fields) {
            size = Math.addExact(size, Math.addExact(Integer.BYTES, field.length));
        }
        ByteBuffer output = ByteBuffer.allocate(size);
        output.putInt(1);
        for (byte[] field : fields) {
            output.putInt(field.length).put(field);
        }
        output.putLong(reference.length());
        return output.array();
    }

    private static void writeStatusSidecar(Path root, StatusObject status) throws IOException {
        Path owners = root.resolve("staged-content").resolve(status.content().contentId() + ".owners");
        DurableContentOwner owner = new DurableContentOwner(DurableContentOwner.Category.STATUS_OBJECT_RECORD,
                status.statusObjectId().value());
        try (DataOutputStream output = new DataOutputStream(Files.newOutputStream(owners))) {
            output.writeByte(2);
            output.writeUTF(status.content().contentId());
            output.writeInt(1);
            output.writeUTF(owner.canonicalForm());
        }
    }

    private static void assertStoreOpenFails(Path root) {
        assertThrows(IllegalStateException.class, () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
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
                    ca1.issuerIds(), ca1.currentIssuanceIssuerId(), ca1.issuanceChainPathId());
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
    void caKeysetPageUsesCanonicalIdentityRatherThanFilesystemEncoding() throws Exception {
        System.out.println("caKeysetPageUsesCanonicalIdentityRatherThanFilesystemEncoding");
        Path root = tmp.resolve("store-ca-keyset-page");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            CaRecord first = TestObjects.minimalCaRecord(store, "ca:z", CaState.ACTIVE);
            CaRecord second = TestObjects.minimalCaRecord(store, "ca:zz", CaState.ACTIVE);
            store.putCa(first);
            store.putCa(second);
            assertEquals(List.of(first.caId()), store.listCasPage(Optional.empty(), 1).stream()
                    .map(CaRecord::caId).toList());
            assertEquals(List.of(second.caId()), store.listCasPage(Optional.of(first.caId()), 1).stream()
                    .map(CaRecord::caId).toList());
            System.out.println("...after=" + first.caId() + " next=" + second.caId());
        }
        System.out.println("caKeysetPageUsesCanonicalIdentityRatherThanFilesystemEncoding...ok");
    }

    @Test
    void caReferencesRequireValidStandaloneCredentialsAndPreserveOrder() throws Exception {
        System.out.println("caReferencesRequireValidStandaloneCredentialsAndPreserveOrder");
        Path root = tmp.resolve("store-ca-authority");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            CaRecord ordered = TestObjects.minimalCaRecord(store, "ca-ordered", CaState.ACTIVE);
            store.putCa(ordered);

            assertEquals(ordered.issuerIds(), store.getCa(ordered.caId()).orElseThrow().issuerIds());
            PkiId missingIssuer = new PkiId("issuer-missing");
            CaRecord missing = new CaRecord(new PkiId("ca-missing"), CaKind.ROOT, CaState.ACTIVE,
                    new KeyRef("key-missing"), new SubjectRef("CN=Missing"),
                    List.of(missingIssuer), missingIssuer, new PkiId("path-missing"));
            assertThrows(IllegalStateException.class, () -> store.putCa(missing));

            Credential selected = store.getCredential(store.getIssuerGeneration(
                    ordered.currentIssuanceIssuerId()).orElseThrow().credentialId()).orElseThrow();
            Files.write(root.resolve("staged-content").resolve(selected.content().contentId() + ".content"),
                    new byte[] { 9, 9, 9 });
            assertThrows(IllegalStateException.class, () -> store.getCa(ordered.caId()));
            assertThrows(IllegalStateException.class, store::listCas);
        }
        System.out.println("caReferencesRequireValidStandaloneCredentialsAndPreserveOrder...ok");
    }

    @Test
    void issuerSerialIndexSeparatesEqualSerialsAndRecoversOnRestart() throws Exception {
        System.out.println("issuerSerialIndexSeparatesEqualSerialsAndRecoversOnRestart");
        Path root = tmp.resolve("store-issuer-serial-index");
        PkiId firstIssuer;
        PkiId secondIssuer;
        PkiId firstCredential;
        PkiId secondCredential;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            CaRecord first = TestObjects.minimalCaRecord(store, "ca-index-one", CaState.ACTIVE);
            CaRecord second = TestObjects.minimalCaRecord(store, "ca-index-two", CaState.ACTIVE);
            store.putCa(first);
            store.putCa(second);
            firstIssuer = first.currentIssuanceIssuerId();
            secondIssuer = second.currentIssuanceIssuerId();
            firstCredential = store.getIssuerGeneration(firstIssuer).orElseThrow().credentialId();
            secondCredential = store.getIssuerGeneration(secondIssuer).orElseThrow().credentialId();
            assertEquals(firstCredential, store.getCredentialByIssuerAndSerial(firstIssuer, BigInteger.ONE)
                    .orElseThrow().credentialId());
            assertEquals(secondCredential, store.getCredentialByIssuerAndSerial(secondIssuer, BigInteger.ONE)
                    .orElseThrow().credentialId());
            assertTrue(store.getCredentialByIssuerAndSerial(firstIssuer, BigInteger.TWO).isEmpty());
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertEquals(firstCredential, reopened.getCredentialByIssuerAndSerial(firstIssuer, BigInteger.ONE)
                    .orElseThrow().credentialId());
            assertEquals(secondCredential, reopened.getCredentialByIssuerAndSerial(secondIssuer, BigInteger.ONE)
                    .orElseThrow().credentialId());
        }
        System.out.println("...same-serial-separated=true");
        System.out.println("issuerSerialIndexSeparatesEqualSerialsAndRecoversOnRestart...ok");
    }

    @Test
    void oldStoreVersionIsRejected() throws Exception {
        System.out.println("oldStoreVersionIsRejected");
        Path root = tmp.resolve("store-old-version");
        Files.createDirectories(root);
        Files.writeString(root.resolve(FsPaths.VERSION_FILE), "v10");

        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
        System.out.println("oldStoreVersionIsRejected...ok");
    }

    @Test
    void exactVersionMarkerReopensNormally() throws Exception {
        Path root = tmp.resolve("store-exact-version");
        try (FilesystemPkiStore ignored = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            // Initial creation writes the canonical marker.
        }
        assertArrayEquals(FilesystemPkiStore.CURRENT_STORE_VERSION.getBytes(StandardCharsets.US_ASCII),
                Files.readAllBytes(root.resolve(FsPaths.VERSION_FILE)));
        try (FilesystemPkiStore ignored = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            // Exact bytes remain accepted on reopen.
        }
    }

    @Test
    void initializationCrashMatrixLeavesUnsupportedUnversionedRootWithoutRetryMutation()
            throws Exception {
        for (FilesystemPkiStore.InitializationFaultPoint point
                : FilesystemPkiStore.InitializationFaultPoint.values()) {
            Path root = tmp.resolve("store-init-" + point);
            FilesystemPkiStore.installInitializationFault(point);
            try {
                assertThrows(IllegalStateException.class,
                        () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
            } finally {
                FilesystemPkiStore.clearInitializationFault();
            }
            assertUnsupportedUnversionedWithoutMutation(root);
        }

        for (DurableMetadataFiles.FaultPoint point : List.of(
                DurableMetadataFiles.FaultPoint.TEMP_CREATE,
                DurableMetadataFiles.FaultPoint.WRITE,
                DurableMetadataFiles.FaultPoint.FILE_FORCE,
                DurableMetadataFiles.FaultPoint.MOVE,
                DurableMetadataFiles.FaultPoint.DIRECTORY_FORCE_AFTER_MOVE)) {
            Path root = tmp.resolve("store-init-namespace-" + point);
            DurableMetadataFiles.installFault(current -> {
                if (current == point) {
                    throw new IOException("injected namespace publication failure");
                }
            });
            try {
                assertThrows(IllegalStateException.class,
                        () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
            } finally {
                DurableMetadataFiles.clearFault();
            }
            assertUnsupportedUnversionedWithoutMutation(root);
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("noncanonicalVersionMarkers")
    void noncanonicalVersionMarkerIsRejectedBeforeMutation(String fixtureName, byte[] marker) throws Exception {
        Path root = tmp.resolve("store-version-" + fixtureName);
        Files.createDirectories(root);
        Path version = root.resolve(FsPaths.VERSION_FILE);
        Path sentinel = root.resolve("sentinel.bin");
        Files.write(version, marker);
        Files.write(sentinel, new byte[] { 4, 5, 6 });

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));

        assertEquals("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED", failure.getMessage());
        assertFalse(failure.toString().contains(root.toString()));
        assertEquals(Set.of(FsPaths.VERSION_FILE, "sentinel.bin"), directEntryNames(root));
        assertArrayEquals(marker, Files.readAllBytes(version));
        assertArrayEquals(new byte[] { 4, 5, 6 }, Files.readAllBytes(sentinel));
    }

    @Test
    void sparseOversizedVersionMarkerIsRejectedBeforeMutation() throws Exception {
        Path root = tmp.resolve("store-version-sparse-oversized");
        Files.createDirectories(root);
        Path version = root.resolve(FsPaths.VERSION_FILE);
        Path sentinel = root.resolve("sentinel.bin");
        long lastOffset = 1024L * 1024L;
        try (FileChannel channel = FileChannel.open(version, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            channel.write(ByteBuffer.wrap(
                    FilesystemPkiStore.CURRENT_STORE_VERSION.getBytes(StandardCharsets.US_ASCII)));
            channel.position(lastOffset);
            channel.write(ByteBuffer.wrap(new byte[] { 0x7f }));
        }
        Files.write(sentinel, new byte[] { 7, 8, 9 });
        long originalSize = Files.size(version);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));

        assertEquals("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED", failure.getMessage());
        assertFalse(failure.toString().contains(root.toString()));
        assertEquals(Set.of(FsPaths.VERSION_FILE, "sentinel.bin"), directEntryNames(root));
        assertEquals(lastOffset + 1L, originalSize);
        assertEquals(originalSize, Files.size(version));
        try (FileChannel channel = FileChannel.open(version, StandardOpenOption.READ)) {
            ByteBuffer prefix = ByteBuffer.allocate(FilesystemPkiStore.CURRENT_STORE_VERSION.length());
            assertEquals(prefix.capacity(), channel.read(prefix));
            assertArrayEquals(FilesystemPkiStore.CURRENT_STORE_VERSION.getBytes(StandardCharsets.US_ASCII),
                    prefix.array());
            ByteBuffer suffix = ByteBuffer.allocate(1);
            assertEquals(1, channel.read(suffix, lastOffset));
            assertEquals(0x7f, Byte.toUnsignedInt(suffix.array()[0]));
        }
        assertArrayEquals(new byte[] { 7, 8, 9 }, Files.readAllBytes(sentinel));
    }

    @Test
    void oldV6RootIsRejectedBeforeLockOrDirectoryMutation() throws Exception {
        Path root = tmp.resolve("store-incomplete-v6");
        Files.createDirectories(root);
        Files.writeString(root.resolve(FsPaths.VERSION_FILE), "v6", StandardCharsets.US_ASCII);
        Files.write(root.resolve("sentinel.bin"), new byte[] { 4, 5, 6 });
        List<String> before;
        try (java.util.stream.Stream<Path> entries = Files.list(root)) {
            before = entries.map(path -> path.getFileName().toString()).sorted().toList();
        }
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
        assertEquals("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED", failure.getMessage());
        List<String> after;
        try (java.util.stream.Stream<Path> entries = Files.list(root)) {
            after = entries.map(path -> path.getFileName().toString()).sorted().toList();
        }
        assertEquals(before, after);
        assertEquals("v6", Files.readString(root.resolve(FsPaths.VERSION_FILE), StandardCharsets.US_ASCII));
        assertArrayEquals(new byte[] { 4, 5, 6 }, Files.readAllBytes(root.resolve("sentinel.bin")));
    }

    @Test
    void snapshotReconstructsIssuerGenerationsWithNewTargetReferences() throws Exception {
        System.out.println("snapshotReconstructsIssuerGenerationsWithNewTargetReferences");
        Path root = tmp.resolve("store-snapshot-authority");
        Path snapshot = tmp.resolve("snapshot-authority");
        FsPkiStoreOptions options = nonStrictSnapshotOptions();
        PkiId credentialId;
        String sourceContentId;
        try (FilesystemPkiStore source = new FilesystemPkiStore(root, options)) {
            CaRecord first = TestObjects.minimalCaRecord(source, "ca-shared-one", CaState.ACTIVE);
            CaRecord second = TestObjects.minimalCaRecord(source, "ca-shared-two", CaState.ACTIVE);
            source.putCa(first);
            source.putCa(second);
            credentialId = source.getIssuerGeneration(first.currentIssuanceIssuerId()).orElseThrow().credentialId();
            sourceContentId = source.getCredential(credentialId).orElseThrow().content().contentId();
            source.exportSnapshot(snapshot, Instant.now());
        }

        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshot, options)) {
            assertEquals(2, restored.listCas().size());
            Credential credential = restored.getCredential(credentialId).orElseThrow();
            assertFalse(sourceContentId.equals(credential.content().contentId()));
            CaRecord restoredAuthority = restored.getCa(new PkiId("ca-shared-one")).orElseThrow();
            assertEquals(credentialId, restored.getIssuerGeneration(
                    restoredAuthority.currentIssuanceIssuerId()).orElseThrow().credentialId());
        }
        assertFalse(Files.exists(snapshot.resolve("credentials")));
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".content")));
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".meta")));
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".owners")));
        System.out.println("snapshotReconstructsIssuerGenerationsWithNewTargetReferences...ok");
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
            assertTrue(restored.getCredential(restored.getIssuerGeneration(
                    ca.currentIssuanceIssuerId()).orElseThrow().credentialId()).isPresent());
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
            assertFalse(sourceContentId.equals(status.content().contentId()));
            assertFalse(credential.content().contentId().equals(status.content().contentId()));
            assertArrayEquals(expected, zeroecho.pki.testkit.PkiTestRuntime.readContent(restored, credential.content()));
            assertArrayEquals(expected, zeroecho.pki.testkit.PkiTestRuntime.readContent(restored, status.content()));
        }
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".content")));
        assertFalse(Files.exists(snapshot.resolve("staged-content").resolve(sourceContentId + ".meta")));
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
            Files.delete(root.resolve("SIGNING_NAMESPACE"));

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
    void snapshotFailsClosedForMissingIssuerAuthorityInEveryMode() throws Exception {
        System.out.println("snapshotFailsClosedForMissingIssuerAuthorityInEveryMode");
        Path root = tmp.resolve("store-snapshot-inconsistent");
        Path strictSnapshot = tmp.resolve("snapshot-inconsistent-strict");
        Path nonStrictSnapshot = tmp.resolve("snapshot-inconsistent-nonstrict");
        FsPkiStoreOptions nonStrict = nonStrictSnapshotOptions();
        try (FilesystemPkiStore source = new FilesystemPkiStore(root, nonStrict)) {
            CaRecord valid = TestObjects.minimalCaRecord(source, "ca-valid", CaState.ACTIVE);
            CaRecord inconsistent = TestObjects.minimalCaRecord(source, "ca-inconsistent", CaState.ACTIVE);
            source.putCa(valid);
            source.putCa(inconsistent);
            MetadataKey missing = AuthorityMetadataCodec.credentialKey(source.getIssuerGeneration(
                    inconsistent.currentIssuanceIssuerId()).orElseThrow().credentialId());
            try (MetadataSnapshot pinned = source.metadataStore().snapshot();
                    MetadataSnapshot.Record record = pinned.get(missing).orElseThrow();
                    MetadataTransaction transaction = source.metadataStore().beginTransaction()) {
                transaction.delete(missing, record.recordRevision());
                assertEquals(MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }

            FsPkiStoreOptions strict = strictSnapshotOptions();
            assertThrows(IllegalStateException.class,
                    () -> new FsSnapshotExporter(strict).exportSnapshot(source, strictSnapshot, Instant.now()));
            assertFalse(Files.exists(strictSnapshot));

            assertThrows(IllegalStateException.class, () -> source.exportSnapshot(nonStrictSnapshot, Instant.now()));
            assertFalse(Files.exists(nonStrictSnapshot));
        }
        System.out.println("...missing-issuer-authority=rejected");
        System.out.println("snapshotFailsClosedForMissingIssuerAuthorityInEveryMode...ok");
    }

    @Test
    void globalRevocationLogPersistsStreamingHistory() throws Exception {
        System.out.println("globalRevocationLogPersistsStreamingHistory");

        Path root = tmp.resolve("store-revocation-history");
        Path restoredRoot = tmp.resolve("store-revocation-history-snapshot");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();
        PkiId credentialId;

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            Credential credential = TestObjects.minimalCredential(store, "SERIAL-REV", "profile-rev");
            credentialId = credential.credentialId();
            store.putCredential(credential);
            store.transitionRevocation(
                    new RevocationCommand.Hold(credential.credentialId(), TestObjects.emptyAttributes()),
                    Instant.EPOCH.plusSeconds(10L));
            store.transitionRevocation(
                    new RevocationCommand.Unhold(credential.credentialId(), TestObjects.emptyAttributes()),
                    Instant.EPOCH.plusSeconds(11L));

            Optional<RevocationRecord> loaded = store.getRevocation(credential.credentialId());
            assertTrue(loaded.isPresent());
            assertEquals(2L, loaded.get().transition().revision());
            try (zeroecho.pki.spi.store.RevocationSnapshot snapshot = store.openRevocationSnapshot()) {
                assertEquals(2L, snapshot.revision());
            }
            try (zeroecho.pki.spi.store.RevocationHistory history =
                    store.openRevocationHistory(credential.credentialId())) {
                assertTrue(history.next());
                assertEquals(1L, history.current().revision());
                assertTrue(history.next());
                assertEquals(2L, history.current().revision());
                assertFalse(history.next());
            }
            store.exportSnapshot(restoredRoot, Instant.now());
        }
        try (FilesystemPkiStore restored = new FilesystemPkiStore(restoredRoot, options)) {
            assertEquals(RevocationState.CLEAR,
                    restored.getRevocation(credentialId).orElseThrow().transition().state());
            try (zeroecho.pki.spi.store.RevocationHistory history =
                    restored.openRevocationHistory(credentialId)) {
                assertTrue(history.next());
                assertTrue(history.next());
                assertFalse(history.next());
            }
            assertTrue(Files.isRegularFile(new FsPaths(restoredRoot).revocationCurrentIndex()));
            assertFalse(Files.exists(restoredRoot.resolve("revocations").resolve("by-credential")));
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("globalRevocationLogPersistsStreamingHistory...ok");
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
        assertFalse(Files.exists(snapshot.resolve("cas")));
        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshot, options)) {
            assertEquals(1, restored.listCas().size());
        }

        System.out.println("snapshotExportClonesNewRootNonStrict...ok");
    }

    @Test
    @RequiresSymlinkCreation
    void snapshotRejectsTruncatedRevocationAuthorityAndObsoleteSchema() throws Exception {
        System.out.println("snapshotRejectsTruncatedRevocationAuthorityAndObsoleteSchema");
        Path sourceRoot = tmp.resolve("snapshot-revocation-corruption-source");
        Path snapshotRoot = tmp.resolve("snapshot-revocation-corruption-target");
        Path oversizedRoot = tmp.resolve("snapshot-revocation-oversized-marker");
        Path symlinkRoot = tmp.resolve("snapshot-revocation-symlink-marker");
        FsPkiStoreOptions options = nonStrictSnapshotOptions();
        try (FilesystemPkiStore source = new FilesystemPkiStore(sourceRoot, options)) {
            Credential credential = TestObjects.minimalCredential(source, "SERIAL-SNAPSHOT-CORRUPT",
                    "profile-snapshot-corrupt");
            source.putCredential(credential);
            source.transitionRevocation(new RevocationCommand.Hold(
                    credential.credentialId(), TestObjects.emptyAttributes()), Instant.now());
            source.exportSnapshot(snapshotRoot, Instant.now());
            source.exportSnapshot(oversizedRoot, Instant.now());
            source.exportSnapshot(symlinkRoot, Instant.now());
        }
        Path log = new FsPaths(snapshotRoot).revocationTransitionLog();
        try (FileChannel channel = FileChannel.open(log, StandardOpenOption.WRITE)) {
            channel.truncate(Files.size(log) - 1L);
        }
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(snapshotRoot, options));

        Files.writeString(new FsPaths(oversizedRoot).revocationSnapshotBoundary(),
                "12345678901234567890", StandardCharsets.US_ASCII);
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(oversizedRoot, options));

        Path symlinkMarker = new FsPaths(symlinkRoot).revocationSnapshotBoundary();
        Files.delete(symlinkMarker);
        Files.createSymbolicLink(symlinkMarker, new FsPaths(symlinkRoot).revocationTransitionLog());
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(symlinkRoot, options));

        Path obsolete = tmp.resolve("snapshot-obsolete-schema");
        Files.createDirectories(obsolete);
        Files.writeString(obsolete.resolve(FsPaths.VERSION_FILE), "v3", StandardCharsets.US_ASCII);
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(obsolete, options));
        System.out.println("snapshotRejectsTruncatedRevocationAuthorityAndObsoleteSchema...ok");
    }

    @Test
    void stableRevocationViewIsImmutableAndExactCheckpointIsReused() throws Exception {
        System.out.println("stableRevocationViewIsImmutableAndExactCheckpointIsReused");
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                tmp.resolve("stable-revocation-view"), FsPkiStoreOptions.defaults())) {
            Credential credential = TestObjects.minimalCredential(store, "SERIAL-STABLE-VIEW",
                    "profile-stable-view");
            store.putCredential(credential);
            store.transitionRevocation(new RevocationCommand.Hold(
                    credential.credentialId(), TestObjects.emptyAttributes()), Instant.EPOCH.plusSeconds(1L));
            try (zeroecho.pki.spi.store.RevocationSnapshot captured = store.openRevocationSnapshot()) {
                assertEquals(1L, captured.revision());
                store.transitionRevocation(new RevocationCommand.Unhold(
                        credential.credentialId(), TestObjects.emptyAttributes()), Instant.EPOCH.plusSeconds(2L));
                try (zeroecho.pki.spi.store.RevocationSnapshot.Cursor cursor = captured.openCursor()) {
                    assertTrue(cursor.next());
                    assertEquals(RevocationState.HELD, cursor.current().transition().state());
                    assertFalse(cursor.next());
                }
            }
            String generation;
            try (zeroecho.pki.spi.store.RevocationSnapshot current = store.openRevocationSnapshot()) {
                generation = current.snapshotId();
                assertEquals(2L, current.revision());
            }
            try (zeroecho.pki.spi.store.RevocationSnapshot reused = store.openRevocationSnapshot()) {
                assertEquals(generation, reused.snapshotId());
                assertEquals(2L, reused.revision());
            }
        }
        System.out.println("stableRevocationViewIsImmutableAndExactCheckpointIsReused...ok");
    }

    @Test
    void concurrentStableViewAndStoreCloseFinishDeterministically() throws Exception {
        System.out.println("concurrentStableViewAndStoreCloseFinishDeterministically");
        FilesystemPkiStore store = new FilesystemPkiStore(
                tmp.resolve("concurrent-revocation-close"), FsPkiStoreOptions.defaults());
        zeroecho.pki.spi.store.RevocationSnapshot view = null;
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Credential credential = TestObjects.minimalCredential(store, "SERIAL-CONCURRENT-CLOSE",
                    "profile-concurrent-close");
            store.putCredential(credential);
            store.transitionRevocation(new RevocationCommand.Hold(
                    credential.credentialId(), TestObjects.emptyAttributes()), Instant.now());
            view = store.openRevocationSnapshot();
            zeroecho.pki.spi.store.RevocationSnapshot captured = view;
            CountDownLatch start = new CountDownLatch(1);
            Future<?> viewClose = executor.submit(() -> {
                start.await();
                captured.close();
                return null;
            });
            Future<?> storeClose = executor.submit(() -> {
                start.await();
                store.close();
                return null;
            });
            start.countDown();
            viewClose.get(5L, TimeUnit.SECONDS);
            storeClose.get(5L, TimeUnit.SECONDS);
            view = null;
        } finally {
            if (view != null) {
                view.close();
            }
            store.close();
            executor.shutdownNow();
        }
        System.out.println("concurrentStableViewAndStoreCloseFinishDeterministically...ok");
    }

    @Test
    void committedTransitionSurvivesDerivedIndexUpdateFailureAndConcurrentRecovery() throws Exception {
        System.out.println("committedTransitionSurvivesDerivedIndexUpdateFailureAndConcurrentRecovery");
        AtomicLong faultCalls = new AtomicLong();
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                tmp.resolve("revocation-derived-failure"), FsPkiStoreOptions.defaults(),
                java.time.Clock.systemUTC(), () -> {
                    if (faultCalls.getAndIncrement() == 0L) {
                        throw new IOException("Injected derived revocation-index update failure");
                    }
                })) {
            Credential credential = TestObjects.minimalCredential(store, "SERIAL-DERIVED-FAILURE",
                    "profile-derived-failure");
            store.putCredential(credential);
            RevocationRecord committed = store.transitionRevocation(new RevocationCommand.Hold(
                    credential.credentialId(), TestObjects.emptyAttributes()), Instant.now());
            assertEquals(1L, committed.transition().revision());

            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                CountDownLatch start = new CountDownLatch(1);
                Future<Optional<RevocationRecord>> first = executor.submit(() -> {
                    start.await();
                    return store.getRevocation(credential.credentialId());
                });
                Future<Optional<RevocationRecord>> second = executor.submit(() -> {
                    start.await();
                    return store.getRevocation(credential.credentialId());
                });
                start.countDown();
                assertEquals(RevocationState.HELD,
                        first.get(5L, TimeUnit.SECONDS).orElseThrow().transition().state());
                assertEquals(RevocationState.HELD,
                        second.get(5L, TimeUnit.SECONDS).orElseThrow().transition().state());
            } finally {
                executor.shutdownNow();
            }
        }
        System.out.println("committedTransitionSurvivesDerivedIndexUpdateFailureAndConcurrentRecovery...ok");
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

    private static Stream<Arguments> noncanonicalVersionMarkers() {
        return Stream.of(
                Arguments.of("prefix-whitespace", " v8".getBytes(StandardCharsets.US_ASCII)),
                Arguments.of("suffix-whitespace", "v8 ".getBytes(StandardCharsets.US_ASCII)),
                Arguments.of("bom-prefix", new byte[] { (byte) 0xef, (byte) 0xbb, (byte) 0xbf, 'v', '8' }),
                Arguments.of("trailing-byte", "v8x".getBytes(StandardCharsets.US_ASCII)),
                Arguments.of("mismatch", "v7".getBytes(StandardCharsets.US_ASCII)));
    }

    private static Set<String> directEntryNames(Path root) throws IOException {
        try (Stream<Path> entries = Files.list(root)) {
            return entries.map(path -> path.getFileName().toString()).collect(Collectors.toUnmodifiableSet());
        }
    }

    private static void assertUnsupportedUnversionedWithoutMutation(Path root)
            throws Exception {
        assertTrue(Files.isDirectory(root));
        assertFalse(Files.exists(root.resolve(FsPaths.VERSION_FILE)));
        assertFalse(directEntryNames(root).isEmpty());
        byte[] before = rootFingerprint(root);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));

        assertEquals("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED",
                failure.getMessage());
        assertFalse(failure.toString().contains(root.toString()));
        assertArrayEquals(before, rootFingerprint(root));
    }

    private static byte[] rootFingerprint(Path root) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException failure) {
            throw new AssertionError(failure);
        }
        byte[] buffer = new byte[8192];
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted().toList()) {
                if (path.equals(root)) {
                    continue;
                }
                digest.update(Files.isDirectory(path) ? (byte) 1 : (byte) 2);
                digest.update(root.relativize(path).toString().getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                if (Files.isRegularFile(path)) {
                    try (InputStream input = Files.newInputStream(path)) {
                        int read;
                        while ((read = input.read(buffer)) >= 0) {
                            if (read > 0) {
                                digest.update(buffer, 0, read);
                            }
                        }
                    }
                }
            }
        }
        return digest.digest();
    }

    private static FsPkiStoreOptions nonStrictSnapshotOptions() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        return new FsPkiStoreOptions(defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), false,
                defaults.signingOperationHorizon(), defaults.signingIdPermittedSkew(),
                defaults.signingMaximumGroupSize(), defaults.signingResidentIndexBudgetBytes(),
                defaults.signingCompactionTransientBudgetBytes(), defaults.initialCrlNumber(), false);
    }

    private static FsPkiStoreOptions strictSnapshotOptions() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        return new FsPkiStoreOptions(defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), true,
                defaults.signingOperationHorizon(), defaults.signingIdPermittedSkew(),
                defaults.signingMaximumGroupSize(), defaults.signingResidentIndexBudgetBytes(),
                defaults.signingCompactionTransientBudgetBytes(), defaults.initialCrlNumber(), false);
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
                profile.subjectPolicy(), profile.leafPolicy(),
                zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.standardOnly(),
                Optional.of(testConfirmationPolicy()));
        byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(canonical);
        CertificateProfileRef reference = new CertificateProfileRef(profile.profileId(), 1, hash);
        store.importProfileVersion(new ImportedCertificateProfileVersion(reference,
                CertificateProfileDefinition.SCHEMA_VERSION, definition, canonical, importedAt));
    }

    private static zeroecho.pki.api.confirmation.CredentialConfirmationPolicy testConfirmationPolicy() {
        return new zeroecho.pki.api.confirmation.CredentialConfirmationPolicy(
                zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy.OWNER_ONLY,
                Duration.ofHours(24L), new zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef(
                        "zeroecho.signature-pop.v1",
                        "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11"));
    }

    static final class TestObjects {

        private static final AtomicLong SEQ = new AtomicLong(1L);

        static CaRecord minimalCaRecord(PkiStore store, String caId, CaState state) throws IOException {
            PkiId id = new PkiId(caId);
            KeyRef issuerKeyRef = new KeyRef("issuer-key-" + caId);
            SubjectRef subjectRef = new SubjectRef("CN=" + caId);
            PkiId credentialId = new PkiId("cred-ca-" + caId);
            PkiId issuerId = IssuerGeneration.idFor(id, credentialId);
            IssuerChainPath path = IssuerChainPath.create(id, issuerId, List.of(credentialId));
            Credential credential = caCredential(store, id, credentialId, issuerId, path.pathId(), subjectRef);
            store.putCredential(credential);
            String commitment = "0".repeat(64);
            store.putIssuerGeneration(new IssuerGeneration(issuerId, id, credentialId, issuerKeyRef,
                    IssuerGenerationState.ACTIVE, commitment, commitment));
            store.putIssuerChainPath(path);
            return new CaRecord(id, CaKind.ROOT, state, issuerKeyRef, subjectRef,
                    List.of(issuerId), issuerId, path.pathId());
        }

        private static Credential caCredential(PkiStore store, PkiId authorityId, PkiId credentialId,
                PkiId issuerId, PkiId pathId, SubjectRef subject) throws IOException {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair keyPair = generator.generateKeyPair();
                X500Name name = new X500Name(subject.value());
                Instant notBefore = Instant.parse("2020-01-01T00:00:00Z");
                Instant notAfter = Instant.parse("2030-01-01T00:00:00Z");
                X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                        java.util.Date.from(notBefore), java.util.Date.from(notAfter), name, keyPair.getPublic());
                byte[] der = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate())).getEncoded();
                zeroecho.pki.api.content.DurableContentReference content =
                        zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(store.stagedContent(), Encoding.DER, der);
                return new Credential(credentialId, BcX509CredentialFramework.FORMAT_ID,
                        new IssuerRef(authorityId, issuerId, pathId), subject,
                        new Validity(notBefore, notAfter), "1",
                        new PkiId("pk-" + authorityId.value()),
                        new CaProfileBinding(new CertificateProfileRef("profile-ca", 1, new byte[32])),
                        CredentialStatus.ISSUED, content, emptyAttributes());
            } catch (java.security.GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException
                    exception) {
                throw new IOException("CA fixture construction failed", exception);
            }
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
