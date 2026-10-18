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

package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.Stream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.profile.CaCertificatePolicy;
import zeroecho.pki.api.profile.CaKeyUsage;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.profile.SubjectPolicy;
import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.FullCrlSnapshotProvenance;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.testkit.PkiTestRuntime;

class PkiSessionFullCrlTest {
    private static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final PkiId CA = new PkiId("ca:session-crl");
    private static final KeyRef KEY = new KeyRef("key:session-crl");
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "session"),
            new Purpose("STATUS_GENERATE"), Optional.empty(), Optional.empty());

    @Test void preparesWithoutDispatchDiscardsAndPublishesBoundedResultThenReopens(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(false, Capability.COMPATIBLE);
        SigningAcceptanceReceipt receipt;
        PkiId statusId;
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            PkiId issuer = fixture.installIssuer(1, IssuerGenerationState.ACTIVE, List.of());
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            long baseline = contents(root);
            PreparedSemanticSigningRequest first = semantic.prepareFullCrl(ACCESS, request(issuer), CancellationSignal.NONE);
            assertEquals(0, fixture.provider.dispatches.get());
            assertEquals(baseline + 1, contents(root));
            semantic.discard(first);
            assertEquals(baseline, contents(root));
            PreparedSemanticSigningRequest second = semantic.prepareFullCrl(ACCESS, request(issuer), CancellationSignal.NONE);
            assertEquals(0, fixture.provider.dispatches.get());
            receipt = semantic.accept(second).receipt();
            SemanticSigningOperation completed = await(semantic, receipt.operationId());
            assertEquals(SemanticSigningState.COMPLETED, completed.state());
            EncodedObject result = completed.result().orElseThrow();
            assertEquals(Encoding.BINARY, result.encoding());
            assertEquals(68, result.bytes().length);
            statusId = new PkiId(new String(result.bytes(), StandardCharsets.US_ASCII));
            assertTrue(statusId.value().matches("crl:[0-9a-f]{64}"));
            PkiOperationResult projected = session.signingCommands().orElseThrow().completedResult(completed);
            assertEquals(new PkiOperationValue.Text(statusId.value()), projected.fields().get("statusObjectId"));
            assertEquals(new PkiOperationValue.Text("BINARY"), projected.fields().get("encoding"));
            assertTrue(projected.field("credentialId").isEmpty());
            StatusObject status = session.repository().statusObject(statusId).orElseThrow();
            assertEquals(CA, status.issuerCaId());
            assertEquals(NOW, status.thisUpdate());
            assertEquals(NOW.plusSeconds(3600), status.nextUpdate().orElseThrow());
            assertEquals("crl:" + status.content().sha256(), statusId.value());
            assertRepositoryContent(session, statusId);
            assertEquals("2", DomainCommandEncoding.decode(fixture.store.getDomainContinuation(receipt.operationId())
                    .orElseThrow().command()).field(10));
            assertEquals(1, fixture.provider.dispatches.get());
        }
        try (PkiSession reopened = fixture.open(root, OptionalLong.empty())) {
            assertEquals(SemanticSigningState.COMPLETED, reopened.semanticSigning().orElseThrow()
                    .find(receipt.operationId()).orElseThrow().state());
            assertTrue(reopened.repository().statusObject(statusId).isPresent());
            assertRepositoryContent(reopened, statusId);
            assertEquals(1, fixture.provider.dispatches.get());
        }
    }

    @Test void administrativeHoldSurvivesRestartAndReleasePublishesFullAndDeltaState(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(false, Capability.COMPATIBLE);
        Path mirror = root.resolve("mirror");
        fixture.publishers = List.of(new ProviderConfig("filesystem", Map.of("root", mirror.toString(), "targetId", "mirror")));
        PkiId issuer;
        PkiId credential = fixture.credentialId(1);
        RevocationExecutionEvidence holdEvidence = RevocationExecutionEvidence.administrative("operator", "realm", "hold-request",
                RevocationExecutionEvidence.Authentication.DIRECT_MTLS, RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                "a".repeat(64), Optional.of("ticket"));
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            PkiId oldIssuer = fixture.installIssuer(1, IssuerGenerationState.ACTIVE, List.of());
            issuer = fixture.installIssuer(2, IssuerGenerationState.ACTIVE, List.of(oldIssuer));
            assertEquals(new PkiResourceScopeResolver.CredentialScope(CA, "root"),
                    session.resourceScopes().holdCredentialScope(credential).orElseThrow());
            assertThrows(IllegalStateException.class, () -> session.resourceScopes().credentialScope(credential));
            assertTrue(RevocationEvidenceExecutor.require(session.operations()).executeHold(new PkiOperation.HoldCredential(credential), holdEvidence, CancellationSignal.NONE)
                    instanceof PkiOperationOutcome.Completed);
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            SemanticSigningOperation full = await(semantic, semantic.accept(semantic.prepareFullCrl(ACCESS,
                    request(issuer), CancellationSignal.NONE)).receipt().operationId());
            java.security.cert.X509CRL crl = readCrl(session, semantic.completedStatusObjectId(full).orElseThrow());
            crl.verify(fixture.key.getPublic());
            assertEquals(java.security.cert.CRLReason.CERTIFICATE_HOLD, crl.getRevokedCertificate(BigInteger.ONE).getRevocationReason());
            assertEquals(java.security.cert.CRLReason.CERTIFICATE_HOLD,
                    publishCrl(session, semantic.completedStatusObjectId(full).orElseThrow(), mirror, "held")
                            .getRevokedCertificate(BigInteger.ONE).getRevocationReason());
        }
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            assertEquals(holdEvidence, RevocationExecutionEvidence.decode(session.revocations().get(credential)
                    .orElseThrow().transition().attributes()).orElseThrow());
            long heldRevision = session.revocations().get(credential).orElseThrow().transition().revision();
            assertTrue(session.operations().execute(new PkiOperation.UnholdCredential(credential), () -> true)
                    instanceof PkiOperationOutcome.Failed);
            assertEquals(heldRevision, session.revocations().get(credential).orElseThrow().transition().revision());
            assertTrue(session.operations().execute(new PkiOperation.UnholdCredential(credential), CancellationSignal.NONE)
                    instanceof PkiOperationOutcome.Completed);
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            SemanticSigningOperation delta = await(semantic, semantic.accept(semantic.prepareDeltaCrl(ACCESS,
                    new DeltaCrlRequest(issuer, Duration.ofHours(1)), CancellationSignal.NONE)).receipt().operationId());
            java.security.cert.X509CRL deltaCrl = readCrl(session, semantic.completedStatusObjectId(delta).orElseThrow());
            deltaCrl.verify(fixture.key.getPublic());
            assertEquals(java.security.cert.CRLReason.REMOVE_FROM_CRL, deltaCrl.getRevokedCertificate(BigInteger.ONE).getRevocationReason());
            java.security.cert.X509CRL publishedDelta = publishCrl(session, semantic.completedStatusObjectId(delta).orElseThrow(), mirror, "released-delta");
            publishedDelta.verify(fixture.key.getPublic());
            assertEquals(java.security.cert.CRLReason.REMOVE_FROM_CRL,
                    publishedDelta.getRevokedCertificate(BigInteger.ONE).getRevocationReason());
            SemanticSigningOperation full = await(semantic, semantic.accept(semantic.prepareFullCrl(ACCESS,
                    request(issuer), CancellationSignal.NONE)).receipt().operationId());
            java.security.cert.X509CRL fullCrl = readCrl(session, semantic.completedStatusObjectId(full).orElseThrow());
            fullCrl.verify(fixture.key.getPublic());
            assertNull(fullCrl.getRevokedCertificate(BigInteger.ONE));
            java.security.cert.X509CRL publishedFull = publishCrl(session, semantic.completedStatusObjectId(full).orElseThrow(), mirror, "released-full");
            publishedFull.verify(fixture.key.getPublic());
            assertNull(publishedFull.getRevokedCertificate(BigInteger.ONE));
            assertTrue(session.operations().execute(new PkiOperation.RevokeCredential(credential, RevocationReason.KEY_COMPROMISE),
                    CancellationSignal.NONE) instanceof PkiOperationOutcome.Completed);
            assertTrue(session.operations().execute(new PkiOperation.UnholdCredential(credential), CancellationSignal.NONE)
                    instanceof PkiOperationOutcome.Failed);
            assertTrue(session.operations().execute(new PkiOperation.HoldCredential(credential), CancellationSignal.NONE)
                    instanceof PkiOperationOutcome.Failed);
        }
    }

    private static java.security.cert.X509CRL publishCrl(PkiSession session, PkiId status, Path mirror, String id) throws Exception {
        zeroecho.pki.api.publication.PublicationTarget target = new zeroecho.pki.api.publication.PublicationTarget(
                zeroecho.pki.api.publication.PublicationTargetType.FILESYSTEM, "mirror");
        PkiId publicationId = new PkiId(id);
        session.publications().orElseThrow().register(new zeroecho.pki.api.publication.PublicationRequest(publicationId,
                zeroecho.pki.api.publication.PublicationSourceType.STATUS_OBJECT, status, target));
        session.publications().orElseThrow().process(publicationId);
        Path destination = mirror.resolve(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(id.getBytes(StandardCharsets.UTF_8))) + ".bin");
        try (InputStream input = Files.newInputStream(destination)) {
            return (java.security.cert.X509CRL) java.security.cert.CertificateFactory.getInstance("X.509").generateCRL(input);
        }
    }

    @Test void deltaReleasesUseGlobalRevisionAtEqualTimesAndKeepFrozenCutoffAcrossRestart(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(false, Capability.COMPATIBLE);
        PkiId deltaOperation;
        PkiId deltaStatus;
        PkiId baseStatus;
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            java.util.ArrayList<PkiId> generations = new java.util.ArrayList<>();
            for (int serial = 1; serial <= 5; serial++) {
                generations.add(fixture.installIssuer(serial, IssuerGenerationState.ACTIVE, List.copyOf(generations)));
            }
            PkiId issuer = generations.getLast();
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            fixture.hold(1);
            fixture.store.transitionRevocation(new RevocationCommand.RevokePermanently(
                    fixture.credentialId(2), RevocationReason.KEY_COMPROMISE, new SimpleAttributeSet()), NOW);
            fixture.hold(3);
            fixture.unhold(3);
            SemanticSigningOperation base = await(semantic, semantic.accept(semantic.prepareFullCrl(ACCESS,
                    request(issuer), CancellationSignal.NONE)).receipt().operationId());
            assertEquals(SemanticSigningState.COMPLETED, base.state());
            baseStatus = semantic.completedStatusObjectId(base).orElseThrow();
            assertEquals(BigInteger.ONE, number(readCrl(session, baseStatus), Extension.cRLNumber.getId()));
            fixture.unhold(1);
            fixture.hold(3);
            fixture.unhold(3);
            DeltaCrlRequest deltaRequest = new DeltaCrlRequest(issuer, Duration.ofHours(1));
            semantic.discard(semantic.prepareDeltaCrl(ACCESS, deltaRequest, CancellationSignal.NONE));
            PreparedSemanticSigningRequest prepared = semantic.prepareDeltaCrl(ACCESS, deltaRequest, CancellationSignal.NONE);
            assertEquals(1, fixture.provider.dispatches.get(), "Preparation and discard must not sign");
            fixture.hold(4); // After the one frozen delta snapshot: excluded from this delta.
            deltaOperation = semantic.accept(prepared).receipt().operationId();
            SemanticSigningOperation delta = await(semantic, deltaOperation);
            assertEquals(SemanticSigningState.COMPLETED, delta.state());
            deltaStatus = semantic.completedStatusObjectId(delta).orElseThrow();
            assertEquals(StatusObjectType.DELTA_CRL, session.repository().statusObject(deltaStatus).orElseThrow().type());
            java.security.cert.X509CRL crl = readCrl(session, deltaStatus);
            crl.verify(fixture.key.getPublic());
            assertEquals(BigInteger.valueOf(3), number(crl, Extension.cRLNumber.getId()), "Discarded number remains a gap");
            assertEquals(BigInteger.ONE, number(crl, Extension.deltaCRLIndicator.getId()));
            assertTrue(crl.getCriticalExtensionOIDs().contains(Extension.deltaCRLIndicator.getId()));
            assertEquals(Set.of(BigInteger.ONE, BigInteger.valueOf(3)), crl.getRevokedCertificates().stream()
                    .map(java.security.cert.X509CRLEntry::getSerialNumber).collect(java.util.stream.Collectors.toSet()));
            for (java.security.cert.X509CRLEntry entry : crl.getRevokedCertificates()) {
                assertEquals(java.security.cert.CRLReason.REMOVE_FROM_CRL, entry.getRevocationReason());
                assertEquals(Date.from(NOW), entry.getRevocationDate());
            }
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(fixture.store
                    .getDomainContinuation(deltaOperation).orElseThrow().command());
            assertEquals("GENERATE_DELTA_CRL", command.operation());
            assertEquals(36, command.fields().size());
            assertEquals(baseStatus.value(), command.field(31));
            assertEquals("4", command.field(33));
            assertEquals("7", command.field(20));
            SemanticSigningOperation full = await(semantic, semantic.accept(semantic.prepareFullCrl(ACCESS,
                    request(issuer), CancellationSignal.NONE)).receipt().operationId());
            assertEquals(SemanticSigningState.COMPLETED, full.state());
            java.security.cert.X509CRL fullCrl = readCrl(session, semantic.completedStatusObjectId(full).orElseThrow());
            assertEquals(BigInteger.valueOf(4), number(fullCrl, Extension.cRLNumber.getId()));
            assertNull(fullCrl.getExtensionValue(Extension.deltaCRLIndicator.getId()));
            assertEquals(Set.of(BigInteger.TWO, BigInteger.valueOf(4)), fullCrl.getRevokedCertificates().stream()
                    .map(java.security.cert.X509CRLEntry::getSerialNumber).collect(java.util.stream.Collectors.toSet()));
            assertEquals(3, fixture.provider.dispatches.get());
        }
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            SemanticSigningOperation recovered = session.semanticSigning().orElseThrow().find(deltaOperation).orElseThrow();
            assertEquals(SemanticSigningState.COMPLETED, recovered.state());
            assertEquals(deltaStatus, session.semanticSigning().orElseThrow().completedStatusObjectId(recovered).orElseThrow());
            assertEquals(baseStatus.value(), DomainCommandEncoding.decode(fixture.store.getDomainContinuation(deltaOperation)
                    .orElseThrow().command()).field(31));
            readCrl(session, deltaStatus).verify(fixture.key.getPublic());
            assertEquals(3, fixture.provider.dispatches.get(), "Recovery must not sign or reselect the base");
        }
    }

    @Test void invalidLatestBaseDoesNotFallBackReserveStageOrDispatch(@TempDir Path root) throws Exception {
        for (String defect : List.of("key", "signed-time", "source", "prefix")) {
            Fixture fixture = new Fixture(false, Capability.COMPATIBLE);
            Path directory = root.resolve(defect);
            try (PkiSession session = fixture.open(directory, OptionalLong.empty())) {
                PkiId issuer = fixture.installIssuer(1, IssuerGenerationState.ACTIVE, List.of());
                SemanticSigningService semantic = session.semanticSigning().orElseThrow();
                SemanticSigningOperation base = await(semantic, semantic.accept(semantic.prepareFullCrl(ACCESS,
                        request(issuer), CancellationSignal.NONE)).receipt().operationId());
                assertEquals(SemanticSigningState.COMPLETED, base.state());
                StatusObject valid = session.repository().statusObject(semantic.completedStatusObjectId(base).orElseThrow()).orElseThrow();
                FullCrlSnapshotProvenance provenance = FullCrlSnapshotProvenance.decode(valid.attributes());
                if (defect.equals("source")) {
                    provenance = new FullCrlSnapshotProvenance(new zeroecho.pki.spi.store.MetadataStoreId("ff".repeat(16)),
                            provenance.revision(), provenance.boundary(), provenance.commitment());
                } else if (defect.equals("prefix")) {
                    provenance = new FullCrlSnapshotProvenance(provenance.sourceStoreId(), provenance.revision(),
                            provenance.boundary(), "ff".repeat(32));
                }
                Instant selectedTime = NOW.plusSeconds(1);
                org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder builder = new org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder(
                        new javax.security.auth.x500.X500Principal("CN=Session CRL"), Date.from(defect.equals("signed-time") ? NOW : selectedTime));
                builder.setNextUpdate(Date.from(NOW.plusSeconds(3600)));
                builder.addExtension(Extension.cRLNumber, false, new org.bouncycastle.asn1.ASN1Integer(BigInteger.valueOf(99)));
                KeyPair signer = fixture.key;
                if (defect.equals("key")) {
                    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                    generator.initialize(2048);
                    signer = generator.generateKeyPair();
                }
                byte[] der = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())).getEncoded();
                zeroecho.pki.api.content.DurableContentReference content = PkiTestRuntime.stageCredential(fixture.store, der);
                fixture.store.putStatusObject(new StatusObject(new PkiId("crl:" + content.sha256()), new FormatId("x509"),
                        CA, StatusObjectType.CRL, selectedTime, Optional.of(NOW.plusSeconds(3600)), content, provenance.attributes()));
                long baseline = contents(directory);
                assertThrows(PkiException.class, () -> semantic.prepareDeltaCrl(ACCESS,
                        new DeltaCrlRequest(issuer, Duration.ofHours(1)), CancellationSignal.NONE), defect);
                assertEquals(baseline, contents(directory), defect);
                assertEquals(1, fixture.provider.dispatches.get(), defect);
                assertEquals(BigInteger.TWO, fixture.store.reserveCrlNumber(issuer), defect);
                assertEquals(2, fixture.store.listStatusObjects(CA).size(), defect);
            }
        }
    }

    @Test void deltaUsesPersistedBaseAfterItsWorkflowHasBeenPurged(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(false, Capability.COMPATIBLE);
        PkiId issuer;
        PkiId baseOperation;
        PkiId baseStatus;
        FullCrlSnapshotProvenance provenance;
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            issuer = fixture.installIssuer(1, IssuerGenerationState.ACTIVE, List.of());
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            baseOperation = semantic.accept(semantic.prepareFullCrl(ACCESS, request(issuer), CancellationSignal.NONE)).receipt().operationId();
            SemanticSigningOperation completed = await(semantic, baseOperation);
            assertEquals(SemanticSigningState.COMPLETED, completed.state());
            baseStatus = semantic.completedStatusObjectId(completed).orElseThrow();
            provenance = FullCrlSnapshotProvenance.decode(session.repository().statusObject(baseStatus).orElseThrow().attributes());
        }
        fixture.clock = Clock.fixed(NOW.plus(Duration.ofDays(91)), ZoneOffset.UTC);
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            fixture.store.purgeExpiredSignRecords();
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            assertTrue(semantic.find(baseOperation).isEmpty());
            assertEquals(provenance, FullCrlSnapshotProvenance.decode(session.repository().statusObject(baseStatus).orElseThrow().attributes()));
            SemanticSigningOperation delta = await(semantic, semantic.accept(semantic.prepareDeltaCrl(ACCESS,
                    new DeltaCrlRequest(issuer, Duration.ofHours(1)), CancellationSignal.NONE)).receipt().operationId());
            assertEquals(SemanticSigningState.COMPLETED, delta.state());
            java.security.cert.X509CRL crl = readCrl(session, semantic.completedStatusObjectId(delta).orElseThrow());
            crl.verify(fixture.key.getPublic());
            assertEquals(BigInteger.ONE, number(crl, Extension.deltaCRLIndicator.getId()));
            assertEquals(BigInteger.TWO, number(crl, Extension.cRLNumber.getId()));
            assertEquals(2, fixture.provider.dispatches.get());
        }
    }

    private static java.security.cert.X509CRL readCrl(PkiSession session, PkiId id) throws Exception {
        try (PkiRepositoryContent content = session.repository().openStatusObject(id); InputStream input = content.openStream()) {
            return (java.security.cert.X509CRL) java.security.cert.CertificateFactory.getInstance("X.509").generateCRL(input);
        }
    }

    private static BigInteger number(java.security.cert.X509CRL crl, String oid) {
        return org.bouncycastle.asn1.ASN1Integer.getInstance(org.bouncycastle.asn1.ASN1OctetString
                .getInstance(crl.getExtensionValue(oid)).getOctets()).getValue();
    }

    @Test void validatesNullCancellationAndClosedSessionBeforeReservation(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(false, Capability.COMPATIBLE);
        SemanticSigningService semantic;
        FullCrlRequest request;
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            PkiId issuer = fixture.installIssuer(1, IssuerGenerationState.ACTIVE, List.of());
            request = request(issuer);
            semantic = session.semanticSigning().orElseThrow();
            assertThrows(NullPointerException.class, () -> semantic.prepareFullCrl(null, request, CancellationSignal.NONE));
            assertThrows(NullPointerException.class, () -> semantic.prepareFullCrl(ACCESS, null, CancellationSignal.NONE));
            assertThrows(NullPointerException.class, () -> semantic.prepareFullCrl(ACCESS, request, null));
            assertThrows(PkiException.class, () -> semantic.prepareFullCrl(ACCESS, request, () -> true));
            assertEquals(BigInteger.ONE, fixture.store.reserveCrlNumber(issuer));
            assertEquals(0, fixture.provider.dispatches.get());
        }
        assertThrows(SigningExecutionException.class, () -> semantic.prepareFullCrl(ACCESS, request, CancellationSignal.NONE));
    }

    @Test void rejectsMissingOrIncompatibleSelectedCapabilityBeforeNumberReservation(@TempDir Path root) throws Exception {
        for (Capability capability : List.of(Capability.ABSENT, Capability.INCOMPATIBLE)) {
            Fixture fixture = new Fixture(false, capability);
            Path directory = root.resolve(capability.name());
            try (PkiSession session = fixture.open(directory, OptionalLong.empty())) {
                PkiId issuer = fixture.installIssuer(1, IssuerGenerationState.ACTIVE, List.of());
                long baseline = contents(directory);
                assertThrows(PkiException.class, () -> session.semanticSigning().orElseThrow()
                        .prepareFullCrl(ACCESS, request(issuer), CancellationSignal.NONE));
                assertEquals(baseline, contents(directory));
                assertEquals(BigInteger.ONE, fixture.store.reserveCrlNumber(issuer));
                assertEquals(0, fixture.provider.dispatches.get());
                assertTrue(fixture.provider.supportedAlgorithms().contains(fixture.algorithm.canonicalForm()));
            }
        }
    }

    @Test void adoptionLimitFailureRetiresTbsAndConsumesNumber(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(true, Capability.COMPATIBLE);
        try (PkiSession session = fixture.open(root, OptionalLong.of(1))) {
            PkiId issuer = fixture.installIssuer(1, IssuerGenerationState.ACTIVE, List.of());
            long baseline = contents(root);
            assertThrows(IllegalArgumentException.class, () -> session.semanticSigning().orElseThrow()
                    .prepareFullCrl(ACCESS, request(issuer), CancellationSignal.NONE));
            assertEquals(baseline, contents(root));
            assertEquals(BigInteger.TWO, fixture.store.reserveCrlNumber(issuer));
            assertEquals(0, fixture.provider.dispatches.get());
        }
    }

    @Test void retiredSameKeyGenerationUsesSharedNumberScope(@TempDir Path root) throws Exception {
        Fixture fixture = new Fixture(false, Capability.COMPATIBLE);
        try (PkiSession session = fixture.open(root, OptionalLong.empty())) {
            PkiId retired = fixture.installIssuer(1, IssuerGenerationState.RETIRED, List.of());
            PkiId active = fixture.installIssuer(2, IssuerGenerationState.ACTIVE, List.of(retired));
            SemanticSigningService semantic = session.semanticSigning().orElseThrow();
            semantic.discard(semantic.prepareFullCrl(ACCESS, request(retired), CancellationSignal.NONE));
            SigningAcceptanceReceipt receipt = semantic.accept(semantic.prepareFullCrl(ACCESS, request(active),
                    CancellationSignal.NONE)).receipt();
            assertEquals(SemanticSigningState.COMPLETED, await(semantic, receipt.operationId()).state());
            assertEquals("2", DomainCommandEncoding.decode(fixture.store.getDomainContinuation(receipt.operationId())
                    .orElseThrow().command()).field(10));
        }
    }

    @Test void unconfiguredSessionHasNoSemanticSigningFacade(@TempDir Path root) throws Exception {
        try (PkiSession session = PkiSession.open(new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", root.toString())), new ProviderConfig("memory", Map.of()),
                Optional.empty(), List.of(), List.of()))) {
            assertTrue(session.semanticSigning().isEmpty());
        }
    }

    private static FullCrlRequest request(PkiId issuer) { return new FullCrlRequest(issuer, Duration.ofHours(1)); }

    private static void assertRepositoryContent(PkiSession session, PkiId statusId) throws Exception {
        try (PkiRepositoryContent content = session.repository().openStatusObject(statusId)) {
            assertEquals(PkiRepositoryContent.Role.CRL, content.role());
            for (int attempt = 0; attempt < 2; attempt++) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                long length = 0L;
                try (InputStream input = content.openStream()) {
                    byte[] chunk = new byte[8192];
                    for (int read; (read = input.read(chunk)) != -1;) {
                        length += read;
                        digest.update(chunk, 0, read);
                    }
                }
                assertEquals(content.length(), length);
                assertEquals(content.sha256(), HexFormat.of().formatHex(digest.digest()));
            }
        }
    }

    private static long contents(Path root) throws Exception {
        try (Stream<Path> paths = Files.walk(root)) {
            return paths.filter(path -> path.getFileName().toString().endsWith(".content")).count();
        }
    }

    private static SemanticSigningOperation await(SemanticSigningService semantic, PkiId id) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        SemanticSigningOperation operation;
        do {
            operation = semantic.find(id).orElseThrow();
            if (operation.state() != SemanticSigningState.SIGNING && operation.state() != SemanticSigningState.PUBLISHING) {
                return operation;
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        } while (System.nanoTime() < deadline);
        throw new AssertionError("CRL completion timed out: " + operation.state());
    }

    private enum Capability { COMPATIBLE, INCOMPATIBLE, ABSENT }

    private static final class Fixture implements DefaultPkiSession.Bootstrap {
        private final AlgorithmIdentity algorithm;
        private final String jcaAlgorithm;
        private final KeyPair key;
        private final Capability capability;
        private final Provider provider = new Provider();
        private PkiStore store;
        private Clock clock = CLOCK;
        private List<ProviderConfig> publishers = List.of();

        private Fixture(boolean edDsa, Capability capability) throws Exception {
            this.capability = capability;
            algorithm = edDsa ? BootstrapAlgorithmIdentities.ED25519_SIGNATURE : BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256;
            jcaAlgorithm = edDsa ? "Ed25519" : "SHA256withRSA";
            KeyPairGenerator generator = KeyPairGenerator.getInstance(edDsa ? "Ed25519" : "RSA");
            if (!edDsa) { generator.initialize(2048); }
            key = generator.generateKeyPair();
        }

        private PkiSession open(Path root, OptionalLong limit) {
            PkiSessionConfiguration.SigningTopology topology = new PkiSessionConfiguration.SigningTopology(
                    new PkiSessionConfiguration.SigningCoordinatorLimits(2, Duration.ofSeconds(10), Duration.ofSeconds(5),
                            Duration.ofDays(1), Duration.ofSeconds(2)), List.of(),
                    new PkiSessionConfiguration.SigningLanePool(1, 4));
            PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                    new ProviderConfig("test-signing", Map.of()), algorithm.canonicalForm(), Duration.ofMinutes(1),
                    Optional.empty(), topology, limit);
            return DefaultPkiSession.open(new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                    new ProviderConfig("fs", Map.of("root", root.toString())), new ProviderConfig("memory", Map.of()),
                    Optional.of(signing), publishers, List.of()), clock, this);
        }

        private PkiId installIssuer(int serial, IssuerGenerationState state, List<PkiId> previous) throws Exception {
            CertificateProfileDefinition definition = new CertificateProfileDefinition(CertificateProfileKind.ROOT_CA,
                    "root", 1, new FormatId("x509"), "Root", Duration.ofDays(365),
                    new SubjectPolicy(false, List.of(new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 253,
                            Optional.empty(), true))), new CaCertificatePolicy(true, 1, true,
                            Set.of(CaKeyUsage.KEY_CERT_SIGN, CaKeyUsage.CRL_SIGN), Set.of("RSA", "Ed25519")),
                    X509AlgorithmBindingPolicy.standardOnly());
            byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
            CertificateProfileRef profile = new CertificateProfileRef("root", 1, MessageDigest.getInstance("SHA-256").digest(canonical));
            store.importProfileVersion(new ImportedCertificateProfileVersion(profile, CertificateProfileDefinition.SCHEMA_VERSION,
                    definition, canonical, NOW));
            String commitment = HexFormat.of().formatHex(profile.canonicalSha256());
            PkiId credentialId = new PkiId("credential:session-crl:" + serial);
            PkiId issuer = IssuerGeneration.idFor(CA, credentialId);
            IssuerChainPath chain = IssuerChainPath.create(CA, issuer, List.of(credentialId));
            X500Name name = new X500Name("CN=Session CRL");
            Instant before = NOW.minusSeconds(3600);
            Instant after = NOW.plus(Duration.ofDays(365));
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(serial),
                    Date.from(before), Date.from(after), name, key.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            byte[] der = builder.build(new JcaContentSignerBuilder(jcaAlgorithm).build(key.getPrivate())).getEncoded();
            store.putCredential(new Credential(credentialId, new FormatId("x509"), new IssuerRef(CA, issuer, chain.pathId()),
                    new SubjectRef("CN=Session CRL"), new Validity(before, after), Integer.toString(serial),
                    new PkiId("public:session-crl"), new CaProfileBinding(profile), CredentialStatus.ISSUED,
                    PkiTestRuntime.stageCredential(store, der), new SimpleAttributeSet()));
            store.putIssuerGeneration(new IssuerGeneration(issuer, CA, credentialId, KEY, state, commitment, commitment));
            store.putIssuerChainPath(chain);
            java.util.ArrayList<PkiId> generations = new java.util.ArrayList<>(previous);
            generations.add(issuer);
            store.putCa(new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, KEY, new SubjectRef("CN=Session CRL"),
                    generations, issuer, chain.pathId()));
            return issuer;
        }

        private PkiId credentialId(int serial) { return new PkiId("credential:session-crl:" + serial); }
        private void hold(int serial) {
            store.transitionRevocation(new RevocationCommand.Hold(credentialId(serial), new SimpleAttributeSet()), NOW);
        }
        private void unhold(int serial) {
            store.transitionRevocation(new RevocationCommand.Unhold(credentialId(serial), new SimpleAttributeSet()), NOW);
        }

        @Override public void validateStore(ProviderConfig configuration) { PkiBootstrap.validateStoreConfiguration(configuration); }
        @Override public void validateAudit(ProviderConfig configuration) { PkiBootstrap.validateAuditConfiguration(configuration); }
        @Override public void validateSigning(ProviderConfig configuration) { }
        @Override public PkiStore openStore(ProviderConfig configuration) {
            return openStore(configuration, new PkiStoreRuntimeDependencies(CLOCK));
        }
        @Override public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            store = PkiBootstrap.openStore(configuration, dependencies);
            return store;
        }
        @Override public AuditSink openAudit(ProviderConfig configuration) { return PkiBootstrap.openAudit(configuration); }
        @Override public PkiBootstrap.SigningComposition openSigningComposition(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            AlgorithmExecutionCapability contribution = new AlgorithmExecutionCapability() {
                @Override public String implementationId() { return "test-signing.exact-provider"; }
                @Override public String domainFingerprint() { return "test-signing:" + capability; }
                @Override public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                    return capability == Capability.COMPATIBLE && direction == Direction.SIGN && identity.equals(algorithm)
                            && suite.signature().equals(algorithm);
                }
            };
            return new PkiBootstrap.SigningComposition(provider, capability == Capability.ABSENT ? List.of() : List.of(contribution));
        }

        private final class Provider implements SigningProvider {
            private final AtomicInteger dispatches = new AtomicInteger();
            @Override public String id() { return "test-session-crl"; }
            @Override public ConfigurationCommitment configurationCommitment() { return new ConfigurationCommitment(new byte[32]); }
            @Override public Set<String> supportedAlgorithms() { return Set.of(algorithm.canonicalForm()); }
            @Override public SigningInputCapabilities inputCapabilities() { return new SigningInputCapabilities(Long.MAX_VALUE, Map.of()); }
            @Override public OperationObservation dispatch(SignRequest request, CallControl control) {
                dispatches.incrementAndGet();
                assertEquals(KEY, request.keyRef());
                assertEquals(algorithm.canonicalForm(), request.algorithmId());
                try (InputStream input = request.content().openStream()) {
                    Signature signature = Signature.getInstance(jcaAlgorithm);
                    signature.initSign(key.getPrivate());
                    byte[] chunk = new byte[8192];
                    for (int read; (read = input.read(chunk)) != -1;) { signature.update(chunk, 0, read); }
                    return new OperationObservation(request.operationId(), ObservationState.SUCCEEDED, clock.instant(),
                            DetailCode.SIGNED, Optional.of(new EncodedObject(Encoding.BINARY, signature.sign())));
                } catch (Exception failure) { throw new AssertionError(failure); }
            }
            @Override public OperationObservation reconcile(PkiId id, CallControl control) {
                throw new AssertionError("Completed CRL must not reconcile");
            }
            @Override public OperationObservation cancel(PkiId id, long fencing, CancellationReason reason, CallControl control) {
                return new OperationObservation(id, ObservationState.CANCELLED, NOW, DetailCode.CANCELLED, Optional.empty());
            }
            @Override public void close() { }
        }
    }
}
