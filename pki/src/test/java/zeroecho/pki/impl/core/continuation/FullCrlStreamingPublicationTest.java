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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.impl.core.PreparedFullCrlTbs;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;

class FullCrlStreamingPublicationTest {
    static final Instant NOW = Instant.parse("2026-09-21T12:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final PkiId CA = new PkiId("ca:full-crl");
    private static final KeyRef KEY = new KeyRef("key:full-crl");
    private static final String HASH = "00".repeat(32);
    private static final CertificateProfileRef PROFILE = new CertificateProfileRef("root", 1, new byte[32]);
    static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "crl"),
            new Purpose("STATUS_GENERATE"), Optional.empty(), Optional.empty());

    @Test void streamsLargeCrlAndReopensCompletedAfterRetirement(@TempDir Path root) throws Exception {
        SigningAcceptanceReceipt receipt;
        PkiId statusId;
        DurableContentReference tbs;
        try (FilesystemPkiStore store = open(root)) {
            Fixture fixture = fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 55_000);
            assertTrue(fixture.prepared().tbsContent().length() > 1_048_576);
            DefaultSemanticSigningService semantic = semantic(store, fixture.algorithm(), Integer.MAX_VALUE - 8L);
            PreparedSemanticSigningRequest prepared = semantic.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE);
            receipt = semantic.accept(prepared).receipt();
            tbs = fixture.prepared().tbsContent();
            assertEquals(tbs, store.getSignWorkflow(receipt.operationId()).orElseThrow().envelope().candidate());
            sign(store, receipt.operationId(), fixture.signature());
            new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(receipt.operationId()).orElseThrow());
            DomainContinuationStore.Record done = store.getDomainContinuation(receipt.operationId()).orElseThrow();
            assertEquals(DomainContinuationStore.State.COMPLETED, done.state());
            assertEquals(68, done.result().orElseThrow().bytes().length);
            statusId = FullCrlSigningCommand.resultId(done.result().orElseThrow());
            StatusObject status = store.getStatusObject(statusId).orElseThrow();
            try (RepeatableContent content = store.stagedContent().openContent(status.content()); InputStream input = content.openStream()) {
                assertArrayEquals(fixture.outer(), input.readAllBytes());
            }
            assertTrue(semantic.find(receipt.operationId()).isPresent());
        }
        try (FilesystemPkiStore store = open(root)) {
            DomainContinuationStore.Record done = store.getDomainContinuation(receipt.operationId()).orElseThrow();
            FullCrlSigningCommand.requireCompleted(store, done);
            assertEquals(statusId, FullCrlSigningCommand.resultId(done.result().orElseThrow()));
            assertTrue(semantic(store, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 1).find(receipt.operationId()).isPresent());
            assertThrows(Exception.class, () -> store.stagedContent().openContent(tbs));
        }
    }

    @Test void reopensSigningAndReplaysPublicationAfterDurableStatus(@TempDir Path root) throws Exception {
        SigningAcceptanceReceipt receipt;
        EncodedObject signature;
        try (FilesystemPkiStore store = open(root)) {
            Fixture fixture = fixture(store, "RSA", "SHA256withRSAandMGF1", BootstrapAlgorithmIdentities.RSA_PSS_SHA256, 2);
            DefaultSemanticSigningService semantic = semantic(store, fixture.algorithm(), 1);
            receipt = semantic.accept(semantic.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE)).receipt();
            signature = fixture.signature();
        }
        try (FilesystemPkiStore store = open(root)) {
            PkiId id = receipt.operationId();
            assertEquals(DomainContinuationStore.State.SIGNING, store.getDomainContinuation(id).orElseThrow().state());
            sign(store, id, signature);
            DomainContinuationPublisher.installPublicationFault(point -> { throw new SimulatedCrash(); });
            try {
                assertThrows(SimulatedCrash.class, () -> new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(id).orElseThrow()));
            } finally { DomainContinuationPublisher.clearPublicationFault(); }
            assertEquals(DomainContinuationStore.State.PUBLISHING, store.getDomainContinuation(id).orElseThrow().state());
            assertEquals(1, store.listStatusObjects(CA).size());
        }
        try (FilesystemPkiStore store = open(root)) {
            PkiId id = receipt.operationId();
            DurableContentReference original = store.listStatusObjects(CA).getFirst().content();
            new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(id).orElseThrow());
            assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(id).orElseThrow().state());
            assertEquals(original, store.listStatusObjects(CA).getFirst().content());
            assertEquals(FullCrlSnapshotProvenance.from(DomainCommandEncoding.decode(
                    store.getDomainContinuation(id).orElseThrow().command())),
                    FullCrlSnapshotProvenance.decode(store.listStatusObjects(CA).getFirst().attributes()));
        }
    }

    @Test void pureEd25519HonorsAdmissionAndVerifiesWithJdkSemantics(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Fixture rejected = fixture(store, "Ed25519", "Ed25519", BootstrapAlgorithmIdentities.ED25519_SIGNATURE, 2);
            long length = rejected.prepared().tbsContent().length();
            assertThrows(IllegalArgumentException.class, () -> semantic(store, rejected.algorithm(), length - 1)
                    .prepareFullCrl(ACCESS, rejected.prepared(), CancellationSignal.NONE));
            assertThrows(Exception.class, () -> store.stagedContent().openContent(rejected.prepared().tbsContent()));
            Fixture accepted = fixture(store, "Ed25519", "Ed25519", BootstrapAlgorithmIdentities.ED25519_SIGNATURE, 2);
            DefaultSemanticSigningService semantic = semantic(store, accepted.algorithm(), accepted.prepared().tbsContent().length());
            SigningAcceptanceReceipt receipt = semantic.accept(semantic.prepareFullCrl(ACCESS, accepted.prepared(), CancellationSignal.NONE)).receipt();
            sign(store, receipt.operationId(), accepted.signature());
            new SigningOuterTerminalDriver(store, StandardX509Bindings.catalog(), accepted.prepared().tbsContent().length())
                    .advance(store.getSignWorkflow(receipt.operationId()).orElseThrow());
            assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(receipt.operationId()).orElseThrow().state());
        }
    }

    @Test void rejectsWrongSignatureAlgorithmIssuerAndTimes(@TempDir Path root) throws Exception {
        for (int changed : new int[] {-1, 9, 3, 7}) {
            try (FilesystemPkiStore store = open(root.resolve("case" + changed))) {
                Fixture fixture = fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 1);
                DomainContinuationTemplate template = FullCrlSigningCommand.template(fixture.prepared());
                if (changed >= 0) {
                    List<String> fields = new ArrayList<>(DomainCommandEncoding.decode(template.command()).fields());
                    fields.set(changed, switch (changed) {
                        case 9 -> "300d06092a864886f70d01010c0500";
                        case 3 -> NOW.minusSeconds(1).toString();
                        default -> "credential:wrong";
                    });
                    template = DomainCommandEncoding.correlatedTemplate(template.kind(), template.correlationId().orElseThrow(),
                            FullCrlSigningCommand.OPERATION, fields.toArray(String[]::new));
                }
                byte[] signature = fixture.signature().bytes();
                if (changed == -1) { signature[0] ^= 1; }
                DomainContinuationStore.Record record = new DomainContinuationStore.Record(new PkiId("test:crl"), 2,
                        template.kind(), template.correlationId(), DomainContinuationStore.State.PUBLISHING, 1,
                        NOW, NOW.plusSeconds(60), template.command(), template.commandCommitment(),
                        Optional.of(fixture.prepared().tbsContent()), Optional.empty(), Optional.empty());
                assertThrows(DomainContinuationPublisher.PostconditionFailure.class,
                        () -> new FullCrlContinuationPublisher(store, StandardX509Bindings.catalog(), 1)
                                .publish(record, new EncodedObject(Encoding.BINARY, signature)));
                assertTrue(store.listStatusObjects(CA).isEmpty());
            }
        }
    }

    @Test void rechecksPureEdDsaLimitBeforePublication(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Fixture fixture = fixture(store, "Ed25519", "Ed25519", BootstrapAlgorithmIdentities.ED25519_SIGNATURE, 2);
            long length = fixture.prepared().tbsContent().length();
            DefaultSemanticSigningService semantic = semantic(store, fixture.algorithm(), length);
            SigningAcceptanceReceipt receipt = semantic.accept(semantic.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE)).receipt();
            sign(store, receipt.operationId(), fixture.signature());
            new SigningOuterTerminalDriver(store, StandardX509Bindings.catalog(), length - 1)
                    .advance(store.getSignWorkflow(receipt.operationId()).orElseThrow());
            assertEquals(DomainContinuationStore.State.FAILED, store.getDomainContinuation(receipt.operationId()).orElseThrow().state());
            assertTrue(store.listStatusObjects(CA).isEmpty());
        }
    }

    @Test void rejectsNoncanonicalMetadataAndCompletionIdentity(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Fixture fixture = fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            DomainContinuationTemplate valid = FullCrlSigningCommand.template(fixture.prepared());
            DomainContinuationValidation.validate(valid);
            List<String> fields = new ArrayList<>(DomainCommandEncoding.decode(valid.command()).fields());
            fields.set(27, "0" + fields.get(27));
            assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(
                    DomainCommandEncoding.template(valid.kind(), FullCrlSigningCommand.OPERATION, fields.toArray(String[]::new))));
            assertThrows(IllegalStateException.class, () -> FullCrlSigningCommand.resultId(new EncodedObject(Encoding.DER, new byte[68])));
            assertThrows(IllegalStateException.class, () -> FullCrlSigningCommand.requireTbs(
                    DomainCommandEncoding.decode(valid.command()), fixture.prepared().issuerContent()));
        }
    }

    @Test void provenanceIsFrozenValidatedAndSurvivesReopenAndWorkflowPurge(@TempDir Path root) throws Exception {
        PkiId operation;
        PkiId statusId;
        FullCrlSnapshotProvenance expected;
        try (FilesystemPkiStore store = open(root)) {
            Fixture fixture = fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 1);
            DomainContinuationTemplate template = FullCrlSigningCommand.template(fixture.prepared());
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(template.command());
            assertEquals(31, command.fields().size());
            assertEquals(fixture.prepared().snapshotSourceStoreId().value(), command.field(30));
            expected = FullCrlSnapshotProvenance.from(command);
            DefaultSemanticSigningService semantic = semantic(store, fixture.algorithm(), 1);
            operation = semantic.accept(semantic.prepareFullCrl(ACCESS, fixture.prepared(), CancellationSignal.NONE))
                    .receipt().operationId();
            sign(store, operation, fixture.signature());
            new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(operation).orElseThrow());
            DomainContinuationStore.Record done = store.getDomainContinuation(operation).orElseThrow();
            assertEquals(DomainContinuationStore.State.COMPLETED, done.state());
            statusId = FullCrlSigningCommand.resultId(done.result().orElseThrow());
            StatusObject published = store.getStatusObject(statusId).orElseThrow();
            assertEquals(5, published.attributes().ids().size());
            assertEquals(expected, FullCrlSnapshotProvenance.decode(published.attributes()));
            FullCrlSigningCommand.requireCompleted(published, done);
            List<SimpleAttributeSet.Entry> reordered = published.attributes().ids().stream()
                    .sorted(java.util.Comparator.comparing(zeroecho.pki.api.attr.AttributeId::value).reversed())
                    .map(id -> new SimpleAttributeSet.Entry(id, published.attributes().getAll(id))).toList();
            StatusObject reorderedStatus = withAttributes(published, new SimpleAttributeSet(reordered));
            FullCrlContinuationPublisher.requirePublished(reorderedStatus, done, published.content());
            FullCrlSigningCommand.requireCompleted(reorderedStatus, done);
            zeroecho.pki.api.attr.AttributeId commandId =
                    new zeroecho.pki.api.attr.AttributeId("zeroecho.pki.full-crl.command-sha256");
            List<SimpleAttributeSet.Entry> noCommand = reordered.stream()
                    .filter(entry -> !entry.id().equals(commandId)).toList();
            List<SimpleAttributeSet.Entry> duplicateCommand = new ArrayList<>(noCommand);
            duplicateCommand.add(new SimpleAttributeSet.Entry(commandId, List.of(
                    new zeroecho.pki.api.attr.AttributeValue.StringValue(done.commandCommitment()),
                    new zeroecho.pki.api.attr.AttributeValue.StringValue(done.commandCommitment()))));
            for (zeroecho.pki.api.attr.AttributeSet invalid : List.of(
                    new SimpleAttributeSet(noCommand), new SimpleAttributeSet(duplicateCommand),
                    SimpleAttributeSet.builder().putAll(published.attributes())
                            .put(commandId, new zeroecho.pki.api.attr.AttributeValue.StringValue("f".repeat(64))).build(),
                    SimpleAttributeSet.builder().putAll(published.attributes())
                            .put(commandId, new zeroecho.pki.api.attr.AttributeValue.IntegerValue(1)).build(),
                    SimpleAttributeSet.builder().putAll(published.attributes())
                            .put(new zeroecho.pki.api.attr.AttributeId("unexpected"),
                                    new zeroecho.pki.api.attr.AttributeValue.StringValue("value")).build())) {
                assertThrows(DomainContinuationPublisher.PostconditionFailure.class,
                        () -> FullCrlContinuationPublisher.requirePublished(withAttributes(published, invalid), done,
                                published.content()));
            }
            for (zeroecho.pki.api.attr.AttributeId id : expected.attributes().ids()) {
                zeroecho.pki.api.attr.AttributeValue old = expected.attributes().getAll(id).getFirst();
                zeroecho.pki.api.attr.AttributeValue changed;
                if (old instanceof zeroecho.pki.api.attr.AttributeValue.IntegerValue number) {
                    changed = new zeroecho.pki.api.attr.AttributeValue.IntegerValue(number.value() + 1);
                } else {
                    int length = ((zeroecho.pki.api.attr.AttributeValue.StringValue) old).value().length();
                    changed = new zeroecho.pki.api.attr.AttributeValue.StringValue("f".repeat(length));
                }
                StatusObject mismatched = new StatusObject(published.statusObjectId(), published.formatId(),
                        published.issuerCaId(), published.type(), published.thisUpdate(), published.nextUpdate(),
                        published.content(), SimpleAttributeSet.builder().putAll(published.attributes()).put(id, changed).build());
                assertThrows(DomainContinuationPublisher.PostconditionFailure.class,
                        () -> FullCrlContinuationPublisher.requirePublished(mismatched, done, published.content()));
                assertThrows(DomainContinuationPublisher.PostconditionFailure.class,
                        () -> FullCrlSigningCommand.requireCompleted(mismatched, done));
            }
        }
        try (FilesystemPkiStore store = open(root)) {
            assertEquals(expected, FullCrlSnapshotProvenance.decode(store.getStatusObject(statusId).orElseThrow().attributes()));
            FullCrlSigningCommand.requireCompleted(store, store.getDomainContinuation(operation).orElseThrow());
        }
        Clock afterRetention = Clock.fixed(NOW.plus(Duration.ofDays(91)), ZoneOffset.UTC);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), afterRetention)) {
            assertEquals(1, store.purgeExpiredSignRecords());
            assertTrue(store.getSignWorkflow(operation).isEmpty());
            assertTrue(store.getDomainContinuation(operation).isEmpty());
            StatusObject retained = store.getStatusObject(statusId).orElseThrow();
            assertEquals(expected, FullCrlSnapshotProvenance.decode(retained.attributes()));
            assertTrue(retained.content().length() > 0);
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), afterRetention)) {
            assertEquals(expected, FullCrlSnapshotProvenance.decode(store.getStatusObject(statusId).orElseThrow().attributes()));
        }
    }

    @Test void currentCommandRejectsMissingOrNoncanonicalSnapshotCoordinates(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = open(root)) {
            Fixture fixture = fixture(store, "RSA", "SHA256withRSA", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, 0);
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(FullCrlSigningCommand.template(fixture.prepared()).command());
            List<String> oldFields = new ArrayList<>(command.fields());
            oldFields.removeLast();
            assertThrows(IllegalArgumentException.class, () -> FullCrlSigningCommand.validate(DomainCommandEncoding.decode(
                    DomainCommandEncoding.template(DomainContinuationStore.Kind.STATUS, command.operation(), oldFields.toArray(String[]::new)).command())));
            for (int field : new int[] {20, 21, 22, 30}) {
                List<String> changed = new ArrayList<>(command.fields());
                changed.set(field, field == 20 || field == 21 ? "01" : "A".repeat(field == 30 ? 32 : 64));
                assertThrows(IllegalArgumentException.class, () -> FullCrlSigningCommand.validate(DomainCommandEncoding.decode(
                        DomainCommandEncoding.template(DomainContinuationStore.Kind.STATUS, command.operation(), changed.toArray(String[]::new)).command())));
            }
        }
    }

    private static StatusObject withAttributes(StatusObject original, zeroecho.pki.api.attr.AttributeSet attributes) {
        return new StatusObject(original.statusObjectId(), original.formatId(), original.issuerCaId(), original.type(),
                original.thisUpdate(), original.nextUpdate(), original.content(), attributes);
    }

    static Fixture fixture(FilesystemPkiStore store, String keyAlgorithm, String signatureAlgorithm,
            AlgorithmIdentity identity, int entries) throws Exception {
        return fixture(store, keyAlgorithm, signatureAlgorithm, identity, entries, false);
    }

    static Fixture fixture(FilesystemPkiStore store, String keyAlgorithm, String signatureAlgorithm,
            AlgorithmIdentity identity, int entries, boolean delta) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm);
        if ("RSA".equals(keyAlgorithm)) { generator.initialize(2048); }
        KeyPair key = generator.generateKeyPair();
        X500Name name = new X500Name("CN=Full CRL Issuer");
        byte[] certificate = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(NOW.minusSeconds(60)), Date.from(NOW.plusSeconds(86400)), name, key.getPublic())
                .build(new JcaContentSignerBuilder(signatureAlgorithm).build(key.getPrivate())).getEncoded();
        PkiId credentialId = new PkiId("x509:" + DomainContinuationPublisher.sha256(certificate));
        PkiId generationId = IssuerGeneration.idFor(CA, credentialId);
        DurableContentReference issuer = PkiTestRuntime.stageCredential(store, certificate);
        store.putCredential(new Credential(credentialId, new FormatId("x509"),
                new IssuerRef(CA, generationId, IssuerChainPath.create(CA, generationId, List.of(credentialId)).pathId()),
                new SubjectRef("CN=Full CRL Issuer"), new Validity(NOW.minusSeconds(60), NOW.plusSeconds(86400)), "1",
                new PkiId("spki:test"), new CaProfileBinding(PROFILE), CredentialStatus.ISSUED, issuer,
                SimpleAttributeSet.builder().build()));
        store.putIssuerGeneration(new IssuerGeneration(generationId, CA, credentialId, KEY,
                IssuerGenerationState.ACTIVE, HASH, HASH));
        X509v2CRLBuilder builder = new X509v2CRLBuilder(name, Date.from(NOW));
        builder.setNextUpdate(Date.from(NOW.plusSeconds(3600)));
        Optional<zeroecho.pki.impl.core.DeltaCrlBase> base = Optional.empty();
        StatusObject baseStatus = null;
        String snapshotId = "snapshot:test";
        zeroecho.pki.spi.store.MetadataStoreId sourceId = new zeroecho.pki.spi.store.MetadataStoreId("102030405060708090a0b0c0d0e0f001");
        long revision = 1;
        long boundary = 1;
        String commitment = HASH;
        if (delta) {
            try (zeroecho.pki.spi.store.RevocationSnapshot snapshot = store.openRevocationSnapshot()) {
                snapshotId = snapshot.snapshotId();
                sourceId = snapshot.sourceStoreId();
                revision = snapshot.revision();
                boundary = snapshot.boundary();
                commitment = snapshot.commitment();
            }
            X509v2CRLBuilder baseBuilder = new X509v2CRLBuilder(name, Date.from(NOW.minusSeconds(1)));
            baseBuilder.setNextUpdate(Date.from(NOW.plusSeconds(3600)));
            baseBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber, false,
                    new org.bouncycastle.asn1.ASN1Integer(BigInteger.ONE));
            byte[] baseDer = baseBuilder.build(new JcaContentSignerBuilder(signatureAlgorithm).build(key.getPrivate())).getEncoded();
            DurableContentReference baseContent = PkiTestRuntime.stageCredential(store, baseDer);
            FullCrlSnapshotProvenance provenance = new FullCrlSnapshotProvenance(sourceId, revision, boundary, commitment);
            PkiId baseId = new PkiId("crl:" + baseContent.sha256());
            baseStatus = new StatusObject(baseId, new FormatId("x509"), CA, zeroecho.pki.api.status.StatusObjectType.CRL,
                    NOW.minusSeconds(1), Optional.of(NOW.plusSeconds(3600)), baseContent, provenance.attributes());
            base = Optional.of(new zeroecho.pki.impl.core.DeltaCrlBase(baseId, BigInteger.ONE, provenance));
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.cRLNumber, false,
                    new org.bouncycastle.asn1.ASN1Integer(BigInteger.TWO));
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator, true,
                    new org.bouncycastle.asn1.ASN1Integer(BigInteger.ONE));
        }
        for (int index = 1; index <= entries; index++) { builder.addCRLEntry(BigInteger.valueOf(index), Date.from(NOW.minusSeconds(1)), 1); }
        X509CRLHolder crl = builder.build(new JcaContentSignerBuilder(signatureAlgorithm).build(key.getPrivate()));
        DurableContentReference tbs = PkiTestRuntime.operationReference(store.stagedContent(), Encoding.DER,
                crl.toASN1Structure().getTBSCertList().getEncoded());
        PreparedFullCrlTbs prepared = new PreparedFullCrlTbs(CA, generationId, credentialId, PROFILE, issuer, HASH,
                HASH, HASH, KEY, identity.canonicalForm(), StandardX509Bindings.descriptors().stream()
                        .filter(binding -> binding.algorithmIdentity().equals(identity)).findFirst().orElseThrow(),
                StandardX509Bindings.catalog().resolve(identity, X509AlgorithmRole.SIGNATURE_ALGORITHM), delta ? BigInteger.TWO : BigInteger.ONE,
                NOW, NOW, NOW.plusSeconds(3600), snapshotId, sourceId, revision, boundary, commitment,
                OptionalLong.of(entries), entries, tbs, base);
        Fixture result = new Fixture(prepared, identity, new EncodedObject(Encoding.BINARY, crl.toASN1Structure().getSignature().getOctets()), crl.getEncoded());
        if (baseStatus != null) {
            registerCa(store, result);
            store.putStatusObject(baseStatus);
        }
        return result;
    }

    static FilesystemPkiStore open(Path root) { return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK); }

    static DefaultSemanticSigningService semantic(FilesystemPkiStore store, AlgorithmIdentity algorithm, long maximum) {
        SigningProvider provider = new SigningProvider() {
            @Override public String id() { return "crl-test"; }
            @Override public ConfigurationCommitment configurationCommitment() { return new ConfigurationCommitment(new byte[32]); }
            @Override public Set<String> supportedAlgorithms() { return Set.of(algorithm.canonicalForm()); }
            @Override public SigningInputCapabilities inputCapabilities() { return new SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of()); }
            @Override public OperationObservation dispatch(SignRequest request, CallControl control) { throw new AssertionError(); }
            @Override public OperationObservation reconcile(PkiId id, CallControl control) { throw new AssertionError(); }
            @Override public OperationObservation cancel(PkiId id, long fence, CancellationReason reason, CallControl control) { throw new AssertionError(); }
            @Override public void close() { }
        };
        DefaultSigningService signing = new DefaultSigningService(store, provider, algorithm, Duration.ofMinutes(1),
                new SecureRandom(), () -> { }, new DefaultSigningService.AcceptanceOperation() {
                    @Override public SignWorkflowStore.AcceptanceResult accept(SignWorkflowStore.AcceptanceCommand command, Runnable custody) {
                        custody.run(); return store.acceptSign(command);
                    }
                    @Override public SignWorkflowStore.AcceptanceResult acceptScheduled(SignWorkflowStore.AcceptanceCommand command,
                            zeroecho.pki.api.schedule.StatusScheduleState.Execution claim, Runnable custody) {
                        custody.run(); return store.acceptScheduledSign(command, claim);
                    }
                }, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
        return new DefaultSemanticSigningService(store, signing, PkiTestRuntime.endEntityPreparation(store, CLOCK), maximum);
    }

    static void sign(FilesystemPkiStore store, PkiId id, EncodedObject signature) {
        SignWorkflowStore.Workflow claimed = store.claimSignStep(id, 0, Duration.ofSeconds(10)).orElseThrow();
        store.transitionSign(id, claimed.revision(), claimed.fence(), SignWorkflowStore.State.SUCCEEDED,
                Optional.of("SIGNED"), Optional.of(signature), Optional.of(NOW)).orElseThrow();
    }

    static void registerCa(FilesystemPkiStore store, Fixture fixture) {
        PreparedFullCrlTbs prepared = fixture.prepared();
        IssuerChainPath path = IssuerChainPath.create(CA, prepared.issuerGenerationId(), List.of(prepared.issuerCredentialId()));
        store.putIssuerChainPath(path);
        store.putCa(new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, KEY, new SubjectRef("CN=Full CRL Issuer"),
                List.of(prepared.issuerGenerationId()), prepared.issuerGenerationId(), path.pathId()));
    }

    record Fixture(PreparedFullCrlTbs prepared, AlgorithmIdentity algorithm, EncodedObject signature, byte[] outer) { }
    private static final class SimulatedCrash extends RuntimeException { private static final long serialVersionUID = 1L; }
}
