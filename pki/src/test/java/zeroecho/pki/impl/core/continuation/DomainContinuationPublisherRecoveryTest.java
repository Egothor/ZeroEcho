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
package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;

final class DomainContinuationPublisherRecoveryTest {
    private static final Instant NOT_BEFORE = Instant.parse("2026-08-20T10:00:00Z");
    private static final Instant NOT_AFTER = Instant.parse("2027-08-20T10:00:00Z");
    private static final String DIGEST = "1".repeat(64);
    // Continuation field 22 carries the co-committed issuance execution evidence; empty here.
    private static final String EMPTY_EVIDENCE = DomainAttributeEncoding.encode(
            zeroecho.pki.impl.core.attr.SimpleAttributeSet.builder().build());

    @Test
    void statusPublicationCrashReusesExactDurableObject(@TempDir Path temporary) throws Exception {
        KeyPair issuerKey = rsa();
        X509CertificateHolder issuer = certificate(issuerKey, "CN=Status Issuer", BigInteger.ONE);
        Instant nextUpdate = NOT_BEFORE.plusSeconds(3600);
        X509CRLHolder crl = new X509v2CRLBuilder(issuer.getSubject(), Date.from(NOT_BEFORE))
                .setNextUpdate(Date.from(nextUpdate))
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate()));
        AttributeSet attributes = SimpleAttributeSet.builder()
                .put(BcX509Attributes.ISSUER_CERT_DER,
                        new AttributeValue.BytesValue(issuer.getEncoded()))
                .build();
        DomainContinuationTemplate template = DomainCommandEncoding.template(
                DomainContinuationStore.Kind.STATUS, "GENERATE_STATUS", "ca:status", "CRL", "x509-crl",
                NOT_BEFORE.toString(), nextUpdate.toString(), "key:status", "entries:test", DIGEST,
                DomainAttributeEncoding.encode(attributes));

        try (FilesystemPkiStore store = new FilesystemPkiStore(temporary, FsPkiStoreOptions.defaults())) {
            DomainContinuationPublisher publisher = new DomainContinuationPublisher(store);
            DomainContinuationStore.Record record = publishing(store, template, "signing:status-recovery");
            DomainContinuationPublisher.installPublicationFault(point -> {
                if (point == DomainContinuationPublisher.PublicationFaultPoint.AFTER_STATUS) {
                    throw new SimulatedCrash();
                }
            });
            try {
                assertThrows(SimulatedCrash.class,
                        () -> publisher.publish(record, new EncodedObject(Encoding.DER, crl.getEncoded())));
            } finally {
                DomainContinuationPublisher.clearPublicationFault();
            }

            publisher.publish(record, new EncodedObject(Encoding.DER, crl.getEncoded()));

            assertEquals(1, store.listStatusObjects(new PkiId("ca:status")).size());
        }
    }

    @Test
    void ocspReconstructionReassemblesByteIdenticalDurableResponse(@TempDir Path temporary) throws Exception {
        KeyPair issuerKey = rsa();
        X509CertificateHolder issuer = certificate(issuerKey, "CN=OCSP Issuer", BigInteger.ONE);
        Instant nextUpdate = NOT_BEFORE.plusSeconds(3600L);
        BigInteger serial = BigInteger.valueOf(42L);

        // Build the OCSP response the way the generator's synchronous path does.
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID certId = new CertificateID(digests.get(CertificateID.HASH_SHA1), issuer, serial);
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(issuer.getSubject()));
        builder.addResponse(certId, CertificateStatus.GOOD, Date.from(NOT_BEFORE), Date.from(nextUpdate), null);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate());
        BasicOCSPResp basic = builder.build(signer, new X509CertificateHolder[0], Date.from(NOT_BEFORE));
        byte[] expected = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();

        BasicOCSPResponse asn1 = BasicOCSPResponse.getInstance(basic.getEncoded());
        byte[] tbsResponseData = asn1.getTbsResponseData().getEncoded();
        byte[] signatureOctets = asn1.getSignature().getOctets();
        byte[] algorithm = asn1.getSignatureAlgorithm().getEncoded();

        AttributeSet attributes = SimpleAttributeSet.builder()
                .put(BcX509Attributes.ISSUER_CERT_DER, new AttributeValue.BytesValue(issuer.getEncoded()))
                .build();
        DomainContinuationTemplate template = DomainCommandEncoding.template(
                DomainContinuationStore.Kind.STATUS, "GENERATE_STATUS", "ca:ocsp", "OCSP", "x509-crl",
                NOT_BEFORE.toString(), nextUpdate.toString(), "key:ocsp", "", "",
                DomainAttributeEncoding.encode(attributes), java.util.HexFormat.of().formatHex(algorithm));

        try (FilesystemPkiStore store = new FilesystemPkiStore(temporary, FsPkiStoreOptions.defaults())) {
            DomainContinuationPublisher publisher = new DomainContinuationPublisher(store);
            DomainContinuationStore.Record record = publishing(store, template, "signing:ocsp-recovery",
                    tbsResponseData);
            EncodedObject reconstructed = publisher.reconstruct(record,
                    new EncodedObject(Encoding.BINARY, signatureOctets.clone()));
            assertArrayEquals(expected, reconstructed.bytes());

            publisher.publish(record, reconstructed);
            assertEquals(1, store.listStatusObjects(new PkiId("ca:ocsp")).size());
        }
    }

    @Test
    void rootRolloverContinuationAdvancesExistingCaAndResumesAfterCrash(@TempDir Path temporary) throws Exception {
        KeyPair key = rsa();
        X509CertificateHolder original = certificate(key, "CN=Rollover Root", BigInteger.valueOf(30L));
        DomainContinuationTemplate create = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                "CREATE_ROOT", "x509", "subject:rollover", "root", "key:rollover", "root", "1", DIGEST,
                NOT_BEFORE.toString(), NOT_AFTER.toString(), "30", "CN=Rollover Root", "policy:test", "binding:test");

        try (FilesystemPkiStore store = new FilesystemPkiStore(temporary, FsPkiStoreOptions.defaults())) {
            DomainContinuationPublisher publisher = new DomainContinuationPublisher(store);
            publisher.publish(publishingCertificate(store, create, "rollover-create", original),
                    new EncodedObject(Encoding.DER, original.getEncoded()));
            zeroecho.pki.api.ca.CaRecord before = store.listCas().getFirst();
            PkiId caId = before.caId();
            PkiId originalGeneration = before.currentIssuanceIssuerId();

            // Rollover: a new self-signed certificate for the SAME subject and key, new serial.
            X509CertificateHolder rolled = certificate(key, "CN=Rollover Root", BigInteger.valueOf(31L));
            DomainContinuationTemplate rollover = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                    "ROLLOVER_ROOT", "x509", "subject:rollover", "root", "key:rollover", "root", "1", DIGEST,
                    NOT_BEFORE.toString(), NOT_AFTER.toString(), "31", "CN=Rollover Root", "policy:test",
                    "binding:test", caId.value());
            DomainContinuationStore.Record record = publishingCertificate(store, rollover, "rollover-advance", rolled);
            DomainContinuationPublisher.installPublicationFault(point -> {
                if (point == DomainContinuationPublisher.PublicationFaultPoint.AFTER_CHAIN_PATH) {
                    throw new SimulatedCrash();
                }
            });
            try {
                assertThrows(SimulatedCrash.class, () -> publisher.publish(record,
                        new EncodedObject(Encoding.DER, rolled.getEncoded())));
            } finally {
                DomainContinuationPublisher.clearPublicationFault();
            }

            publisher.publish(record, new EncodedObject(Encoding.DER, rolled.getEncoded()));

            zeroecho.pki.api.ca.CaRecord after = store.getCa(caId).orElseThrow();
            assertNotEquals(originalGeneration, after.currentIssuanceIssuerId(),
                    "rollover advances the current generation");
            assertEquals(2, after.issuerIds().size(), "both generations retained");
            assertTrue(after.issuerIds().contains(originalGeneration), "historical generation retained");
            assertTrue(after.issuerIds().contains(after.currentIssuanceIssuerId()), "new generation is current");
        }
    }

    @Test
    void issuancePublicationCrashReusesExactDurableCredential(@TempDir Path temporary) throws Exception {
        KeyPair issuerKey = rsa();
        X509CertificateHolder issuerCertificate = certificate(issuerKey, "CN=Issuer", BigInteger.ONE);
        KeyPair subjectKey = rsa();
        BigInteger serial = BigInteger.valueOf(3L);
        X509CertificateHolder issued = issuedCertificate(issuerCertificate, issuerKey, subjectKey,
                "CN=Issued", serial);
        DomainContinuationTemplate root = DomainCommandEncoding.template(
                DomainContinuationStore.Kind.CA, "CREATE_ROOT", "x509", "subject:issuer", "root", "key:issuer",
                "root", "1", DIGEST, NOT_BEFORE.toString(), NOT_AFTER.toString(), "1",
                "CN=Issuer", "policy:test", "binding:test");

        try (FilesystemPkiStore store = new FilesystemPkiStore(temporary, FsPkiStoreOptions.defaults())) {
            DomainContinuationPublisher publisher = new DomainContinuationPublisher(store);
            publisher.publish(publishingCertificate(store, root, "issuance-root", issuerCertificate),
                    new EncodedObject(Encoding.DER, issuerCertificate.getEncoded()));
            zeroecho.pki.api.ca.CaRecord authority = store.listCas().getFirst();
            zeroecho.pki.api.ca.IssuerGeneration generation = store
                    .getIssuerGeneration(authority.currentIssuanceIssuerId()).orElseThrow();
            zeroecho.pki.api.ca.IssuerChainPath path = store
                    .getIssuerChainPath(authority.issuanceChainPathId()).orElseThrow();
            String fingerprint = DomainContinuationPublisher.sha256SubjectPublicKey(zeroecho.pkix.Pkix.parseCertificate(issued.getEncoded()));
            zeroecho.pki.api.credential.Credential issuerCredential = store.getCredential(generation.credentialId()).orElseThrow();
            DomainContinuationTemplate issuance = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.ISSUANCE, "ISSUE_END_ENTITY",
                    authority.caId().value(), generation.issuerId().value(), path.pathId().value(),
                    path.pathCommitment(), "leaf", "1", DIGEST, "subject:issued",
                    NOT_BEFORE.toString(), NOT_AFTER.toString(), serial.toString(), generation.signingKeyRef().value(),
                    issuerCredential.content().contentId(), issuerCredential.content().sha256(), fingerprint, "", "", "CN=Issued", "[]", "[]", "[]",
                    "binding:test", EMPTY_EVIDENCE);
            DomainContinuationStore.Record record = publishingCertificate(store, issuance, "issuance-recovery", issued);
            DomainContinuationPublisher.installPublicationFault(point -> {
                if (point == DomainContinuationPublisher.PublicationFaultPoint.AFTER_CREDENTIAL) {
                    throw new SimulatedCrash();
                }
            });
            try {
                assertThrows(SimulatedCrash.class,
                        () -> publisher.publish(record, new EncodedObject(Encoding.DER, issued.getEncoded())));
            } finally {
                DomainContinuationPublisher.clearPublicationFault();
            }

            publisher.publish(record, new EncodedObject(Encoding.DER, issued.getEncoded()));

            PkiId credentialId = new PkiId("x509:" + DomainContinuationPublisher.sha256(issued.getEncoded()));
            assertEquals(credentialId, store.getCredential(credentialId).orElseThrow().credentialId());
            zeroecho.pki.spi.store.SignWorkflowStore.Workflow workflow = store.getSignWorkflow(record.operationId()).orElseThrow();
            zeroecho.pki.api.signing.SemanticSigningScope scope = new zeroecho.pki.api.signing.SemanticSigningScope(
                    zeroecho.pki.api.signing.SemanticSigningKind.ISSUANCE, "ISSUE_END_ENTITY",
                    workflow.envelope().accessContext(), generation.signingKeyRef(), Optional.of(authority.caId()),
                    Optional.empty(), Optional.of("leaf"), Optional.empty());
            byte[] retainedDer = issued.getEncoded();
            zeroecho.pki.api.signing.SemanticSigningOperation completed = new zeroecho.pki.api.signing.SemanticSigningOperation(
                    zeroecho.pki.api.orch.SigningSubmissionId.parse(record.operationId()), scope,
                    zeroecho.pki.api.signing.SigningOperationState.SUCCEEDED,
                    zeroecho.pki.api.signing.SemanticSigningState.COMPLETED, workflow.revision(), record.revision(),
                    record.createdAt(), record.deadline(), Optional.of("COMPLETED"),
                    Optional.of(new EncodedObject(Encoding.DER, retainedDer)));
            retainedDer[0] ^= 1;
            completed.result().orElseThrow().bytes()[0] ^= 1;
            assertEquals(Optional.of(credentialId), completed.completedCredentialId());
            assertEquals(credentialId, store.getCredential(completed.completedCredentialId().orElseThrow())
                    .orElseThrow().credentialId());
        }
    }

    @Test
    void rootPublicationResumesEveryExactDurablePrefix(@TempDir Path temporary) throws Exception {
        for (DomainContinuationPublisher.PublicationFaultPoint point : new DomainContinuationPublisher.PublicationFaultPoint[] {
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CREDENTIAL,
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_ISSUER_GENERATION,
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CHAIN_PATH,
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CA }) {
            Path root = temporary.resolve(point.name().toLowerCase(java.util.Locale.ROOT));
            KeyPair key = rsa();
            X509CertificateHolder certificate = certificate(key, "CN=Root", BigInteger.TWO);
            DomainContinuationTemplate template = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.CA, "CREATE_ROOT", "x509", "subject:root", "root", "key:root",
                    "root", "1", DIGEST, NOT_BEFORE.toString(), NOT_AFTER.toString(), "2",
                    "CN=Root", "policy:test", "binding:test");
            try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
                DomainContinuationPublisher publisher = new DomainContinuationPublisher(store);
                DomainContinuationStore.Record record = publishingCertificate(store, template,
                        "root-" + point.name().toLowerCase(java.util.Locale.ROOT), certificate);
                DomainContinuationPublisher.installPublicationFault(observed -> {
                    if (observed == point) {
                        throw new SimulatedCrash();
                    }
                });
                try {
                    assertThrows(SimulatedCrash.class, () -> publisher.publish(record,
                            new EncodedObject(Encoding.DER, certificate.getEncoded())));
                } finally {
                    DomainContinuationPublisher.clearPublicationFault();
                }

                publisher.publish(record, new EncodedObject(Encoding.DER, certificate.getEncoded()));

                assertEquals(1, store.listCas().size());
                assertEquals(1, store.listIssuerGenerations(store.listCas().getFirst().caId()).size());
            }
        }
    }

    @Test
    void signingOwnerRejectsChangedCertificateCommitmentAndOperation(@TempDir Path root) throws Exception {
        KeyPair key = rsa();
        X509CertificateHolder certificate = certificate(key, "CN=Exact Root", BigInteger.TWO);
        DomainContinuationTemplate template = DomainCommandEncoding.template(
                DomainContinuationStore.Kind.CA, "CREATE_ROOT", "x509", "subject:root", "root", "key:root",
                "root", "1", DIGEST, NOT_BEFORE.toString(), NOT_AFTER.toString(), "2",
                "CN=Exact Root", "policy:test", "binding:test");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            DomainContinuationStore.Record domain = publishingCertificate(store, template, "exact-owner", certificate);
            new DomainContinuationPublisher(store).publish(domain, new EncodedObject(Encoding.DER, certificate.getEncoded()));
            zeroecho.pki.api.ca.CaRecord ca = store.listCas().getFirst();
            zeroecho.pki.api.credential.Credential original = store.getCredential(store.getIssuerGeneration(
                    ca.currentIssuanceIssuerId()).orElseThrow().credentialId()).orElseThrow();
            store.putCredentialFromSigning(original, domain.operationId(), domain.commandCommitment());
            assertThrows(IllegalStateException.class, () -> store.putCredential(original));
            assertThrows(IllegalStateException.class, () -> store.putCredentialFromSigning(original,
                    domain.operationId(), "domain:v1:" + "ff".repeat(32)));
            PkiId absent = zeroecho.pki.api.orch.SigningSubmissionId.create(store.signingNamespace() + ".publication-test",
                    store.signingNow(), new java.security.SecureRandom()).id();
            assertThrows(IllegalStateException.class, () -> store.putCredentialFromSigning(original,
                    absent, domain.commandCommitment()));
            byte[] changed = certificate(key, "CN=Changed", BigInteger.TWO).getEncoded();
            zeroecho.pki.api.credential.Credential different = new zeroecho.pki.api.credential.Credential(
                    original.credentialId(), original.formatId(), original.issuerRef(), original.subjectRef(), original.validity(),
                    original.serialOrUniqueId(), original.publicKeyId(), original.profileBinding(), original.status(),
                    zeroecho.pki.testkit.PkiTestRuntime.stageCredential(store, changed), original.attributes());
            assertThrows(IllegalStateException.class, () -> store.putCredentialFromSigning(different,
                    domain.operationId(), domain.commandCommitment()));
        }
    }

    private static DomainContinuationStore.Record publishing(FilesystemPkiStore store,
            DomainContinuationTemplate template, String operationId) throws Exception {
        return publishing(store, template, operationId, new byte[] { 1 });
    }

    @Test
    void signedReservationSurvivesPurgeSnapshotRemintingAndReexport(@TempDir Path root) throws Exception {
        java.util.concurrent.atomic.AtomicReference<Instant> now = new java.util.concurrent.atomic.AtomicReference<>(NOT_BEFORE);
        java.time.Clock clock = new java.time.Clock() {
            @Override public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }
            @Override public java.time.Clock withZone(java.time.ZoneId zone) { return java.time.Clock.fixed(now.get(), zone); }
            @Override public Instant instant() { return now.get(); }
        };
        KeyPair key = rsa();
        X509CertificateHolder certificate = certificate(key, "CN=Snapshot Root", BigInteger.TWO);
        DomainContinuationTemplate template = DomainCommandEncoding.template(
                DomainContinuationStore.Kind.CA, "CREATE_ROOT", "x509", "subject:root", "root", "key:root",
                "root", "1", DIGEST, NOT_BEFORE.toString(), NOT_AFTER.toString(), "2",
                "CN=Snapshot Root", "policy:test", "binding:test");
        PkiId credentialId;
        String originalContentId;
        Path snapshot = root.resolve("snapshot");
        Path reexport = root.resolve("reexport");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root.resolve("source"), FsPkiStoreOptions.defaults(), clock)) {
            DomainContinuationStore.Record domain = publishingCertificate(store, template, "snapshot-root", certificate);
            new SigningOuterTerminalDriver(store).advance(store.getSignWorkflow(domain.operationId()).orElseThrow());
            zeroecho.pki.api.ca.CaRecord ca = store.listCas().getFirst();
            credentialId = store.getIssuerGeneration(ca.currentIssuanceIssuerId()).orElseThrow().credentialId();
            originalContentId = store.getCredential(credentialId).orElseThrow().content().contentId();
            now.set(NOT_BEFORE.plus(java.time.Duration.ofDays(91)));
            assertEquals(1, store.purgeExpiredSignRecords());
            store.exportSnapshot(snapshot, Instant.now());
        }
        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshot, FsPkiStoreOptions.defaults(), clock)) {
            zeroecho.pki.api.credential.Credential credential = restored.getCredential(credentialId).orElseThrow();
            org.junit.jupiter.api.Assertions.assertNotEquals(originalContentId, credential.content().contentId());
            assertThrows(IllegalStateException.class, () -> restored.putCredential(credential));
            restored.exportSnapshot(reexport, Instant.now());
        }
        try (FilesystemPkiStore restored = new FilesystemPkiStore(reexport, FsPkiStoreOptions.defaults(), clock)) {
            zeroecho.pki.api.credential.Credential credential = restored.getCredential(credentialId).orElseThrow();
            assertThrows(IllegalStateException.class, () -> restored.putCredential(credential));
            assertArrayEquals(certificate.getEncoded(), credentialBytes(restored, credential));
        }
    }

    private static byte[] credentialBytes(FilesystemPkiStore store, zeroecho.pki.api.credential.Credential credential)
            throws Exception {
        try (zeroecho.core.io.RepeatableContent content = store.stagedContent().openContent(credential.content());
                java.io.InputStream input = content.openStream()) {
            return input.readAllBytes();
        }
    }

    static DomainContinuationStore.Record publishingCertificate(FilesystemPkiStore store,
            DomainContinuationTemplate template, String correlation, X509CertificateHolder certificate) throws Exception {
        return publishingCertificate(store, template, correlation, certificate, "SHA256withRSA");
    }

    static DomainContinuationStore.Record publishingCertificate(FilesystemPkiStore store,
            DomainContinuationTemplate template, String correlation, X509CertificateHolder certificate, String algorithm)
            throws Exception {
        Instant now = store.signingNow();
        String namespace = store.signingNamespace() + ".publication-test";
        PkiId operation = zeroecho.pki.api.orch.SigningSubmissionId.create(namespace, now,
                new java.security.SecureRandom()).id();
        DomainCommandEncoding.Decoded decoded = DomainCommandEncoding.decode(template.command());
        boolean root = "CREATE_ROOT".equals(decoded.operation()) || "ROLLOVER_ROOT".equals(decoded.operation());
        if (root) {
            zeroecho.pki.api.profile.CertificateProfileDefinition definition = zeroecho.pki.testkit.RootCreationFixture.definition(
                    decoded.field(4), zeroecho.pki.api.profile.CertificateProfileKind.ROOT_CA, java.time.Duration.ofDays(365),
                    zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.standardOnly());
            byte[] canonical = zeroecho.pki.api.profile.CertificateProfileDocumentCodec.writeCanonical(definition);
            zeroecho.pki.api.profile.CertificateProfileRef profile = new zeroecho.pki.api.profile.CertificateProfileRef(
                    definition.profileId(), definition.profileVersion(), java.security.MessageDigest.getInstance("SHA-256").digest(canonical));
            if (store.getProfileVersion(definition.profileId(), definition.profileVersion()).isEmpty()) {
                store.importProfileVersion(new zeroecho.pki.api.profile.ImportedCertificateProfileVersion(profile,
                        zeroecho.pki.api.profile.CertificateProfileDefinition.SCHEMA_VERSION, definition, canonical, NOT_BEFORE));
            }
            java.util.List<String> fields = new java.util.ArrayList<>(decoded.fields());
            fields.set(6, java.util.HexFormat.of().formatHex(profile.canonicalSha256()));
            template = DomainCommandEncoding.template(template.kind(), decoded.operation(), fields.toArray(String[]::new));
            decoded = DomainCommandEncoding.decode(template.command());
        }
        if ("CREATE_ROOT".equals(decoded.operation())) {
            java.util.List<String> fields = new java.util.ArrayList<>(decoded.fields());
            fields.add(DomainCommandEncoding.rootAuthorityId(operation).value());
            template = DomainCommandEncoding.template(template.kind(), decoded.operation(), fields.toArray(String[]::new));
            decoded = DomainCommandEncoding.decode(template.command());
        }
        boolean issuance = template.kind() == DomainContinuationStore.Kind.ISSUANCE;
        DurableContentReference tbs = zeroecho.pki.testkit.PkiTestRuntime.operationReference(store.stagedContent(),
                Encoding.DER, certificate.toASN1Structure().getTBSCertificate().getEncoded());
        zeroecho.pki.api.audit.AccessContext access = new zeroecho.pki.api.audit.AccessContext(
                new zeroecho.pki.api.audit.Principal("TEST", "publisher"), new zeroecho.pki.api.audit.Purpose("SIGN"),
                Optional.empty(), Optional.empty());
        zeroecho.pki.spi.store.SignWorkflowStore.OuterCommand outer = new zeroecho.pki.spi.store.SignWorkflowStore.OuterCommand(
                template.kind(), correlation, template.command(), template.commandCommitment());
        zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceCommand command = new zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceCommand(
                operation, namespace, new zeroecho.pki.spi.crypto.SigningProvider.ConfigurationCommitment(new byte[32]),
                access, new zeroecho.pki.api.KeyRef(decoded.field(root ? 3 : issuance ? 11 : 14)),
                new PkiId(decoded.field(root ? 13 : issuance ? 0 : 1)), algorithm, Encoding.BINARY,
                now, now.plusSeconds(60), tbs, Optional.of(outer),
                zeroecho.pki.spi.store.SignWorkflowStore.Mode.NORMAL, Optional.empty());
        assertEquals(zeroecho.pki.spi.store.SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(command));
        zeroecho.pki.spi.store.SignWorkflowStore.Workflow claimed = store.claimSignStep(operation, 0,
                java.time.Duration.ofSeconds(10)).orElseThrow();
        store.transitionSign(operation, claimed.revision(), claimed.fence(), zeroecho.pki.spi.store.SignWorkflowStore.State.SUCCEEDED,
                Optional.of("SIGNED"), Optional.of(new EncodedObject(Encoding.BINARY, certificate.getSignature())),
                Optional.of(now)).orElseThrow();
        return store.transitionDomainContinuation(operation, 0, DomainContinuationStore.State.PUBLISHING,
                Optional.empty(), Optional.empty()).orElseThrow();
    }

    private static DomainContinuationStore.Record publishing(FilesystemPkiStore store,
            DomainContinuationTemplate template, String operationId, byte[] signingContent) throws Exception {
        DurableContentReference content;
        try (ContentSink sink = store.stagedContent().beginContent(Encoding.BINARY,
                DurableContentReference.Lifecycle.OPERATION); OutputStream output = sink.outputStream()) {
            output.write(signingContent);
            content = sink.complete();
        }
        return new DomainContinuationStore.Record(new PkiId(operationId), 2, template.kind(),
                template.correlationId(), DomainContinuationStore.State.PUBLISHING, 1L,
                NOT_BEFORE.minusSeconds(60), NOT_AFTER, template.command(), template.commandCommitment(),
                Optional.of(content), Optional.empty(), Optional.empty());
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static X509CertificateHolder certificate(KeyPair key, String name, BigInteger serial) throws Exception {
        X500Name subject = new X500Name(name);
        return new JcaX509v3CertificateBuilder(subject, serial, Date.from(NOT_BEFORE), Date.from(NOT_AFTER),
                subject, key.getPublic()).build(
                        new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate()));
    }

    private static X509CertificateHolder issuedCertificate(X509CertificateHolder issuer, KeyPair issuerKey,
            KeyPair subjectKey, String subjectName, BigInteger serial) throws Exception {
        return new JcaX509v3CertificateBuilder(issuer.getSubject(), serial, Date.from(NOT_BEFORE),
                Date.from(NOT_AFTER), new X500Name(subjectName), subjectKey.getPublic()).build(
                        new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate()));
    }

    private static final class SimulatedCrash extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
