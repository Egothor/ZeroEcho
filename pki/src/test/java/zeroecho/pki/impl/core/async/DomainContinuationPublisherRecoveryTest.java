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
package zeroecho.pki.impl.core.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static zeroecho.pki.testkit.PkiTestRuntime.signingAuthority;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

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
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;

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
            publisher.publish(publishing(store, create, "signing:rollover-create"),
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
            DomainContinuationStore.Record record = publishing(store, rollover, "signing:rollover-advance");
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
            publisher.publish(publishing(store, root, "signing:issuance-root"),
                    new EncodedObject(Encoding.DER, issuerCertificate.getEncoded()));
            zeroecho.pki.api.ca.CaRecord authority = store.listCas().getFirst();
            zeroecho.pki.api.ca.IssuerGeneration generation = store
                    .getIssuerGeneration(authority.currentIssuanceIssuerId()).orElseThrow();
            zeroecho.pki.api.ca.IssuerChainPath path = store
                    .getIssuerChainPath(authority.issuanceChainPathId()).orElseThrow();
            String fingerprint = DomainContinuationPublisher.sha256SubjectPublicKey(zeroecho.pkix.Pkix.parseCertificate(issued.getEncoded()));
            DomainContinuationTemplate issuance = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.ISSUANCE, "ISSUE_END_ENTITY",
                    authority.caId().value(), generation.issuerId().value(), path.pathId().value(),
                    path.pathCommitment(), "leaf", "1", DIGEST, "subject:issued",
                    NOT_BEFORE.toString(), NOT_AFTER.toString(), serial.toString(), "key:issued",
                    "content:issued", DIGEST, fingerprint, "", "", "CN=Issued", "[]", "[]", "[]",
                    "binding:test", EMPTY_EVIDENCE);
            DomainContinuationStore.Record record = publishing(store, issuance, "signing:issuance-recovery");
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
                DomainContinuationStore.Record record = publishing(store, template,
                        "signing:root-" + point.name().toLowerCase(java.util.Locale.ROOT));
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
    void crashBeforeOuterCompletionRestartsEveryDomainToCompletedAndReclaimed(@TempDir Path temporary)
            throws Exception {
        Map<String, Function<FilesystemPkiStore, Scenario>> scenarios = Map.of(
                "root", DomainContinuationPublisherRecoveryTest::rootScenario,
                "issuance", DomainContinuationPublisherRecoveryTest::issuanceScenario,
                "status", DomainContinuationPublisherRecoveryTest::statusScenario,
                "intermediate", DomainContinuationPublisherRecoveryTest::intermediateScenario);
        for (Map.Entry<String, Function<FilesystemPkiStore, Scenario>> entry : scenarios.entrySet()) {
            assertCompletionRestart(temporary.resolve(entry.getKey()), entry.getValue());
        }
    }

    private static void assertCompletionRestart(Path root,
            Function<FilesystemPkiStore, Scenario> scenarioFactory) throws Exception {
        PkiId operationId;
        DurableContentReference signingContent;
        Scenario scenario;
        Clock clock = Clock.fixed(NOT_BEFORE, ZoneOffset.UTC);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            scenario = scenarioFactory.apply(store);
            InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
            SignedParts signed = signedParts(scenario.result(), scenario.template().kind());
            operationId = persistSucceededDomain(store, workflow, scenario.template(), signed);
            signingContent = store.getDomainContinuation(operationId).orElseThrow().signingContent().orElseThrow();
            try (SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                    PkiSigningBus bus = PkiSigningBus.attach(store, workflow,
                            signingAuthority(workflow), runtime)) {
                DomainContinuationPublisher.installPublicationFault(point -> {
                    if (point == DomainContinuationPublisher.PublicationFaultPoint.BEFORE_CONTINUATION_DONE) {
                        throw new SimulatedCrash();
                    }
                });
                try {
                    assertThrows(SimulatedCrash.class, () -> bus.reconcileDomainContinuation(operationId));
                } finally {
                    DomainContinuationPublisher.clearPublicationFault();
                }
                assertEquals(DomainContinuationStore.State.PUBLISHING,
                        store.getDomainContinuation(operationId).orElseThrow().state());
            }
            workflow.close();
        }

        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), clock)) {
            InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(), false);
            try (SigningExecutionRuntime runtime = new SigningExecutionRuntime(1, 0,
                        Duration.ofMillis(100), Duration.ofMillis(100));
                    PkiSigningBus bus = PkiSigningBus.attach(reopened, workflow,
                            signingAuthority(workflow), runtime)) {
                assertTrue(bus.reconcileDomainContinuation(operationId));
                assertEquals(DomainContinuationStore.State.COMPLETED,
                        reopened.getDomainContinuation(operationId).orElseThrow().state());
                assertEquals(SignWorkflowStore.State.RETIRED,
                        reopened.getSignRecord(operationId).orElseThrow().state());
                assertThrows(java.io.IOException.class,
                        () -> reopened.stagedContent().openContent(signingContent));
                scenario.assertPublished().accept(reopened);
            }
            workflow.close();
        }
    }

    private static DomainContinuationStore.Record publishing(FilesystemPkiStore store,
            DomainContinuationTemplate template, String operationId) throws Exception {
        return publishing(store, template, operationId, new byte[] { 1 });
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

    private static Scenario rootScenario(FilesystemPkiStore store) {
        try {
            KeyPair key = rsa();
            X509CertificateHolder certificate = certificate(key, "CN=Lifecycle Root", BigInteger.valueOf(11L));
            DomainContinuationTemplate template = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.CA, "CREATE_ROOT", "x509", "subject:lifecycle-root", "root",
                    "key:lifecycle-root", "root", "1", DIGEST, NOT_BEFORE.toString(), NOT_AFTER.toString(), "11",
                    "CN=Lifecycle Root", "policy:test", "binding:test");
            return new Scenario(template, new EncodedObject(Encoding.DER, certificate.getEncoded()),
                    exact -> assertEquals(1, exact.listCas().size()));
        } catch (Exception failure) {
            throw new AssertionError(failure);
        }
    }

    private static Scenario statusScenario(FilesystemPkiStore store) {
        try {
            KeyPair issuerKey = rsa();
            X509CertificateHolder issuer = certificate(issuerKey, "CN=Lifecycle Status", BigInteger.valueOf(12L));
            Instant nextUpdate = NOT_BEFORE.plusSeconds(3600L);
            X509CRLHolder crl = new X509v2CRLBuilder(issuer.getSubject(), Date.from(NOT_BEFORE))
                    .setNextUpdate(Date.from(nextUpdate))
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate()));
            AttributeSet attributes = SimpleAttributeSet.builder()
                    .put(BcX509Attributes.ISSUER_CERT_DER,
                            new AttributeValue.BytesValue(issuer.getEncoded()))
                    .build();
            DomainContinuationTemplate template = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.STATUS, "GENERATE_STATUS", "ca:lifecycle-status", "CRL",
                    "x509-crl", NOT_BEFORE.toString(), nextUpdate.toString(), "key:lifecycle-status", "entries",
                    DIGEST, DomainAttributeEncoding.encode(attributes));
            return new Scenario(template, new EncodedObject(Encoding.DER, crl.getEncoded()),
                    exact -> assertEquals(1,
                            exact.listStatusObjects(new PkiId("ca:lifecycle-status")).size()));
        } catch (Exception failure) {
            throw new AssertionError(failure);
        }
    }

    private static Scenario issuanceScenario(FilesystemPkiStore store) {
        try {
            CaFixture issuer = publishRootFixture(store, "issuance");
            KeyPair subjectKey = rsa();
            BigInteger serial = BigInteger.valueOf(13L);
            X509CertificateHolder issued = issuedCertificate(issuer.certificate(), issuer.key(), subjectKey,
                    "CN=Lifecycle Issued", serial);
            String fingerprint = DomainContinuationPublisher.sha256SubjectPublicKey(zeroecho.pkix.Pkix.parseCertificate(issued.getEncoded()));
            DomainContinuationTemplate template = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.ISSUANCE, "ISSUE_END_ENTITY",
                    issuer.authorityId().value(), issuer.issuerId().value(), issuer.pathId().value(),
                    issuer.pathCommitment(), "leaf", "1", DIGEST, "subject:lifecycle-issued",
                    NOT_BEFORE.toString(), NOT_AFTER.toString(), serial.toString(), "key:lifecycle-issued",
                    "content:issuer", DIGEST, fingerprint, "", "", "CN=Lifecycle Issued", "[]", "[]", "[]",
                    "binding:test", EMPTY_EVIDENCE);
            PkiId credentialId = new PkiId("x509:" + DomainContinuationPublisher.sha256(issued.getEncoded()));
            return new Scenario(template, new EncodedObject(Encoding.DER, issued.getEncoded()),
                    exact -> assertEquals(credentialId,
                            exact.getCredential(credentialId).orElseThrow().credentialId()));
        } catch (Exception failure) {
            throw new AssertionError(failure);
        }
    }

    private static Scenario intermediateScenario(FilesystemPkiStore store) {
        try {
            CaFixture issuer = publishRootFixture(store, "intermediate");
            KeyPair subjectKey = rsa();
            BigInteger serial = BigInteger.valueOf(14L);
            X509CertificateHolder issued = issuedCertificate(issuer.certificate(), issuer.key(), subjectKey,
                    "CN=Lifecycle Intermediate", serial);
            PkiId subjectCaId = new PkiId("ca:lifecycle-intermediate");
            DomainContinuationTemplate template = DomainCommandEncoding.template(
                    DomainContinuationStore.Kind.CA, "CREATE_INTERMEDIATE", "x509",
                    issuer.authorityId().value(), subjectCaId.value(), issuer.issuerId().value(),
                    issuer.pathId().value(), issuer.pathCommitment(), "key:lifecycle-intermediate",
                    "intermediate", "1", DIGEST, "subject:lifecycle-intermediate",
                    NOT_BEFORE.toString(), NOT_AFTER.toString(), serial.toString(), "key:issuer", "content:issuer",
                    DIGEST, DomainContinuationPublisher.sha256SubjectPublicKey(zeroecho.pkix.Pkix.parseCertificate(issued.getEncoded())), "CN=Lifecycle Intermediate",
                    "policy:test", "binding:test");
            return new Scenario(template, new EncodedObject(Encoding.DER, issued.getEncoded()), exact -> {
                assertEquals(2, exact.listCas().size());
                assertEquals(subjectCaId, exact.getCa(subjectCaId).orElseThrow().caId());
            });
        } catch (Exception failure) {
            throw new AssertionError(failure);
        }
    }

    private static CaFixture publishRootFixture(FilesystemPkiStore store, String suffix) throws Exception {
        KeyPair key = rsa();
        X509CertificateHolder certificate = certificate(key, "CN=Lifecycle " + suffix, BigInteger.valueOf(20L));
        DomainContinuationTemplate template = DomainCommandEncoding.template(
                DomainContinuationStore.Kind.CA, "CREATE_ROOT", "x509", "subject:" + suffix, "root",
                "key:" + suffix, "root", "1", DIGEST, NOT_BEFORE.toString(), NOT_AFTER.toString(), "20",
                "CN=Lifecycle " + suffix, "policy:test", "binding:test");
        new DomainContinuationPublisher(store).publish(
                publishing(store, template, "signing:fixture-" + suffix),
                new EncodedObject(Encoding.DER, certificate.getEncoded()));
        zeroecho.pki.api.ca.CaRecord authority = store.listCas().getFirst();
        zeroecho.pki.api.ca.IssuerGeneration generation = store
                .getIssuerGeneration(authority.currentIssuanceIssuerId()).orElseThrow();
        zeroecho.pki.api.ca.IssuerChainPath path = store
                .getIssuerChainPath(authority.issuanceChainPathId()).orElseThrow();
        return new CaFixture(key, certificate, authority.caId(), generation.issuerId(), path.pathId(),
                path.pathCommitment());
    }

    private static PkiId persistSucceededDomain(FilesystemPkiStore store, SignatureWorkflow workflow,
            DomainContinuationTemplate template, SignedParts signed) {
        String namespace = store.signingNamespace() + "."
                + SigningExecutionSupport.workflowImplementationId(workflow);
        Instant createdAt = NOT_BEFORE.minusSeconds(60L);
        PkiId operationId = SigningSubmissionId.create(namespace, createdAt, new SecureRandom()).id();
        DurableContentReference reference;
        try (ContentSink sink = store.stagedContent().beginContent(Encoding.BINARY,
                    DurableContentReference.Lifecycle.OPERATION);
                OutputStream output = sink.outputStream()) {
            output.write(signed.toBeSigned());
            reference = sink.complete();
        } catch (java.io.IOException failure) {
            throw new AssertionError(failure);
        }
        AccessContext access = new AccessContext(new Principal("TEST", "owner"), new Purpose("SIGN"),
                Optional.empty(), Optional.empty());
        PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(access,
                "SHA256withRSA", reference, new KeyRef("key:test"), Encoding.BINARY,
                Optional.of(operationId));
        Instant deadline = createdAt.plusSeconds(300L);
        SignatureWorkflow.ConfigurationCommitment configuration = workflow.configurationCommitment();
        SignWorkflowStore.Record intent = new SignWorkflowStore.Record(operationId, namespace,
                continuation.semanticFingerprint(configuration, namespace, deadline), configuration,
                access.principal(), createdAt, deadline, continuation.encode(), SignWorkflowStore.State.INTENT,
                0L, 0L, Optional.empty(), Optional.of("INTENT"), Optional.empty(), Optional.empty(), 0,
                Optional.empty(), Optional.empty());
        DomainContinuationStore.Record domain = new DomainContinuationStore.Record(operationId, 2,
                template.kind(), template.correlationId(), DomainContinuationStore.State.SIGNING, 0L,
                createdAt, deadline, template.command(), template.commandCommitment(), Optional.of(reference),
                Optional.empty(), Optional.empty());
        try (SignWorkflowStore.SignAdmission admission = store.reserveSignAdmission(operationId)) {
            store.createSignIntent(admission, intent, domain);
        }
        SignWorkflowStore.Record claimed = store.tryClaimSign(operationId, 0L, Duration.ofSeconds(30L))
                .orElseThrow();
        SignWorkflowStore.Record dispatched = store.transitionSign(operationId, claimed.revision(), claimed.fence(),
                SignWorkflowStore.State.DISPATCHED, Optional.of("DISPATCHED"), Optional.empty(), Optional.empty())
                .orElseThrow();
        store.transitionSign(operationId, dispatched.revision(), dispatched.fence(),
                SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                Optional.of(new EncodedObject(Encoding.BINARY, signed.signature())),
                Optional.of(NOT_BEFORE.minusSeconds(1L))).orElseThrow();
        return operationId;
    }

    private static SignedParts signedParts(EncodedObject result, DomainContinuationStore.Kind kind) {
        try {
            if (kind == DomainContinuationStore.Kind.STATUS) {
                org.bouncycastle.asn1.x509.CertificateList crl = new X509CRLHolder(result.bytes())
                        .toASN1Structure();
                return new SignedParts(crl.getTBSCertList().getEncoded(), crl.getSignature().getOctets());
            }
            org.bouncycastle.asn1.x509.Certificate certificate = new X509CertificateHolder(result.bytes())
                    .toASN1Structure();
            return new SignedParts(certificate.getTBSCertificate().getEncoded(),
                    certificate.getSignature().getOctets());
        } catch (java.io.IOException failure) {
            throw new AssertionError(failure);
        }
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509CertificateHolder certificate(KeyPair key, String name, BigInteger serial) throws Exception {
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

    private record Scenario(DomainContinuationTemplate template, EncodedObject result,
            Consumer<FilesystemPkiStore> assertPublished) { }

    private record SignedParts(byte[] toBeSigned, byte[] signature) { }

    private record CaFixture(KeyPair key, X509CertificateHolder certificate, PkiId authorityId,
            PkiId issuerId, PkiId pathId, String pathCommitment) { }

    private static final class SimulatedCrash extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
