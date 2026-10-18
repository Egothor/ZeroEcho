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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.IssuanceApprovalRequirement;
import zeroecho.pki.api.request.ProofOfPossessionReason;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.impl.core.DefaultCertificationRequestService;
import zeroecho.pki.impl.framework.x509.bc.BcX509CertificationRequestParser;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.server.acme.AcmeControlStore;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.CmpTransaction;
import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;
import zeroecho.pki.server.enrollment.EnrollmentRuntime;
import zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.ProofOfPossessionVerifier;

/** Durable protocol identity, approvals, receipt ordering and restart contracts. */
class EnrollmentCoordinatorTest {
    @TempDir Path directory;
    private static byte[] csr;
    private static byte[] crmf;
    private static byte[] replacementCrmf;
    private static byte[] keygenRecipientDer;
    private static KeyPair keygenSigner;
    private static final PkiId AUTHORITY = new PkiId("ca:enrollment");
    private static final PkiId ISSUER = new PkiId("issuer:enrollment");

    @BeforeAll static void request() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        keygenSigner = pair;
        javax.security.auth.x500.X500Principal name = new javax.security.auth.x500.X500Principal("CN=Keygen Recipient");
        keygenRecipientDer = zeroecho.pkix.Pkix.certificateBuilder().subject(name).issuer(name).serialNumber(java.math.BigInteger.ONE)
                .publicKey(pair.getPublic()).validity(ServerTestSupport.CLOCK.instant().minusSeconds(60), ServerTestSupport.CLOCK.instant().plusSeconds(3600))
                .basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(), true).keyUsage(Set.of(zeroecho.pkix.KeyUsage.KEY_ENCIPHERMENT), true)
                .build(zeroecho.pkix.Pkix.signer(pair.getPrivate(), zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11"))).getEncoded();
        csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Applicant"), pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())).getEncoded();
        crmf = new org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder(java.math.BigInteger.valueOf(7))
                .setSubject(new X500Name("CN=Applicant"))
                .setPublicKey(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()))
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())).build().getEncoded();
        replacementCrmf = new org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder(java.math.BigInteger.valueOf(7))
                .setSubject(new X500Name("CN=Applicant"))
                .setPublicKey(org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()))
                .addControl(new org.bouncycastle.cert.crmf.Control() {
                    @Override public org.bouncycastle.asn1.ASN1ObjectIdentifier getType() { return org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers.id_regCtrl_oldCertID; }
                    @Override public org.bouncycastle.asn1.ASN1Encodable getValue() { return new org.bouncycastle.asn1.crmf.CertId(
                            new org.bouncycastle.asn1.x509.GeneralName(new X500Name("CN=Issuer")), java.math.BigInteger.ONE); }
                })
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())).build().getEncoded();
    }

    @Test void estServicePersistsEncryptedGeneratedKeyBeforeApprovalAndNeverRegeneratesOnRetry() throws Exception {
        EnrollmentRuntimeConfiguration base = keygenConfiguration(directory.resolve("encrypted"), 3, 64, 1);
        EnrollmentRuntimeConfiguration config = new EnrollmentRuntimeConfiguration(base.budgets(), base.keyrings(), base.credentialSets(), base.activeCredentials(),
                Optional.of(new EnrollmentRuntimeConfiguration.KeygenArtifacts(directory.resolve("encrypted"), 16_384, 32_768, 3, 1, Duration.ofMinutes(10))));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("domain"), 1, ServerTestSupport.CLOCK, config)) {
            KeygenInput input = keygenInput(fixture, "a");
            org.bouncycastle.pkcs.PKCS10CertificationRequest original = new org.bouncycastle.pkcs.PKCS10CertificationRequest(input.admission().payload().der());
            org.bouncycastle.asn1.ASN1EncodableVector attributes = new org.bouncycastle.asn1.ASN1EncodableVector();
            for (org.bouncycastle.asn1.pkcs.Attribute attribute : original.getAttributes()) attributes.add(attribute);
            org.bouncycastle.asn1.x509.Extensions extensions = new org.bouncycastle.asn1.x509.Extensions(
                    new org.bouncycastle.asn1.x509.Extension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                            new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(
                                    org.bouncycastle.asn1.x509.GeneralName.dNSName, "app.example.test")).getEncoded()));
            attributes.add(new org.bouncycastle.asn1.pkcs.Attribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    new org.bouncycastle.asn1.DERSet(extensions)));
            org.bouncycastle.asn1.pkcs.CertificationRequestInfo info = new org.bouncycastle.asn1.pkcs.CertificationRequestInfo(original.getSubject(),
                    new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                            new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4")), new byte[] {1}), new org.bouncycastle.asn1.DERSet(attributes));
            byte[] template = new org.bouncycastle.asn1.pkcs.CertificationRequest(info, original.getSignatureAlgorithm(),
                    new org.bouncycastle.asn1.DERBitString(new byte[] {1})).getEncoded("DER");
            EnrollmentRuntime.CredentialLease lease = mock(EnrollmentRuntime.CredentialLease.class);
            when(lease.privateKey()).thenReturn(keygenSigner.getPrivate());
            java.security.cert.X509Certificate recipient = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(keygenRecipientDer));
            when(lease.responseChain()).thenReturn(List.of(recipient));
            when(fixture.runtime.acquire("est-generator")).thenReturn(lease);
            ServerRealmContext context = mock(ServerRealmContext.class);
            when(context.configuration()).thenReturn(fixture.realm);
            when(context.session()).thenReturn(fixture.session);
            when(context.enrollmentEndpoints()).thenReturn(fixture.endpoints);
            when(context.enrollmentCoordinator()).thenReturn(Optional.of(fixture.coordinator));
            when(context.enrollmentRuntime()).thenReturn(Optional.of(fixture.runtime));
            zeroecho.pki.server.est.EstService service = new zeroecho.pki.server.est.EstService(context);
            EstEndpoint endpoint = (EstEndpoint) fixture.endpoints.find(EnrollmentEndpointRegistry.Protocol.EST, "est").orElseThrow();
            assertEquals(503, assertThrows(zeroecho.pki.server.est.EstProtocolException.class,
                    () -> service.serverkeygen(endpoint, template, recipient, () -> true)).httpStatus());
            org.mockito.Mockito.verify(fixture.runtime, org.mockito.Mockito.never()).acquire(any());
            assertEquals(0, opened.store().protocolRecords(ServerControlStore.ENROLLMENT_KEYGEN, 0, 10).values().size());
            zeroecho.pki.server.est.EstServerKeygenResponse first = service.serverkeygen(endpoint, template, recipient);
            assertEquals(202, first.status());
            EnrollmentTransaction enrollment = fixture.coordinator.list(0, 10).values().getFirst();
            assertEquals(EnrollmentTransaction.State.PENDING, enrollment.state());
            byte[] generated = fixture.requests.encodedX509Request(fixture.requests.get(enrollment.intent().requestId()).orElseThrow()).der();
            zeroecho.pkix.csr.CertificationRequest proved = zeroecho.pkix.Pkix.parseCsr(generated);
            assertEquals("RSA", proved.publicKey().getAlgorithm());
            assertEquals(1, proved.requestedSubjectAlternativeNames().size());
            assertEquals("2.5.29.17", proved.requestedExtensions().getFirst().oid());
            assertTrue(proved.attributes().isEmpty());
            byte[] ciphertext = java.nio.file.Files.readAllBytes(directory.resolve("encrypted").resolve(enrollment.intent().artifact().orElseThrow().artifactId() + ".cms"));
            assertTrue(ciphertext.length > 1024);
            zeroecho.pki.server.est.EstServerKeygenResponse retry = service.serverkeygen(endpoint, template, recipient);
            assertEquals(202, retry.status());
            assertEquals(1, fixture.coordinator.list(0, 10).values().size());
            org.mockito.Mockito.verify(fixture.runtime).acquire("est-generator");
            org.mockito.Mockito.verify(lease).close();
            org.mockito.Mockito.verify(fixture.signing, org.mockito.Mockito.never()).accept(any());
            assertArrayEquals(ciphertext, java.nio.file.Files.readAllBytes(directory.resolve("encrypted").resolve(enrollment.intent().artifact().orElseThrow().artifactId() + ".cms")));
            java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean();
            when(fixture.runtime.acquire("est-generator")).thenAnswer(invocation -> { cancelled.set(true); return lease; });
            byte[] interruptedTemplate = keygenInput(fixture, "b").admission().payload().der();
            assertEquals(503, assertThrows(zeroecho.pki.server.est.EstProtocolException.class,
                    () -> service.serverkeygen(endpoint, interruptedTemplate, recipient, cancelled::get)).httpStatus());
            assertEquals(500, service.serverkeygen(endpoint, interruptedTemplate, recipient).status());
            org.mockito.Mockito.verify(fixture.runtime, org.mockito.Mockito.times(2)).acquire("est-generator");
            org.mockito.Mockito.verify(fixture.signing, org.mockito.Mockito.never()).accept(any());
        }
    }

    @Test void keygenGeneratedRequestStillRequiresValidProofDespiteIgnoredOriginalSignature() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 2, 32, 1);
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("domain"), 1, ServerTestSupport.CLOCK, config)) {
            KeygenInput input = keygenInput(fixture, "a");
            org.mockito.Mockito.doAnswer(invocation -> {
                try { zeroecho.pkix.Pkix.parseCsr(fixture.requests.encodedX509Request(invocation.getArgument(0)).der()); }
                catch (zeroecho.pkix.CertificationRequestException invalid) { throw new IllegalArgumentException("Invalid generated proof"); }
                return null;
            }).when(fixture.requests).requireProfileProof(any(), any());
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(input.admission(), input.recipient())) {
                org.mockito.Mockito.verify(fixture.requests, org.mockito.Mockito.never()).requireProfileProof(any(), any());
                byte[] invalid = csr.clone(); invalid[invalid.length - 1] ^= 1;
                assertThrows(RuntimeException.class, () -> generation.attach(new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, invalid), new byte[] {1}));
            }
            assertTrue(fixture.coordinator.list(0, 10).values().isEmpty());
            org.mockito.Mockito.verify(fixture.signing, org.mockito.Mockito.never()).accept(any());
        }
    }

    @Test void keygenAtomicAttachmentPreservesTemplateAndCiphertextAcrossPhysicalRestart() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 3, 64, 2);
        EnrollmentTransaction attached;
        KeygenInput input;
        byte[] encrypted = {1, 2, 3, 4};
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("keygen-domain"), 1, ServerTestSupport.CLOCK, config)) {
            input = keygenInput(fixture, "a");
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(input.admission(), input.recipient())) {
                assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.GENERATING, generation.descriptor().state());
                EnrollmentTransaction.Intent template = generation.descriptor().template();
                assertEquals(Optional.of("est-generator"), template.source().credentialId());
                EnrollmentTransaction.Source source = template.source();
                EnrollmentTransaction.Source missing = new EnrollmentTransaction.Source(source.protocol(), source.label(), source.recordId(), source.revision(),
                        source.commitment(), source.enrollmentProfileId(), source.enrollmentCommitment(), Optional.empty());
                assertThrows(IllegalArgumentException.class, () -> keygenIntent(template, missing, EnrollmentTransaction.Operation.SERVER_KEYGEN));
                assertThrows(IllegalArgumentException.class, () -> keygenIntent(template, source, EnrollmentTransaction.Operation.ISSUE));
                assertTrue(fixture.coordinator.list(0, 10).values().isEmpty());
                org.mockito.Mockito.verify(fixture.requests, org.mockito.Mockito.never()).requireProfileProof(any(), any());
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.beginKeygen(input.admission(), input.recipient()));
                attached = generation.attach(generatedKeygenRequest("Applicant"), encrypted);
                org.mockito.Mockito.verify(fixture.requests).requireProfileProof(any(), org.mockito.ArgumentMatchers.eq(template.profile()));
                assertEquals(EnrollmentTransaction.State.PENDING, attached.state());
                assertTrue(attached.intent().artifact().isPresent());
                assertFalse(attached.intent().requestSha256().equals(generation.descriptor().template().requestSha256()));
            }
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.keygenDelivery(input.admission()));
            assertEquals(1, opened.store().protocolRecords(ServerControlStore.ENROLLMENT_KEYGEN, 0, 10).values().size());
            assertEquals(1, fixture.coordinator.list(0, 10).values().size());
        }
        try (ServerControlStore control = new ServerControlStore(DurableTransactionalMetadataStore.open(directory.resolve("server-control.log"), OptionalLong.of(1_048_576)));
                Fixture fixture = new Fixture(control, directory.resolve("keygen-domain"), 1, ServerTestSupport.CLOCK, config)) {
            zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact retained = fixture.coordinator.findKeygen(input.admission()).orElseThrow();
            when(fixture.runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.EST, AUTHORITY.value())).thenReturn("est-rotated");
            when(fixture.runtime.admissionDeadline("est-rotated")).thenReturn(ServerTestSupport.CLOCK.instant().plusSeconds(600));
            assertEquals(Optional.of("est-generator"), fixture.coordinator.findKeygen(input.admission()).orElseThrow().template().source().credentialId());
            org.mockito.Mockito.verify(fixture.runtime, org.mockito.Mockito.atLeastOnce()).requireRetainedCredential(
                    EnrollmentRuntimeConfiguration.Protocol.EST, "est-generator", AUTHORITY.value(), retained.template().issuerId().value(), retained.template().pathId().value());
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.ATTACHED, retained.state());
            assertEquals(attached.intentCommitment(), fixture.coordinator.find(attached.id()).orElseThrow().intentCommitment());
            assertArrayEquals(encrypted, java.nio.file.Files.readAllBytes(config.keygenArtifacts().orElseThrow().directory().resolve(retained.id() + ".cms")));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.beginKeygen(input.admission(), input.recipient()));
            java.nio.file.Files.write(config.keygenArtifacts().orElseThrow().directory().resolve(retained.id() + ".cms"), new byte[] {4, 3, 2, 1});
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
        }
    }

    @Test void keygenDeliveryCannotOutliveFrozenGeneratorValidity() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 2, 64, 1);
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("domain"), 1, ServerTestSupport.CLOCK, config)) {
            Instant signerExpiry = ServerTestSupport.CLOCK.instant().plusSeconds(30);
            when(fixture.runtime.credentialNotAfter("est-generator")).thenReturn(signerExpiry);
            when(fixture.runtime.admissionDeadline("est-generator")).thenReturn(signerExpiry);
            KeygenInput input = keygenInput(fixture, "a");
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(input.admission(), input.recipient())) {
                assertEquals(signerExpiry, generation.descriptor().deliveryDeadline());
                assertEquals(signerExpiry, generation.descriptor().template().expiresAt());
            }
            when(fixture.runtime.credentialNotAfter("est-generator")).thenReturn(signerExpiry.minusSeconds(1));
            fixture.coordinator.close();
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
        }
    }

    private static EnrollmentTransaction.Intent keygenIntent(EnrollmentTransaction.Intent value, EnrollmentTransaction.Source source,
            EnrollmentTransaction.Operation operation) {
        return new EnrollmentTransaction.Intent(value.realmId(), source, value.requester(), value.transactionId(), operation, value.requestId(), value.requestKind(),
                value.requestSha256(), value.requestBytes(), value.authorityId(), value.profile(), value.issuerId(), value.pathId(), value.pathCommitment(),
                value.validity(), value.predecessorId(), value.predecessorSha256(), value.approvalCategory(), value.approvalPolicy(), value.artifact(),
                value.createdAt(), value.expiresAt());
    }

    @Test void keygenUnknownReservationAndAttachmentAcksFenceThenRecoverWithoutRegeneration() throws Exception {
        for (boolean attachment : List.of(false, true)) {
            Path root = java.nio.file.Files.createDirectory(directory.resolve("ack-" + attachment));
            EnrollmentRuntimeConfiguration config = keygenConfiguration(root.resolve("encrypted"), 3, 64, 2);
            KeygenInput input;
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(root)) {
                ServerControlStore uncertain = mock(ServerControlStore.class, org.mockito.AdditionalAnswers.delegatesTo(opened.store()));
                try (Fixture fixture = new Fixture(uncertain, root.resolve("pki"), 0, ServerTestSupport.CLOCK, config)) {
                    input = keygenInput(fixture, "a");
                    EnrollmentCoordinator.KeygenGeneration generation = attachment
                            ? fixture.coordinator.beginKeygen(input.admission(), input.recipient()) : null;
                    org.mockito.Mockito.doAnswer(invocation -> {
                        List<ServerControlStore.ProtocolMutation> mutations = invocation.getArgument(0);
                        if (attachment) assertEquals(Set.of(ServerControlStore.ENROLLMENT_KEYGEN, ServerControlStore.ENROLLMENT_REQUEST),
                                mutations.stream().map(value -> value.record().namespace()).collect(java.util.stream.Collectors.toSet()));
                        opened.store().mutateProtocol(mutations);
                        throw new IllegalStateException("Injected acknowledgement loss");
                    }).when(uncertain).mutateProtocol(any());
                    if (generation == null) assertThrows(IllegalStateException.class, () -> fixture.coordinator.beginKeygen(input.admission(), input.recipient()));
                    else try (generation) { assertThrows(IllegalStateException.class, () -> generation.attach(generatedKeygenRequest("Applicant"), new byte[] {9, 8})); }
                    if (!attachment) {
                        String owned = opened.store().protocolRecords(ServerControlStore.ENROLLMENT_KEYGEN, 0, 10).values().getFirst().recordId();
                        java.nio.file.Files.write(config.keygenArtifacts().orElseThrow().directory().resolve(owned + ".part"), new byte[] {8});
                        java.nio.file.Files.write(config.keygenArtifacts().orElseThrow().directory().resolve(owned + ".cms"), new byte[] {9});
                    }
                    assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(fixture.admission()));
                }
                try (Fixture fixture = new Fixture(opened.store(), root.resolve("pki"), 0, ServerTestSupport.CLOCK, config)) {
                    zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact recovered = fixture.coordinator.findKeygen(input.admission()).orElseThrow();
                    assertEquals(attachment ? zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.ATTACHED
                            : zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.FAILED, recovered.state());
                    assertEquals(!attachment, recovered.bytesReleased());
                    if (!attachment) {
                        assertFalse(java.nio.file.Files.exists(config.keygenArtifacts().orElseThrow().directory().resolve(recovered.id() + ".part")));
                        assertFalse(java.nio.file.Files.exists(config.keygenArtifacts().orElseThrow().directory().resolve(recovered.id() + ".cms")));
                    }
                    assertEquals(attachment ? 1 : 0, fixture.coordinator.list(0, 10).values().size());
                    assertThrows(IllegalStateException.class, () -> fixture.coordinator.beginKeygen(input.admission(), input.recipient()));
                }
            }
        }
    }

    @Test void keygenCapacityPrecedesGenerationAndFailedTemplateSubstitutionLeavesOnlyTombstone() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 2, 32, 1);
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, ServerTestSupport.CLOCK, config)) {
            KeygenInput first = keygenInput(fixture, "a");
            KeygenInput second = keygenInput(fixture, "b");
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(first.admission(), first.recipient())) {
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.beginKeygen(second.admission(), second.recipient()));
                assertThrows(IllegalStateException.class, () -> generation.attach(generatedKeygenRequest("Changed"), new byte[] {1}));
            }
            zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact failed = fixture.coordinator.findKeygen(first.admission()).orElseThrow();
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.FAILED, failed.state());
            assertTrue(failed.bytesReleased());
            assertTrue(fixture.coordinator.list(0, 10).values().isEmpty());
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(second.admission(), second.recipient())) {
                assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.GENERATING, generation.descriptor().state());
            }
            // Deletion releases ciphertext bytes, but terminal replay descriptors still consume their count.
            KeygenInput third = keygenInput(fixture, "c");
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.beginKeygen(third.admission(), third.recipient()));
        }
    }

    @Test void keygenAbandonedDeliveryExpiresAndReclaimsBytesOnNewAdmission() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 2, 32, 1);
        java.time.Clock clock = mock(java.time.Clock.class);
        AtomicReference<java.time.Instant> now = new AtomicReference<>(ServerTestSupport.CLOCK.instant());
        when(clock.instant()).thenAnswer(ignored -> now.get());
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, clock, config)) {
            KeygenInput first = keygenInput(fixture, "a");
            EnrollmentTransaction attached;
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(first.admission(), first.recipient())) {
                attached = generation.attach(generatedKeygenRequest("Applicant"), new byte[] {1});
            }
            now.set(now.get().plusSeconds(601));
            KeygenInput second = keygenInput(fixture, "b");
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(second.admission(), second.recipient())) {
                assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.GENERATING, generation.descriptor().state());
            }
            zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact expired = fixture.coordinator.findKeygen(first.admission()).orElseThrow();
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.EXPIRED, expired.state());
            assertTrue(expired.bytesReleased());
            assertEquals(EnrollmentTransaction.State.EXPIRED, fixture.coordinator.find(attached.id()).orElseThrow().state());
            assertFalse(java.nio.file.Files.exists(config.keygenArtifacts().orElseThrow().directory().resolve(expired.id() + ".cms")));
        }
    }

    @Test void keygenDeliveryCapacityDoesNotFenceAndLeasesPinExpiredCiphertext() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 3, 64, 1);
        java.time.Clock clock = mock(java.time.Clock.class);
        AtomicReference<java.time.Instant> now = new AtomicReference<>(ServerTestSupport.CLOCK.instant());
        when(clock.instant()).thenAnswer(ignored -> now.get());
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, clock, config);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            KeygenInput first = keygenInput(fixture, "a");
            EnrollmentTransaction attached;
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(first.admission(), first.recipient())) {
                attached = generation.attach(generatedKeygenRequest("Applicant"), new byte[] {1, 7});
            }
            EnrollmentTransaction issued = new EnrollmentTransaction(attached.id(), attached.revision() + 1, attached.intent(), EnrollmentTransaction.State.ISSUED,
                    List.of(), Optional.of(preparation.prepared().receipt()), Optional.of(new PkiId("x509:completed")));
            persistKeygenTestEnrollment(opened.store(), attached, issued);
            java.util.ArrayList<EnrollmentCoordinator.KeygenDelivery> leases = new java.util.ArrayList<>();
            try {
                for (int index = 0; index < config.budgets().maximumConcurrentDispatches(); index++) leases.add(fixture.coordinator.keygenDelivery(first.admission()));
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.keygenDelivery(first.admission()));
                leases.removeLast().close();
                try (EnrollmentCoordinator.KeygenDelivery retry = fixture.coordinator.keygenDelivery(first.admission());
                        java.io.InputStream input = retry.openStream()) { assertArrayEquals(new byte[] {1, 7}, input.readAllBytes()); }
                leases.add(fixture.coordinator.keygenDelivery(first.admission()));
                assertTrue(fixture.coordinator.find(issued.id()).isPresent());
                now.set(now.get().plusSeconds(601));
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.keygenDelivery(first.admission()));
                zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact expired = fixture.coordinator.findKeygen(first.admission()).orElseThrow();
                assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.EXPIRED, expired.state());
                assertFalse(expired.bytesReleased());
                assertTrue(java.nio.file.Files.exists(config.keygenArtifacts().orElseThrow().directory().resolve(expired.id() + ".cms")));
            } finally { for (EnrollmentCoordinator.KeygenDelivery lease : leases) lease.close(); }
            KeygenInput second = keygenInput(fixture, "b");
            {
                EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(second.admission(), second.recipient());
                try (generation) {
                    assertTrue(fixture.coordinator.findKeygen(first.admission()).orElseThrow().bytesReleased());
                }
            }
        }
    }

    @Test void keygenAcceptedUncertaintyPinsCiphertextAndForgedExpiryCannotDeleteIt() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 2, 32, 1);
        java.time.Clock clock = mock(java.time.Clock.class);
        AtomicReference<java.time.Instant> now = new AtomicReference<>(ServerTestSupport.CLOCK.instant());
        when(clock.instant()).thenAnswer(ignored -> now.get());
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, clock, config);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            KeygenInput first = keygenInput(fixture, "a");
            EnrollmentTransaction attached;
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(first.admission(), first.recipient())) {
                attached = generation.attach(generatedKeygenRequest("Applicant"), new byte[] {4, 2});
            }
            EnrollmentTransaction accepted = new EnrollmentTransaction(attached.id(), attached.revision() + 1, attached.intent(), EnrollmentTransaction.State.UNCERTAIN,
                    List.of(), Optional.of(preparation.prepared().receipt()), Optional.empty());
            persistKeygenTestEnrollment(opened.store(), attached, accepted);
            now.set(now.get().plusSeconds(601));
            KeygenInput second = keygenInput(fixture, "b");
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.beginKeygen(second.admission(), second.recipient()));
            zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact retained = fixture.coordinator.findKeygen(first.admission()).orElseThrow();
            assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.ATTACHED, retained.state());
            Path encrypted = config.keygenArtifacts().orElseThrow().directory().resolve(retained.id() + ".cms");
            assertTrue(java.nio.file.Files.exists(encrypted));
            for (boolean released : List.of(false, true)) {
                zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact forged = new zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact(retained.id(),
                        retained.revision() + 1, retained.template(), retained.algorithm(), retained.maximumKeySizeBits(), retained.maximumCiphertextBytes(),
                        retained.maximumGeneratedRequestBytes(), retained.deliveryDeadline(), zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.EXPIRED,
                        retained.artifact(), released);
                ServerControlStore.ProtocolRecord prior = opened.store().protocolRecord(ServerControlStore.ENROLLMENT_KEYGEN, retained.id()).orElseThrow();
                opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                        zeroecho.pki.server.enrollment.KeygenSpoolTestSupport.record(forged), Optional.of(prior.commitment()))));
                assertThrows(IllegalStateException.class, fixture::openCoordinator);
                assertArrayEquals(new byte[] {4, 2}, java.nio.file.Files.readAllBytes(encrypted));
            }
        }
    }

    @Test void keygenFailedTerminalizationAckReleasesGenerationForShutdownAndRecovery() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 2, 32, 1);
        KeygenInput input;
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            ServerControlStore uncertain = mock(ServerControlStore.class, org.mockito.AdditionalAnswers.delegatesTo(opened.store()));
            try (Fixture fixture = new Fixture(uncertain, directory.resolve("pki"), 0, ServerTestSupport.CLOCK, config)) {
                input = keygenInput(fixture, "a");
                EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(input.admission(), input.recipient());
                org.mockito.Mockito.doAnswer(invocation -> {
                    opened.store().mutateProtocol(invocation.getArgument(0));
                    throw new IllegalStateException("Injected terminalization acknowledgement loss");
                }).when(uncertain).mutateProtocol(any());
                assertThrows(IllegalStateException.class, generation::close);
                fixture.coordinator.close();
                generation.close();
            }
            try (Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, ServerTestSupport.CLOCK, config)) {
                zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact failed = fixture.coordinator.findKeygen(input.admission()).orElseThrow();
                assertEquals(zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.FAILED, failed.state());
                assertTrue(failed.bytesReleased());
            }
        }
    }

    @Test void keygenGlobalReservationRejectsBeforeTemplatePersistenceOrGeneration() throws Exception {
        EnrollmentRuntimeConfiguration full = keygenConfiguration(directory.resolve("encrypted"), 2, 64, 1);
        EnrollmentRuntimeConfiguration.Budgets b = full.budgets();
        EnrollmentRuntimeConfiguration constrained = new EnrollmentRuntimeConfiguration(new EnrollmentRuntimeConfiguration.Budgets(
                b.maximumTransactions(), b.maximumPending(), b.maximumRequestBytes(), b.maximumRequestBytes(),
                b.maximumConcurrentDispatches(), b.pendingLifetime(), b.retryAfter()), full.keyrings(), full.credentialSets(),
                full.activeCredentials(), full.keygenArtifacts());
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, ServerTestSupport.CLOCK, constrained)) {
            KeygenInput input = keygenInput(fixture, "a");
            PkiId request = fixture.requests.parseX509(input.admission().payload()).requestId();
            assertTrue(fixture.requests.get(request).isEmpty());
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.beginKeygen(input.admission(), input.recipient()));
            assertTrue(fixture.requests.get(request).isEmpty());
            assertTrue(opened.store().protocolRecords(ServerControlStore.ENROLLMENT_KEYGEN, 0, 10).values().isEmpty());
            assertTrue(fixture.coordinator.list(0, 10).values().isEmpty());
        }
    }

    @Test void keygenStrictDescriptorAndMissingRequestFailBeforeCiphertextCleanup() throws Exception {
        EnrollmentRuntimeConfiguration config = keygenConfiguration(directory.resolve("encrypted"), 2, 64, 1);
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, ServerTestSupport.CLOCK, config)) {
            KeygenInput input = keygenInput(fixture, "a");
            EnrollmentTransaction enrollment;
            try (EnrollmentCoordinator.KeygenGeneration generation = fixture.coordinator.beginKeygen(input.admission(), input.recipient())) {
                enrollment = generation.attach(generatedKeygenRequest("Applicant"), new byte[] {3, 4});
            }
            String id = enrollment.intent().artifact().orElseThrow().artifactId();
            Path ciphertext = config.keygenArtifacts().orElseThrow().directory().resolve(id + ".cms");
            ServerControlStore.ProtocolRecord original = opened.store().protocolRecord(ServerControlStore.ENROLLMENT_KEYGEN, id).orElseThrow();
            for (int version : List.of(0, 2)) {
                byte[] modified = original.payload(); modified[3] = (byte) version;
                String hash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(modified));
                ServerControlStore.ProtocolRecord prior = opened.store().protocolRecord(ServerControlStore.ENROLLMENT_KEYGEN, id).orElseThrow();
                opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                        new ServerControlStore.ProtocolRecord(ServerControlStore.ENROLLMENT_KEYGEN, id, hash, modified), Optional.of(prior.commitment()))));
                assertThrows(IllegalArgumentException.class, fixture::openCoordinator);
                assertArrayEquals(new byte[] {3, 4}, java.nio.file.Files.readAllBytes(ciphertext));
            }
            ServerControlStore.ProtocolRecord modified = opened.store().protocolRecord(ServerControlStore.ENROLLMENT_KEYGEN, id).orElseThrow();
            opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(original, Optional.of(modified.commitment()))));
            when(fixture.session.requests()).thenReturn(Optional.of(mock(CertificationRequestService.class)));
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
            assertArrayEquals(new byte[] {3, 4}, java.nio.file.Files.readAllBytes(ciphertext));
            when(fixture.session.requests()).thenReturn(Optional.of(fixture.requests));
            Path unknown = config.keygenArtifacts().orElseThrow().directory().resolve("f".repeat(64) + ".cms");
            java.nio.file.Files.write(unknown, new byte[] {9});
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
            assertTrue(java.nio.file.Files.exists(unknown));
            assertArrayEquals(new byte[] {3, 4}, java.nio.file.Files.readAllBytes(ciphertext));
        }
    }

    private static void persistKeygenTestEnrollment(ServerControlStore control, EnrollmentTransaction before, EnrollmentTransaction after) {
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(zeroecho.pki.server.enrollment.KeygenSpoolTestSupport.record(after),
                Optional.of(before.commitment()))));
    }

    private record KeygenInput(EnrollmentCoordinator.Admission admission, java.security.cert.X509Certificate recipient) { }
    private static KeygenInput keygenInput(Fixture fixture, String transaction) throws Exception {
        if (!((EstEndpoint) fixture.endpoints.find(EnrollmentEndpointRegistry.Protocol.EST, "est").orElseThrow()).keygen().enabled())
            fixture.endpoints.register(new EstEndpoint("est", AUTHORITY.value(), "leaf", "policy",
                    new zeroecho.pki.server.est.KeygenPolicy(true, List.of("RSA"), 2048, false)));
        byte[] encodedCertificate = keygenRecipientDer;
        String digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(encodedCertificate));
        CertificateIdentityEvidence evidence = new CertificateIdentityEvidence(ServerTestSupport.REALM, digest, "1".repeat(64),
                Set.of("1".repeat(64)), "2".repeat(64));
        EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.EST_CLIENT,
                "keygen-client", IssuanceExecutionEvidence.Authentication.EST_MTLS, Optional.of(evidence), Optional.of(evidence.canonicalKeySha256()),
                evidence.legacySpkiSha256(), new EnrollmentIdentityAliases.Snapshot(ServerTestSupport.REALM, Set.of()));
        java.security.cert.X509Certificate certificate = mock(java.security.cert.X509Certificate.class);
        when(certificate.getEncoded()).thenReturn(encodedCertificate);
        when(certificate.getNotAfter()).thenReturn(java.util.Date.from(ServerTestSupport.CLOCK.instant().plusSeconds(3600)));
        org.bouncycastle.pkcs.PKCS10CertificationRequest original = new org.bouncycastle.pkcs.PKCS10CertificationRequest(csr);
        java.security.PublicKey publicKey = new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest(original).getPublicKey();
        when(certificate.getPublicKey()).thenReturn(publicKey);
        org.bouncycastle.asn1.ASN1EncodableVector attributes = new org.bouncycastle.asn1.ASN1EncodableVector();
        attributes.add(new org.bouncycastle.asn1.pkcs.Attribute(new org.bouncycastle.asn1.ASN1ObjectIdentifier(zeroecho.pkix.EstKeygen.CAPABILITIES_OID),
                new org.bouncycastle.asn1.DERSet(new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.DERSequence(
                        org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption)))));
        attributes.add(new org.bouncycastle.asn1.pkcs.Attribute(new org.bouncycastle.asn1.ASN1ObjectIdentifier(zeroecho.pkix.EstKeygen.RECIPIENT_KEY_ID_OID),
                new org.bouncycastle.asn1.DERSet(new org.bouncycastle.asn1.DEROctetString(
                        java.security.MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded())))));
        org.bouncycastle.asn1.pkcs.CertificationRequestInfo info = new org.bouncycastle.asn1.pkcs.CertificationRequestInfo(
                original.getSubject(), original.getSubjectPublicKeyInfo(), new org.bouncycastle.asn1.DERSet(attributes));
        byte[] template = new org.bouncycastle.asn1.pkcs.CertificationRequest(info, original.getSignatureAlgorithm(),
                new org.bouncycastle.asn1.DERBitString(new byte[] {1})).getEncoded("DER");
        return new KeygenInput(new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.EST, "est", requester, transaction.repeat(64),
                EnrollmentTransaction.Operation.SERVER_KEYGEN, new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, template),
                Optional.empty(), Optional.empty()), certificate);
    }
    private static X509EnrollmentPayload generatedKeygenRequest(String subject) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=" + subject), pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())).getEncoded());
    }
    private static EnrollmentRuntimeConfiguration keygenConfiguration(Path spool, int count, long bytes, int concurrency) throws Exception {
        java.nio.file.Files.createDirectories(spool);
        java.nio.file.Files.setPosixFilePermissions(spool, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        EnrollmentRuntimeConfiguration base = EnrollmentTestSupport.runtimeConfiguration();
        return new EnrollmentRuntimeConfiguration(base.budgets(), List.of(), List.of(), List.of(),
                Optional.of(new EnrollmentRuntimeConfiguration.KeygenArtifacts(spool, 32, bytes, count, concurrency, Duration.ofMinutes(10))));
    }

    @Test void independentThresholdDecisionsSurvivePhysicalControlRestart() throws Exception {
        Path log;
        EnrollmentTransaction admitted;
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 2)) {
            log = opened.log(); admitted = fixture.coordinator.admit(fixture.admission());
            assertEquals(EnrollmentTransaction.State.PENDING, admitted.state());
            assertTrue(fixture.requests.get(admitted.intent().requestId()).isPresent());
            assertFalse(new String(opened.store().protocolRecord(ServerControlStore.ENROLLMENT_REQUEST, admitted.id()).orElseThrow().payload(),
                    java.nio.charset.StandardCharsets.ISO_8859_1).contains("BEGIN CERTIFICATE REQUEST"));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.decide(admitted.id(), admitted.commitment(),
                    new AdministrativeDecisionActor("one", Optional.empty()), ApprovalService.Choice.APPROVE, "Approved"));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.decide(admitted.id(), admitted.commitment(),
                    actor("one", "1"), ApprovalService.Choice.APPROVE, "Self"));
            EnrollmentTransaction first = fixture.coordinator.decide(admitted.id(), admitted.commitment(), actor("one", "2"), ApprovalService.Choice.APPROVE, "Reviewed");
            assertEquals(EnrollmentTransaction.State.PENDING, first.state());
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.decide(first.id(), first.commitment(), actor("two", "2"), ApprovalService.Choice.APPROVE, "Same key"));
        }
        try (ServerControlStore control = new ServerControlStore(DurableTransactionalMetadataStore.open(log, OptionalLong.of(1_048_576)));
                Fixture fixture = new Fixture(control, directory.resolve("pki"), 2)) {
            EnrollmentTransaction first = fixture.coordinator.find(admitted.id()).orElseThrow();
            assertEquals(1, first.decisions().size());
            EnrollmentTransaction approved = fixture.coordinator.decide(first.id(), first.commitment(), actor("two", "3"), ApprovalService.Choice.APPROVE, "Independently reviewed");
            assertEquals(EnrollmentTransaction.State.APPROVED, approved.state());
            assertEquals(admitted.intentCommitment(), approved.intentCommitment());
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.decide(approved.id(), approved.commitment(), actor("three", "4"), ApprovalService.Choice.APPROVE, "Duplicate"));
        }
    }

    @Test void suspensionBlocksClaimButIdenticalReplayAndEndpointAbaRetainOriginalIdentity() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0)) {
            EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission());
            fixture.profiles.setState("policy", EnrollmentProfileState.SUSPENDED);
            assertEquals(value.id(), fixture.coordinator.admit(fixture.admission()).id());
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.dispatch(value.id()));
            verify(fixture.signing, never()).prepareCorrelatedEndEntity(any(), any(), any(), any());
            fixture.profiles.setState("policy", EnrollmentProfileState.ACTIVE);
            fixture.endpoints.deregister(EnrollmentEndpointRegistry.Protocol.EST, "est");
            fixture.endpoints.register(fixture.endpoint);
            assertEquals(value.id(), fixture.coordinator.admit(fixture.admission()).id());
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.dispatch(value.id()));
            assertEquals(1, fixture.coordinator.list(0, 10).values().size());
        }
    }


    @Test void cancellationBeforeClaimDiscardsPreparedReceiptWithoutAcceptance() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission());
            java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean(true);
            assertThrows(zeroecho.pki.api.PkiException.class, () -> fixture.coordinator.dispatch(value.id(), cancelled::get));
            verify(fixture.signing, never()).prepareCorrelatedEndEntity(any(), any(), any(), any());
            cancelled.set(false);
            when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any())).thenAnswer(invocation -> {
                cancelled.set(true);
                return new CorrelatedIssuancePreparation.Prepared(preparation.prepared());
            });
            assertThrows(zeroecho.pki.api.PkiException.class, () -> fixture.coordinator.dispatch(value.id(), cancelled::get));
            verify(fixture.signing).discard(preparation.prepared());
            verify(fixture.signing, never()).accept(any());
            assertEquals(EnrollmentTransaction.State.APPROVED, fixture.coordinator.find(value.id()).orElseThrow().state());
            assertTrue(fixture.coordinator.find(value.id()).orElseThrow().receipt().isEmpty());
        }
    }

    @Test void transportClaimValidationFailuresAndCancellationNeverAcceptAndReleaseDispatchSlot() throws Exception {
        for (int failurePosition : List.of(1, 2)) {
            for (boolean cancellation : List.of(false, true)) {
                Path root = java.nio.file.Files.createDirectory(directory.resolve("guard-" + failurePosition + "-" + cancellation));
                try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(root);
                        Fixture fixture = new Fixture(opened.store(), root.resolve("pki"), 0);
                        SemanticPreparationFixture preparation = SemanticPreparationFixture.open(root.resolve("custody"))) {
                    EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission());
                    when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any()))
                            .thenReturn(new CorrelatedIssuancePreparation.Prepared(preparation.prepared()));
                    java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
                    java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean();
                    assertThrows(RuntimeException.class, () -> fixture.coordinator.dispatch(value.id(), cancelled::get, () -> {
                        assertFalse(Thread.holdsLock(opened.store()));
                        if (calls.incrementAndGet() == failurePosition) {
                            if (cancellation) cancelled.set(true);
                            else throw new IllegalArgumentException("Current requester status denied");
                        }
                    }));
                    assertEquals(failurePosition, calls.get());
                    verify(fixture.signing, org.mockito.Mockito.times(failurePosition - 1)).prepareCorrelatedEndEntity(any(), any(), any(), any());
                    verify(fixture.signing, org.mockito.Mockito.times(failurePosition - 1)).discard(preparation.prepared());
                    verify(fixture.signing, never()).accept(any());
                    assertEquals(EnrollmentTransaction.State.APPROVED, fixture.coordinator.find(value.id()).orElseThrow().state());
                    cancelled.set(false);
                    assertThrows(IllegalArgumentException.class, () -> fixture.coordinator.dispatch(value.id(), cancelled::get,
                            () -> { throw new IllegalArgumentException("Slot was released"); }));
                }
            }
        }
    }

    @Test void protocolDeadlineExpiresPendingPollAndCrossingPreparationCannotClaim() throws Exception {
        java.time.Clock clock = mock(java.time.Clock.class);
        AtomicReference<java.time.Instant> now = new AtomicReference<>(ServerTestSupport.CLOCK.instant());
        when(clock.instant()).thenAnswer(invocation -> now.get());
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, clock, EnrollmentTestSupport.runtimeConfiguration());
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            EnrollmentCoordinator.Admission original = fixture.admission();
            EnrollmentCoordinator.Admission capped = new EnrollmentCoordinator.Admission(original.protocol(), original.endpointId(),
                    original.requester(), original.transactionId(), original.operation(), original.payload(), original.validity(),
                    original.predecessorId(), Optional.of(now.get().plusSeconds(1)));
            EnrollmentTransaction value = fixture.coordinator.admit(capped);
            assertEquals(now.get().plusSeconds(1), value.intent().expiresAt());
            when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any())).thenAnswer(invocation -> {
                now.set(now.get().plusSeconds(1));
                return new CorrelatedIssuancePreparation.Prepared(preparation.prepared());
            });
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.dispatch(value.id()));
            assertEquals(EnrollmentTransaction.State.EXPIRED, fixture.coordinator.find(value.id()).orElseThrow().state());
            verify(fixture.signing).discard(preparation.prepared());
            verify(fixture.signing, never()).accept(any());
        }
        java.nio.file.Files.createDirectory(directory.resolve("pending"));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory.resolve("pending"));
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pending-domain"), 1, clock, EnrollmentTestSupport.runtimeConfiguration())) {
            EnrollmentTransaction pending = fixture.coordinator.admit(fixture.admission());
            now.set(pending.intent().expiresAt());
            assertEquals(EnrollmentTransaction.State.EXPIRED, fixture.coordinator.dispatch(pending.id()).state());
            verify(fixture.signing, never()).prepareCorrelatedEndEntity(any(), any(), any(), any());
        }
    }

    @Test void persistsExactReceiptBeforeAcceptAndUnknownResolutionCannotPrepareAgain() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission());
            when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any())).thenReturn(new CorrelatedIssuancePreparation.Prepared(preparation.prepared()));
            when(fixture.signing.accept(preparation.prepared())).thenAnswer(invocation -> {
                EnrollmentTransaction claimed = fixture.coordinator.find(value.id()).orElseThrow();
                assertEquals(EnrollmentTransaction.State.DISPATCHING, claimed.state());
                assertEquals(preparation.prepared().receipt(), claimed.receipt().orElseThrow());
                // A second caller must never interpret this live, pre-acceptance claim as absent.
                assertEquals(claimed, fixture.coordinator.dispatch(value.id()));
                throw new IllegalStateException("lost acknowledgement");
            });
            when(fixture.signing.resolve(preparation.prepared().receipt())).thenThrow(new IllegalStateException("unavailable"));
            assertEquals(EnrollmentTransaction.State.UNCERTAIN, fixture.coordinator.dispatch(value.id()).state());
            assertEquals(EnrollmentTransaction.State.UNCERTAIN, fixture.coordinator.dispatch(value.id(), zeroecho.core.io.CancellationSignal.NONE,
                    () -> { throw new AssertionError("Uncertain recovery must not require new authorization"); }).state());
            org.mockito.Mockito.doReturn(SigningAcceptanceResolution.NOT_ACCEPTED).when(fixture.signing).resolve(preparation.prepared().receipt());
            assertThrows(IllegalArgumentException.class, () -> fixture.coordinator.dispatch(value.id(), zeroecho.core.io.CancellationSignal.NONE,
                    () -> { throw new IllegalArgumentException("Resolved retry requires current authorization"); }));
            verify(fixture.signing, org.mockito.Mockito.times(1)).prepareCorrelatedEndEntity(any(), any(), any(), any());
            verify(fixture.signing, never()).discard(any());
        }
    }





    @Test void historicalAccountAliasesRemainExcludedAfterConfigurationChange() throws Exception {
        byte[] a = lineageKey(1); byte[] b = lineageKey(2); byte[] c = lineageKey(3);
        String bHash = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(b).equivalentSubjectPublicKeyInfoSha256().iterator().next();
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 1)) {
            fixture.coordinator.close();
            AcmeControlStore acme = org.mockito.Mockito.spy(new AcmeControlStore(opened.store()));
            zeroecho.pki.server.acme.AcmeState.Directory directory = mock(zeroecho.pki.server.acme.AcmeState.Directory.class);
            IssuerChainPath path = fixture.session.repository().chainPath(
                    fixture.session.repository().authority(AUTHORITY).orElseThrow().issuanceChainPathId()).orElseThrow();
            when(directory.alias()).thenReturn("lineage"); when(directory.directoryId()).thenReturn("directory:lineage");
            when(directory.revision()).thenReturn(1); when(directory.commitment()).thenReturn("a".repeat(64));
            when(directory.profile()).thenReturn(new CertificateProfileRef("leaf", 1, new byte[32]));
            when(directory.enrollmentProfileId()).thenReturn("policy"); when(directory.authorityId()).thenReturn(AUTHORITY);
            when(directory.issuerId()).thenReturn(ISSUER); when(directory.issuancePathId()).thenReturn(path.pathId());
            when(directory.issuancePathCommitment()).thenReturn(path.pathCommitment());
            when(directory.status()).thenReturn(zeroecho.pki.server.acme.AcmeState.DirectoryStatus.ACTIVE);
            org.mockito.Mockito.doReturn(Optional.of(directory)).when(acme).get(zeroecho.pki.server.acme.AcmeState.Directory.class, "directory:lineage");
            EnrollmentIdentityAliases observedWhileCurrent = lineageAliases(List.of(new PkiServerConfiguration.ClientCertificateMapping(
                    "old-mapping", "two", Optional.empty(), Optional.of(bHash), Optional.empty())));
            EnrollmentTransaction pending;
            try (EnrollmentCoordinator coordinator = new EnrollmentCoordinator(opened.store(), fixture.realm, fixture.session,
                    fixture.endpoints, fixture.profiles, acme, fixture.runtime, fixture.aliases, fixture.clock)) {
                zeroecho.pki.server.acme.AcmeState.Account account = coordinator.storeAcmeAccount(Optional.empty(), lineageAccount("account:one", a));
                zeroecho.pkix.PublicKeyIdentity identity = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(a);
                EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT,
                        account.accountId(), IssuanceExecutionEvidence.Authentication.ACME_ACCOUNT_JWS, Optional.empty(),
                        Optional.of(identity.canonicalSha256()), identity.equivalentSubjectPublicKeyInfoSha256(),
                        new EnrollmentIdentityAliases.Snapshot(ServerTestSupport.REALM, Set.of()));
                pending = coordinator.admit(new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.ACME, "directory:lineage",
                        requester, "1".repeat(64), EnrollmentTransaction.Operation.ISSUE, fixture.admission().payload(),
                        Optional.empty(), Optional.empty(), Optional.of(fixture.clock.instant().plusSeconds(60))));
                account = coordinator.storeAcmeAccount(Optional.of(account), lineageAccount("account:one", b));
                assertTrue(account.keyHistory().stream().allMatch(value -> value.aliases().isEmpty()));
            }
            try (EnrollmentCoordinator coordinator = new EnrollmentCoordinator(opened.store(), fixture.realm, fixture.session,
                    fixture.endpoints, fixture.profiles, acme, fixture.runtime, observedWhileCurrent, fixture.clock)) {
                zeroecho.pki.server.acme.AcmeState.Account account = acme.get(
                        zeroecho.pki.server.acme.AcmeState.Account.class, "account:one").orElseThrow();
                coordinator.storeAcmeAccount(Optional.of(account), lineageAccount("account:one", c));
            }
            EnrollmentIdentityAliases changed = lineageAliases(List.of(new PkiServerConfiguration.ClientCertificateMapping(
                    "new-mapping", "three", Optional.empty(), Optional.of(bHash), Optional.empty())));
            try (EnrollmentCoordinator reopened = new EnrollmentCoordinator(opened.store(), fixture.realm, fixture.session,
                    fixture.endpoints, fixture.profiles, acme, fixture.runtime, changed, fixture.clock)) {
                zeroecho.pki.server.acme.AcmeState.Account authoritative = acme.get(
                        zeroecho.pki.server.acme.AcmeState.Account.class, "account:one").orElseThrow();
                zeroecho.pki.server.acme.AcmeState.Account fabricatedPrior = new zeroecho.pki.server.acme.AcmeState.Account(
                        authoritative.accountId(), authoritative.directoryId(), authoritative.directoryRevision(),
                        authoritative.directoryPolicyCommitment(), authoritative.keyThumbprint(), authoritative.publicKeySpki(),
                        authoritative.status(), authoritative.contacts(), authoritative.termsAgreed(), authoritative.eabPolicyCommitment(),
                        authoritative.createdAt(), authoritative.updatedAt(), authoritative.commitment());
                assertEquals(1, fabricatedPrior.keyHistory().size());
                assertEquals(3, reopened.storeAcmeAccount(Optional.of(fabricatedPrior), authoritative).keyHistory().size());
                assertThrows(IllegalStateException.class, () -> reopened.decide(pending.id(), pending.commitment(), actor("two", "7"),
                        ApprovalService.Choice.APPROVE, "Frozen alias cannot approve"));
                assertThrows(IllegalStateException.class, () -> reopened.decide(pending.id(), pending.commitment(), actor("three", "8"),
                        ApprovalService.Choice.APPROVE, "Current alias cannot approve"));
                assertEquals(EnrollmentTransaction.State.APPROVED, reopened.decide(pending.id(), pending.commitment(), actor("one", "9"),
                        ApprovalService.Choice.APPROVE, "Independent review").state());
                assertEquals(pending.intentCommitment(), reopened.find(pending.id()).orElseThrow().intentCommitment());
            }
        }
    }

    @Test void authenticatedEndpointCommitmentMustMatchBeforeAnyAdmissionWrite() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0)) {
            String commitment = fixture.endpoints.requireCurrent(fixture.endpoint).commitment();
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(fixture.admission(), "f".repeat(64)));
            assertTrue(fixture.coordinator.list(0, 10).values().isEmpty());
            EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission(), commitment);
            assertEquals(value.id(), fixture.coordinator.admit(fixture.admission(), commitment).id());
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(fixture.admission(), "f".repeat(64)));
        }
    }

    @Test void checksumConsistentAccountHistoryMissingCurrentKeyFailsStartup() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0)) {
            zeroecho.pki.server.acme.AcmeState.Account account = fixture.coordinator.storeAcmeAccount(
                    Optional.empty(), lineageAccount("account:one", lineageKey(1)));
            ServerControlStore.ProtocolRecord retained = opened.store().protocolRecord(
                    ServerControlStore.ACME_ACCOUNT, account.accountId()).orElseThrow();
            byte[] payload = retained.payload();
            byte[] identity = account.keyHistory().getFirst().canonicalSha256().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            int offset = -1;
            for (int index = 0; index <= payload.length - identity.length; index++) {
                if (java.util.Arrays.equals(payload, index, index + identity.length, identity, 0, identity.length)) {
                    offset = index; break;
                }
            }
            assertTrue(offset >= 0);
            java.util.Arrays.fill(payload, offset, offset + identity.length, (byte) 'f');
            java.util.Arrays.fill(payload, payload.length - 64, payload.length, (byte) '0');
            String hash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(payload));
            System.arraycopy(hash.getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, payload, payload.length - 64, 64);
            opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                    ServerControlStore.ACME_ACCOUNT, account.accountId(), hash, payload), Optional.of(retained.commitment()))));
            fixture.coordinator.close();
            assertThrows(IllegalArgumentException.class, fixture::openCoordinator);
        }
    }

    @Test void accountHistorySharesTransactionCapacityAndRebuildsAfterUnknownCreation() throws Exception {
        EnrollmentRuntimeConfiguration limited = EnrollmentRuntimeConfiguration.decode(EnrollmentTestSupport.runtimeJson()
                .replace("\"maximumTransactions\":1000", "\"maximumTransactions\":1")
                .replace("\"maximumPending\":100", "\"maximumPending\":1").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, ServerTestSupport.CLOCK, limited)) {
            fixture.coordinator.close();
            AcmeControlStore acme = org.mockito.Mockito.spy(new AcmeControlStore(opened.store()));
            org.mockito.Mockito.doAnswer(invocation -> {
                invocation.callRealMethod();
                throw new IllegalStateException("Lost account commit acknowledgement");
            }).when(acme).create(any(zeroecho.pki.server.acme.AcmeState.Account.class));
            try (EnrollmentCoordinator uncertain = new EnrollmentCoordinator(opened.store(), fixture.realm, fixture.session,
                    fixture.endpoints, fixture.profiles, acme, fixture.runtime, fixture.aliases, fixture.clock)) {
                zeroecho.pki.server.acme.AcmeState.Account account = lineageAccount("account:one", lineageKey(1));
                assertThrows(IllegalStateException.class, () -> uncertain.storeAcmeAccount(Optional.empty(), account));
                assertTrue(acme.get(zeroecho.pki.server.acme.AcmeState.Account.class, account.accountId()).isPresent());
                assertThrows(IllegalStateException.class, () -> uncertain.storeAcmeAccount(Optional.empty(), lineageAccount("account:two", lineageKey(2))));
            }
            try (EnrollmentCoordinator reopened = fixture.openCoordinator()) {
                assertThrows(IllegalStateException.class, () -> reopened.storeAcmeAccount(Optional.empty(), lineageAccount("account:two", lineageKey(2))));
                assertThrows(IllegalStateException.class, () -> reopened.admit(fixture.admission()));
                assertEquals(1, new AcmeControlStore(opened.store()).page(zeroecho.pki.server.acme.AcmeState.Account.class, 0, 256).values().size());
            }
        }
    }

    @Test void accountHistoryByteExhaustionRejectsCreationAndRolloverBeforeMutation() throws Exception {
        EnrollmentRuntimeConfiguration limited = EnrollmentRuntimeConfiguration.decode(EnrollmentTestSupport.runtimeJson()
                .replace("\"maximumRequestBytes\":1048576", "\"maximumRequestBytes\":4096")
                .replace("\"maximumRetainedRequestBytes\":10485760", "\"maximumRetainedRequestBytes\":4096")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] firstKey = lineageKey(1); byte[] secondKey = lineageKey(2);
        String hash = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(secondKey).equivalentSubjectPublicKeyInfoSha256().iterator().next();
        List<PkiServerConfiguration.ClientCertificateMapping> mappings = new java.util.ArrayList<>();
        for (int index = 0; index < 80; index++) mappings.add(new PkiServerConfiguration.ClientCertificateMapping(
                "mapping-" + index, "alias-" + index + "x".repeat(64), Optional.empty(), Optional.of(hash), Optional.empty()));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0, ServerTestSupport.CLOCK, limited)) {
            fixture.coordinator.close();
            EnrollmentIdentityAliases aliases = lineageAliases(mappings);
            try (EnrollmentCoordinator coordinator = new EnrollmentCoordinator(opened.store(), fixture.realm, fixture.session,
                    fixture.endpoints, fixture.profiles, new AcmeControlStore(opened.store()), fixture.runtime, aliases, fixture.clock)) {
                assertThrows(IllegalStateException.class, () -> coordinator.storeAcmeAccount(Optional.empty(), lineageAccount("account:too-large", secondKey)));
                zeroecho.pki.server.acme.AcmeState.Account created = coordinator.storeAcmeAccount(Optional.empty(), lineageAccount("account:one", firstKey));
                assertThrows(IllegalStateException.class, () -> coordinator.storeAcmeAccount(Optional.of(created), lineageAccount("account:one", secondKey)));
                zeroecho.pki.server.acme.AcmeState.Account retained = new AcmeControlStore(opened.store())
                        .get(zeroecho.pki.server.acme.AcmeState.Account.class, created.accountId()).orElseThrow();
                assertEquals(created.commitment(), retained.commitment());
                assertEquals(1, retained.keyHistory().size());
            }
        }
    }

    private static EnrollmentIdentityAliases lineageAliases(List<PkiServerConfiguration.ClientCertificateMapping> mappings) {
        return new EnrollmentIdentityAliases(ServerTestSupport.REALM, new PkiServerConfiguration.Authentication(
                AdministrativeAuthenticationMode.DIRECT_MTLS, mappings, List.of(), List.of(), Set.of(),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0));
    }

    private static byte[] lineageKey(int seed) {
        try {
            java.security.SecureRandom random = java.security.SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(new byte[] {(byte) seed});
            java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
            generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), random);
            return generator.generateKeyPair().getPublic().getEncoded();
        } catch (java.security.GeneralSecurityException failure) { throw new AssertionError(failure); }
    }

    private static zeroecho.pki.server.acme.AcmeState.Account lineageAccount(String id, byte[] spki) {
        return new zeroecho.pki.server.acme.AcmeState.Account(id, "directory:lineage", 1, "a".repeat(64), "b".repeat(64),
                spki, zeroecho.pki.server.acme.AcmeState.AccountStatus.VALID, List.of(), true, Optional.empty(),
                ServerTestSupport.CLOCK.instant(), ServerTestSupport.CLOCK.instant(), "0".repeat(64));
    }

    @Test void uncertainNonacceptanceAfterRestartRequiresCurrentPolicyBeforeNewReceipt() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"));
                SemanticPreparationFixture retryPreparation = SemanticPreparationFixture.open(directory.resolve("retry-custody"))) {
            EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission());
            zeroecho.pki.api.signing.SigningAcceptanceReceipt first = preparation.prepared().receipt();
            when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any()))
                    .thenReturn(new CorrelatedIssuancePreparation.Prepared(preparation.prepared()));
            when(fixture.signing.accept(preparation.prepared())).thenThrow(new IllegalStateException("Unknown acknowledgement"));
            when(fixture.signing.resolve(first)).thenThrow(new IllegalStateException("Unavailable"));
            assertEquals(EnrollmentTransaction.State.UNCERTAIN, fixture.coordinator.dispatch(value.id()).state());
            fixture.coordinator.close();
            org.mockito.Mockito.doReturn(SigningAcceptanceResolution.NOT_ACCEPTED).when(fixture.signing).resolve(first);
            fixture.profiles.setState("policy", EnrollmentProfileState.SUSPENDED);
            try (EnrollmentCoordinator reopened = fixture.openCoordinator()) {
                assertEquals(EnrollmentTransaction.State.APPROVED, reopened.find(value.id()).orElseThrow().state());
                assertThrows(IllegalStateException.class, () -> reopened.dispatch(value.id()));
                verify(fixture.signing, org.mockito.Mockito.times(1)).prepareCorrelatedEndEntity(any(), any(), any(), any());
                fixture.profiles.setState("policy", EnrollmentProfileState.ACTIVE);
                zeroecho.pki.api.signing.PreparedSemanticSigningRequest retry = retryPreparation.prepared();
                zeroecho.pki.api.signing.SigningAcceptanceReceipt next = retry.receipt();
                when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any()))
                        .thenReturn(new CorrelatedIssuancePreparation.Prepared(retry));
                when(fixture.signing.accept(retry)).thenAnswer(invocation -> {
                    assertEquals(next, reopened.find(value.id()).orElseThrow().receipt().orElseThrow());
                    return new SigningAcceptanceResult(SigningAcceptanceDisposition.ACCEPTED, next);
                });
                when(fixture.signing.resolve(next)).thenReturn(SigningAcceptanceResolution.MATCHED);
                zeroecho.pki.api.signing.SemanticSigningOperation operation = mock(zeroecho.pki.api.signing.SemanticSigningOperation.class);
                when(operation.submissionId()).thenReturn(new zeroecho.pki.api.orch.SigningSubmissionId(next.operationId(), "test", fixture.clock.instant()));
                when(operation.state()).thenReturn(zeroecho.pki.api.signing.SemanticSigningState.SIGNING);
                when(fixture.signing.findIssuance(any(zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest.class))).thenReturn(Optional.of(operation));
                EnrollmentTransaction accepted = reopened.dispatch(value.id());
                assertEquals(EnrollmentTransaction.State.ACCEPTED, accepted.state());
                assertEquals(next, accepted.receipt().orElseThrow());
            }
        }
    }

    @Test void establishedAcceptanceSurvivesLookupFailureAndContradictoryNonacceptanceFences() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission());
            zeroecho.pki.api.signing.SigningAcceptanceReceipt receipt = preparation.prepared().receipt();
            when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any()))
                    .thenReturn(new CorrelatedIssuancePreparation.Prepared(preparation.prepared()));
            when(fixture.signing.accept(preparation.prepared())).thenReturn(new SigningAcceptanceResult(SigningAcceptanceDisposition.ACCEPTED, receipt));
            when(fixture.signing.resolve(receipt)).thenReturn(SigningAcceptanceResolution.MATCHED);
            zeroecho.pki.api.signing.SemanticSigningOperation operation = mock(zeroecho.pki.api.signing.SemanticSigningOperation.class);
            when(operation.submissionId()).thenReturn(new zeroecho.pki.api.orch.SigningSubmissionId(receipt.operationId(), "test", fixture.clock.instant()));
            when(operation.state()).thenReturn(zeroecho.pki.api.signing.SemanticSigningState.SIGNING);
            when(fixture.signing.findIssuance(any(zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest.class))).thenReturn(Optional.of(operation));
            assertEquals(EnrollmentTransaction.State.ACCEPTED, fixture.coordinator.dispatch(value.id()).state());
            when(fixture.signing.resolve(receipt)).thenThrow(new IllegalStateException("Temporary lookup failure"));
            assertEquals(EnrollmentTransaction.State.ACCEPTED, fixture.coordinator.dispatch(value.id(), zeroecho.core.io.CancellationSignal.NONE,
                    () -> { throw new AssertionError("Accepted recovery must not require new authorization"); }).state());
            fixture.coordinator.close();
            try (EnrollmentCoordinator reopened = fixture.openCoordinator()) {
                assertEquals(EnrollmentTransaction.State.ACCEPTED, reopened.find(value.id()).orElseThrow().state());
                org.mockito.Mockito.doReturn(SigningAcceptanceResolution.NOT_ACCEPTED).when(fixture.signing).resolve(receipt);
                assertThrows(IllegalStateException.class, () -> reopened.dispatch(value.id()));
                assertThrows(IllegalStateException.class, () -> reopened.dispatch(value.id()));
            }
            verify(fixture.signing, org.mockito.Mockito.times(1)).prepareCorrelatedEndEntity(any(), any(), any(), any());
        }
    }

    @Test void provenNonacceptanceRevalidatesSuspensionAndMissingRetainedInputBlocksRestart() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission());
            when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any())).thenReturn(new CorrelatedIssuancePreparation.Prepared(preparation.prepared()));
            when(fixture.signing.accept(preparation.prepared())).thenReturn(new SigningAcceptanceResult(SigningAcceptanceDisposition.CAPACITY_REJECTED, preparation.prepared().receipt()));
            when(fixture.signing.resolve(preparation.prepared().receipt())).thenReturn(SigningAcceptanceResolution.NOT_ACCEPTED);
            assertEquals(EnrollmentTransaction.State.APPROVED, fixture.coordinator.dispatch(value.id()).state());
            fixture.profiles.setState("policy", EnrollmentProfileState.SUSPENDED);
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.dispatch(value.id()));
            CertificationRequestService missing = mock(CertificationRequestService.class);
            when(fixture.session.requests()).thenReturn(Optional.of(missing));
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
        }
    }

    @Test void expiredPendingReleasesOnlyPendingBudgetAndRetainsReplayAcrossRestart() throws Exception {
        java.time.Clock clock = mock(java.time.Clock.class);
        AtomicReference<java.time.Instant> now = new AtomicReference<>(ServerTestSupport.CLOCK.instant());
        when(clock.instant()).thenAnswer(invocation -> now.get());
        EnrollmentRuntimeConfiguration configuration = EnrollmentRuntimeConfiguration.decode(EnrollmentTestSupport.runtimeJson()
                .replace("\"maximumTransactions\":1000", "\"maximumTransactions\":2")
                .replace("\"maximumPending\":100", "\"maximumPending\":1").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 1, clock, configuration)) {
            EnrollmentTransaction first = fixture.coordinator.admit(fixture.admission());
            EnrollmentCoordinator.Admission second = transaction(fixture.admission(), "b");
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(second));
            now.set(now.get().plusSeconds(301));
            EnrollmentTransaction admitted = fixture.coordinator.admit(second);
            assertEquals(EnrollmentTransaction.State.EXPIRED, fixture.coordinator.admit(fixture.admission()).state());
            assertEquals(EnrollmentTransaction.State.PENDING, admitted.state());
            now.set(now.get().plusSeconds(301));
            fixture.coordinator.close();
            try (EnrollmentCoordinator reopened = fixture.openCoordinator()) {
                assertEquals(EnrollmentTransaction.State.EXPIRED, reopened.find(first.id()).orElseThrow().state());
                assertEquals(EnrollmentTransaction.State.EXPIRED, reopened.find(admitted.id()).orElseThrow().state());
                assertThrows(IllegalStateException.class, () -> reopened.admit(transaction(second, "c")));
                assertEquals(2, reopened.list(0, 10).values().size());
            }
        }
    }

    @Test void metadataAndFutureDecisionReservationAreChargedBeforeRequestStorage() throws Exception {
        EnrollmentRuntimeConfiguration configuration = EnrollmentRuntimeConfiguration.decode(EnrollmentTestSupport.runtimeJson()
                .replace("\"maximumRequestBytes\":1048576", "\"maximumRequestBytes\":4096")
                .replace("\"maximumRetainedRequestBytes\":10485760", "\"maximumRetainedRequestBytes\":4096")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 1, ServerTestSupport.CLOCK, configuration)) {
            assertTrue(csr.length < 4096);
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(fixture.admission()));
            assertTrue(fixture.coordinator.list(0, 10).values().isEmpty());
            assertTrue(fixture.requests.get(fixture.requests.parseX509(fixture.admission().payload()).requestId()).isEmpty());
        }
    }

    @Test void futureFormatAndTamperedPersistentMetadataFailStartup() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0)) {
            EnrollmentTransaction value = fixture.coordinator.admit(fixture.admission());
            ServerControlStore.ProtocolRecord original = opened.store().protocolRecord(ServerControlStore.ENROLLMENT_REQUEST, value.id()).orElseThrow();
            byte[] old = original.payload(); old[3] = 1;
            String oldHash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(old));
            opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                    ServerControlStore.ENROLLMENT_REQUEST, value.id(), oldHash, old), Optional.of(original.commitment()))));
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
            byte[] future = original.payload(); future[3] = 3;
            String hash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(future));
            opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                    ServerControlStore.ENROLLMENT_REQUEST, value.id(), hash, future), Optional.of(oldHash))));
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
            byte[] tampered = original.payload(); tampered[tampered.length - 1] ^= 1;
            String tamperedHash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(tampered));
            opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                    ServerControlStore.ENROLLMENT_REQUEST, value.id(), tamperedHash, tampered), Optional.of(hash))));
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
        }
    }

    @Test void uncertainDurableAdmissionFencesInstanceAndRestartRecoversOriginalRequest() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            ServerControlStore uncertain = mock(ServerControlStore.class, org.mockito.AdditionalAnswers.delegatesTo(opened.store()));
            try (Fixture fixture = new Fixture(uncertain, directory.resolve("pki"), 1)) {
                org.mockito.Mockito.doAnswer(invocation -> {
                    opened.store().mutateProtocol(invocation.getArgument(0));
                    throw new IllegalStateException("Lost control-store acknowledgement");
                }).when(uncertain).mutateProtocol(any());
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(fixture.admission()));
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(transaction(fixture.admission(), "b")));
                assertEquals(1, opened.store().protocolRecords(ServerControlStore.ENROLLMENT_REQUEST, 0, 10).values().size());
            }
            try (Fixture reopened = new Fixture(opened.store(), directory.resolve("pki"), 1)) {
                EnrollmentTransaction recovered = reopened.coordinator.admit(reopened.admission());
                assertEquals(EnrollmentTransaction.State.PENDING, recovered.state());
                assertEquals(1, reopened.coordinator.list(0, 10).values().size());
            }
        }
    }

    @Test void admissionBudgetAndShutdownFenceWhileParserRunsOutsideControlMonitor() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0);
                java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newSingleThreadExecutor()) {
            java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
            CertificationRequestService slow = mock(CertificationRequestService.class, org.mockito.AdditionalAnswers.delegatesTo(fixture.requests));
            org.mockito.Mockito.doAnswer(invocation -> {
                assertFalse(Thread.holdsLock(opened.store())); entered.countDown();
                assertTrue(release.await(5, java.util.concurrent.TimeUnit.SECONDS));
                return fixture.requests.parseX509(invocation.getArgument(0));
            }).when(slow).parseX509(any());
            when(fixture.session.requests()).thenReturn(Optional.of(slow));
            java.util.concurrent.Future<?> pending = executor.submit(() -> fixture.coordinator.admit(fixture.admission()));
            try {
                assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(transaction(fixture.admission(), "b")));
                assertThrows(IllegalStateException.class, fixture.coordinator::close);
            } finally { release.countDown(); }
            assertThrows(java.util.concurrent.ExecutionException.class, () -> pending.get(5, java.util.concurrent.TimeUnit.SECONDS));
            fixture.coordinator.close();
            assertTrue(fixture.coordinator.list(0, 10).values().isEmpty());
        }
    }

    @Test void conflictingAcceptanceFencesWithoutFreshPreparationAndRejectionIsFinal() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 1);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            EnrollmentTransaction first = fixture.coordinator.admit(fixture.admission());
            EnrollmentTransaction rejected = fixture.coordinator.decide(first.id(), first.commitment(), actor("one", "2"), ApprovalService.Choice.REJECT, "Identity rejected");
            assertEquals(EnrollmentTransaction.State.REJECTED, fixture.coordinator.dispatch(rejected.id()).state());
            assertEquals(rejected, fixture.coordinator.admit(fixture.admission()));
            EnrollmentTransaction second = fixture.coordinator.admit(transaction(fixture.admission(), "b"));
            fixture.coordinator.decide(second.id(), second.commitment(), actor("one", "2"), ApprovalService.Choice.APPROVE, "Reviewed");
            when(fixture.signing.prepareCorrelatedEndEntity(any(), any(), any(), any())).thenReturn(new CorrelatedIssuancePreparation.Prepared(preparation.prepared()));
            when(fixture.signing.accept(preparation.prepared())).thenThrow(new IllegalStateException("lost acknowledgement"));
            when(fixture.signing.resolve(preparation.prepared().receipt())).thenReturn(SigningAcceptanceResolution.CONFLICT);
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.dispatch(second.id()));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.dispatch(second.id()));
            verify(fixture.signing, org.mockito.Mockito.times(1)).prepareCorrelatedEndEntity(any(), any(), any(), any());
        }
    }

    @Test void protocolSnapshotIsConsistentAndOwnsItsCursorLifetime() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0)) {
            EnrollmentTransaction first = fixture.coordinator.admit(fixture.admission());
            ServerControlStore.ProtocolCursor cursor = opened.store().protocolSnapshot(ServerControlStore.ENROLLMENT_REQUEST);
            try (cursor) {
                fixture.coordinator.admit(transaction(fixture.admission(), "b"));
                assertEquals(first.id(), cursor.next().orElseThrow().recordId());
                assertTrue(cursor.next().isEmpty());
            }
            assertThrows(IllegalStateException.class, cursor::next);
            assertEquals(2, fixture.coordinator.list(0, 10).values().size());
        }
    }

    @Test void protocolCursorClosesEachRecordBeforeReturningOrRejectingIt() throws Exception {
        DurableTransactionalMetadataStore durable = DurableTransactionalMetadataStore.create(directory.resolve("metadata.log"), ServerTestSupport.STORE_ID);
        zeroecho.pki.spi.store.TransactionalMetadataStore metadata = mock(zeroecho.pki.spi.store.TransactionalMetadataStore.class,
                org.mockito.AdditionalAnswers.delegatesTo(durable));
        java.util.concurrent.atomic.AtomicInteger openedRecords = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger closedRecords = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicBoolean corruptKey = new java.util.concurrent.atomic.AtomicBoolean();
        try (ServerControlStore control = new ServerControlStore(metadata)) {
            new EnrollmentProfileService(control).register(new EnrollmentProfile("snapshot", "Snapshot test", EnrollmentProfileState.ACTIVE,
                    "leaf", Set.of(), Optional.empty(), List.of(), false));
            when(metadata.snapshot()).thenAnswer(ignored -> {
                zeroecho.pki.spi.store.MetadataSnapshot actual = durable.snapshot();
                zeroecho.pki.spi.store.MetadataSnapshot wrapped = mock(zeroecho.pki.spi.store.MetadataSnapshot.class, org.mockito.AdditionalAnswers.delegatesTo(actual));
                org.mockito.Mockito.doAnswer(scan -> {
                    zeroecho.pki.spi.store.MetadataCursor source = actual.scan(scan.getArgument(0), scan.getArgument(1));
                    zeroecho.pki.spi.store.MetadataCursor cursor = mock(zeroecho.pki.spi.store.MetadataCursor.class, org.mockito.AdditionalAnswers.delegatesTo(source));
                    org.mockito.Mockito.doAnswer(next -> source.next(next.getArgument(0)).map(record -> {
                        openedRecords.incrementAndGet();
                        zeroecho.pki.spi.store.MetadataSnapshot.Record result = mock(zeroecho.pki.spi.store.MetadataSnapshot.Record.class,
                                org.mockito.AdditionalAnswers.delegatesTo(record));
                        if (corruptKey.get()) when(result.key()).thenReturn(new zeroecho.pki.spi.store.MetadataKey(ServerControlStore.ENROLLMENT_PROFILE, "wrong"));
                        try {
                            org.mockito.Mockito.doAnswer(close -> { record.close(); closedRecords.incrementAndGet(); return null; }).when(result).close();
                        } catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
                        return result;
                    })).when(cursor).next(any());
                    return cursor;
                }).when(wrapped).scan(any(), any());
                return wrapped;
            });
            try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.ENROLLMENT_PROFILE)) {
                assertTrue(cursor.next().isPresent()); assertEquals(1, closedRecords.get());
                assertTrue(cursor.next().isEmpty());
            }
            corruptKey.set(true);
            try (ServerControlStore.ProtocolCursor cursor = control.protocolSnapshot(ServerControlStore.ENROLLMENT_PROFILE)) {
                assertThrows(IllegalStateException.class, cursor::next);
                assertEquals(openedRecords.get(), closedRecords.get());
                assertEquals(2, closedRecords.get());
            }
        }
    }

    @Test void protocolRequesterSeparationCannotBeDisabledByGenericApprovalPolicy() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 2)) {
            when(fixture.realm.approvalPolicies()).thenReturn(Map.of(OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_THRESHOLD,
                    new ApprovalService.Policy("relaxed-admin", 2, Set.of("one", "two", "three"), Set.of(), false, Duration.ofMinutes(5), true)));
            EnrollmentCoordinator.Admission original = fixture.admission();
            EnrollmentTransaction.Requester requester = original.requester();
            EnrollmentTransaction.Requester aliased = new EnrollmentTransaction.Requester(requester.type(), requester.actorId(), requester.authentication(),
                    requester.certificate(), requester.canonicalKeySha256(), requester.legacySpkiSha256(),
                    new EnrollmentIdentityAliases.Snapshot(ServerTestSupport.REALM, Set.of("three")));
            EnrollmentTransaction pending = fixture.coordinator.admit(new EnrollmentCoordinator.Admission(original.protocol(), original.endpointId(), aliased,
                    original.transactionId(), original.operation(), original.payload(), original.validity(), original.predecessorId()));
            assertFalse(pending.intent().approvalPolicy().orElseThrow().requesterSeparation());
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.decide(pending.id(), pending.commitment(), actor("one", "1"), ApprovalService.Choice.APPROVE, "Same key"));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.decide(pending.id(), pending.commitment(), actor("three", "4"), ApprovalService.Choice.APPROVE, "Frozen alias"));
            CertificateIdentityEvidence sameCertificate = new CertificateIdentityEvidence(ServerTestSupport.REALM, "1".repeat(64), "9".repeat(64), Set.of("9".repeat(64)), "9".repeat(64));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.decide(pending.id(), pending.commitment(),
                    new AdministrativeDecisionActor("one", Optional.of(sameCertificate)), ApprovalService.Choice.APPROVE, "Same certificate"));
            EnrollmentTransaction one = fixture.coordinator.decide(pending.id(), pending.commitment(), actor("one", "2"), ApprovalService.Choice.APPROVE, "Independent");
            assertEquals(EnrollmentTransaction.State.APPROVED, fixture.coordinator.decide(one.id(), one.commitment(), actor("two", "3"), ApprovalService.Choice.APPROVE, "Independent").state());
        }
    }

    @Test void forgedFrozenDecisionsFailConstructionAndChecksumConsistentRecovery() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 2)) {
            EnrollmentCoordinator.Admission original = fixture.admission();
            EnrollmentTransaction.Requester requester = original.requester();
            EnrollmentTransaction.Requester aliased = new EnrollmentTransaction.Requester(requester.type(), requester.actorId(), requester.authentication(),
                    requester.certificate(), requester.canonicalKeySha256(), requester.legacySpkiSha256(),
                    new EnrollmentIdentityAliases.Snapshot(ServerTestSupport.REALM, Set.of("alias")));
            EnrollmentTransaction value = fixture.coordinator.admit(new EnrollmentCoordinator.Admission(original.protocol(), original.endpointId(), aliased,
                    original.transactionId(), original.operation(), original.payload(), original.validity(), original.predecessorId()));
            EnrollmentTransaction first = fixture.coordinator.decide(value.id(), value.commitment(), actor("one", "2"), ApprovalService.Choice.APPROVE, "Original justification");
            EnrollmentTransaction approved = fixture.coordinator.decide(first.id(), first.commitment(), actor("two", "3"), ApprovalService.Choice.APPROVE, "Unique justification");
            for (EnrollmentTransaction.Decision invalid : List.of(
                    new EnrollmentTransaction.Decision("two", evidence("1"), ApprovalService.Choice.APPROVE, "Justified", ServerTestSupport.CLOCK.instant()),
                    new EnrollmentTransaction.Decision("alias", evidence("3"), ApprovalService.Choice.APPROVE, "Justified", ServerTestSupport.CLOCK.instant()),
                    new EnrollmentTransaction.Decision("two", evidence("3"), ApprovalService.Choice.APPROVE, " ", ServerTestSupport.CLOCK.instant()))) {
                assertThrows(IllegalArgumentException.class, () -> new EnrollmentTransaction(approved.id(), approved.revision(), approved.intent(), approved.state(),
                        List.of(approved.decisions().getFirst(), invalid), approved.receipt(), approved.credentialId()));
            }
            ServerControlStore.ProtocolRecord retained = opened.store().protocolRecord(ServerControlStore.ENROLLMENT_REQUEST, approved.id()).orElseThrow();
            String expected = retained.commitment();
            for (String[] replacement : List.of(new String[] {"3".repeat(64), "1".repeat(64)},
                    new String[] {"Unique justification", " ".repeat("Unique justification".length())}, new String[] {"two", "alias"})) {
                byte[] malformed = replaceUtf(retained.payload(), replacement[0], replacement[1]);
                String digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(malformed));
                opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                        ServerControlStore.ENROLLMENT_REQUEST, approved.id(), digest, malformed), Optional.of(expected))));
                assertThrows(IllegalStateException.class, fixture::openCoordinator);
                expected = digest;
            }
        }
    }

    @Test void frozenProofValidationRunsBeforeAdmissionAndDuringRecovery() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0)) {
            org.mockito.Mockito.doThrow(new IllegalArgumentException("Forbidden proof binding")).when(fixture.requests).requireProfileProof(any(), any());
            assertThrows(IllegalArgumentException.class, () -> fixture.coordinator.admit(fixture.admission()));
            assertTrue(fixture.coordinator.list(0, 10).values().isEmpty());
            assertTrue(fixture.requests.get(fixture.requests.parseX509(fixture.admission().payload()).requestId()).isEmpty());
            org.mockito.Mockito.doNothing().when(fixture.requests).requireProfileProof(any(), any());
            EnrollmentTransaction admitted = fixture.coordinator.admit(fixture.admission());
            org.mockito.Mockito.doThrow(new IllegalArgumentException("Unavailable frozen proof")).when(fixture.requests).requireProfileProof(any(), any());
            assertThrows(IllegalArgumentException.class, fixture::openCoordinator);
            verify(fixture.signing, never()).prepareCorrelatedEndEntity(any(), any(), any(), any());
            assertEquals(EnrollmentTransaction.State.APPROVED, admitted.state());
        }
    }

    private static byte[] replaceUtf(byte[] original, String before, String after) throws Exception {
        java.io.ByteArrayOutputStream oldBuffer = new java.io.ByteArrayOutputStream();
        new java.io.DataOutputStream(oldBuffer).writeUTF(before);
        java.io.ByteArrayOutputStream replacement = new java.io.ByteArrayOutputStream();
        new java.io.DataOutputStream(replacement).writeUTF(after);
        byte[] target = oldBuffer.toByteArray();
        // Digest targets first occur in the second vote's certificate; names/justification use the last field.
        int direction = before.length() == 64 ? 1 : -1;
        for (int index = direction == 1 ? 0 : original.length - target.length;
                index >= 0 && index <= original.length - target.length; index += direction) {
            if (java.util.Arrays.equals(original, index, index + target.length, target, 0, target.length)) {
                java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
                output.write(original, 0, index); output.write(replacement.toByteArray()); output.write(original, index + target.length, original.length - index - target.length);
                return output.toByteArray();
            }
        }
        throw new AssertionError("Target field missing");
    }

    private static EnrollmentCoordinator.Admission transaction(EnrollmentCoordinator.Admission value, String digit) {
        return new EnrollmentCoordinator.Admission(value.protocol(), value.endpointId(), value.requester(), digit.repeat(64), value.operation(),
                value.payload(), value.validity(), value.predecessorId());
    }

    @Test void administrativeGatewayUsesRetainedScopeAndTrustedEvidenceForRealDecision() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 1)) {
            EnrollmentTransaction pending = fixture.coordinator.admit(fixture.admission());
            Permission.Scope scope = new Permission.Scope(ServerTestSupport.REALM, Optional.of(AUTHORITY), Optional.of(ISSUER), Optional.of("leaf"));
            for (Permission.Action action : List.of(Permission.Action.REQUEST_READ_ANY, Permission.Action.REQUEST_APPROVE)) {
                opened.store().createGrant(ServerTestSupport.grant("grant-" + action.name(), "one", Permission.Effect.ALLOW,
                        action, Permission.ResourceType.ENROLLMENT_REQUEST, scope, Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            }
            ServerOperationGateway gateway = new ServerOperationGateway(ServerTestSupport.REALM, fixture.realm.authorityExposure(), opened.store(),
                    RoleTemplateCatalog.load(getClass().getClassLoader()), new AuthorizationEngine(ServerTestSupport.CLOCK),
                    new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit()),
                    new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit()), mock(DisclosureService.class),
                    mock(CredentialPublicationGate.class), new AuditorViews(ServerTestSupport.CLOCK, opened.audit()), Optional.empty(),
                    new OperationSecurityDescriptors(), mock(zeroecho.pki.application.PkiOperationExecutor.class),
                    mock(ServerOperationGateway.SigningExecutor.class), mock(zeroecho.pki.application.PkiResourceScopeResolver.class),
                    Map.of(), ignored -> IssuanceApprovalRequirement.NONE, ServerTestSupport.CLOCK, opened.audit(), () -> { }, () -> { });
            gateway.installEnrollmentCoordinator(fixture.coordinator);
            ServerControlOperation decision = new ServerControlOperation.DecideEnrollmentRequest(pending.id(), pending.commitment(),
                    ApprovalService.Choice.APPROVE, "Reviewed exact request identity");
            Permission.Resource noScope = new Permission.Resource(Permission.ResourceType.ENROLLMENT_REQUEST,
                    new Permission.Scope(ServerTestSupport.REALM, Optional.empty(), Optional.empty(), Optional.empty()), Optional.empty(), Optional.empty());
            ServerOperationGateway.Outcome missingEvidence = gateway.execute(gatewayRequest("one", decision, noScope, Optional.empty()), zeroecho.core.io.CancellationSignal.NONE);
            assertEquals(EnrollmentTransaction.State.PENDING, fixture.coordinator.find(pending.id()).orElseThrow().state());
            assertFalse(successful(missingEvidence));
            Permission.Resource wrongScope = new Permission.Resource(Permission.ResourceType.ENROLLMENT_REQUEST,
                    new Permission.Scope(ServerTestSupport.REALM, Optional.of(new PkiId("ca:other")), Optional.empty(), Optional.empty()), Optional.empty(), Optional.empty());
            assertFalse(successful(gateway.execute(gatewayRequest("one", decision, wrongScope, Optional.of(evidence("2"))), zeroecho.core.io.CancellationSignal.NONE)));
            assertFalse(successful(gateway.execute(gatewayRequest("two", decision, noScope, Optional.of(evidence("3"))), zeroecho.core.io.CancellationSignal.NONE)));
            ServerOperationGateway.Outcome inspected = gateway.execute(gatewayRequest("one", new ServerControlOperation.InspectEnrollmentRequest(pending.id()),
                    noScope, Optional.of(evidence("2"))), zeroecho.core.io.CancellationSignal.NONE);
            assertTrue(successful(inspected), inspected.toString());
            ServerOperationGateway.Outcome approved = gateway.execute(gatewayRequest("one", decision, noScope, Optional.of(evidence("2"))), zeroecho.core.io.CancellationSignal.NONE);
            assertTrue(successful(approved), approved.toString());
            EnrollmentTransaction retained = fixture.coordinator.find(pending.id()).orElseThrow();
            assertEquals(EnrollmentTransaction.State.APPROVED, retained.state());
            assertEquals(evidence("2"), retained.decisions().getFirst().evidence());
            assertEquals(pending.intentCommitment(), retained.intentCommitment());
        }
    }


    @Test void cmpNonEnrollmentFreshEffectsRevalidateSourceButRetainedResponsesRemainReadable() throws Exception {
        for (String change : List.of("suspend", "profile", "delete")) {
            Path root = java.nio.file.Files.createDirectory(directory.resolve(change));
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(root);
                    Fixture fixture = new Fixture(opened.store(), root.resolve("pki"), 0)) {
                CmpTransaction reserved = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "a", false, 2000));
                fixture.coordinator.requireCmpCurrentSource(reserved);
                when(fixture.runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.CMP, AUTHORITY.value())).thenReturn("cmp-rotated");
                fixture.coordinator.requireCmpCurrentSource(reserved);
                byte[] response = { 1, 2, 3 };
                CmpTransaction published = fixture.coordinator.storeCmpResponse(reserved, response, cmpResponse(response, "b", true));
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.requireCmpCurrentSource(reserved));
                if (change.equals("suspend")) fixture.profiles.setState("policy", EnrollmentProfileState.SUSPENDED);
                else if (change.equals("delete")) fixture.endpoints.deregister(EnrollmentEndpointRegistry.Protocol.CMP, "cmp");
                else {
                    EnrollmentProfile profile = fixture.profiles.find("policy").orElseThrow();
                    fixture.profiles.update(new EnrollmentProfile(profile.id(), "Changed policy", profile.state(), profile.certificateProfileId(),
                            profile.allowedAuthorityIds(), profile.subjectDnPattern(), profile.requiredSanDomains(), profile.requireApproval()));
                }
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.requireCmpCurrentSource(published));
                org.junit.jupiter.api.Assertions.assertArrayEquals(response, fixture.coordinator.cmpResponse(published));
            }
        }
    }

    @Test void cmpFixedResponseSlotsSurviveRestartAndShrinkWithoutStaleBytes() throws Exception {
        Path log; CmpTransaction retained; byte[] large = new byte[1_048_700];
        java.util.Arrays.fill(large, (byte) 37);
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0)) {
            log = opened.log();
            CmpTransaction reserved = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "a", false, 1_100_000));
            assertEquals(reserved, fixture.coordinator.reserveCmp(reserved.frozen()));
            assertEquals(0, fixture.coordinator.cmpResponse(reserved).length);
            retained = fixture.coordinator.storeCmpResponse(reserved, large, cmpResponse(large, "b", false));
            assertEquals(5, opened.store().protocolRecords(ServerControlStore.CMP_RESPONSE, 0, 20).values().size());
            org.junit.jupiter.api.Assertions.assertArrayEquals(large, fixture.coordinator.cmpResponse(retained));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.storeCmpResponse(reserved, large, cmpResponse(large, "c", false)));
            assertEquals(retained, fixture.coordinator.findCmp("cmp", "a".repeat(64)).orElseThrow());
        }
        try (ServerControlStore control = new ServerControlStore(DurableTransactionalMetadataStore.open(log, OptionalLong.of(1_048_576)));
                Fixture fixture = new Fixture(control, directory.resolve("pki"), 0)) {
            org.junit.jupiter.api.Assertions.assertArrayEquals(large, fixture.coordinator.cmpResponse(retained));
            byte[] shortResponse = new byte[] { 3, 1, 4 };
            CmpTransaction terminal = fixture.coordinator.storeCmpResponse(retained, shortResponse, cmpResponse(shortResponse, "c", true));
            org.junit.jupiter.api.Assertions.assertArrayEquals(shortResponse, fixture.coordinator.cmpResponse(terminal));
            for (int index = 1; index < 5; index++) assertTrue(control.protocolRecord(ServerControlStore.CMP_RESPONSE,
                    terminal.id() + ":" + index).orElseThrow().payload().length < 256);
            fixture.coordinator.close();
            try (EnrollmentCoordinator reopened = fixture.openCoordinator()) {
                org.junit.jupiter.api.Assertions.assertArrayEquals(shortResponse, reopened.cmpResponse(terminal));
                assertThrows(IllegalStateException.class, () -> reopened.storeCmpResponse(terminal, shortResponse, cmpResponse(shortResponse, "d", true)));
            }
        }
    }

    @Test void cmpUnlinkedReservationSurvivesCrashAndAttachmentChargesOneLogicalTransaction() throws Exception {
        EnrollmentRuntimeConfiguration config = EnrollmentRuntimeConfiguration.decode(EnrollmentTestSupport.runtimeJson()
                .replace("\"maximumTransactions\":1000", "\"maximumTransactions\":1")
                .replace("\"maximumPending\":100", "\"maximumPending\":1").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 1, ServerTestSupport.CLOCK, config)) {
            CmpTransaction reserved = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "a", true, 2000));
            // The domain write may have completed before a crash while neither cross-store reference was published.
            zeroecho.pki.api.request.ParsedCertificationRequest parsed = fixture.requests.parseX509(cmpAdmission(reserved).payload());
            fixture.requests.store(parsed, zeroecho.pki.api.request.RequestStorePolicy.STORE_ALWAYS);
            fixture.coordinator.close();
            try (EnrollmentCoordinator reopened = fixture.openCoordinator()) {
                assertEquals(reserved, reopened.findCmp("cmp", "a".repeat(64)).orElseThrow());
                assertThrows(IllegalStateException.class, () -> reopened.admit(fixture.admission()));
                EnrollmentTransaction enrollment = reopened.admitCmp(cmpAdmission(reserved), reserved);
                CmpTransaction linked = reopened.findCmp("cmp", "a".repeat(64)).orElseThrow();
                assertEquals(Optional.of(enrollment.id()), linked.enrollmentId());
                assertEquals(EnrollmentTransaction.State.PENDING, enrollment.state());
                assertEquals(enrollment, reopened.admitCmp(cmpAdmission(linked), linked));
                assertThrows(IllegalStateException.class, () -> reopened.admitCmp(cmpAdmission(reserved), reserved));
                assertThrows(IllegalStateException.class, () -> reopened.reserveCmp(cmpFrozen(fixture, "b", false, 1000)));
            }
            // A published immutable request reference is authority, never replaceable from retry bytes.
            CertificationRequestService missing = mock(CertificationRequestService.class);
            when(fixture.session.requests()).thenReturn(Optional.of(missing));
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
        }
    }

    @Test void cmpAttachmentIsAtomicAndUnknownAcknowledgementFencesAllProtocolWrites() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            ServerControlStore uncertain = mock(ServerControlStore.class, org.mockito.AdditionalAnswers.delegatesTo(opened.store()));
            CmpTransaction reserved;
            try (Fixture fixture = new Fixture(uncertain, directory.resolve("pki"), 1)) {
                reserved = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "a", true, 2000));
                org.mockito.Mockito.doAnswer(invocation -> {
                    List<ServerControlStore.ProtocolMutation> mutations = invocation.getArgument(0);
                    assertEquals(Set.of(ServerControlStore.CMP_TRANSACTION, ServerControlStore.ENROLLMENT_REQUEST),
                            mutations.stream().map(value -> value.record().namespace()).collect(java.util.stream.Collectors.toSet()));
                    assertEquals(2, mutations.size());
                    opened.store().mutateProtocol(mutations);
                    throw new IllegalStateException("Lost acknowledgement");
                }).when(uncertain).mutateProtocol(any());
                CmpTransaction expected = reserved;
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.admitCmp(cmpAdmission(expected), expected));
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(fixture.admission()));
                assertThrows(IllegalStateException.class, () -> fixture.coordinator.cmpResponse(expected));
            }
            try (Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 1)) {
                CmpTransaction linked = fixture.coordinator.findCmp("cmp", "a".repeat(64)).orElseThrow();
                assertTrue(linked.enrollmentId().isPresent());
                assertEquals(linked.enrollmentId().orElseThrow(), fixture.coordinator.admitCmp(cmpAdmission(linked), linked).id());
            }
        }
    }

    @Test void cmpUnknownReservationAndResponseWritesRecoverWithoutRefundOrNonceLoss() throws Exception {
        for (boolean responseWrite : List.of(false, true)) {
            Path root = directory.resolve(Boolean.toString(responseWrite));
            java.nio.file.Files.createDirectory(root);
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(root)) {
                ServerControlStore uncertain = mock(ServerControlStore.class, org.mockito.AdditionalAnswers.delegatesTo(opened.store()));
                byte[] bytes = new byte[] { 5, 8, 13 };
                try (Fixture fixture = new Fixture(uncertain, root.resolve("pki"), 0)) {
                    CmpTransaction.Frozen frozen = cmpFrozen(fixture, "a", false, 2000);
                    CmpTransaction prior = responseWrite ? fixture.coordinator.reserveCmp(frozen) : null;
                    org.mockito.Mockito.doAnswer(invocation -> {
                        opened.store().mutateProtocol(invocation.getArgument(0));
                        throw new IllegalStateException("Lost acknowledgement");
                    }).when(uncertain).mutateProtocol(any());
                    if (responseWrite) assertThrows(IllegalStateException.class, () -> fixture.coordinator.storeCmpResponse(prior, bytes, cmpResponse(bytes, "b", false)));
                    else assertThrows(IllegalStateException.class, () -> fixture.coordinator.reserveCmp(frozen));
                    assertThrows(IllegalStateException.class, () -> fixture.coordinator.admit(fixture.admission()));
                }
                try (Fixture fixture = new Fixture(opened.store(), root.resolve("pki"), 0)) {
                    CmpTransaction recovered = fixture.coordinator.findCmp("cmp", "a".repeat(64)).orElseThrow();
                    assertEquals(responseWrite, recovered.response().isPresent());
                    org.junit.jupiter.api.Assertions.assertArrayEquals(responseWrite ? bytes : new byte[0], fixture.coordinator.cmpResponse(recovered));
                }
            }
        }
    }

    @Test void cmpSharedByteCapacityRejectsBeforeDomainStorageAndReconstructsOnRestart() throws Exception {
        EnrollmentRuntimeConfiguration config = EnrollmentRuntimeConfiguration.decode(EnrollmentTestSupport.runtimeJson()
                .replace("\"maximumRequestBytes\":1048576", "\"maximumRequestBytes\":4096")
                .replace("\"maximumRetainedRequestBytes\":10485760", "\"maximumRetainedRequestBytes\":10000")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 1, ServerTestSupport.CLOCK, config)) {
            CmpTransaction reserved = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "a", true, 1000));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.admitCmp(cmpAdmission(reserved), reserved));
            verify(fixture.requests, never()).store(any(), any());
            assertTrue(fixture.coordinator.findCmp("cmp", "a".repeat(64)).orElseThrow().enrollmentId().isEmpty());
            fixture.coordinator.close();
            try (EnrollmentCoordinator reopened = fixture.openCoordinator()) {
                assertThrows(IllegalStateException.class, () -> reopened.reserveCmp(cmpFrozen(fixture, "b", false, 1000)));
            }
        }
    }

    @Test void cmpFutureMalformedOrphanAndCorruptSlotRecordsFailRecovery() throws Exception {
        for (String corruption : List.of("version", "orphan", "extra", "data")) {
            Path root = directory.resolve(corruption);
            java.nio.file.Files.createDirectory(root);
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(root);
                    Fixture fixture = new Fixture(opened.store(), root.resolve("pki"), 0)) {
                CmpTransaction reserved = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "a", false, 2000));
                byte[] bytes = new byte[] { 1, 2, 3 };
                CmpTransaction current = fixture.coordinator.storeCmpResponse(reserved, bytes, cmpResponse(bytes, "b", false));
                boolean manifest = corruption.equals("version");
                ServerControlStore.ProtocolRecord prior = opened.store().protocolRecord(
                        manifest ? ServerControlStore.CMP_TRANSACTION : ServerControlStore.CMP_RESPONSE,
                        manifest ? current.id() : current.id() + ":0").orElseThrow();
                byte[] payload = prior.payload();
                String id = prior.recordId();
                Optional<String> expected = Optional.of(prior.commitment());
                if (manifest) payload[3] = 2;
                else if (corruption.equals("data")) payload[payload.length - 1] ^= 1;
                else { id = corruption.equals("orphan") ? "cmp:" + "f".repeat(64) + ":0" : current.id() + ":1"; expected = Optional.empty(); }
                opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                        new ServerControlStore.ProtocolRecord(prior.namespace(), id, hash(payload), payload), expected)));
                assertThrows(IllegalStateException.class, fixture::openCoordinator, corruption);
            }
        }
    }


    @Test void cmpExactRequestIdentifierAndOriginalTypeRejectSubstitutionBeforeStorageAndOnRecovery() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0)) {
            CmpTransaction.Frozen original = cmpFrozen(fixture, "a", true, 2000);
            CmpTransaction wrongId = fixture.coordinator.reserveCmp(cmpRequest(original, 0, java.math.BigInteger.valueOf(8), hash(crmf)));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.admitCmp(cmpAdmission(wrongId), wrongId));
            CmpTransaction wrongKur = fixture.coordinator.reserveCmp(cmpRequest(cmpFrozen(fixture, "b", true, 2000), 7, java.math.BigInteger.valueOf(7), hash(crmf)));
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.admitCmp(cmpAdmission(wrongKur), wrongKur));
            CmpTransaction wrongIssue = fixture.coordinator.reserveCmp(cmpRequest(cmpFrozen(fixture, "c", true, 2000), 0, java.math.BigInteger.valueOf(7), hash(replacementCrmf)));
            EnrollmentCoordinator.Admission withOldId = new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.CMP, "cmp",
                    wrongIssue.frozen().requester(), wrongIssue.frozen().transactionSha256(), EnrollmentTransaction.Operation.ISSUE,
                    new X509EnrollmentPayload(X509EnrollmentPayload.Kind.CRMF, replacementCrmf), Optional.empty(), Optional.empty());
            assertThrows(IllegalStateException.class, () -> fixture.coordinator.admitCmp(withOldId, wrongIssue));
            verify(fixture.requests, never()).store(any(), any());
            CmpTransaction valid = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "d", true, 2000));
            fixture.coordinator.admitCmp(cmpAdmission(valid), valid);
            CmpTransaction linked = fixture.coordinator.findCmp("cmp", "d".repeat(64)).orElseThrow();
            ServerControlStore.ProtocolRecord record = opened.store().protocolRecord(ServerControlStore.CMP_TRANSACTION, linked.id()).orElseThrow();
            byte[] malformed = replaceUtf(record.payload(), "7", "8");
            opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                    record.namespace(), record.recordId(), hash(malformed), malformed), Optional.of(record.commitment()))));
            assertThrows(IllegalStateException.class, fixture::openCoordinator);
        }
    }

    @Test void cmpReplacementUsesExactPayloadCorrelatedPreparationAndRecovery() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0);
                SemanticPreparationFixture preparation = SemanticPreparationFixture.open(directory.resolve("custody"))) {
            PkiId predecessorId = new PkiId("credential:predecessor");
            zeroecho.pki.api.credential.Credential predecessor = mock(zeroecho.pki.api.credential.Credential.class);
            zeroecho.pki.api.content.DurableContentReference content = mock(zeroecho.pki.api.content.DurableContentReference.class);
            when(content.sha256()).thenReturn("e".repeat(64)); when(predecessor.content()).thenReturn(content);
            when(predecessor.issuerRef()).thenReturn(new zeroecho.pki.api.IssuerRef(AUTHORITY));
            when(predecessor.profileBinding()).thenReturn(new zeroecho.pki.api.credential.EndEntityProfileBinding(new CertificateProfileRef("leaf", 1, new byte[32])));
            when(fixture.session.repository().credential(predecessorId)).thenReturn(Optional.of(predecessor));
            CmpTransaction reserved = fixture.coordinator.reserveCmp(cmpRequest(cmpFrozen(fixture, "a", true, 2000),
                    7, java.math.BigInteger.valueOf(7), hash(replacementCrmf)));
            EnrollmentCoordinator.Admission admission = new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.CMP, "cmp",
                    reserved.frozen().requester(), reserved.frozen().transactionSha256(), EnrollmentTransaction.Operation.REPLACE,
                    new X509EnrollmentPayload(X509EnrollmentPayload.Kind.CRMF, replacementCrmf), Optional.empty(), Optional.of(predecessorId));
            EnrollmentTransaction pending = fixture.coordinator.admitCmp(admission, reserved);
            org.mockito.ArgumentCaptor<zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest> command =
                    org.mockito.ArgumentCaptor.forClass(zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest.class);
            when(fixture.signing.prepareCorrelatedReplacement(any(), command.capture(), any(), any()))
                    .thenReturn(new CorrelatedIssuancePreparation.Prepared(preparation.prepared()));
            when(fixture.signing.accept(preparation.prepared())).thenReturn(
                    new SigningAcceptanceResult(SigningAcceptanceDisposition.ACCEPTED, preparation.prepared().receipt()));
            when(fixture.signing.resolve(preparation.prepared().receipt())).thenReturn(SigningAcceptanceResolution.MATCHED);
            zeroecho.pki.api.signing.SemanticSigningOperation operation = mock(zeroecho.pki.api.signing.SemanticSigningOperation.class);
            when(operation.submissionId()).thenReturn(new zeroecho.pki.api.orch.SigningSubmissionId(preparation.prepared().receipt().operationId(), "test", fixture.clock.instant()));
            when(operation.state()).thenReturn(zeroecho.pki.api.signing.SemanticSigningState.SIGNING);
            when(fixture.signing.findReplacement(any())).thenReturn(Optional.of(operation));
            assertEquals(EnrollmentTransaction.State.ACCEPTED, fixture.coordinator.dispatch(pending.id()).state());
            assertEquals(predecessorId, command.getValue().request().existingCredentialId());
            org.junit.jupiter.api.Assertions.assertArrayEquals(replacementCrmf, command.getValue().request().payload().der());
            verify(fixture.signing, never()).prepareCorrelatedEndEntity(any(), any(), any(), any());
            verify(fixture.signing, never()).prepareCorrelatedRenewal(any(), any(), any(), any());
            fixture.coordinator.close();
            try (EnrollmentCoordinator reopened = fixture.openCoordinator()) {
                assertEquals(EnrollmentTransaction.State.ACCEPTED, reopened.find(pending.id()).orElseThrow().state());
                assertEquals(EnrollmentTransaction.State.ACCEPTED, reopened.dispatch(pending.id()).state());
            }
            verify(fixture.signing, org.mockito.Mockito.times(1)).prepareCorrelatedReplacement(any(), any(), any(), any());
        }
    }

    @Test void cmpConcurrentResponseCasPublishesExactlyOneNonceAndDoesNotFenceLoser() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                Fixture fixture = new Fixture(opened.store(), directory.resolve("pki"), 0);
                java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            CmpTransaction reserved = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "a", false, 2000));
            java.util.concurrent.CyclicBarrier start = new java.util.concurrent.CyclicBarrier(2);
            List<java.util.concurrent.Future<Boolean>> results = new java.util.ArrayList<>();
            for (String token : List.of("b", "c")) results.add(executor.submit(() -> {
                start.await(5, java.util.concurrent.TimeUnit.SECONDS);
                byte[] bytes = token.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                try { fixture.coordinator.storeCmpResponse(reserved, bytes, new CmpTransaction.Response(token.repeat(64),
                        hash(bytes), bytes.length, token.repeat(32), "a".repeat(32), Optional.empty(), CmpTransaction.Confirmation.NONE, false)); return true; }
                catch (IllegalStateException stale) { return false; }
            }));
            int acknowledged = 0;
            for (java.util.concurrent.Future<Boolean> result : results) if (result.get(5, java.util.concurrent.TimeUnit.SECONDS)) acknowledged++;
            assertEquals(1, acknowledged);
            CmpTransaction current = fixture.coordinator.findCmp("cmp", "a".repeat(64)).orElseThrow();
            String winner = new String(fixture.coordinator.cmpResponse(current), java.nio.charset.StandardCharsets.US_ASCII);
            assertEquals(winner.repeat(32), current.response().orElseThrow().senderNonce());
            assertEquals(2, current.revision());
        }
    }


    @Test void cmpConfirmationVerdictsAndMissingSlotsRemainStrictOnRestart() throws Exception {
        for (CmpTransaction.Confirmation verdict : List.of(CmpTransaction.Confirmation.ACCEPTED, CmpTransaction.Confirmation.REJECTED,
                CmpTransaction.Confirmation.EXPIRED)) {
            Path root = java.nio.file.Files.createDirectory(directory.resolve(verdict.name()));
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(root);
                    Fixture fixture = new Fixture(opened.store(), root.resolve("pki"), 0)) {
                CmpTransaction reserved = fixture.coordinator.reserveCmp(cmpFrozen(fixture, "a", true, 2000));
                fixture.coordinator.admitCmp(cmpAdmission(reserved), reserved);
                CmpTransaction linked = fixture.coordinator.findCmp("cmp", "a".repeat(64)).orElseThrow();
                byte[] bytes = new byte[] { 1, 3, 5 };
                CmpTransaction awaiting = fixture.coordinator.storeCmpResponse(linked, bytes,
                        new CmpTransaction.Response("b".repeat(64), hash(bytes), bytes.length, "1".repeat(32), "2".repeat(32),
                                Optional.of(fixture.clock.instant().plusSeconds(60)), CmpTransaction.Confirmation.AWAITING, false));
                fixture.coordinator.close();
                {
                    EnrollmentCoordinator reopened = fixture.openCoordinator();
                    try (reopened) {
                        assertEquals(CmpTransaction.Confirmation.AWAITING, reopened.findCmp("cmp", "a".repeat(64)).orElseThrow().response().orElseThrow().confirmation());
                        CmpTransaction terminal = reopened.storeCmpResponse(awaiting, bytes,
                                new CmpTransaction.Response("c".repeat(64), hash(bytes), bytes.length, "3".repeat(32), "4".repeat(32),
                                        Optional.empty(), verdict, true));
                        reopened.close();
                        try (EnrollmentCoordinator twice = fixture.openCoordinator()) {
                            assertEquals(verdict, twice.findCmp("cmp", "a".repeat(64)).orElseThrow().response().orElseThrow().confirmation());
                            org.junit.jupiter.api.Assertions.assertArrayEquals(bytes, twice.cmpResponse(terminal));
                        }
                    }
                }
                ServerControlStore missing = mock(ServerControlStore.class, org.mockito.AdditionalAnswers.delegatesTo(opened.store()));
                org.mockito.Mockito.doReturn(Optional.empty()).when(missing).protocolRecord(ServerControlStore.CMP_RESPONSE, reserved.id() + ":0");
                assertThrows(IllegalStateException.class, () -> new EnrollmentCoordinator(missing, fixture.realm, fixture.session,
                        fixture.endpoints, fixture.profiles, new AcmeControlStore(missing), fixture.runtime, fixture.aliases, fixture.clock));
            }
        }
        assertThrows(IllegalArgumentException.class, () -> new CmpTransaction.Response("a".repeat(64), "b".repeat(64), 3,
                "1".repeat(32), "2".repeat(32), Optional.empty(), CmpTransaction.Confirmation.AWAITING, false));
        assertThrows(IllegalArgumentException.class, () -> new CmpTransaction.Response("a".repeat(64), "b".repeat(64), 3,
                "1".repeat(32), "2".repeat(32), Optional.empty(), CmpTransaction.Confirmation.ACCEPTED, false));
    }

    private static CmpTransaction.Frozen cmpRequest(CmpTransaction.Frozen f, int type, java.math.BigInteger requestId, String digest) {
        return new CmpTransaction.Frozen(f.realmId(), f.source(), f.requester(), f.authorityId(), f.profile(), f.issuerId(), f.pathId(), f.pathCommitment(),
                f.transactionSha256(), f.originalWireSha256(), type, requestId, Optional.of(digest), f.implicitConfirmation(),
                f.createdAt(), f.expiresAt(), f.maximumResponseBytes());
    }

    private static CmpTransaction.Frozen cmpFrozen(Fixture fixture, String transaction, boolean enrollment, int maximumResponse) {
        zeroecho.pki.server.cmp.CmpEndpoint endpoint = new zeroecho.pki.server.cmp.CmpEndpoint("cmp", AUTHORITY.value(), "leaf", "policy",
                zeroecho.pki.server.cmp.CmpProtectionPolicy.SIGNATURE_BASED);
        if (fixture.endpoints.find(EnrollmentEndpointRegistry.Protocol.CMP, "cmp").isEmpty()) fixture.endpoints.register(endpoint);
        EnrollmentEndpointRegistry.Snapshot snapshot = fixture.endpoints.requireCurrent(endpoint);
        EnrollmentTransaction.Source source = new EnrollmentTransaction.Source(EnrollmentTransaction.Protocol.CMP, "cmp", "CMP:cmp",
                snapshot.revision(), snapshot.commitment(), "policy", EnrollmentProfileService.commitment(fixture.profiles.find("policy").orElseThrow()), Optional.of("cmp-credential"));
        CertificateIdentityEvidence identity = evidence("1");
        EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.CMP_SIGNER,
                "cmp-client", IssuanceExecutionEvidence.Authentication.CMP_SIGNATURE, Optional.of(identity), Optional.of(identity.canonicalKeySha256()),
                identity.legacySpkiSha256(), fixture.aliases.knownAliases(identity));
        IssuerChainPath path = IssuerChainPath.create(AUTHORITY, ISSUER, List.of(new PkiId("x509:issuer")));
        return new CmpTransaction.Frozen(ServerTestSupport.REALM, source, requester, AUTHORITY, new CertificateProfileRef("leaf", 1, new byte[32]),
                ISSUER, path.pathId(), path.pathCommitment(), transaction.repeat(64), "9".repeat(64), enrollment ? 0 : 21,
                enrollment ? java.math.BigInteger.valueOf(7) : java.math.BigInteger.ZERO, enrollment ? Optional.of(hash(crmf)) : Optional.empty(), false,
                fixture.clock.instant(), fixture.clock.instant().plusSeconds(600), maximumResponse);
    }

    private static EnrollmentCoordinator.Admission cmpAdmission(CmpTransaction manifest) {
        return new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.CMP, "cmp", manifest.frozen().requester(),
                manifest.frozen().transactionSha256(), EnrollmentTransaction.Operation.ISSUE,
                new X509EnrollmentPayload(X509EnrollmentPayload.Kind.CRMF, crmf), Optional.empty(), Optional.empty());
    }

    private static CmpTransaction.Response cmpResponse(byte[] bytes, String request, boolean terminal) {
        return new CmpTransaction.Response(request.repeat(64), hash(bytes), bytes.length, "1".repeat(32), "2".repeat(32), Optional.empty(), CmpTransaction.Confirmation.NONE, terminal);
    }

    private static String hash(byte[] bytes) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static boolean successful(ServerOperationGateway.Outcome outcome) {
        return outcome instanceof ServerOperationGateway.Outcome.ControlExecuted executed
                && executed.outcome() instanceof ServerControlOperationOutcome.Ordinary ordinary
                && ordinary.outcome() instanceof zeroecho.pki.application.PkiOperationOutcome.Completed;
    }

    private static ServerOperationGateway.Request gatewayRequest(String principal, ServerControlOperation operation,
            Permission.Resource resource, Optional<CertificateIdentityEvidence> evidence) {
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, principal, AdministrativeAuthenticationMode.DIRECT_MTLS,
                Optional.empty(), evidence, new AdministrativeOperation.Control(operation), resource, Permission.Relationship.ANY,
                Permission.Context.empty(), Optional.empty(), "enrollment-admin-test");
    }

    private static CertificateIdentityEvidence evidence(String digit) {
        return new CertificateIdentityEvidence(ServerTestSupport.REALM, digit.repeat(64), digit.repeat(64), Set.of(digit.repeat(64)), digit.repeat(64));
    }
    private static AdministrativeDecisionActor actor(String name, String digit) { return new AdministrativeDecisionActor(name, Optional.of(evidence(digit))); }

    private static final class Fixture implements AutoCloseable {
        final java.time.Clock clock;
        final ServerControlStore control;
        final FilesystemPkiStore domain;
        final CertificationRequestService requests;
        final PkiSession session = mock(PkiSession.class);
        final SemanticSigningService signing = mock(SemanticSigningService.class);
        final EnrollmentProfileService profiles;
        final EnrollmentEndpointRegistry endpoints;
        final EstEndpoint endpoint = new EstEndpoint("est", AUTHORITY.value(), "leaf", "policy", zeroecho.pki.server.est.KeygenPolicy.DISABLED);
        final ServerRealmConfiguration realm = mock(ServerRealmConfiguration.class);
        final EnrollmentRuntime runtime = mock(EnrollmentRuntime.class);
        final EnrollmentIdentityAliases aliases;
        final EnrollmentCoordinator coordinator;
        final AutoCloseable keygenSpool;

        Fixture(ServerControlStore control, Path domainPath, int threshold) throws Exception {
            this(control, domainPath, threshold, ServerTestSupport.CLOCK, EnrollmentTestSupport.runtimeConfiguration());
        }
        Fixture(ServerControlStore control, Path domainPath, int threshold, java.time.Clock clock,
                EnrollmentRuntimeConfiguration configuration) throws Exception {
            this.control = control;
            this.clock = clock;
            domain = new FilesystemPkiStore(domainPath, FsPkiStoreOptions.defaults(), ServerTestSupport.CLOCK);
            CredentialFramework framework = mock(CredentialFramework.class);
            when(framework.requestParser()).thenReturn(new BcX509CertificationRequestParser());
            ProofOfPossessionVerifier verifier = mock(ProofOfPossessionVerifier.class);
            when(verifier.verify(any(), any())).thenReturn(ProofOfPossessionResult.of(ProofOfPossessionReason.VERIFIED));
            when(framework.proofOfPossessionVerifier()).thenReturn(verifier);
            requests = mock(CertificationRequestService.class, org.mockito.AdditionalAnswers.delegatesTo(new DefaultCertificationRequestService(domain, framework)));
            // State-machine fixtures stub crypto policy; real configured validation is covered by issuance/core tests.
            org.mockito.Mockito.doNothing().when(requests).requireProfileProof(any(), any());
            when(session.requests()).thenReturn(Optional.of(requests));
            when(session.semanticSigning()).thenReturn(Optional.of(signing));
            zeroecho.pki.api.ProfileService certificateProfiles = mock(zeroecho.pki.api.ProfileService.class);
            CertificateProfileDefinition definition = mock(CertificateProfileDefinition.class);
            when(definition.approvalRequirement()).thenReturn(threshold > 1 ? IssuanceApprovalRequirement.THRESHOLD : IssuanceApprovalRequirement.NONE);
            ActiveCertificateProfile active = mock(ActiveCertificateProfile.class);
            when(active.definition()).thenReturn(definition); when(active.reference()).thenReturn(new CertificateProfileRef("leaf", 1, new byte[32]));
            when(certificateProfiles.requireActiveProfile("leaf")).thenReturn(active);
            zeroecho.pki.api.profile.ImportedCertificateProfileVersion imported = mock(zeroecho.pki.api.profile.ImportedCertificateProfileVersion.class);
            when(imported.reference()).thenReturn(new CertificateProfileRef("leaf", 1, new byte[32]));
            when(imported.definition()).thenReturn(definition);
            when(certificateProfiles.getImportedVersion("leaf", 1)).thenReturn(Optional.of(imported));
            when(session.profiles()).thenReturn(certificateProfiles);
            IssuerChainPath path = IssuerChainPath.create(AUTHORITY, ISSUER, List.of(new PkiId("x509:issuer")));
            PkiRepository repository = mock(PkiRepository.class);
            when(repository.authority(AUTHORITY)).thenReturn(Optional.of(new CaRecord(AUTHORITY, CaKind.ROOT, CaState.ACTIVE,
                    new KeyRef("key:issuer"), new SubjectRef("CN=Issuer"), List.of(ISSUER), ISSUER, path.pathId())));
            when(repository.chainPath(path.pathId())).thenReturn(Optional.of(path)); when(session.repository()).thenReturn(repository);
            zeroecho.pki.api.ca.IssuerGeneration issuer = mock(zeroecho.pki.api.ca.IssuerGeneration.class);
            when(issuer.authorityId()).thenReturn(AUTHORITY); when(repository.issuer(ISSUER)).thenReturn(Optional.of(issuer));
            when(realm.realmId()).thenReturn(ServerTestSupport.REALM);
            when(realm.authorityExposure()).thenReturn(new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), false));
            when(realm.approvalPolicies()).thenReturn(threshold == 0 ? Map.of() : Map.of(threshold > 1
                    ? OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_THRESHOLD : OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_SINGLE,
                    new ApprovalService.Policy("enrollment", threshold, Set.of("one", "two", "three"), Set.of(), true, Duration.ofMinutes(5), true)));
            for (String name : List.of("one", "two", "three")) {
                if (control.principals(0, 10).values().stream().noneMatch(value -> value.principalId().equals(name))) control.createPrincipal(ServerTestSupport.principal(name));
            }
            when(runtime.configuration()).thenReturn(configuration);
            keygenSpool = configuration.keygenArtifacts().isPresent()
                    ? zeroecho.pki.server.enrollment.KeygenSpoolTestSupport.install(runtime, configuration) : () -> { };
            when(runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.CMP, AUTHORITY.value())).thenReturn("cmp-credential");
            when(runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.EST, AUTHORITY.value())).thenReturn("est-generator");
            when(runtime.admissionDeadline("est-generator")).thenAnswer(invocation -> clock.instant().plusSeconds(600));
            when(runtime.credentialNotAfter("est-generator")).thenReturn(Instant.parse("2028-01-01T00:00:00Z"));
            when(runtime.credentialNotAfter("est-rotated")).thenReturn(Instant.parse("2028-01-01T00:00:00Z"));
            when(runtime.admissionDeadline("cmp-credential")).thenAnswer(invocation -> clock.instant().plusSeconds(600));
            profiles = new EnrollmentProfileService(control);
            if (profiles.find("policy").isEmpty()) profiles.register(new EnrollmentProfile("policy", "Enrollment policy", EnrollmentProfileState.ACTIVE,
                    "leaf", Set.of(AUTHORITY.value()), Optional.empty(), List.of(), threshold > 0));
            endpoints = new EnrollmentEndpointRegistry(control, profiles);
            if (endpoints.find(EnrollmentEndpointRegistry.Protocol.EST, "est").isEmpty()) endpoints.register(endpoint);
            aliases = new EnrollmentIdentityAliases(ServerTestSupport.REALM, new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                    List.of(new PkiServerConfiguration.ClientCertificateMapping("one", "one", Optional.of("2".repeat(64)), Optional.empty(), Optional.empty())),
                    List.of(), List.of(), Set.of(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0));
            coordinator = openCoordinator();
        }
        EnrollmentCoordinator openCoordinator() {
            return new EnrollmentCoordinator(control, realm, session, endpoints, profiles, new AcmeControlStore(control), runtime, aliases, clock);
        }
        EnrollmentCoordinator.Admission admission() {
            CertificateIdentityEvidence evidence = evidence("1");
            EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.EST_CLIENT, "client", IssuanceExecutionEvidence.Authentication.EST_MTLS,
                    Optional.of(evidence), Optional.of(evidence.canonicalKeySha256()), evidence.legacySpkiSha256(), new EnrollmentIdentityAliases.Snapshot(ServerTestSupport.REALM, Set.of()));
            return new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.EST, "est", requester, "a".repeat(64), EnrollmentTransaction.Operation.ISSUE,
                    new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, csr), Optional.empty(), Optional.empty());
        }
        @Override public void close() throws java.io.IOException {
            coordinator.close();
            try { keygenSpool.close(); } catch (Exception failure) { throw new java.io.IOException(failure); }
            domain.close();
        }
    }
}
