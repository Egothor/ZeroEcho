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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;

/** Durable responder binding, activation, recovery and dependency-failure coverage. */
class OcspResponderServiceTest {
    @TempDir Path temporaryDirectory;

    @Test
    void persistsExactIssuerBindingAndFailsOnChangedRegistryCommitment() throws Exception {
        System.out.println("persistsExactIssuerBindingAndFailsOnChangedRegistryCommitment");
        PkiId credentialId = new PkiId("credential:ocsp-root");
        PkiId issuerId = IssuerGeneration.idFor(ServerTestSupport.AUTHORITY, credentialId);
        KeyRef keyRef = new KeyRef("kref:v1:keyring:ocsp-root");
        IssuerGeneration issuer = new IssuerGeneration(issuerId, ServerTestSupport.AUTHORITY, credentialId,
                keyRef, IssuerGenerationState.ACTIVE, ServerTestSupport.DIGEST, ServerTestSupport.DIGEST);
        IssuerChainPath path = IssuerChainPath.create(ServerTestSupport.AUTHORITY, issuerId,
                java.util.List.of(credentialId));
        PkiRepository repository = mock(PkiRepository.class);
        when(repository.issuer(issuerId)).thenReturn(Optional.of(issuer));
        when(repository.chainPath(path.pathId())).thenReturn(Optional.of(path));
        byte[] certificate = certificate();
        when(repository.openCredential(credentialId)).thenAnswer(ignored -> content(certificate));
        X509AlgorithmBindingRegistry bindings = mock(X509AlgorithmBindingRegistry.class);
        when(bindings.commitment()).thenReturn(ServerTestSupport.DIGEST);
        OcspResponseService signing = mock(OcspResponseService.class);

        Path log;
        String responderId;
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            log = opened.log();
            OcspResponderService service = new OcspResponderService(ServerTestSupport.REALM, opened.store(),
                    repository, bindings, Optional.of(signing), ServerTestSupport.CLOCK);
            OcspResponderService.Registration registration = new OcspResponderService.Registration(
                    "ocsp-root", "root", ServerTestSupport.AUTHORITY,
                    issuerId, OcspResponderService.SigningMode.ISSUER_SIGNED, credentialId, keyRef, path.pathId(),
                    "SHA256withRSA", Optional.empty(), ServerTestSupport.DIGEST,
                    OcspResponseService.ResponderId.BY_KEY, Duration.ofMinutes(5),
                    OcspResponderService.NoncePolicy.OPTIONAL_ECHO, 64,
                    Set.of(OcspResponseService.CertIdHash.SHA1, OcspResponseService.CertIdHash.SHA256),
                    16_384, 8, Duration.ofMinutes(1));
            responderId = service.register(registration).responderId();
            assertThrows(IllegalStateException.class, () -> service.requireActiveAlias("root"));
            OcspResponderService.Registration duplicateAlias = new OcspResponderService.Registration(
                    "ocsp-root-duplicate", "root", ServerTestSupport.AUTHORITY, issuerId,
                    OcspResponderService.SigningMode.ISSUER_SIGNED, credentialId, keyRef, path.pathId(),
                    "SHA256withRSA", Optional.empty(), ServerTestSupport.DIGEST,
                    OcspResponseService.ResponderId.BY_KEY, Duration.ofMinutes(5),
                    OcspResponderService.NoncePolicy.REJECT, 64,
                    Set.of(OcspResponseService.CertIdHash.SHA1), 16_384, 8, Duration.ofMinutes(1));
            assertThrows(IllegalStateException.class, () -> service.register(duplicateAlias));
            assertEquals(OcspResponderService.State.ACTIVE, service.setActive(responderId, true).state());
            assertEquals(responderId, service.requireActiveAlias("root").responderId());
        }

        try (ServerControlStore reopened = new ServerControlStore(DurableTransactionalMetadataStore.open(log,
                OptionalLong.of(1_048_576)))) {
            OcspResponderService recovered = new OcspResponderService(ServerTestSupport.REALM, reopened,
                    repository, bindings, Optional.of(signing), ServerTestSupport.CLOCK);
            recovered.validateAll();
            assertEquals(responderId, recovered.requireActiveAlias("root").responderId());
            verify(signing, atLeast(3)).validateSigningBinding(credentialId, keyRef,
                    "SHA256withRSA", Optional.empty());
            when(bindings.commitment()).thenReturn("f".repeat(64));
            assertThrows(IllegalStateException.class, recovered::validateAll);
        }
        System.out.println("...durable-recovery=true changed-binding-rejected=true");
        System.out.println("persistsExactIssuerBindingAndFailsOnChangedRegistryCommitment...ok");
    }

    @Test
    void validatesDelegatedResponderIssuerEkuUsageAndSigningCapability() throws Exception {
        System.out.println("validatesDelegatedResponderIssuerEkuUsageAndSigningCapability");
        CertificatePair certificates = delegatedCertificates();
        PkiId issuerCredential = new PkiId("credential:delegated-issuer");
        PkiId responderCredential = new PkiId("credential:delegated-responder");
        PkiId issuerId = IssuerGeneration.idFor(ServerTestSupport.AUTHORITY, issuerCredential);
        IssuerGeneration issuer = new IssuerGeneration(issuerId, ServerTestSupport.AUTHORITY, issuerCredential,
                new KeyRef("kref:v1:keyring:delegated-issuer"), IssuerGenerationState.ACTIVE,
                ServerTestSupport.DIGEST, ServerTestSupport.DIGEST);
        IssuerChainPath path = IssuerChainPath.create(ServerTestSupport.AUTHORITY, issuerId,
                java.util.List.of(issuerCredential));
        PkiRepository repository = mock(PkiRepository.class);
        when(repository.issuer(issuerId)).thenReturn(Optional.of(issuer));
        when(repository.chainPath(path.pathId())).thenReturn(Optional.of(path));
        when(repository.openCredential(issuerCredential)).thenAnswer(ignored -> content(certificates.issuer()));
        when(repository.openCredential(responderCredential)).thenAnswer(
                ignored -> content(certificates.responder()));
        X509AlgorithmBindingRegistry bindings = mock(X509AlgorithmBindingRegistry.class);
        when(bindings.commitment()).thenReturn(ServerTestSupport.DIGEST);
        OcspResponseService signing = mock(OcspResponseService.class);
        KeyRef responderKey = new KeyRef("kref:v1:keyring:delegated-responder");
        Path delegatedDirectory = temporaryDirectory.resolve("delegated");
        Files.createDirectory(delegatedDirectory);
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(delegatedDirectory)) {
            OcspResponderService service = new OcspResponderService(ServerTestSupport.REALM, opened.store(),
                    repository, bindings, Optional.of(signing), ServerTestSupport.CLOCK);
            OcspResponderService.Registration registration = new OcspResponderService.Registration(
                    "ocsp-delegated", "delegated", ServerTestSupport.AUTHORITY, issuerId,
                    OcspResponderService.SigningMode.DELEGATED_RESPONDER, responderCredential, responderKey,
                    path.pathId(), "SHA256withRSA", Optional.empty(), ServerTestSupport.DIGEST,
                    OcspResponseService.ResponderId.BY_NAME, Duration.ofMinutes(5),
                    OcspResponderService.NoncePolicy.REJECT, 64,
                    Set.of(OcspResponseService.CertIdHash.SHA256), 16_384, 8, Duration.ofMinutes(1));
            OcspResponderService.Responder registered = service.register(registration);
            assertEquals(OcspResponderService.SigningMode.DELEGATED_RESPONDER, registered.signingMode());
            verify(signing).validateSigningBinding(responderCredential, responderKey,
                    "SHA256withRSA", Optional.empty());
        }
        System.out.println("...delegated-eku-and-key-usage=true");
        System.out.println("validatesDelegatedResponderIssuerEkuUsageAndSigningCapability...ok");
    }

    private static PkiRepositoryContent content(byte[] encoded) throws Exception {
        PkiRepositoryContent content = mock(PkiRepositoryContent.class);
        when(content.openStream()).thenAnswer(ignored -> new ByteArrayInputStream(encoded));
        return content;
    }

    private static byte[] certificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=OCSP Responder Root");
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(Instant.parse("2025-01-01T00:00:00Z")),
                Date.from(Instant.parse("2030-01-01T00:00:00Z")), name,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()));
        X509CertificateHolder certificate = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate()));
        return certificate.getEncoded();
    }

    private static CertificatePair delegatedCertificates() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair issuerKeys = generator.generateKeyPair();
        KeyPair responderKeys = generator.generateKeyPair();
        X500Name issuerName = new X500Name("CN=Delegated OCSP Issuer");
        X509v3CertificateBuilder issuerBuilder = new X509v3CertificateBuilder(issuerName, BigInteger.ONE,
                Date.from(Instant.parse("2025-01-01T00:00:00Z")),
                Date.from(Instant.parse("2030-01-01T00:00:00Z")), issuerName,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(issuerKeys.getPublic().getEncoded()));
        X509CertificateHolder issuer = issuerBuilder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate()));
        X509v3CertificateBuilder responderBuilder = new X509v3CertificateBuilder(issuerName, BigInteger.TWO,
                Date.from(Instant.parse("2025-01-01T00:00:00Z")),
                Date.from(Instant.parse("2030-01-01T00:00:00Z")), new X500Name("CN=Delegated OCSP Responder"),
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(responderKeys.getPublic().getEncoded()));
        responderBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        responderBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        X509CertificateHolder responder = responderBuilder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate()));
        return new CertificatePair(issuer.getEncoded(), responder.getEncoded());
    }

    private record CertificatePair(byte[] issuer, byte[] responder) {
        private CertificatePair { issuer = issuer.clone(); responder = responder.clone(); }
        @Override public byte[] issuer() { return issuer.clone(); }
        @Override public byte[] responder() { return responder.clone(); }
    }
}
