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
package zeroecho.pki.e2e;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.issuance.BundleCommand;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.ValidatedCaCertificateRequest;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.testkit.PkiTestRuntime;

/**
 * End-to-end test for PKI core services.
 */
public final class PkiCoreE2eTest {

    @Test
    void nonUsableAndIndeterminateCredentialsFailClosedAcrossReachableTrustPaths(@TempDir Path tempDir)
            throws Exception {
        assertAll(() -> assertRejectedAcrossTrustPaths(tempDir.resolve("held"), EffectiveCredentialStatus.HELD, false),
                () -> assertRejectedAcrossTrustPaths(tempDir.resolve("expired"), EffectiveCredentialStatus.EXPIRED,
                        false),
                () -> assertRejectedAcrossTrustPaths(tempDir.resolve("not-yet-valid"),
                        EffectiveCredentialStatus.NOT_YET_VALID, false),
                () -> assertRejectedAcrossTrustPaths(tempDir.resolve("permanently-revoked"),
                        EffectiveCredentialStatus.PERMANENTLY_REVOKED, false),
                () -> assertRejectedAcrossTrustPaths(tempDir.resolve("resolution-failure"), null, true));
    }

    @Test
    void explicitIssuerSelectionNeverFallsBackByCollectionOrder(@TempDir Path tempDir) throws Exception {
        KeyPair rootKey = genRsa();
        KeyPair leafKey = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:matrix-root");
        Map<KeyRef, KeyPair> keys = Map.of(rootKeyRef, rootKey);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Matrix Root"), "root-ca", Optional.of(rootKeyRef), emptyAttributes()));
            Credential usable = runtime.caCredential(runtime.caService().getCa(rootCaId), 0);
            Credential unusable = copyWithId(usable, new PkiId("credential:matrix-unusable"));
            runtime.store().putCredential(unusable);
            CaRecord root = runtime.caService().getCa(rootCaId);
            runtime.selectIssuerCredential(root, unusable, true);

            List<PkiId> resolved = new ArrayList<>();
            EffectiveCredentialStatusResolver resolver = scriptedResolver(credential -> {
                resolved.add(credential.credentialId());
                return credential.credentialId().equals(unusable.credentialId()) ? EffectiveCredentialStatus.HELD
                        : EffectiveCredentialStatus.USABLE;
            }, false);
            CountingIssuerBackend backend = new CountingIssuerBackend(runtime.issuerBackend());
            IssuanceService issuance = runtime.issuanceService(backend, resolver);
            ParsedCertificationRequest leafRequest = runtime.certificationRequestService()
                    .parse(new CertificationRequest(runtime.framework().formatId(),
                            new EncodedObject(Encoding.DER, makeCsr(leafKey, "CN=Matrix Leaf").getEncoded())));

            assertThrows(PkiException.class, () -> issuance.issueEndEntity(
                    new IssueEndEntityCommand(rootCaId, leafRequest, "default", Optional.empty())));
            assertEquals(List.of(unusable.credentialId()), List.copyOf(resolved));
            resolved.clear();

            runtime.caService().selectIssuancePath(rootCaId, root.currentIssuanceIssuerId(),
                    root.issuanceChainPathId(), "restore explicit test selection");
            issuance.issueEndEntity(new IssueEndEntityCommand(rootCaId, leafRequest, "default", Optional.empty()));
            assertEquals(List.of(usable.credentialId()), List.copyOf(resolved));
            assertEquals(1, backend.endEntityCalls.get());
        }
    }

    @Test
    void crossSignedIssuerPathsRemainExplicitAndDoNotChangeIssuanceSelection(@TempDir Path tempDir)
            throws Exception {
        System.out.println("crossSignedIssuerPathsRemainExplicitAndDoNotChangeIssuanceSelection");
        KeyPair rootKey = genRsa();
        KeyPair intermediateKey = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:cross-root");
        KeyRef intermediateKeyRef = new KeyRef("kref:v1:keyring:test:cross-intermediate");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey, intermediateKeyRef, intermediateKey))) {
            PkiId rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Cross Root"), "root-ca", Optional.of(rootKeyRef), emptyAttributes()));
            PkiId intermediateId = runtime.caService().createIntermediate(new IntermediateCreateCommand(
                    runtime.framework().formatId(), rootId, new SubjectRef("CN=Cross Intermediate"),
                    "intermediate-ca", Optional.of(intermediateKeyRef), emptyAttributes()));
            CaRecord originalRoot = runtime.caService().getCa(rootId);
            CaRecord intermediate = runtime.caService().getCa(intermediateId);
            PkiId originalIssuancePath = intermediate.issuanceChainPathId();

            Credential rootCredential = runtime.caCredential(originalRoot, 0);
            Credential alternateRootCredential = copyWithId(rootCredential,
                    new PkiId("credential:cross-root-alternate"));
            runtime.store().putCredential(alternateRootCredential);
            CaRecord rotatedRoot = runtime.selectIssuerCredential(originalRoot, alternateRootCredential, true);
            PkiId alternateRootPath = rotatedRoot.issuanceChainPathId();

            zeroecho.pki.api.ca.IssuerChainPath alternate = runtime.caService().registerIssuerChainPath(
                    intermediateId, intermediate.currentIssuanceIssuerId(), alternateRootPath);
            assertEquals(2, runtime.caService().listIssuerChainPaths(
                    intermediate.currentIssuanceIssuerId()).size());
            assertFalse(originalIssuancePath.equals(alternate.pathId()));
            assertEquals(originalIssuancePath,
                    runtime.caService().getCa(intermediateId).issuanceChainPathId());
            assertEquals(alternateRootCredential.credentialId(),
                    alternate.orderedCredentialIds().getLast());
            System.out.println("...issuerId=" + intermediate.currentIssuanceIssuerId().value()
                    + " paths=2 selected=" + originalIssuancePath.value());
        }
        System.out.println("...ok");
    }

    @Test
    void permanentlyRevokedIssuerIsRejectedByEveryReachableTrustPath(@TempDir Path tempDir) throws Exception {
        KeyPair rootKey = genRsa();
        KeyPair intermediateKey = genRsa();
        KeyPair nextIntermediateKey = genRsa();
        KeyPair leafKey = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:h6-root");
        KeyRef intermediateKeyRef = new KeyRef("kref:v1:keyring:test:h6-intermediate");
        KeyRef nextIntermediateKeyRef = new KeyRef("kref:v1:keyring:test:h6-next-intermediate");
        Map<KeyRef, KeyPair> keys = Map.of(rootKeyRef, rootKey, intermediateKeyRef, intermediateKey,
                nextIntermediateKeyRef, nextIntermediateKey);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=H6 Root"), "root-ca", Optional.of(rootKeyRef), emptyAttributes()));
            PkiId intermediateCaId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootCaId,
                            new SubjectRef("CN=H6 Intermediate"), "intermediate-ca", Optional.of(intermediateKeyRef),
                            emptyAttributes()));
            PkiId rootCredentialId = runtime.store().getIssuerGeneration(
                    runtime.caService().getCa(rootCaId).currentIssuanceIssuerId()).orElseThrow().credentialId();
            runtime.revocationService().revokePermanently(new RevocationCommand.RevokePermanently(rootCredentialId,
                    RevocationReason.KEY_COMPROMISE, emptyAttributes()));
            int submissionsBeforeRejections = runtime.submittedSignCount();

            CertificationRequest request = new CertificationRequest(runtime.framework().formatId(),
                    new EncodedObject(Encoding.DER, makeCsr(leafKey, "CN=H6 Leaf").getEncoded()));
            ParsedCertificationRequest parsed = runtime.certificationRequestService().parse(request);
            PkiException endEntityFailure = assertThrows(PkiException.class, () -> runtime.issuanceService()
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, parsed, "default", Optional.empty())));
            assertTrue(endEntityFailure.getMessage().contains("ISSUER_CREDENTIAL_UNAVAILABLE"));

            assertThrows(PkiException.class,
                    () -> runtime.caService()
                            .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootCaId,
                                    new SubjectRef("CN=H6 Rejected"), "intermediate-ca",
                                    Optional.of(nextIntermediateKeyRef), emptyAttributes())));
            assertThrows(PkiException.class,
                    () -> runtime.caService().issueIntermediateCertificate(
                            new IntermediateCertIssueCommand(runtime.framework().formatId(), rootCaId, intermediateCaId,
                                    "intermediate-ca", Optional.empty(), emptyAttributes())));
            assertThrows(PkiException.class,
                    () -> runtime.statusObjectService().generate(new StatusObjectGenerateCommand(rootCaId,
                            StatusObjectType.CRL, runtime.framework().formatId(), emptyAttributes())));
            assertThrows(PkiException.class, () -> runtime.issuanceService()
                    .buildBundle(new BundleCommand(rootCredentialId, Optional.empty(), Optional.empty())));

            assertEquals(submissionsBeforeRejections, runtime.submittedSignCount());
            assertTrue(runtime.store().getCredential(rootCredentialId).isPresent());
            assertTrue(runtime.caService().getCa(intermediateCaId).issuerIds().size() == 1);
        }
    }

    @Test
    void e2eRootIssueRevokeCrl(@TempDir Path tempDir) throws Exception {
        System.out.println("e2eRootIssueRevokeCrl");

        Path busFile = tempDir.resolve("bus.log");

        KeyPair rootKp = genRsa();
        KeyPair eeKp = genRsa();

        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef eeKeyRef = new KeyRef("kref:v1:keyring:test:ee");

        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKp);
        keys.put(eeKeyRef, eeKp);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, busFile, keys)) {
            CaService caSvc = runtime.caService();
            CertificationRequestService reqSvc = runtime.certificationRequestService();
            IssuanceService issSvc = runtime.issuanceService();
            RevocationService revSvc = runtime.revocationService();
            StatusObjectService stSvc = runtime.statusObjectService();

            // Create ROOT CA (self-signed).
            PkiId rootCaId = caSvc.createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), emptyAttributes()));
            System.out.println("...rootCaId=" + rootCaId.value());

            // CSR for end entity.
            PKCS10CertificationRequest csr = makeCsr(eeKp, "CN=Alice");
            CertificationRequest req = new CertificationRequest(runtime.framework().formatId(),
                    new EncodedObject(Encoding.DER, csr.getEncoded()));
            ParsedCertificationRequest parsed = reqSvc.parse(req);
            System.out.println("...csrId=" + parsed.requestId().value());

            ProofOfPossessionResult pop = reqSvc.verifyProofOfPossession(parsed,
                    new VerificationPolicy(true, Optional.empty()));
            assertEquals(ProofOfPossessionStatus.VERIFIED, pop.status());

            reqSvc.store(parsed, RequestStorePolicy.STORE_ALWAYS);

            CredentialBundle bundle = issSvc
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, parsed, "default", Optional.empty()));

            assertNotNull(bundle);
            assertEquals(1, bundle.supportingObjects().size());
            CredentialBundle rebuilt = issSvc.buildBundle(new BundleCommand(
                    bundle.credential().credentialId(), Optional.empty(), Optional.empty()));
            assertEquals(bundle.supportingObjects(), rebuilt.supportingObjects());
            System.out.println("...issuedCredentialId=" + bundle.credential().credentialId().value());

            X509CertificateHolder eeCert = new X509CertificateHolder(runtime.credentialBytes(bundle.credential()));
            assertEquals("CN=Root", eeCert.getIssuer().toString());
            assertEquals("CN=Alice", eeCert.getSubject().toString());

            revSvc.revokePermanently(new RevocationCommand.RevokePermanently(bundle.credential().credentialId(),
                    RevocationReason.KEY_COMPROMISE, emptyAttributes()));

            StatusObject crl = stSvc.generate(new StatusObjectGenerateCommand(rootCaId, StatusObjectType.CRL,
                    runtime.framework().formatId(), emptyAttributes()));
            assertNotNull(crl);
            System.out.println("...crlId=" + crl.statusObjectId().value());

            X509CRLHolder crlHolder = new X509CRLHolder(
                    PkiTestRuntime.readContent(runtime.signingBus(), crl.content()));
            assertTrue(crlHolder.getRevokedCertificate(eeCert.getSerialNumber()) != null);
        }

        System.out.println("e2eRootIssueRevokeCrl...ok");
    }

    private static void assertRejectedAcrossTrustPaths(Path tempDir, EffectiveCredentialStatus status,
            boolean resolutionFailure) throws Exception {
        KeyPair rootKey = genRsa();
        KeyPair intermediateKey = genRsa();
        KeyPair nextIntermediateKey = genRsa();
        KeyPair leafKey = genRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:reject-root");
        KeyRef intermediateKeyRef = new KeyRef("kref:v1:keyring:test:reject-intermediate");
        KeyRef nextIntermediateKeyRef = new KeyRef("kref:v1:keyring:test:reject-next");
        Map<KeyRef, KeyPair> keys = Map.of(rootKeyRef, rootKey, intermediateKeyRef, intermediateKey,
                nextIntermediateKeyRef, nextIntermediateKey);

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Rejected Root"), "root-ca", Optional.of(rootKeyRef), emptyAttributes()));
            PkiId intermediateCaId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootCaId,
                            new SubjectRef("CN=Rejected Intermediate"), "intermediate-ca",
                            Optional.of(intermediateKeyRef), emptyAttributes()));
            Credential rootCredential = runtime.caCredential(runtime.caService().getCa(rootCaId), 0);
            EffectiveCredentialStatusResolver resolver = scriptedResolver(credential -> status, resolutionFailure);
            CountingIssuerBackend backend = new CountingIssuerBackend(runtime.issuerBackend());
            IssuanceService issuance = runtime.issuanceService(backend, resolver);
            CaService caService = runtime.caService(backend, resolver);
            StatusObjectService statusService = runtime.statusObjectService(resolver);
            ParsedCertificationRequest leafRequest = runtime.certificationRequestService()
                    .parse(new CertificationRequest(runtime.framework().formatId(),
                            new EncodedObject(Encoding.DER, makeCsr(leafKey, "CN=Rejected Leaf").getEncoded())));
            int signCount = runtime.submittedSignCount();
            int caCount = runtime.store().listCas().size();
            int statusCount = runtime.store().listStatusObjects(rootCaId).size();
            int intermediateCredentialCount = runtime.caService().getCa(intermediateCaId).issuerIds().size();

            assertThrows(PkiException.class, () -> issuance
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, leafRequest, "default", Optional.empty())));
            assertThrows(PkiException.class,
                    () -> caService.createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(),
                            rootCaId, new SubjectRef("CN=Rejected Next"), "intermediate-ca",
                            Optional.of(nextIntermediateKeyRef), emptyAttributes())));
            assertThrows(PkiException.class,
                    () -> caService.issueIntermediateCertificate(
                            new IntermediateCertIssueCommand(runtime.framework().formatId(), rootCaId, intermediateCaId,
                                    "intermediate-ca", Optional.empty(), emptyAttributes())));
            assertThrows(PkiException.class, () -> statusService.generate(new StatusObjectGenerateCommand(rootCaId,
                    StatusObjectType.CRL, runtime.framework().formatId(), emptyAttributes())));
            assertThrows(PkiException.class, () -> issuance
                    .buildBundle(new BundleCommand(rootCredential.credentialId(), Optional.empty(), Optional.empty())));

            assertEquals(0, backend.endEntityCalls.get());
            assertEquals(0, backend.intermediateCalls.get());
            assertEquals(signCount, runtime.submittedSignCount());
            assertEquals(caCount, runtime.store().listCas().size());
            assertEquals(statusCount, runtime.store().listStatusObjects(rootCaId).size());
            assertEquals(intermediateCredentialCount,
                    runtime.caService().getCa(intermediateCaId).issuerIds().size());
            assertTrue(runtime.store().getCredential(rootCredential.credentialId()).isPresent());
            assertFalse(runtime.auditSink().snapshot().toString().contains("DO_NOT_EXPOSE_REVOCATION_SENTINEL"));
        }
    }

    private static EffectiveCredentialStatusResolver scriptedResolver(
            Function<Credential, EffectiveCredentialStatus> status, boolean fail) {
        return () -> new EffectiveCredentialStatusResolver.Evaluation() {
            @Override
            public Instant evaluationTime() {
                return Instant.parse("2026-06-01T12:00:00Z");
            }

            @Override
            public EffectiveCredentialStatus resolve(Credential credential) {
                if (fail) {
                    throw new PkiException(
                            "Credential status resolution failed: code=CREDENTIAL_STATUS_RESOLUTION_FAILED");
                }
                return status.apply(credential);
            }

            @Override
            public Credential requireUsable(Credential credential, CredentialUse use) {
                if (resolve(credential) != EffectiveCredentialStatus.USABLE) {
                    throw new PkiException("Credential trust rejected: code=CREDENTIAL_NOT_USABLE");
                }
                return credential;
            }
        };
    }

    private static Credential copyWithId(Credential source, PkiId id) {
        return new Credential(id, source.formatId(), source.issuerRef(), source.subjectRef(), source.validity(),
                source.serialOrUniqueId(), source.publicKeyId(), source.profileBinding(), source.status(),
                source.content(), source.attributes());
    }

    private static final class CountingIssuerBackend implements CredentialIssuerBackend {
        private final CredentialIssuerBackend delegate;
        private final AtomicInteger endEntityCalls;
        private final AtomicInteger intermediateCalls;

        private CountingIssuerBackend(CredentialIssuerBackend delegate) {
            this.delegate = delegate;
            this.endEntityCalls = new AtomicInteger();
            this.intermediateCalls = new AtomicInteger();
        }

        @Override
        public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate, zeroecho.pki.api.content.DurableContentReference issuerCertificate,
                KeyRef issuerKeyRef, BigInteger serial) {
            endEntityCalls.incrementAndGet();
            return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
        }

        @Override
        public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
            intermediateCalls.incrementAndGet();
            return delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
        }
    }

    private static KeyPair genRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static PKCS10CertificationRequest makeCsr(KeyPair kp, String dn) throws Exception {
        X500Name subject = new X500Name(dn);
        PKCS10CertificationRequestBuilder b = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return b.build(cs);
    }

    /**
     * Codec-friendly {@link AttributeSet} for tests.
     *
     * <p>
     * The filesystem store codec expects persisted value types to be either
     * primitive/string-like, or be a simple record structure. Using internal
     * runtime attribute implementations may break persistence decoding.
     * </p>
     */
    private static AttributeSet emptyAttributes() {
        return new SimpleAttributeSet();
    }
}
