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

package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
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
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509CertificationRequestParser;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.H7ProfileDocuments;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pkix.Pkix;

final class EndEntityLifecyclePreparationTest {
    private static final Instant NOW = Instant.parse("2026-09-20T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final PkiId CA = new PkiId("ca:lifecycle");
    private static final String PROFILE = "h7-no-san-eku";
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "lifecycle"),
            new Purpose("RENEW"), Optional.empty(), Optional.empty());
    static KeyPair key;
    private static KeyPair otherKey;

    @BeforeAll static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
        otherKey = generator.generateKeyPair();
    }

    @Test void dtoBoundsAndDefensiveCopies() throws Exception {
        byte[] csr = csr(key);
        byte[] original = csr.clone();
        EndEntityReplacementRequest request = new EndEntityReplacementRequest(CA, csr, PROFILE);
        csr[0] ^= 1;
        request.csrDer()[0] ^= 1;
        assertArrayEquals(original, request.csrDer());
        assertThrows(IllegalArgumentException.class, () -> new EndEntityReplacementRequest(CA, new byte[1048577], PROFILE));
        assertThrows(IllegalArgumentException.class, () -> new EndEntityReplacementRequest(CA, new byte[0], PROFILE));
        assertThrows(IllegalArgumentException.class, () -> new EndEntityReplacementRequest(CA, original, " "));
        assertThrows(IllegalArgumentException.class, () -> new EndEntityRenewalRequest(CA, null));
        assertThrows(IllegalArgumentException.class, () -> new EndEntityReissueRequest(null));
    }

    @Test void renewalAndReissuePreserveIdentityAndCaptureOneTimeEvenWhenExpired(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            for (Validity validity : List.of(new Validity(NOW.minusSeconds(200), NOW.minusSeconds(100)),
                    new Validity(NOW.plusSeconds(100), NOW.plusSeconds(200)))) {
                Credential leaf = leaf(store, "CN=Applicant", validity);
                AtomicInteger reads = new AtomicInteger();
                Clock counting = new Clock() {
                    @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
                    @Override public Clock withZone(java.time.ZoneId zone) { return this; }
                    @Override public Instant instant() { reads.incrementAndGet(); return NOW; }
                };
                EndEntityLifecyclePreparation preparation = preparation(readOnly(store), counting);
                EndEntityIssuancePreparation.Prepared renewed = preparation.prepareRenewal(ACCESS,
                        new EndEntityRenewalRequest(leaf.credentialId(), Optional.empty()), CancellationSignal.NONE).issuance();
                assertEquals(1, reads.get());
                assertEquals(leaf.subjectRef(), renewed.request().subjectRef());
                assertArrayEquals(key.getPublic().getEncoded(), renewed.request().exactPublicKey().bytes());
                assertEquals(NOW, renewed.request().validity().notBefore());
                assertEquals(renewed.request().subjectRdns(), preparation.prepareReissue(ACCESS,
                        new EndEntityReissueRequest(leaf.credentialId()), CancellationSignal.NONE).issuance().request().subjectRdns());
                assertEquals(2, reads.get());
            }
        }
    }

    @Test void enrollmentRenewalIdentityReparsesOriginalAndRejectsChangedOrForgedFields(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(100), NOW.plusSeconds(100)));
            zeroecho.pki.spi.framework.CredentialFramework framework = (zeroecho.pki.spi.framework.CredentialFramework)
                    Proxy.newProxyInstance(zeroecho.pki.spi.framework.CredentialFramework.class.getClassLoader(),
                            new Class<?>[] { zeroecho.pki.spi.framework.CredentialFramework.class }, (proxy, method, args) -> {
                                if (method.getName().equals("requestParser")) return new BcX509CertificationRequestParser();
                                throw new AssertionError(method.getName());
                            });
            DefaultCertificationRequestService requests = new DefaultCertificationRequestService(readOnly(store), framework);
            zeroecho.pki.api.request.ParsedCertificationRequest parsed = requests.parseX509(new zeroecho.pki.api.request.X509EnrollmentPayload(
                    zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, csr(key)));
            requests.requireRenewalIdentity(parsed, leaf.credentialId());
            assertThrows(PkiException.class, () -> requests.requireRenewalIdentity(parsed, new PkiId("missing")));
            assertThrows(IllegalArgumentException.class, () -> requests.requireRenewalIdentity(parsed, new PkiId("credential:issuer")));
            zeroecho.pki.api.request.ParsedCertificationRequest changedKey = requests.parseX509(new zeroecho.pki.api.request.X509EnrollmentPayload(
                    zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, csr(otherKey)));
            assertThrows(IllegalArgumentException.class, () -> requests.requireRenewalIdentity(changedKey, leaf.credentialId()));
            byte[] changedSubject = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Other"), key.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
            zeroecho.pki.api.request.ParsedCertificationRequest changed = requests.parseX509(new zeroecho.pki.api.request.X509EnrollmentPayload(
                    zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, changedSubject));
            assertThrows(IllegalArgumentException.class, () -> requests.requireRenewalIdentity(changed, leaf.credentialId()));
            org.bouncycastle.asn1.x509.ExtensionsGenerator extensions = new org.bouncycastle.asn1.x509.ExtensionsGenerator();
            extensions.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                    new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(
                            org.bouncycastle.asn1.x509.GeneralName.dNSName, "changed.example.test")));
            byte[] changedSan = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Applicant"), key.getPublic())
                    .addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
            zeroecho.pki.api.request.ParsedCertificationRequest changedNames = requests.parseX509(new zeroecho.pki.api.request.X509EnrollmentPayload(
                    zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, changedSan));
            assertThrows(IllegalArgumentException.class, () -> requests.requireRenewalIdentity(changedNames, leaf.credentialId()));
            zeroecho.pki.api.request.ParsedCertificationRequest missingPayload = new zeroecho.pki.api.request.ParsedCertificationRequest(
                    parsed.requestId(), parsed.formatId(), parsed.subjectRef(), parsed.publicKeyInfo(), Optional.empty(), Optional.empty(),
                    parsed.subjectRdns(), parsed.subjectAlternativeNames(), false, new SimpleAttributeSet());
            assertThrows(IllegalArgumentException.class, () -> requests.requireRenewalIdentity(missingPayload, leaf.credentialId()));
            for (zeroecho.pki.api.request.ParsedCertificationRequest forged : List.of(
                    new zeroecho.pki.api.request.ParsedCertificationRequest(parsed.requestId(), parsed.formatId(), changed.subjectRef(),
                            parsed.publicKeyInfo(), Optional.empty(), Optional.empty(), parsed.subjectRdns(), parsed.subjectAlternativeNames(), false, parsed.attributes()),
                    new zeroecho.pki.api.request.ParsedCertificationRequest(parsed.requestId(), parsed.formatId(), parsed.subjectRef(),
                            parsed.publicKeyInfo(), Optional.empty(), Optional.empty(), changed.subjectRdns(), parsed.subjectAlternativeNames(), false, parsed.attributes()),
                    new zeroecho.pki.api.request.ParsedCertificationRequest(parsed.requestId(), parsed.formatId(), parsed.subjectRef(),
                            changedKey.publicKeyInfo(), Optional.empty(), Optional.empty(), parsed.subjectRdns(), parsed.subjectAlternativeNames(), false, parsed.attributes()),
                    new zeroecho.pki.api.request.ParsedCertificationRequest(parsed.requestId(), parsed.formatId(), parsed.subjectRef(),
                            parsed.publicKeyInfo(), Optional.empty(), Optional.empty(), parsed.subjectRdns(),
                            List.of(new zeroecho.pki.api.request.SubjectAlternativeName.DnsName("example.test")), true, parsed.attributes()))) {
                assertThrows(IllegalArgumentException.class, () -> requests.requireRenewalIdentity(forged, leaf.credentialId()));
            }
            Credential wrong = new Credential(leaf.credentialId(), leaf.formatId(), leaf.issuerRef(), new SubjectRef("CN=Other"), leaf.validity(),
                    leaf.serialOrUniqueId(), leaf.publicKeyId(), leaf.profileBinding(), leaf.status(), leaf.content(), leaf.attributes());
            DefaultCertificationRequestService inconsistent = new DefaultCertificationRequestService(overrideCredential(store, leaf.credentialId(), wrong), framework);
            assertThrows(IllegalArgumentException.class, () -> inconsistent.requireRenewalIdentity(parsed, leaf.credentialId()));
        }
    }

    @Test void originalRenewalProofUsesExactFrozenBindingAtValidationAndDispatch(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            zeroecho.pki.testkit.AcceptancePrivateBinding source = new zeroecho.pki.testkit.AcceptancePrivateBinding();
            zeroecho.pki.api.algorithm.X509AlgorithmBinding template = zeroecho.pki.testkit.AcceptancePrivateBinding.DESCRIPTOR;
            zeroecho.pki.api.algorithm.X509AlgorithmBinding binding = new zeroecho.pki.api.algorithm.X509AlgorithmBinding(
                    template.bindingId(), template.algorithmIdentity(), zeroecho.pki.api.algorithm.X509AlgorithmBinding.Role.CSR_SIGNATURE,
                    template.oid(), template.origin(), template.encodingVersion(), template.parameterRule(), template.publicKeyEncoding(),
                    template.signatureEncoding(), template.interoperability(), template.providerId(), "renewal-proof-v1");
            zeroecho.pki.impl.framework.x509.X509BindingRule rule = (zeroecho.pki.impl.framework.x509.X509BindingRule) Proxy.newProxyInstance(
                    getClass().getClassLoader(), new Class<?>[] {zeroecho.pki.impl.framework.x509.X509BindingRule.class},
                    (proxy, method, args) -> switch (method.getName()) {
                        case "bindings" -> List.of(binding);
                        case "semanticFingerprint" -> binding.semanticCommitment();
                        default -> method.invoke(source, args);
                    });
            List<zeroecho.pki.api.algorithm.X509AlgorithmBinding> descriptors = new java.util.ArrayList<>(StandardX509Bindings.descriptors());
            descriptors.add(binding);
            zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry registry = ImmutableX509AlgorithmBindingRegistry.create(descriptors);
            BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
            X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(new zeroecho.pki.impl.framework.x509.X509BindingRuleProvider() {
                @Override public List<zeroecho.pki.impl.framework.x509.X509BindingRule> rules() { return List.of(rule); }
            }), List.of(verifier),
                    List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID, AlgorithmExecutionCapability.Direction.VERIFY, verifier)),
                    new X509AlgorithmResolver.Policy() {
                        @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) { return true; }
                        @Override public String semanticFingerprint() { return "renewal-proof-validation"; }
                    });
            zeroecho.pki.api.profile.CertificateProfileDefinition base = store.requireActiveProfile(PROFILE).definition();
            zeroecho.pki.api.profile.X509AlgorithmBindingPolicy policy = new zeroecho.pki.api.profile.X509AlgorithmBindingPolicy(
                    zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.Mode.EXPLICIT, Optional.empty(),
                    Optional.of(new zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.BindingReference(binding.bindingId(), binding.semanticCommitment())),
                    Optional.empty(), Optional.empty());
            zeroecho.pki.api.profile.CertificateProfileDefinition restricted = new zeroecho.pki.api.profile.CertificateProfileDefinition(
                    base.certificateType(), PROFILE, 2, base.formatId(), "Restricted renewal proof", base.maximumValidity(), base.approvalRequirement(),
                    base.subjectPolicy(), base.certificatePolicy(), policy, base.confirmationPolicy());
            DefaultProfileService profiles = new DefaultProfileService(store, CLOCK, new InMemoryAuditSink(), registry);
            CertificateProfileRef frozen = profiles.importProfile(zeroecho.pki.api.profile.CertificateProfileDocumentCodec.writeCanonical(restricted));
            profiles.activateProfile(PROFILE, 2);
            Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(100), NOW.plusSeconds(100)));
            PkiStore immutable = readOnly(store);
            DefaultCertificationRequestService requests = new DefaultCertificationRequestService(immutable,
                    new zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework(authority, verifier), registry);
            byte[] alternate = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Applicant"), key.getPublic())
                    .build(new JcaContentSignerBuilder("SHA384withRSA").build(key.getPrivate())).getEncoded();
            zeroecho.pki.api.request.X509EnrollmentPayload allowed = new zeroecho.pki.api.request.X509EnrollmentPayload(zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, csr(key));
            CertificateProfileRef standardProfile = store.getProfileVersion(PROFILE, 1).orElseThrow().reference();
            zeroecho.pki.api.request.X509EnrollmentPayload denied = new zeroecho.pki.api.request.X509EnrollmentPayload(zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, alternate);
            zeroecho.pki.api.request.ParsedCertificationRequest parsed = requests.parseX509(denied);
            assertEquals(zeroecho.pki.api.request.ProofOfPossessionStatus.VERIFIED,
                    requests.verifyProofOfPossession(parsed, new zeroecho.pki.api.issuance.VerificationPolicy(true, Optional.empty())).status());
            requests.requireRenewalIdentity(parsed, leaf.credentialId());
            assertThrows(IllegalArgumentException.class, () -> requests.requireProfileProof(parsed, frozen));
            requests.requireProfileProof(requests.parseX509(allowed), standardProfile);
            org.bouncycastle.asn1.pkcs.CertificationRequest standard = org.bouncycastle.asn1.pkcs.CertificationRequest.getInstance(allowed.der());
            byte[] absentParameters = new org.bouncycastle.asn1.pkcs.CertificationRequest(standard.getCertificationRequestInfo(),
                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(standard.getSignatureAlgorithm().getAlgorithm()), standard.getSignature()).getEncoded();
            zeroecho.pki.api.request.ParsedCertificationRequest alternateEncoding = requests.parseX509(new zeroecho.pki.api.request.X509EnrollmentPayload(
                    zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, absentParameters));
            assertEquals(zeroecho.pki.api.request.ProofOfPossessionStatus.NOT_SUPPORTED,
                    requests.verifyProofOfPossession(alternateEncoding, new zeroecho.pki.api.issuance.VerificationPolicy(true, Optional.empty())).status());
            assertThrows(IllegalArgumentException.class, () -> requests.requireProfileProof(alternateEncoding, standardProfile));
            assertThrows(IllegalArgumentException.class, () -> requests.requireProfileProof(parsed, new CertificateProfileRef(PROFILE, 2, new byte[32])));
            assertThrows(IllegalArgumentException.class, () -> requests.requireProfileProof(parsed, new CertificateProfileRef(PROFILE, 99, new byte[32])));
            profiles.activateProfile(PROFILE, 1); // Recovery must still use the frozen version two.
            assertThrows(IllegalArgumentException.class, () -> requests.requireProfileProof(parsed, frozen));
            requests.requireProfileProof(requests.parseX509(allowed), standardProfile);
            CaRecord ca = store.getCa(CA).orElseThrow();
            IssuerChainPath path = store.getIssuerChainPath(ca.issuanceChainPathId()).orElseThrow();
            zeroecho.pki.api.issuance.IssuanceIntent intent = new zeroecho.pki.api.issuance.IssuanceIntent("renewal-proof", "1".repeat(64), frozen,
                    ca.currentIssuanceIssuerId(), path.pathId(), path.pathCommitment());
            EndEntityLifecyclePreparation preparation = new EndEntityLifecyclePreparation(immutable, CLOCK, authority, verifier, registry,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
            zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest rejected = new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(
                    CA, new EndEntityRenewalRequest(leaf.credentialId(), Optional.empty()), leaf.content().sha256(), intent, Optional.of(denied));
            assertThrows(PkiException.class, () -> preparation.prepareCorrelatedRenewal(ACCESS, rejected, intent, CancellationSignal.NONE));
            zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest accepted = new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(
                    CA, rejected.request(), leaf.content().sha256(), new zeroecho.pki.api.issuance.IssuanceIntent("renewal-standard", "2".repeat(64), standardProfile,
                            ca.currentIssuanceIssuerId(), path.pathId(), path.pathCommitment()), Optional.of(allowed));
            assertEquals(standardProfile, preparation.prepareCorrelatedRenewal(ACCESS, accepted, accepted.intent(), CancellationSignal.NONE).issuance().request().profileReference());
            zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest forbiddenReplacement =
                    new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(CA,
                            new EndEntityReplacementRequest(leaf.credentialId(), denied, PROFILE), leaf.content().sha256(), intent);
            assertThrows(PkiException.class, () -> preparation.prepareCorrelatedReplacement(
                    ACCESS, forbiddenReplacement, intent, CancellationSignal.NONE));
            zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest allowedReplacement =
                    new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(CA,
                            new EndEntityReplacementRequest(leaf.credentialId(), allowed, PROFILE), leaf.content().sha256(), accepted.intent());
            assertEquals(standardProfile, preparation.prepareCorrelatedReplacement(ACCESS, allowedReplacement,
                    allowedReplacement.intent(), CancellationSignal.NONE).issuance().request().profileReference());
        }
    }

    @Test void missingNonleafAndInconsistentMetadataFailBeforeWrites(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            EndEntityLifecyclePreparation preparation = preparation(readOnly(store), CLOCK);
            assertThrows(PkiException.class, () -> preparation.prepareReissue(ACCESS,
                    new EndEntityReissueRequest(new PkiId("missing")), CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> preparation.prepareReissue(ACCESS,
                    new EndEntityReissueRequest(new PkiId("credential:issuer")), CancellationSignal.NONE));
            Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)));
            Credential changed = new Credential(leaf.credentialId(), leaf.formatId(), leaf.issuerRef(), leaf.subjectRef(),
                    leaf.validity(), "999", leaf.publicKeyId(), leaf.profileBinding(), leaf.status(), leaf.content(), leaf.attributes());
            PkiStore mismatched = overrideCredential(readOnly(store), leaf.credentialId(), changed);
            assertThrows(PkiException.class, () -> preparation(mismatched, CLOCK).prepareReissue(ACCESS,
                    new EndEntityReissueRequest(leaf.credentialId()), CancellationSignal.NONE));
        }
    }

    @Test void revokedAndHeldRejectReuseButAllowVerifiedDifferentReplacementKey(@TempDir Path root) throws Exception {
        for (boolean held : List.of(true, false)) {
            try (FilesystemPkiStore store = fixture(root.resolve(Boolean.toString(held)))) {
                Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)));
                store.transitionRevocation(held ? new RevocationCommand.Hold(leaf.credentialId(), new SimpleAttributeSet())
                        : new RevocationCommand.RevokePermanently(leaf.credentialId(), RevocationReason.KEY_COMPROMISE,
                                new SimpleAttributeSet()), NOW);
                EndEntityLifecyclePreparation preparation = preparation(readOnly(store), CLOCK);
                assertThrows(PkiException.class, () -> preparation.prepareRenewal(ACCESS,
                        new EndEntityRenewalRequest(leaf.credentialId(), Optional.empty()), CancellationSignal.NONE));
                assertThrows(PkiException.class, () -> preparation.prepareReissue(ACCESS,
                        new EndEntityReissueRequest(leaf.credentialId()), CancellationSignal.NONE));
                byte[] same = csr(key);
                assertThrows(PkiException.class, () -> preparation.prepareReplacement(ACCESS,
                        new EndEntityReplacementRequest(leaf.credentialId(), same, PROFILE), CancellationSignal.NONE));
                assertArrayEquals(otherKey.getPublic().getEncoded(), preparation.prepareReplacement(ACCESS,
                        new EndEntityReplacementRequest(leaf.credentialId(), csr(otherKey), PROFILE), CancellationSignal.NONE)
                        .issuance().request().exactPublicKey().bytes());
            }
        }
    }

    @Test void replacementSameKeyAllowedWhenUsableButBadProofRejected(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)));
            EndEntityLifecyclePreparation preparation = preparation(readOnly(store), CLOCK);
            assertArrayEquals(key.getPublic().getEncoded(), preparation.prepareReplacement(ACCESS,
                    new EndEntityReplacementRequest(leaf.credentialId(), csr(key), PROFILE), CancellationSignal.NONE)
                    .issuance().request().exactPublicKey().bytes());
            byte[] bad = csr(key);
            bad[bad.length - 1] ^= 1;
            assertThrows(PkiException.class, () -> preparation.prepareReplacement(ACCESS,
                    new EndEntityReplacementRequest(leaf.credentialId(), bad, PROFILE), CancellationSignal.NONE));
        }
    }

    @Test void currentTightenedProfileRejectsReconstruction(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)));
            String changed = new String(H7ProfileDocuments.noSanOrEkuProfile(), StandardCharsets.UTF_8)
                    .replace("\"profileVersion\":1", "\"profileVersion\":2")
                    .replace("\"maximumUtf8Bytes\":256", "\"maximumUtf8Bytes\":2");
            activate(store, changed.getBytes(StandardCharsets.UTF_8), 2);
            assertThrows(PkiException.class, () -> preparation(readOnly(store), CLOCK).prepareReissue(ACCESS,
                    new EndEntityReissueRequest(leaf.credentialId()), CancellationSignal.NONE));
        }
    }

    @Test void reconstructedFixedRdnIsCheckedAndNeverDuplicated(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            String fixed = new String(H7ProfileDocuments.noSanOrEkuProfile(), StandardCharsets.UTF_8)
                    .replace("\"profileVersion\":1", "\"profileVersion\":2")
                    .replace("\"source\":\"REQUESTER\"", "\"source\":\"PROFILE_FIXED\",\"fixedValue\":\"Applicant\"");
            activate(store, fixed.getBytes(StandardCharsets.UTF_8), 2);
            Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)));
            assertEquals(1, preparation(readOnly(store), CLOCK).prepareReissue(ACCESS,
                    new EndEntityReissueRequest(leaf.credentialId()), CancellationSignal.NONE).issuance().request().subjectRdns().size());
            activate(store, fixed.replace("\"profileVersion\":2", "\"profileVersion\":3")
                    .replace("Applicant", "Changed").getBytes(StandardCharsets.UTF_8), 3);
            assertThrows(PkiException.class, () -> preparation(readOnly(store), CLOCK).prepareReissue(ACCESS,
                    new EndEntityReissueRequest(leaf.credentialId()), CancellationSignal.NONE));
        }
    }

    @Test void forbiddenPredecessorSignatureIsRejectedBeforeWrites(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)),
                    "SHA1withRSA");
            assertThrows(PkiException.class, () -> preparation(readOnly(store), CLOCK).prepareReissue(ACCESS,
                    new EndEntityReissueRequest(leaf.credentialId()), CancellationSignal.NONE));
        }
    }

    @Test void configuredVerificationDenialRejectsValidPredecessorBeforeWrites(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            Credential leaf = leaf(store, "CN=Applicant", new Validity(NOW.minusSeconds(10), NOW.plusSeconds(100)));
            assertThrows(PkiException.class, () -> preparation(readOnly(store), CLOCK, false).prepareReissue(ACCESS,
                    new EndEntityReissueRequest(leaf.credentialId()), CancellationSignal.NONE));
        }
    }

    private static EndEntityLifecyclePreparation preparation(PkiStore store, Clock clock) {
        return preparation(store, clock, true);
    }

    private static EndEntityLifecyclePreparation preparation(PkiStore store, Clock clock, boolean allowVerification) {
        BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, verifier)), new X509AlgorithmResolver.Policy() {
                    @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                        return direction != AlgorithmExecutionCapability.Direction.VERIFY || allowVerification;
                    }
                    @Override public String semanticFingerprint() { return "lifecycle-test:" + allowVerification; }
                });
        return new EndEntityLifecyclePreparation(store, clock, authority, verifier,
                ImmutableX509AlgorithmBindingRegistry.create(StandardX509Bindings.descriptors()),
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
    }

    static FilesystemPkiStore fixture(Path root) throws Exception {
        FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK);
        activate(store, H7ProfileDocuments.noSanOrEkuProfile(), 1);
        X500Name name = new X500Name("CN=Issuer");
        Validity validity = new Validity(NOW.minusSeconds(1000), NOW.plusSeconds(800L * 86400));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(validity.notBefore()), Date.from(validity.notAfter()), name, key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        byte[] encoded = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
        PkiId id = new PkiId("credential:issuer");
        PkiId rootIssuer = IssuerGeneration.idFor(CA, id);
        Credential credential = new Credential(id, new FormatId("x509"),
                new IssuerRef(CA, rootIssuer, IssuerChainPath.create(CA, rootIssuer, List.of(id)).pathId()), new SubjectRef("CN=Issuer"),
                validity, "1", new PkiId("public:issuer"), new CaProfileBinding(new CertificateProfileRef("root", 1, new byte[32])),
                CredentialStatus.ISSUED, PkiTestRuntime.stageCredential(store, encoded), new SimpleAttributeSet());
        KeyRef signingKey = new KeyRef("key:issuer");
        IssuerGeneration generation = new IssuerGeneration(IssuerGeneration.idFor(CA, id), CA, id, signingKey,
                IssuerGenerationState.ACTIVE, "00".repeat(32), "00".repeat(32));
        IssuerChainPath path = IssuerChainPath.create(CA, generation.issuerId(), List.of(id));
        store.putCredential(credential);
        store.putIssuerGeneration(generation);
        store.putIssuerChainPath(path);
        store.putCa(new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, signingKey, credential.subjectRef(), List.of(generation.issuerId()),
                generation.issuerId(), path.pathId()));
        return store;
    }

    static Credential leaf(FilesystemPkiStore store, String subject, Validity validity) throws Exception {
        return leaf(store, subject, validity, "SHA256withRSA");
    }

    private static Credential leaf(FilesystemPkiStore store, String subject, Validity validity, String signature)
            throws Exception {
        BigInteger serial = BigInteger.valueOf(validity.notBefore().getEpochSecond());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name("CN=Issuer"), serial,
                Date.from(validity.notBefore()), Date.from(validity.notAfter()), new X500Name(subject), key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        byte[] der = builder.build(new JcaContentSignerBuilder(signature).build(key.getPrivate())).getEncoded();
        CaRecord ca = store.getCa(CA).orElseThrow();
        SubjectRef subjectRef = BcX509CertificationRequestParser.reconstructForRenewal(Pkix.parseCertificate(der),
                new FormatId("x509")).subjectRef();
        Credential result = new Credential(new PkiId("x509:" + sha256(der)), new FormatId("x509"),
                new IssuerRef(CA, ca.currentIssuanceIssuerId(), ca.issuanceChainPathId()), subjectRef, validity, serial.toString(),
                new PkiId("spki:" + sha256(key.getPublic().getEncoded())),
                new EndEntityProfileBinding(store.getActiveProfileRef(PROFILE).orElseThrow()), CredentialStatus.ISSUED,
                PkiTestRuntime.stageCredential(store, der), new SimpleAttributeSet());
        store.putCredential(result);
        return result;
    }

    private static void activate(FilesystemPkiStore store, byte[] document, long version) {
        DefaultProfileService profiles = new DefaultProfileService(store, CLOCK, new InMemoryAuditSink());
        profiles.importProfile(document);
        profiles.activateProfile(PROFILE, version);
    }

    private static PkiStore readOnly(PkiStore delegate) {
        StagedContentStore content = (StagedContentStore) Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(),
                new Class<?>[] { StagedContentStore.class }, (proxy, method, args) -> {
                    if (!method.getName().equals("openContent")) { throw new AssertionError("Unexpected staging: " + method.getName()); }
                    try { return method.invoke(delegate.stagedContent(), args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("stagedContent")) { return content; }
                    if (!method.getName().startsWith("get") && !method.getName().equals("requireActiveProfile")) {
                        throw new AssertionError("Unexpected write: " + method.getName());
                    }
                    try { return method.invoke(delegate, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    private static PkiStore overrideCredential(PkiStore delegate, PkiId id, Credential replacement) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("getCredential") && id.equals(args[0])) { return Optional.of(replacement); }
                    try { return method.invoke(delegate, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    static byte[] csr(KeyPair pair) throws Exception {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Applicant"), pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())).getEncoded();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
