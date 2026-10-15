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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;
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
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
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
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedIssuancePreparation;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.signing.DefaultSigningService;
import zeroecho.pki.impl.core.signing.DefaultSemanticSigningService;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.testkit.H7ProfileDocuments;
import zeroecho.pki.testkit.PkiTestRuntime;

final class EndEntityIssuancePreparationTest {
    private static final Instant NOW = Instant.parse("2026-09-20T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final PkiId CA = new PkiId("ca:test");
    private static final KeyRef KEY = new KeyRef("key:issuer");
    private static final String PROFILE = "h7-no-san-eku";
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "issuer"),
            new Purpose("ISSUE"), Optional.empty(), Optional.empty());
    private static KeyPair key;
    private static byte[] csr;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
        csr = csr("CN=Applicant");
    }

    @Test
    void immutableRequestRejectsInvalidAndOversizedInput() {
        byte[] input = csr.clone();
        EndEntityIssuanceRequest request = request(input);
        input[0] ^= 1;
        byte[] exposed = request.csrDer();
        exposed[0] ^= 1;
        assertArrayEquals(csr, request.csrDer());
        assertThrows(IllegalArgumentException.class, () -> request(new byte[1024 * 1024 + 1]));
        assertThrows(IllegalArgumentException.class, () -> request(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> request(null));
        assertThrows(IllegalArgumentException.class,
                () -> new EndEntityIssuanceRequest(null, csr, PROFILE, Optional.empty()));
        assertThrows(IllegalArgumentException.class,
                () -> new EndEntityIssuanceRequest(CA, csr, " ", Optional.empty()));
        assertThrows(IllegalArgumentException.class,
                () -> new EndEntityIssuanceRequest(CA, csr, PROFILE, null));
    }

    @Test
    void crmfProofAndProfileChecksPrecedeAnyWrites(@TempDir Path root) throws Exception {
        byte[] der;
        try (java.io.InputStream source = getClass().getResourceAsStream("/crmf/rsa2048-nosan.der")) {
            der = java.util.Objects.requireNonNull(source).readAllBytes();
        }
        try (FilesystemPkiStore store = fixture(root)) {
            EndEntityIssuancePreparation preparation = preparer(readOnly(store), CLOCK,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
            zeroecho.pki.api.request.X509EnrollmentPayload payload = new zeroecho.pki.api.request.X509EnrollmentPayload(
                    zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, der);
            EndEntityIssuanceRequest input = new EndEntityIssuanceRequest(CA, payload, PROFILE, Optional.empty());
            assertThrows(IllegalStateException.class, input::csrDer);
            assertEquals(PROFILE, preparation.prepare(ACCESS, input, CancellationSignal.NONE).request().profileId());
            byte[] subjectTamper = der.clone();
            byte[] subjectText = "Applicant".getBytes(StandardCharsets.US_ASCII);
            int subjectOffset = byteSequence(subjectTamper, subjectText);
            subjectTamper[subjectOffset] = 'B';
            byte[] keyTamper = der.clone();
            byte[] spki = zeroecho.pkix.cmp.CrmfRequest.parse(der).subjectPublicKeyInfo();
            byte[] spkiContent = java.util.Arrays.copyOfRange(spki, 4, spki.length);
            keyTamper[byteSequence(keyTamper, spkiContent) + spkiContent.length - 10] ^= 1;
            for (byte[] invalid : List.of(subjectTamper, keyTamper)) {
                PkiException failure = assertThrows(PkiException.class, () -> preparation.prepare(ACCESS,
                        new EndEntityIssuanceRequest(CA, new zeroecho.pki.api.request.X509EnrollmentPayload(
                                zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, invalid), PROFILE, Optional.empty()),
                        CancellationSignal.NONE));
                assertTrue(failure.getMessage().contains("CSR_PROOF_INVALID"));
            }
            byte[] tampered = der.clone();
            tampered[tampered.length - 1] ^= 1;
            assertThrows(PkiException.class, () -> preparation.prepare(ACCESS, new EndEntityIssuanceRequest(CA,
                    new zeroecho.pki.api.request.X509EnrollmentPayload(
                            zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, tampered),
                    PROFILE, Optional.empty()), CancellationSignal.NONE));
            try (java.io.InputStream source = getClass().getResourceAsStream("/crmf/rsa2048-sha256.der")) {
                byte[] withSan = java.util.Objects.requireNonNull(source).readAllBytes();
                byte[] changedSan = withSan.clone();
                // The domain occurs in subject and SAN; mutate the final occurrence (the signed SAN).
                byte[] domain = "leaf.example.test".getBytes(StandardCharsets.US_ASCII);
                int last = -1;
                for (int index = 0; index <= changedSan.length - domain.length; index++) {
                    if (java.util.Arrays.equals(changedSan, index, index + domain.length, domain, 0, domain.length)) last = index;
                }
                assertTrue(last >= 0);
                changedSan[last] = 'x';
                PkiException altered = assertThrows(PkiException.class, () -> preparation.prepare(ACCESS,
                        new EndEntityIssuanceRequest(CA, new zeroecho.pki.api.request.X509EnrollmentPayload(
                                zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, changedSan), PROFILE, Optional.empty()),
                        CancellationSignal.NONE));
                assertTrue(altered.getMessage().contains("CSR_PROOF_INVALID"));
                assertThrows(PkiException.class, () -> preparation.prepare(ACCESS, new EndEntityIssuanceRequest(CA,
                        new zeroecho.pki.api.request.X509EnrollmentPayload(
                                zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, withSan),
                        PROFILE, Optional.empty()), CancellationSignal.NONE));
            }
        }
    }

    private static int byteSequence(byte[] container, byte[] target) {
        for (int index = 0; index <= container.length - target.length; index++) {
            if (java.util.Arrays.equals(container, index, index + target.length, target, 0, target.length)) return index;
        }
        throw new AssertionError("Fixture sequence not found");
    }

    @Test
    void validCrmfProofCannotBypassFrozenCsrSignatureBinding(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            zeroecho.pki.api.algorithm.X509AlgorithmBinding source = zeroecho.pki.testkit.AcceptancePrivateBinding.DESCRIPTOR;
            zeroecho.pki.api.algorithm.X509AlgorithmBinding binding = new zeroecho.pki.api.algorithm.X509AlgorithmBinding(
                    "test.crmf.proof.v1", source.algorithmIdentity(), zeroecho.pki.api.algorithm.X509AlgorithmBinding.Role.CSR_SIGNATURE,
                    source.oid(), source.origin(), source.encodingVersion(), source.parameterRule(), source.publicKeyEncoding(),
                    source.signatureEncoding(), source.interoperability(), source.providerId(), "test-crmf-proof-v1");
            List<zeroecho.pki.api.algorithm.X509AlgorithmBinding> descriptors = new java.util.ArrayList<>(StandardX509Bindings.descriptors());
            descriptors.add(binding);
            zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry registry = ImmutableX509AlgorithmBindingRegistry.create(descriptors);
            zeroecho.pki.api.profile.CertificateProfileDefinition base = store.requireActiveProfile(PROFILE).definition();
            zeroecho.pki.api.profile.X509AlgorithmBindingPolicy policy = new zeroecho.pki.api.profile.X509AlgorithmBindingPolicy(
                    zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.Mode.EXPLICIT, Optional.empty(),
                    Optional.of(new zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.BindingReference(
                            binding.bindingId(), binding.semanticCommitment())), Optional.empty(), Optional.empty());
            zeroecho.pki.api.profile.CertificateProfileDefinition definition = new zeroecho.pki.api.profile.CertificateProfileDefinition(
                    base.certificateType(), "crmf-sha256", 1, base.formatId(), "CRMF proof binding", base.maximumValidity(),
                    base.approvalRequirement(), base.subjectPolicy(), base.certificatePolicy(), policy, base.confirmationPolicy());
            DefaultProfileService profiles = new DefaultProfileService(store, CLOCK, new InMemoryAuditSink(), registry);
            profiles.importProfile(CertificateProfileDocumentCodec.writeCanonical(definition));
            profiles.activateProfile("crmf-sha256", 1);
            BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
            X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
                    List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                            AlgorithmExecutionCapability.Direction.VERIFY, verifier)), new X509AlgorithmResolver.Policy() {
                        @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) { return true; }
                        @Override public String semanticFingerprint() { return "crmf-binding-test"; }
                    });
            EndEntityIssuancePreparation preparation = new EndEntityIssuancePreparation(readOnly(store), CLOCK,
                    authority, verifier, registry, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
            try (java.io.InputStream fixtureSource = getClass().getResourceAsStream("/crmf/rsa2048-sha384.der")) {
                zeroecho.pki.api.request.X509EnrollmentPayload payload = new zeroecho.pki.api.request.X509EnrollmentPayload(
                        zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, java.util.Objects.requireNonNull(fixtureSource).readAllBytes());
                assertEquals(PROFILE, preparation.prepare(ACCESS,
                        new EndEntityIssuanceRequest(CA, payload, PROFILE, Optional.empty()), CancellationSignal.NONE).request().profileId());
                PkiException rejected = assertThrows(PkiException.class, () -> preparation.prepare(ACCESS,
                        new EndEntityIssuanceRequest(CA, payload, "crmf-sha256", Optional.empty()), CancellationSignal.NONE));
                assertTrue(rejected.getMessage().contains("ISSUANCE_BINDING_INVALID"), rejected.getMessage());
            }
        }
    }

    @Test
    void freezesVerifiedPolicyAndAuthoritativeSelectionWithoutWrites(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            AtomicInteger clockReads = new AtomicInteger();
            Clock countingClock = new Clock() {
                @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public Clock withZone(java.time.ZoneId zone) { return this; }
                @Override public Instant instant() { clockReads.incrementAndGet(); return NOW; }
            };
            EndEntityIssuancePreparation.Prepared prepared = preparer(readOnly(store), countingClock,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm()).prepare(
                            ACCESS, request(csr), CancellationSignal.NONE);
            assertEquals(1, clockReads.get());
            assertEquals(KEY, prepared.keyRef());
            assertEquals(NOW, prepared.evaluationTime());
            assertEquals(PROFILE, prepared.request().profileId());
            assertEquals(NOW, prepared.request().validity().notBefore());
            assertEquals(store.getCa(CA).orElseThrow().currentIssuanceIssuerId(),
                    prepared.request().frozenIssuance().orElseThrow().issuerId());
            assertTrue(prepared.serial().signum() > 0);
            assertTrue(prepared.serial().bitLength() <= 159);
            assertTrue(prepared.request().extendedKeyUsages().isEmpty());
            assertTrue(prepared.request().basicConstraintsCritical());
        }
    }

    @Test
    void rejectsMalformedProofAndPolicyBeforeAnyWrite(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            EndEntityIssuancePreparation preparer = preparer(readOnly(store), CLOCK,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
            assertThrows(PkiException.class, () -> preparer.prepare(ACCESS, request(new byte[] { 5, 0 }),
                    CancellationSignal.NONE));
            byte[] trailing = Arrays.copyOf(csr, csr.length + 1);
            assertThrows(PkiException.class, () -> preparer.prepare(ACCESS, request(trailing), CancellationSignal.NONE));
            byte[] invalidProof = csr.clone();
            invalidProof[invalidProof.length - 1] ^= 1;
            assertThrows(PkiException.class, () -> preparer.prepare(ACCESS, request(invalidProof), CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> preparer.prepare(ACCESS, request(csr("CN=Applicant,O=Forbidden")),
                    CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> preparer.prepare(ACCESS, request(csr("CN=One,CN=Two")),
                    CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> preparer.prepare(ACCESS, request(csrWithSan()), CancellationSignal.NONE));
            KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
            ecGenerator.initialize(256);
            KeyPair ecKey = ecGenerator.generateKeyPair();
            byte[] ecCsr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Applicant"), ecKey.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withECDSA").build(ecKey.getPrivate())).getEncoded();
            assertThrows(PkiException.class, () -> preparer.prepare(ACCESS, request(ecCsr), CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> preparer.prepare(ACCESS,
                    new EndEntityIssuanceRequest(CA, csr, PROFILE,
                            Optional.of(new Validity(NOW, NOW.plusSeconds(400L * 86400)))), CancellationSignal.NONE));
            assertThrows(java.io.InterruptedIOException.class,
                    () -> preparer.prepare(ACCESS, request(csr), () -> true));
        }
    }

    @Test
    void rejectsUnavailableProfileAndRevokedOrExpiredIssuer(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            EndEntityIssuancePreparation preparation = preparer(readOnly(store), CLOCK,
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
            assertThrows(PkiException.class, () -> preparation.prepare(ACCESS,
                    new EndEntityIssuanceRequest(CA, csr, "inactive", Optional.empty()), CancellationSignal.NONE));
            assertThrows(PkiException.class, () -> preparer(readOnly(store),
                    Clock.fixed(NOW.plusSeconds(900L * 86400), ZoneOffset.UTC),
                    BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm())
                            .prepare(ACCESS, request(csr), CancellationSignal.NONE));
            PkiId credentialId = store.getIssuerGeneration(store.getCa(CA).orElseThrow().currentIssuanceIssuerId())
                    .orElseThrow().credentialId();
            store.transitionRevocation(new RevocationCommand.RevokePermanently(credentialId,
                    RevocationReason.KEY_COMPROMISE, SimpleAttributeSet.builder().build()), NOW.minusSeconds(1));
            assertRejected(store, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
        }
    }

    @Test
    void rejectsChangedBindingCommitmentBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            String bindingId = StandardX509Bindings.descriptors().stream()
                    .filter(binding -> binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256)
                            && binding.role() == zeroecho.pki.api.algorithm.X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE)
                    .findFirst().orElseThrow().bindingId();
            String json = new String(H7ProfileDocuments.noSanOrEkuProfile(), StandardCharsets.UTF_8)
                    .replace("\"mode\":\"STANDARD_ONLY\"", "\"mode\":\"EXPLICIT\",\"certificateSignature\":{\"bindingId\":\""
                            + bindingId + "\",\"semanticCommitment\":\"changed-commitment\"}");
            CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(json.getBytes(StandardCharsets.UTF_8));
            ActiveCertificateProfile profile = new ActiveCertificateProfile(new CertificateProfileRef(PROFILE, 1,
                    MessageDigest.getInstance("SHA-256").digest(CertificateProfileDocumentCodec.writeCanonical(definition))),
                    definition);
            PkiStore alteredProfile = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        if (method.getName().equals("requireActiveProfile")) { return profile; }
                        try { return method.invoke(store, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            assertRejected(alteredProfile, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
        }
    }

    @Test
    void rejectsInactiveIssuerInconsistentKeyAndIncompatibleAlgorithm(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            CaRecord original = store.getCa(CA).orElseThrow();
            store.putCa(new CaRecord(CA, original.kind(), CaState.DISABLED, KEY, original.subjectRef(),
                    original.issuerIds(), original.currentIssuanceIssuerId(), original.issuanceChainPathId()));
            assertRejected(store, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
            CaRecord inconsistent = new CaRecord(CA, original.kind(), CaState.ACTIVE, new KeyRef("wrong"), original.subjectRef(),
                    original.issuerIds(), original.currentIssuanceIssuerId(), original.issuanceChainPathId());
            assertThrows(IllegalStateException.class, () -> store.putCa(inconsistent));
            PkiStore altered = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        if (method.getName().equals("getCa")) { return Optional.of(inconsistent); }
                        try { return method.invoke(store, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            assertRejected(altered, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
            store.putCa(original);
            assertRejected(store, BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm());
        }
    }

    private static void assertRejected(PkiStore store, String signature) {
        assertThrows(PkiException.class, () -> preparer(readOnly(store), CLOCK, signature)
                .prepare(ACCESS, request(csr), CancellationSignal.NONE));
    }

    @Test
    void roundsOnlyTheAlreadyApprovedValidityAndPreservesEvaluationTime(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            String algorithm = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm();
            Instant evaluation = NOW.plusNanos(800_000_000);
            Duration requested = Duration.ofSeconds(2).plusNanos(900_000_000);
            EndEntityIssuanceRequest input = new EndEntityIssuanceRequest(CA, csr, PROFILE,
                    Optional.of(new Validity(NOW, NOW.plus(requested))));
            EndEntityIssuancePreparation.Prepared approved = preparer(readOnly(store),
                    Clock.fixed(evaluation, ZoneOffset.UTC), algorithm).prepare(ACCESS, input, CancellationSignal.NONE);
            assertEquals(evaluation, approved.evaluationTime());
            assertEquals(new Validity(NOW.plusSeconds(1), NOW.plusSeconds(3)), approved.request().validity());
            EndEntityIssuancePreparation.Prepared integral = preparer(readOnly(store), CLOCK, algorithm).prepare(ACCESS,
                    new EndEntityIssuanceRequest(CA, csr, PROFILE,
                            Optional.of(new Validity(NOW, NOW.plusSeconds(2)))), CancellationSignal.NONE);
            assertEquals(new Validity(NOW, NOW.plusSeconds(2)), integral.request().validity());

            PkiException profileFailure = assertThrows(PkiException.class, () -> preparer(readOnly(store),
                    Clock.fixed(evaluation, ZoneOffset.UTC), algorithm).prepare(ACCESS,
                            new EndEntityIssuanceRequest(CA, csr, PROFILE,
                                    Optional.of(new Validity(NOW, NOW.plusSeconds(365L * 86400).plusNanos(1)))),
                            CancellationSignal.NONE));
            assertTrue(profileFailure.getMessage().contains("VALIDITY_EXCEEDS_PROFILE"));
            Instant nearIssuerExpiry = NOW.plusSeconds(800L * 86400).minusSeconds(2).plusNanos(900_000_000);
            PkiException issuerFailure = assertThrows(PkiException.class, () -> preparer(readOnly(store),
                    Clock.fixed(nearIssuerExpiry, ZoneOffset.UTC), algorithm).prepare(ACCESS,
                            new EndEntityIssuanceRequest(CA, csr, PROFILE,
                                    Optional.of(new Validity(NOW, NOW.plusSeconds(1).plusNanos(200_000_000)))),
                            CancellationSignal.NONE));
            assertTrue(issuerFailure.getMessage().contains("VALIDITY_EXCEEDS_ISSUER"));
        }
    }

    @Test
    void fractionalPublicPreparationHasExactTbsAndContinuationTimesAndRejectsEmptyBeforeStaging(@TempDir Path root)
            throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            AtomicInteger stages = new AtomicInteger();
            AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
            PkiStore observed = observePreparation(store, stages, candidate, new AtomicBoolean(), false);
            Clock fractionalClock = Clock.fixed(NOW.plusNanos(123_456_789), ZoneOffset.UTC);
            SemanticSigningService service = semantic(observed, new CountingProvider(), () -> { }, fractionalClock);
            PkiException empty = assertThrows(PkiException.class, () -> service.prepareEndEntity(ACCESS,
                    new EndEntityIssuanceRequest(CA, csr, PROFILE, Optional.of(new Validity(NOW, NOW.plusNanos(100_000_000)))), Optional.empty(),
                    CancellationSignal.NONE));
            assertTrue(empty.getMessage().contains("VALIDITY_INVALID"));
            assertEquals(0, stages.get());
            PreparedSemanticSigningRequest prepared = service.prepareEndEntity(ACCESS, request(csr), Optional.empty(), CancellationSignal.NONE);
            TBSCertificate tbs = TBSCertificate.getInstance(PkiTestRuntime.readContent(store, candidate.get()));
            assertEquals(NOW.plusSeconds(1), tbs.getStartDate().getDate().toInstant());
            assertEquals(NOW.plusSeconds(365L * 86400), tbs.getEndDate().getDate().toInstant());
            service.accept(prepared);
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(store.getSignWorkflow(
                    prepared.receipt().operationId()).orElseThrow().envelope().outer().orElseThrow().command());
            assertEquals(tbs.getStartDate().getDate().toInstant(), Instant.parse(command.field(8)));
            assertEquals(tbs.getEndDate().getDate().toInstant(), Instant.parse(command.field(9)));
        }
    }

    @Test
    void publicPreparationUsesOnlyApprovedSanAndEkuAndDiscardRetiresCandidates(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            DefaultProfileService profiles = new DefaultProfileService(store, CLOCK, new InMemoryAuditSink());
            profiles.importProfile(H7ProfileDocuments.mixedSanProfile());
            profiles.activateProfile("h7-mixed", 1L);
            GeneralNames names = new GeneralNames(new GeneralName[] {
                    new GeneralName(GeneralName.dNSName, "app.example.test"),
                    new GeneralName(GeneralName.iPAddress, "192.0.2.1"),
                    new GeneralName(GeneralName.rfc822Name, "user@example.test"),
                    new GeneralName(GeneralName.uniformResourceIdentifier, "https://app.example.test/resource") });
            EndEntityIssuanceRequest request = new EndEntityIssuanceRequest(CA, csrWithNames(names), "h7-mixed", Optional.empty());
            AtomicInteger stages = new AtomicInteger();
            AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
            CountingProvider provider = new CountingProvider();
            SemanticSigningService service = semantic(observePreparation(store, stages, candidate, new AtomicBoolean(), false),
                    provider, () -> { });
            PreparedSemanticSigningRequest prepared = service.prepareEndEntity(ACCESS, request, Optional.empty(), CancellationSignal.NONE);
            DurableContentReference first = candidate.get();
            TBSCertificate tbs = TBSCertificate.getInstance(PkiTestRuntime.readContent(store, first));
            assertArrayEquals(names.getEncoded(), GeneralNames.fromExtensions(tbs.getExtensions(),
                    Extension.subjectAlternativeName).getEncoded());
            assertEquals(Set.of(Extension.basicConstraints, Extension.keyUsage, Extension.extendedKeyUsage,
                    Extension.subjectAlternativeName), Set.of(tbs.getExtensions().getExtensionOIDs()));
            assertTrue(!tbs.getExtensions().getExtension(Extension.extendedKeyUsage).isCritical());
            assertTrue(!tbs.getExtensions().getExtension(Extension.subjectAlternativeName).isCritical());
            assertEquals(List.of(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth),
                    List.of(org.bouncycastle.asn1.x509.ExtendedKeyUsage.fromExtensions(tbs.getExtensions()).getUsages()));
            PreparedSemanticSigningRequest second = service.prepareEndEntity(ACCESS, request, Optional.empty(), CancellationSignal.NONE);
            assertTrue(!prepared.receipt().operationId().equals(second.receipt().operationId()));
            assertEquals(2, stages.get());
            service.discard(prepared);
            service.discard(second);
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, first));
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
            assertEquals(0, provider.calls.get());
        }
    }

    @Test
    void publicPreparationStagesOneExactLeafAndTransfersCustodyOnlyOnAcceptance(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            AtomicInteger stages = new AtomicInteger();
            AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
            PkiStore observed = observePreparation(store, stages, candidate, new AtomicBoolean(), false);
            CountingProvider provider = new CountingProvider();
            SemanticSigningService service = semantic(observed, provider, () -> { });
            byte[] supplied = csr.clone();
            EndEntityIssuanceRequest request = request(supplied);
            PreparedSemanticSigningRequest prepared = service.prepareEndEntity(ACCESS, request, Optional.empty(), CancellationSignal.NONE);
            supplied[0] ^= 1;
            request.csrDer()[0] ^= 1;
            assertEquals(1, stages.get());
            assertEquals(0, provider.calls.get());
            assertTrue(store.getSignWorkflow(prepared.receipt().operationId()).isEmpty());
            DurableContentReference reference = candidate.get();
            assertEquals(DurableContentReference.Lifecycle.OPERATION, reference.lifecycle());
            byte[] tbs = PkiTestRuntime.readContent(store, reference);
            TBSCertificate certificate = TBSCertificate.getInstance(tbs);
            assertEquals(new X500Name("CN=Applicant"), certificate.getSubject());
            assertEquals(new X500Name("CN=Issuer"), certificate.getIssuer());
            assertArrayEquals(key.getPublic().getEncoded(), certificate.getSubjectPublicKeyInfo().getEncoded());
            assertEquals(NOW, certificate.getStartDate().getDate().toInstant());
            assertTrue(certificate.getSerialNumber().getValue().signum() > 0);
            assertEquals(Set.of(Extension.basicConstraints, Extension.keyUsage),
                    Set.of(certificate.getExtensions().getExtensionOIDs()));
            assertTrue(certificate.getExtensions().getExtension(Extension.basicConstraints).isCritical());
            assertTrue(!BasicConstraints.fromExtensions(certificate.getExtensions()).isCA());
            assertEquals(SigningAcceptanceDisposition.ACCEPTED, service.accept(prepared).disposition());
            assertEquals(0, provider.calls.get());
            SignWorkflowStore.Workflow workflow = store.getSignWorkflow(prepared.receipt().operationId()).orElseThrow();
            assertEquals(CA, workflow.envelope().fairnessAuthorityId());
            assertEquals(KEY, workflow.envelope().keyRef());
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(workflow.envelope().outer().orElseThrow().command());
            command.requireFields(23);
            assertEquals("", command.field(15));
            assertEquals("", command.field(16));
            assertTrue(IssuanceExecutionEvidence.decode(DomainAttributeEncoding.decode(command.field(22))).isEmpty());
            assertEquals(certificate.getSerialNumber().getValue().toString(), command.field(10));
            assertEquals("issue." + java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(prepared.receipt().operationId().value().getBytes(StandardCharsets.UTF_8))),
                    workflow.envelope().outer().orElseThrow().correlationId());
            assertThrows(IllegalStateException.class, () -> service.discard(prepared));
        }
    }

    @Test
    void cancellationAndAdoptionFailureRetireTheirUnownedTbs(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            AtomicInteger stages = new AtomicInteger();
            AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
            AtomicBoolean cancelled = new AtomicBoolean();
            PkiStore observed = observePreparation(store, stages, candidate, cancelled, true);
            CountingProvider provider = new CountingProvider();
            SemanticSigningService service = semantic(observed, provider, () -> { });
            assertThrows(PkiException.class, () -> service.prepareEndEntity(ACCESS, request(csr), Optional.empty(), cancelled::get));
            assertEquals(1, stages.get());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
            assertEquals(0, provider.calls.get());
            AtomicInteger lifecycleChecks = new AtomicInteger();
            SemanticSigningService closing = semantic(observePreparation(store, stages, candidate, cancelled, false), provider,
                    () -> { if (lifecycleChecks.incrementAndGet() == 3) { throw new IllegalStateException("closed"); } });
            assertThrows(IllegalStateException.class, () -> closing.prepareEndEntity(ACCESS, request(csr), Optional.empty(), CancellationSignal.NONE));
            assertEquals(2, stages.get());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
        }
    }

    static SemanticSigningService semantic(PkiStore store, CountingProvider provider, Runnable guard) {
        return semantic(store, provider, guard, CLOCK);
    }

    @Test
    void rejectsNullAndMismatchedIssuanceEvidenceBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            AtomicInteger stages = new AtomicInteger();
            CountingProvider provider = new CountingProvider();
            SemanticSigningService service = semantic(observePreparation(store, stages, new AtomicReference<>(),
                    new AtomicBoolean(), false), provider, () -> { });
            AccessContext access = new AccessContext(new Principal("ACME_ACCOUNT", "account"), ACCESS.purpose(),
                    Optional.empty(), Optional.empty());
            CorrelatedEndEntityIssuanceRequest correlated = correlated(store);
            assertThrows(NullPointerException.class,
                    () -> service.prepareEndEntity(access, request(csr), null, CancellationSignal.NONE));
            assertThrows(NullPointerException.class,
                    () -> service.prepareCorrelatedEndEntity(access, correlated, null, CancellationSignal.NONE));
            for (IssuanceExecutionEvidence mismatch : List.of(
                    IssuanceExecutionEvidence.acme("other-actor", "realm", "invocation", CA.value(), PROFILE),
                    IssuanceExecutionEvidence.administrative("account", "realm", "invocation",
                            IssuanceExecutionEvidence.Authentication.DIRECT_MTLS,
                            IssuanceExecutionEvidence.AuthorizationPath.ORDINARY_GRANT, "0".repeat(64), CA.value(), PROFILE),
                    IssuanceExecutionEvidence.acme("account", "realm", "invocation", "other-ca", PROFILE),
                    IssuanceExecutionEvidence.acme("account", "realm", "invocation", CA.value(), "other-profile"))) {
                IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                        () -> service.prepareEndEntity(access, request(csr), Optional.of(mismatch), CancellationSignal.NONE));
                assertEquals("Issuance execution evidence binding differs", failure.getMessage());
                assertThrows(IllegalArgumentException.class,
                        () -> service.prepareCorrelatedEndEntity(access, correlated, Optional.of(mismatch), CancellationSignal.NONE));
            }
            assertEquals(0, stages.get());
            assertEquals(0, provider.calls.get());
            assertTrue(store.listSignWorkflows().isEmpty());
        }
    }

    @Test
    void correlatedAttachmentAndReplayPreserveWinnerEvidenceWithoutPolicyLookup(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            AtomicInteger stages = new AtomicInteger();
            AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
            CountingProvider provider = new CountingProvider();
            SemanticSigningService service = semantic(observePreparation(store, stages, candidate,
                    new AtomicBoolean(), false), provider, () -> { });
            CorrelatedEndEntityIssuanceRequest input = correlated(store);
            AccessContext firstAccess = new AccessContext(new Principal("ACME_ACCOUNT", "first-account"), ACCESS.purpose(),
                    Optional.empty(), Optional.empty());
            AccessContext retryAccess = new AccessContext(new Principal("ACME_ACCOUNT", "retry-account"), ACCESS.purpose(),
                    Optional.empty(), Optional.empty());
            IssuanceExecutionEvidence winner = IssuanceExecutionEvidence.acme(
                    "first-account", "first-realm", "first-invocation", CA.value(), PROFILE);
            IssuanceExecutionEvidence retry = IssuanceExecutionEvidence.acme(
                    "retry-account", "retry-realm", "retry-invocation", CA.value(), PROFILE);
            PreparedSemanticSigningRequest first = ((CorrelatedIssuancePreparation.Prepared)
                    service.prepareCorrelatedEndEntity(firstAccess, input, Optional.of(winner), CancellationSignal.NONE)).prepared();
            PreparedSemanticSigningRequest second = ((CorrelatedIssuancePreparation.Prepared)
                    service.prepareCorrelatedEndEntity(retryAccess, input, Optional.of(retry), CancellationSignal.NONE)).prepared();
            DurableContentReference losingContent = candidate.get();
            assertEquals(SigningAcceptanceDisposition.ACCEPTED, service.accept(first).disposition());
            assertEquals(SigningAcceptanceDisposition.ATTACHED_EXISTING, service.accept(second).disposition());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, losingContent));

            PkiStore points = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        assertTrue(Set.of("getDomainContinuation", "getSignWorkflow", "signingNamespace", "signingNow",
                                "signingHorizon", "signingPermittedSkew").contains(method.getName()),
                                "Replay must not revalidate policy or stage content: " + method.getName());
                        try { return method.invoke(store, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            SemanticSigningService replay = semantic(points, provider, () -> { });
            CorrelatedIssuancePreparation.Existing existing = (CorrelatedIssuancePreparation.Existing)
                    replay.prepareCorrelatedEndEntity(retryAccess, input, Optional.of(retry), CancellationSignal.NONE);
            assertEquals(first.receipt().operationId(), existing.operation().submissionId().id());
            assertEquals(firstAccess, existing.operation().scope().accessContext());
            assertThrows(IllegalArgumentException.class,
                    () -> replay.prepareCorrelatedEndEntity(firstAccess, input, Optional.of(retry), CancellationSignal.NONE));
            assertThrows(NullPointerException.class,
                    () -> replay.prepareCorrelatedEndEntity(retryAccess, input, null, CancellationSignal.NONE));
            assertTrue(replay.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE)
                    instanceof CorrelatedIssuancePreparation.Existing);
            DomainCommandEncoding.Decoded retained = DomainCommandEncoding.decode(store.getSignWorkflow(
                    first.receipt().operationId()).orElseThrow().envelope().outer().orElseThrow().command());
            assertEquals(winner, IssuanceExecutionEvidence.decode(DomainAttributeEncoding.decode(retained.field(22))).orElseThrow());
            assertEquals(2, stages.get());
            assertEquals(0, provider.calls.get());
        }
    }

    @Test
    void correlatedPreparationUsesFrozenImportedProfileAndPersistsEffectiveIntent(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            CorrelatedEndEntityIssuanceRequest input = correlated(store);
            DefaultProfileService profiles = new DefaultProfileService(store, CLOCK, new InMemoryAuditSink());
            byte[] newer = new String(H7ProfileDocuments.noSanOrEkuProfile(), StandardCharsets.UTF_8)
                    .replace("\"profileVersion\":1", "\"profileVersion\":2").getBytes(StandardCharsets.UTF_8);
            profiles.importProfile(newer);
            profiles.activateProfile(PROFILE, 2L);
            AtomicInteger stages = new AtomicInteger();
            AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
            CountingProvider provider = new CountingProvider();
            PkiStore observed = observePreparation(store, stages, candidate, new AtomicBoolean(), false);
            PkiStore frozenOnly = (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                    new Class<?>[] { PkiStore.class }, (proxy, method, args) -> {
                        if (method.getName().equals("requireActiveProfile") || method.getName().equals("getActiveProfileRef")) {
                            throw new AssertionError("Correlated preparation must not select active profile");
                        }
                        try { return method.invoke(observed, args); }
                        catch (InvocationTargetException failure) { throw failure.getCause(); }
                    });
            SemanticSigningService service = semantic(frozenOnly, provider, () -> { });
            CorrelatedIssuancePreparation result = service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE);
            PreparedSemanticSigningRequest prepared = ((CorrelatedIssuancePreparation.Prepared) result).prepared();
            assertEquals(1, stages.get());
            assertEquals(0, provider.calls.get());
            assertTrue(store.getSignWorkflow(prepared.receipt().operationId()).isEmpty());
            assertEquals(DurableContentReference.Lifecycle.OPERATION, candidate.get().lifecycle());
            service.accept(prepared);
            SignWorkflowStore.OuterCommand outer = store.getSignWorkflow(prepared.receipt().operationId()).orElseThrow()
                    .envelope().outer().orElseThrow();
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.command()).requireFields(23);
            assertEquals("ISSUE_END_ENTITY", command.operation());
            assertEquals("1", command.field(5));
            assertEquals(java.util.HexFormat.of().formatHex(input.intent().expectedProfile().canonicalSha256()), command.field(6));
            assertEquals(input.intent().expectedIssuerId().value(), command.field(1));
            assertEquals(input.intent().expectedChainPathId().value(), command.field(2));
            assertEquals(input.intent().expectedChainPathCommitment(), command.field(3));
            assertEquals(input.intent().issuanceId(), command.field(15));
            assertEquals(CorrelatedIssuanceIdentity.derive(input).effectiveCommitment(), command.field(16));
            assertEquals(CorrelatedIssuanceIdentity.derive(input).correlationId(), outer.correlationId());
            assertEquals(0, provider.calls.get());
        }
    }

    @Test
    void correlatedPreparationRejectsAbsentOrDifferentFrozenSelectionBeforeStaging(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            CorrelatedEndEntityIssuanceRequest input = correlated(store);
            AtomicInteger stages = new AtomicInteger();
            CountingProvider provider = new CountingProvider();
            SemanticSigningService service = semantic(observePreparation(store, stages, new AtomicReference<>(),
                    new AtomicBoolean(), false), provider, () -> { });
            IssuanceIntent intent = input.intent();
            for (int field = 0; field < 5; field++) {
                CertificateProfileRef profile = new CertificateProfileRef(PROFILE, field == 0 ? 99 : 1,
                        field == 1 ? new byte[32] : intent.expectedProfile().canonicalSha256());
                IssuanceIntent changed = new IssuanceIntent(intent.issuanceId(), intent.commandCommitment(), profile,
                        field == 2 ? new PkiId("stale-issuer") : intent.expectedIssuerId(),
                        field == 3 ? new PkiId("stale-path") : intent.expectedChainPathId(),
                        field == 4 ? "0".repeat(64) : intent.expectedChainPathCommitment());
                assertThrows(PkiException.class, () -> service.prepareCorrelatedEndEntity(ACCESS,
                        new CorrelatedEndEntityIssuanceRequest(input.request(), changed), Optional.empty(), CancellationSignal.NONE));
            }
            assertEquals(0, stages.get());
            assertEquals(0, provider.calls.get());
        }
    }

    @Test
    void correlatedPreparationRetainsProofPolicyAndCleanupGates(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = fixture(root)) {
            CorrelatedEndEntityIssuanceRequest input = correlated(store);
            AtomicInteger stages = new AtomicInteger();
            AtomicReference<DurableContentReference> candidate = new AtomicReference<>();
            CountingProvider provider = new CountingProvider();
            SemanticSigningService service = semantic(observePreparation(store, stages, candidate,
                    new AtomicBoolean(), false), provider, () -> { });
            byte[] badProof = csr.clone();
            badProof[badProof.length - 1] ^= 1;
            for (byte[] invalid : List.of(new byte[] { 5, 0 }, badProof, csr("CN=Applicant,O=Forbidden"))) {
                assertThrows(PkiException.class, () -> service.prepareCorrelatedEndEntity(ACCESS,
                        new CorrelatedEndEntityIssuanceRequest(request(invalid), input.intent()), Optional.empty(), CancellationSignal.NONE));
            }
            assertThrows(PkiException.class, () -> service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), () -> true));
            assertEquals(0, stages.get());
            PreparedSemanticSigningRequest prepared = ((CorrelatedIssuancePreparation.Prepared)
                    service.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE)).prepared();
            assertEquals(1, stages.get());
            service.discard(prepared);
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
            AtomicBoolean cancelled = new AtomicBoolean();
            SemanticSigningService cancelling = semantic(observePreparation(store, stages, candidate, cancelled, true),
                    provider, () -> { });
            assertThrows(PkiException.class, () -> cancelling.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), cancelled::get));
            assertEquals(2, stages.get());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
            candidate.set(null);
            SemanticSigningService closing = semantic(observePreparation(store, stages, candidate,
                    new AtomicBoolean(), false), provider, () -> {
                        if (candidate.get() != null) { throw new IllegalStateException("closed after staging"); }
                    });
            assertThrows(IllegalStateException.class,
                    () -> closing.prepareCorrelatedEndEntity(ACCESS, input, Optional.empty(), CancellationSignal.NONE));
            assertEquals(3, stages.get());
            assertThrows(Exception.class, () -> PkiTestRuntime.readContent(store, candidate.get()));
            assertEquals(0, provider.calls.get());
        }
    }

    private static CorrelatedEndEntityIssuanceRequest correlated(PkiStore store) {
        CaRecord ca = store.getCa(CA).orElseThrow();
        IssuerChainPath path = store.getIssuerChainPath(ca.issuanceChainPathId()).orElseThrow();
        IssuanceIntent intent = new IssuanceIntent("order-1", "1".repeat(64),
                store.requireActiveProfile(PROFILE).reference(), ca.currentIssuanceIssuerId(), path.pathId(), path.pathCommitment());
        return new CorrelatedEndEntityIssuanceRequest(request(csr), intent);
    }

    private static SemanticSigningService semantic(PkiStore store, CountingProvider provider, Runnable guard, Clock clock) {
        String algorithm = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm();
        DefaultSigningService signing = new DefaultSigningService(store, provider, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256, Duration.ofMinutes(1),
                new SecureRandom(), guard, (command, custody) -> { custody.run(); return store.acceptSign(command); }, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
        return new DefaultSemanticSigningService(store, signing,
                new EndEntitySigningPreparation(store, preparer(store, clock, algorithm)));
    }

    static PkiStore observePreparation(PkiStore store, AtomicInteger stages,
            AtomicReference<DurableContentReference> candidate, AtomicBoolean cancelled, boolean cancelAfterCompletion) {
        StagedContentStore content = (StagedContentStore) Proxy.newProxyInstance(StagedContentStore.class.getClassLoader(),
                new Class<?>[] { StagedContentStore.class }, (proxy, method, args) -> {
                    try {
                        Object result = method.invoke(store.stagedContent(), args);
                        if (method.getName().equals("beginContent")) {
                            stages.incrementAndGet();
                            zeroecho.pki.spi.store.ContentSink sink = (zeroecho.pki.spi.store.ContentSink) result;
                            return Proxy.newProxyInstance(zeroecho.pki.spi.store.ContentSink.class.getClassLoader(),
                                    new Class<?>[] { zeroecho.pki.spi.store.ContentSink.class }, (sinkProxy, sinkMethod, sinkArgs) -> {
                                        try {
                                            Object sinkResult = sinkMethod.invoke(sink, sinkArgs);
                                            if (sinkMethod.getName().equals("complete")) {
                                                candidate.set((DurableContentReference) sinkResult);
                                                if (cancelAfterCompletion) { cancelled.set(true); }
                                            }
                                            return sinkResult;
                                        } catch (InvocationTargetException failure) { throw failure.getCause(); }
                                    });
                        }
                        return result;
                    } catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("stagedContent")) { return content; }
                    try { return method.invoke(store, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
    }

    @Test
    void configuredPrivateAndParameterizedBindingsPassRealPreparationAndAcceptance(@TempDir Path root) throws Exception {
        for (boolean privateBinding : new boolean[] {true, false}) {
            try (FilesystemPkiStore store = fixture(root.resolve(privateBinding ? "private" : "pss"))) {
                String signature = (privateBinding ? BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256
                        : BootstrapAlgorithmIdentities.RSA_PSS_SHA256).canonicalForm();
                BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
                zeroecho.pki.testkit.AcceptancePrivateBinding extension = new zeroecho.pki.testkit.AcceptancePrivateBinding();
                X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(privateBinding ? List.of(extension) : List.of(),
                        List.of(verifier), List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                                AlgorithmExecutionCapability.Direction.VERIFY, verifier)), new X509AlgorithmResolver.Policy() {
                            @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) { return true; }
                            @Override public String semanticFingerprint() { return "acceptance-configured-binding"; }
                        });
                List<zeroecho.pki.api.algorithm.X509AlgorithmBinding> descriptors = new java.util.ArrayList<>(StandardX509Bindings.descriptors());
                if (privateBinding) { descriptors.add(zeroecho.pki.testkit.AcceptancePrivateBinding.DESCRIPTOR); }
                zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry registry = ImmutableX509AlgorithmBindingRegistry.create(descriptors);
                String profileId = PROFILE;
                if (privateBinding) {
                    zeroecho.pki.api.profile.CertificateProfileDefinition base = store.requireActiveProfile(PROFILE).definition();
                    zeroecho.pki.api.algorithm.X509AlgorithmBinding binding = zeroecho.pki.testkit.AcceptancePrivateBinding.DESCRIPTOR;
                    zeroecho.pki.api.profile.X509AlgorithmBindingPolicy policy = new zeroecho.pki.api.profile.X509AlgorithmBindingPolicy(
                            zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.Mode.EXPLICIT, Optional.empty(), Optional.empty(),
                            Optional.of(new zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.BindingReference(binding.bindingId(), binding.semanticCommitment())),
                            Optional.empty());
                    profileId = "acceptance-private";
                    zeroecho.pki.api.profile.CertificateProfileDefinition definition = new zeroecho.pki.api.profile.CertificateProfileDefinition(
                            base.certificateType(), profileId, 1, base.formatId(), "Acceptance private binding", base.maximumValidity(),
                            base.approvalRequirement(), base.subjectPolicy(), base.certificatePolicy(), policy, base.confirmationPolicy());
                    DefaultProfileService profiles = new DefaultProfileService(store, CLOCK, new InMemoryAuditSink(), registry);
                    profiles.importProfile(zeroecho.pki.api.profile.CertificateProfileDocumentCodec.writeCanonical(definition));
                    profiles.activateProfile(profileId, 1);
                    EndEntityIssuanceRequest rejected = new EndEntityIssuanceRequest(CA, csr, profileId, Optional.empty());
                    assertThrows(PkiException.class, () -> preparer(store, CLOCK, signature).prepare(ACCESS, rejected, CancellationSignal.NONE));
                }
                EndEntitySigningPreparation preparation = new EndEntitySigningPreparation(store, CLOCK, authority, verifier, registry, signature);
                CountingProvider provider = new CountingProvider(signature);
                DefaultSigningService signing = new DefaultSigningService(store, provider, authority.resolveIdentity(signature), Duration.ofMinutes(1),
                        new SecureRandom(), () -> { }, (command, custody) -> { custody.run(); return store.acceptSign(command); }, () -> { },
                (boundedWaitId, boundedWaitCancellation) -> { throw new UnsupportedOperationException("Fixture has no reactor wait"); });
                DefaultSemanticSigningService service = new DefaultSemanticSigningService(store, signing, preparation);
                PreparedSemanticSigningRequest prepared = service.prepareEndEntity(ACCESS,
                        new EndEntityIssuanceRequest(CA, csr, profileId, Optional.empty()), Optional.empty(), CancellationSignal.NONE);
                assertEquals(SigningAcceptanceDisposition.ACCEPTED, service.accept(prepared).disposition());
                SignWorkflowStore.Workflow accepted = store.getSignWorkflow(prepared.receipt().operationId()).orElseThrow();
                byte[] tbs = PkiTestRuntime.readContent(store, accepted.envelope().candidate());
                org.bouncycastle.asn1.x509.TBSCertificate candidate = org.bouncycastle.asn1.x509.TBSCertificate.getInstance(tbs);
                assertEquals(privateBinding ? extension.oid() : StandardX509Bindings.OID_RSA_PSS,
                        candidate.getSignature().getAlgorithm().getId());
                if (!privateBinding) { assertTrue(candidate.getSignature().getParameters() != null); }
                assertEquals(0, provider.calls.get());
            }
        }
    }

    static final class CountingProvider implements SigningProvider {
        @Override public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
            return new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of());
        }
        final AtomicInteger calls = new AtomicInteger();
        private final String algorithm;
        CountingProvider() { this(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm()); }
        CountingProvider(String algorithm) { this.algorithm = algorithm; }
        @Override public String id() { return "issuance-test"; }
        @Override public ConfigurationCommitment configurationCommitment() { return new ConfigurationCommitment(new byte[32]); }
        @Override public Set<String> supportedAlgorithms() { return Set.of(algorithm); }
        @Override public OperationObservation dispatch(SignRequest request, CallControl control) { calls.incrementAndGet(); throw new AssertionError("Unexpected dispatch"); }
        @Override public OperationObservation reconcile(PkiId id, CallControl control) { calls.incrementAndGet(); throw new AssertionError("Unexpected reconciliation"); }
        @Override public OperationObservation cancel(PkiId id, long fence, CancellationReason reason, CallControl control) { calls.incrementAndGet(); throw new AssertionError("Unexpected cancellation"); }
        @Override public void close() { }
    }

    private static EndEntityIssuancePreparation preparer(PkiStore store, Clock clock, String signature) {
        BcX509VerificationExecutor verifier = new BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, verifier)), new X509AlgorithmResolver.Policy() {
                    @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                        return true;
                    }
                    @Override public String semanticFingerprint() { return "issuance-test"; }
                });
        return new EndEntityIssuancePreparation(store, clock, authority, verifier,
                ImmutableX509AlgorithmBindingRegistry.create(StandardX509Bindings.descriptors()), signature);
    }

    private static FilesystemPkiStore fixture(Path root) throws Exception {
        FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK);
        DefaultProfileService profiles = new DefaultProfileService(store, CLOCK, new InMemoryAuditSink());
        profiles.importProfile(H7ProfileDocuments.noSanOrEkuProfile());
        profiles.activateProfile(PROFILE, 1L);
        X500Name subject = new X500Name("CN=Issuer");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                Date.from(NOW.minusSeconds(60)), Date.from(NOW.plusSeconds(800L * 86400)), subject, key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        byte[] encoded = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
        PkiId credentialId = new PkiId("credential:issuer");
        PkiId rootIssuer = IssuerGeneration.idFor(CA, credentialId);
        Credential credential = new Credential(credentialId, new FormatId("x509"),
                new IssuerRef(CA, rootIssuer, IssuerChainPath.create(CA, rootIssuer, List.of(credentialId)).pathId()),
                new SubjectRef("CN=Issuer"), new Validity(NOW.minusSeconds(60), NOW.plusSeconds(800L * 86400)),
                "1", new PkiId("public:issuer"), new CaProfileBinding(new CertificateProfileRef("root", 1, new byte[32])),
                CredentialStatus.ISSUED, PkiTestRuntime.stageCredential(store, encoded), SimpleAttributeSet.builder().build());
        IssuerGeneration generation = new IssuerGeneration(IssuerGeneration.idFor(CA, credentialId), CA, credentialId,
                KEY, IssuerGenerationState.ACTIVE, "00".repeat(32), "00".repeat(32));
        IssuerChainPath path = IssuerChainPath.create(CA, generation.issuerId(), List.of(credentialId));
        store.putCredential(credential);
        store.putIssuerGeneration(generation);
        store.putIssuerChainPath(path);
        store.putCa(new CaRecord(CA, CaKind.ROOT, CaState.ACTIVE, KEY, credential.subjectRef(), List.of(generation.issuerId()),
                generation.issuerId(), path.pathId()));
        return store;
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

    private static EndEntityIssuanceRequest request(byte[] bytes) {
        return new EndEntityIssuanceRequest(CA, bytes, PROFILE, Optional.empty());
    }

    private static byte[] csr(String name) throws Exception {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name(name), key.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
    }

    private static byte[] csrWithSan() throws Exception {
        return csrWithNames(new GeneralNames(new GeneralName(GeneralName.dNSName, "app.example.test")));
    }

    private static byte[] csrWithNames(GeneralNames names) throws Exception {
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.subjectAlternativeName, false, names);
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Applicant"), key.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key.getPrivate())).getEncoded();
    }
}
