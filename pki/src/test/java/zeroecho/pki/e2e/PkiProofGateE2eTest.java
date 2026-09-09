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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaImportCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.credential.CredentialProfileBinding;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.ReissueCommand;
import zeroecho.pki.api.issuance.RenewCommand;
import zeroecho.pki.api.issuance.ReplaceCommand;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionReason;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.core.DefaultIssuanceService;
import zeroecho.pki.impl.core.ValidatedCaCertificateRequest;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialIssuerBackend;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProofOfPossessionVerifier;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.testkit.PkiTestRuntime;

/**
 * End-to-end regression tests for PKI proof-of-possession issuance gates.
 */
final class PkiProofGateE2eTest {

    @Test
    void issuerBackendApiRequiresOpaqueGateProducedInputs() throws Exception {
        System.out.println("issuerBackendApiRequiresOpaqueGateProducedInputs");

        assertTrue(Modifier.isFinal(ValidatedCertificateRequest.class.getModifiers()));
        assertTrue(Modifier.isFinal(ValidatedCaCertificateRequest.class.getModifiers()));
        assertTrue(java.util.Arrays.stream(ValidatedCertificateRequest.class.getDeclaredConstructors())
                .noneMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
        assertTrue(java.util.Arrays.stream(ValidatedCaCertificateRequest.class.getDeclaredConstructors())
                .noneMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
        Class<?> managedKeyProof = Class.forName("zeroecho.pki.impl.core.CaProofGate$ManagedKeyProof");
        assertTrue(java.util.Arrays.stream(managedKeyProof.getDeclaredConstructors())
                .noneMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
        Class<?> caProofGate = Class.forName("zeroecho.pki.impl.core.CaProofGate");
        assertTrue(java.util.Arrays.stream(caProofGate.getDeclaredClasses())
                .noneMatch(type -> type.getSimpleName().equals("BusBackedContentSigner")));
        assertTrue(java.util.Arrays.stream(caProofGate.getDeclaredMethods())
                .filter(method -> method.getName().equals("signer"))
                .allMatch(method -> method.getReturnType().getName()
                        .equals("zeroecho.pki.impl.framework.x509.bc.PkiBusContentSigner")));
        assertTrue(java.util.Arrays.stream(CredentialFramework.class.getMethods())
                .noneMatch(method -> method.getName().equals("issuerBackend")));

        Class<?> contentReference = zeroecho.pki.api.content.DurableContentReference.class;
        Class<?> cancellationSignal = zeroecho.core.io.CancellationSignal.class;
        Method legacyEndEntity = CredentialIssuerBackend.class.getMethod("issueEndEntity",
                ValidatedCertificateRequest.class, contentReference, KeyRef.class, BigInteger.class);
        Method cancellableEndEntity = CredentialIssuerBackend.class.getMethod("issueEndEntity",
                ValidatedCertificateRequest.class, contentReference, KeyRef.class, BigInteger.class,
                cancellationSignal);
        Method legacyIntermediate = CredentialIssuerBackend.class.getMethod("issueIntermediateCertificate",
                ValidatedCaCertificateRequest.class, contentReference, KeyRef.class);
        Method cancellableIntermediate = CredentialIssuerBackend.class.getMethod("issueIntermediateCertificate",
                ValidatedCaCertificateRequest.class, contentReference, KeyRef.class, cancellationSignal);
        assertArrayEquals(new Class<?>[] { ValidatedCertificateRequest.class, contentReference,
                KeyRef.class, BigInteger.class }, legacyEndEntity.getParameterTypes());
        assertArrayEquals(new Class<?>[] { ValidatedCertificateRequest.class, contentReference,
                KeyRef.class, BigInteger.class, cancellationSignal }, cancellableEndEntity.getParameterTypes());
        assertArrayEquals(new Class<?>[] { ValidatedCaCertificateRequest.class, contentReference, KeyRef.class },
                legacyIntermediate.getParameterTypes());
        assertArrayEquals(new Class<?>[] { ValidatedCaCertificateRequest.class, contentReference, KeyRef.class,
                cancellationSignal }, cancellableIntermediate.getParameterTypes());
        assertTrue(java.util.Arrays.stream(BcX509CredentialIssuerBackend.class.getMethods())
                .filter(method -> method.getName().startsWith("issue"))
                .noneMatch(method -> java.util.Arrays.asList(method.getParameterTypes())
                        .contains(IssueEndEntityCommand.class)
                        || java.util.Arrays.asList(method.getParameterTypes())
                                .contains(IntermediateCertIssueCommand.class)));

        System.out.println("...backend methods=" + legacyEndEntity.getParameterTypes()[0].getSimpleName() + ","
                + legacyIntermediate.getParameterTypes()[0].getSimpleName());
        System.out.println("issuerBackendApiRequiresOpaqueGateProducedInputs...ok");
    }

    @Test
    void proofGatesAloneCanReachIssuerBackend(@TempDir Path tempDir) throws Exception {
        System.out.println("proofGatesAloneCanReachIssuerBackend");

        KeyPair rootKey = generateRsa();
        KeyPair subjectKey = generateRsa();
        KeyPair wrongKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef subjectKeyRef = new KeyRef("kref:v1:keyring:test:subject");
        Map<KeyRef, KeyPair> keys = Map.of(rootKeyRef, rootKey, subjectKeyRef, subjectKey);
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), keys)) {
            CountingIssuerBackend counting = new CountingIssuerBackend(runtime.issuerBackend());
            DefaultIssuanceService issuance = new DefaultIssuanceService(runtime.store(), runtime.framework(), counting,
                    runtime.auditSink(), runtime.statusResolver(), runtime.profileService(), Clock.systemUTC(), runtime.revocationService());
            ParsedCertificationRequest valid = parse(runtime, makeCsr(subjectKey, subjectKey, "CN=Leaf"));

            assertThrows(PkiException.class,
                    () -> issuance.issueEndEntity(new IssueEndEntityCommand(new PkiId("ca:absent"),
                            parse(runtime, makeCsr(subjectKey, wrongKey, "CN=Leaf")), "default", Optional.empty())));
            assertEquals(0, counting.endEntityCalls.get());

            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            CredentialBundle issued = issuance
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, valid, "default", Optional.empty()));
            assertEquals(1, counting.endEntityCalls.get());
            assertArrayEquals(subjectKey.getPublic().getEncoded(),
                    new X509CertificateHolder(runtime.credentialBytes(issued.credential())).getSubjectPublicKeyInfo()
                            .getEncoded());

            CaService caService = runtime.caService(counting);
            caService.createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootCaId,
                    new SubjectRef("CN=Intermediate"), "intermediate-ca", Optional.of(subjectKeyRef),
                    new SimpleAttributeSet()));
            assertEquals(1, counting.intermediateCalls.get());

            runtime.replaceResolvedKey(subjectKeyRef, wrongKey.getPublic());
            assertThrows(PkiException.class,
                    () -> caService.createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(),
                            rootCaId, new SubjectRef("CN=Rejected"), "intermediate-ca", Optional.of(subjectKeyRef),
                            new SimpleAttributeSet())));
            assertEquals(1, counting.intermediateCalls.get());

            System.out.println(
                    "...backend calls=" + counting.endEntityCalls.get() + "/" + counting.intermediateCalls.get());
        }

        System.out.println("proofGatesAloneCanReachIssuerBackend...ok");
    }

    @Test
    void unsupportedIssuanceVariantsFailWithoutSideEffects(@TempDir Path tempDir) throws Exception {
        System.out.println("unsupportedIssuanceVariantsFailWithoutSideEffects");

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), Map.of())) {
            CountingIssuerBackend counting = new CountingIssuerBackend(runtime.issuerBackend());
            DefaultIssuanceService issuance = new DefaultIssuanceService(runtime.store(), runtime.framework(), counting,
                    runtime.auditSink(), runtime.statusResolver(), runtime.profileService(), Clock.systemUTC(), runtime.revocationService());
            CaService caService = runtime.caService(counting);
            int auditCount = runtime.auditSink().snapshot().size();
            ParsedCertificationRequest request = new ParsedCertificationRequest(new PkiId("csr:unsupported"),
                    runtime.framework().formatId(), new SubjectRef("CN=Unsupported"),
                    new EncodedObject(Encoding.DER, new byte[] { 1 }), Optional.empty(), Optional.empty(),
                    new SimpleAttributeSet());
            PkiId objectId = new PkiId("object:unsupported");
            long filesBefore;
            try (java.util.stream.Stream<Path> files = Files.walk(tempDir)) {
                filesBefore = files.filter(Files::isRegularFile).count();
            }

            assertThrows(PkiException.class,
                    () -> issuance.renew(new RenewCommand(objectId, Optional.empty(), new SimpleAttributeSet())));
            assertThrows(PkiException.class,
                    () -> issuance.replace(new ReplaceCommand(objectId, request, "default", new SimpleAttributeSet())));
            assertThrows(PkiException.class,
                    () -> issuance.reissue(new ReissueCommand(objectId, new SimpleAttributeSet())));
            assertThrows(PkiException.class, () -> caService.rolloverCaCertificate(
                    new CaRolloverCommand(objectId, Optional.empty(), Optional.empty(), new SimpleAttributeSet())));
            assertThrows(PkiException.class, () -> caService.rotateCaKey(
                    new CaKeyRotationCommand(objectId, Optional.empty(), Optional.empty(), new SimpleAttributeSet())));

            long filesAfter;
            try (java.util.stream.Stream<Path> files = Files.walk(tempDir)) {
                filesAfter = files.filter(Files::isRegularFile).count();
            }
            assertEquals(filesBefore, filesAfter);
            assertEquals(0, counting.endEntityCalls.get());
            assertEquals(0, counting.intermediateCalls.get());
            assertEquals(0, runtime.submittedSignCount());
            assertTrue(runtime.store().listCas().isEmpty());
            assertTrue(runtime.store().listWorkflowStates().isEmpty());
            assertEquals(auditCount, runtime.auditSink().snapshot().size());

            System.out.println("...unsupported operations=5");
        }

        System.out.println("unsupportedIssuanceVariantsFailWithoutSideEffects...ok");
    }

    @Test
    void endEntityGateRejectsMalformedTamperedAndSubstitutedRequests(@TempDir Path tempDir) throws Exception {
        System.out.println("endEntityGateRejectsMalformedTamperedAndSubstitutedRequests");

        KeyPair rootKey = generateRsa();
        KeyPair subjectKey = generateRsa();
        KeyPair otherKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef subjectKeyRef = new KeyRef("kref:v1:keyring:test:subject");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey, subjectKeyRef, subjectKey))) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            PKCS10CertificationRequest validCsr = makeCsr(subjectKey, subjectKey, "CN=Subject");
            ParsedCertificationRequest valid = parse(runtime, validCsr);
            ParsedCertificationRequest pss = parse(runtime,
                    makeCsr(subjectKey, subjectKey, "CN=PssSubject", "SHA256withRSAandMGF1"));
            ProofOfPossessionResult pssProof = standaloneBcVerifier().verify(pss,
                    new zeroecho.pki.api.issuance.VerificationPolicy(true, Optional.empty()));
            assertEquals(ProofOfPossessionStatus.VERIFIED, pssProof.status());
            org.bouncycastle.asn1.pkcs.CertificationRequest original = validCsr.toASN1Structure();
            CertificationRequestInfo requestInfo = original.getCertificationRequestInfo();
            org.bouncycastle.asn1.pkcs.CertificationRequest unknownAlgorithm = new org.bouncycastle.asn1.pkcs.CertificationRequest(
                    requestInfo, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4.5.6.7")),
                    original.getSignature());
            ParsedCertificationRequest unsupported = parse(runtime, new PKCS10CertificationRequest(unknownAlgorithm));
            ProofOfPossessionResult unsupportedProof = standaloneBcVerifier().verify(unsupported,
                    new zeroecho.pki.api.issuance.VerificationPolicy(true, Optional.empty()));
            assertEquals(ProofOfPossessionStatus.NOT_SUPPORTED, unsupportedProof.status());
            assertEquals(ProofOfPossessionReason.UNSUPPORTED_ALGORITHM, unsupportedProof.reason());

            assertRejected(runtime, rootCaId, withAttributes(valid, new SimpleAttributeSet()), "CSR_MISSING");
            assertRejected(runtime, rootCaId, withCsr(valid, new byte[] { 0x01 }), "CSR_MALFORMED");

            byte[] tampered = csrDer(valid).clone();
            tampered[tampered.length - 1] ^= 0x01;
            ParsedCertificationRequest tamperedParsed = parse(runtime, new PKCS10CertificationRequest(tampered));
            assertRejected(runtime, rootCaId, tamperedParsed, "PROOF_FAILED");

            ParsedCertificationRequest wrongSigner = parse(runtime, makeCsr(subjectKey, otherKey, "CN=Subject"));
            assertRejected(runtime, rootCaId, wrongSigner, "PROOF_FAILED");

            assertRejected(runtime, rootCaId,
                    new ParsedCertificationRequest(new PkiId("csr:substituted"), valid.formatId(), valid.subjectRef(),
                            valid.publicKeyInfo(), valid.requestedValidity(), valid.requestedProfileId(),
                            valid.subjectRdns(), valid.subjectAlternativeNames(), valid.subjectAlternativeNamePresent(),
                            valid.attributes()),
                    "REQUEST_ID_MISMATCH");
            assertRejected(runtime, rootCaId,
                    new ParsedCertificationRequest(valid.requestId(), valid.formatId(), new SubjectRef("CN=Other"),
                            valid.publicKeyInfo(), valid.requestedValidity(), valid.requestedProfileId(),
                            valid.subjectRdns(), valid.subjectAlternativeNames(), valid.subjectAlternativeNamePresent(),
                            valid.attributes()),
                    "SUBJECT_MISMATCH");
            assertRejected(runtime, rootCaId,
                    new ParsedCertificationRequest(valid.requestId(), valid.formatId(), valid.subjectRef(),
                            new EncodedObject(Encoding.DER, otherKey.getPublic().getEncoded()),
                            valid.requestedValidity(), valid.requestedProfileId(), valid.subjectRdns(),
                            valid.subjectAlternativeNames(), valid.subjectAlternativeNamePresent(), valid.attributes()),
                    "SPKI_MISMATCH");
            assertRejected(runtime, rootCaId,
                    new ParsedCertificationRequest(valid.requestId(), new FormatId("unsupported"), valid.subjectRef(),
                            valid.publicKeyInfo(), valid.requestedValidity(), valid.requestedProfileId(),
                            valid.subjectRdns(), valid.subjectAlternativeNames(), valid.subjectAlternativeNamePresent(),
                            valid.attributes()),
                    "FORMAT_UNSUPPORTED");
            byte[] maximum = new byte[1024 * 1024];
            System.arraycopy(csrDer(valid), 0, maximum, 0, csrDer(valid).length);
            assertRejected(runtime, rootCaId, withCsr(valid, maximum), "CSR_MALFORMED");
            assertRejected(runtime, rootCaId, withCsr(valid, new byte[1024 * 1024 + 1]), "CSR_TOO_LARGE");

            assertEquals(1, runtime.store().listCas().size());
            AuditEvent last = runtime.auditSink().snapshot().get(runtime.auditSink().snapshot().size() - 1);
            assertEquals("ISSUE_END_ENTITY_REJECTED", last.action());
            assertEquals("SYSTEM", last.principal().type());
            assertEquals("pki", last.principal().name());
            assertEquals(Set.of("code"), last.details().keySet());
        }

        System.out.println("endEntityGateRejectsMalformedTamperedAndSubstitutedRequests...ok");
    }

    @Test
    void endEntityGateForcesRequiredPolicyAndRejectsEveryNonVerifiedStatus(@TempDir Path tempDir) throws Exception {
        System.out.println("endEntityGateForcesRequiredPolicyAndRejectsEveryNonVerifiedStatus");

        KeyPair rootKey = generateRsa();
        KeyPair subjectKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef subjectKeyRef = new KeyRef("kref:v1:keyring:test:subject");
        for (ProofOfPossessionReason reason : new ProofOfPossessionReason[] { ProofOfPossessionReason.NOT_PRESENT,
                ProofOfPossessionReason.UNSUPPORTED_ALGORITHM, ProofOfPossessionReason.SIGNATURE_INVALID }) {
            AtomicBoolean required = new AtomicBoolean();
            Path caseDir = tempDir.resolve(reason.status().name());
            try (PkiTestRuntime runtime = PkiTestRuntime.create(caseDir, caseDir.resolve("bus.log"),
                    Map.of(rootKeyRef, rootKey, subjectKeyRef, subjectKey),
                    Map.of(rootKeyRef, rootKey.getPublic(), subjectKeyRef, subjectKey.getPublic()),
                    (request, policy) -> {
                        required.set(policy.requireProofOfPossession());
                        return ProofOfPossessionResult.of(reason);
                    })) {
                PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                        new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
                ParsedCertificationRequest parsed = parse(runtime, makeCsr(subjectKey, subjectKey, "CN=Subject"));
                assertThrows(PkiException.class, () -> issue(runtime, rootCaId, parsed));
                assertTrue(required.get());
                assertTrue(runtime.auditSink().snapshot().stream()
                        .anyMatch(event -> ("PROOF_" + reason.status().name()).equals(event.details().get("code"))));
                assertEquals(1, runtime.store().listCas().size());
            }
        }

        System.out.println("endEntityGateForcesRequiredPolicyAndRejectsEveryNonVerifiedStatus...ok");
    }

    @Test
    void verifiedSnapshotSurvivesCallerArrayMutationAndIssuerOverrides(@TempDir Path tempDir) throws Exception {
        System.out.println("verifiedSnapshotSurvivesCallerArrayMutationAndIssuerOverrides");

        KeyPair rootKey = generateRsa();
        KeyPair subjectKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef subjectKeyRef = new KeyRef("kref:v1:keyring:test:subject");
        AtomicReference<Runnable> mutation = new AtomicReference<>(() -> {
        });
        BcX509ProofOfPossessionVerifier delegate = standaloneBcVerifier();

        Map<KeyRef, KeyPair> signingKeys = Map.of(rootKeyRef, rootKey, subjectKeyRef, subjectKey);
        Map<KeyRef, PublicKey> resolvedKeys = Map.of(rootKeyRef, rootKey.getPublic(), subjectKeyRef,
                subjectKey.getPublic());
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"), signingKeys,
                resolvedKeys, (request, policy) -> {
                    ProofOfPossessionResult result = delegate.verify(request, policy);
                    mutation.get().run();
                    return result;
                })) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            ParsedCertificationRequest parsed = parse(runtime, makeCsr(subjectKey, subjectKey, "CN=Subject"));
            byte[] callerCsr = csrDer(parsed);
            byte[] callerSpki = parsed.publicKeyInfo().bytes();
            mutation.set(() -> {
                callerCsr[0] ^= 0x7f;
                callerSpki[0] ^= 0x7f;
            });

            AttributeSet hostileOverrides = SimpleAttributeSet.builder()
                    .put(BcX509Attributes.ISSUER_CERT_DER, new AttributeValue.BytesValue(new byte[] { 0x01 }))
                    .put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue("attacker-key")).build();
            CredentialBundle bundle = runtime.issuanceService()
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, parsed, "default", Optional.empty()));

            X509CertificateHolder issued = new X509CertificateHolder(runtime.credentialBytes(bundle.credential()));
            assertEquals("CN=Root", issued.getIssuer().toString());
            assertEquals("CN=Subject", issued.getSubject().toString());
            assertArrayEquals(subjectKey.getPublic().getEncoded(), issued.getSubjectPublicKeyInfo().getEncoded());
        }

        System.out.println("verifiedSnapshotSurvivesCallerArrayMutationAndIssuerOverrides...ok");
    }

    @Test
    void caProofGatesVerifyRootAndManagedIntermediateKeys(@TempDir Path tempDir) throws Exception {
        System.out.println("caProofGatesVerifyRootAndManagedIntermediateKeys");

        KeyPair expectedRoot = generateRsa();
        KeyPair wrongRootSigner = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        Path wrongDir = tempDir.resolve("wrong-root");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(wrongDir, wrongDir.resolve("bus.log"),
                Map.of(rootKeyRef, wrongRootSigner), Map.of(rootKeyRef, expectedRoot.getPublic()),
                standaloneBcVerifier())) {
            assertThrows(PkiException.class,
                    () -> runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                            new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet())));
            assertTrue(runtime.store().listCas().isEmpty());
            assertTrue(runtime.store().listWorkflowStates().isEmpty());
            assertEquals(1, runtime.submittedSignCount());
            assertTrue(runtime.auditSink().snapshot().stream()
                    .anyMatch(event -> "MANAGED_KEY_PROOF_FAILED".equals(event.details().get("code"))));
        }
        Path failedDir = tempDir.resolve("failed-workflow");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(failedDir, failedDir.resolve("bus.log"), Map.of(),
                Map.of(rootKeyRef, expectedRoot.getPublic()), standaloneBcVerifier())) {
            assertThrows(PkiException.class,
                    () -> runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                            new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet())));
            assertTrue(runtime.store().listWorkflowStates().isEmpty());
            assertEquals(1, runtime.submittedSignCount());
        }

        KeyPair rootKey = generateRsa();
        KeyPair intermediateKey = generateRsa();
        KeyRef intermediateKeyRef = new KeyRef("kref:v1:keyring:test:intermediate");
        Path validDir = tempDir.resolve("valid-intermediate");
        Map<KeyRef, KeyPair> keys = new HashMap<>();
        keys.put(rootKeyRef, rootKey);
        keys.put(intermediateKeyRef, intermediateKey);
        try (PkiTestRuntime runtime = PkiTestRuntime.create(validDir, validDir.resolve("bus.log"), keys)) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            AttributeSet approved = new SimpleAttributeSet();
            PkiId intermediateCaId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootCaId,
                            new SubjectRef("CN=Intermediate"), "intermediate-ca", Optional.of(intermediateKeyRef),
                            approved));

            Credential first = runtime.caCredential(runtime.caService().getCa(intermediateCaId), 0);
            X509CertificateHolder firstHolder = new X509CertificateHolder(runtime.credentialBytes(first));
            assertEquals("CN=Root", firstHolder.getIssuer().toString());
            assertEquals("CN=Intermediate", firstHolder.getSubject().toString());
            assertArrayEquals(intermediateKey.getPublic().getEncoded(),
                    firstHolder.getSubjectPublicKeyInfo().getEncoded());

            Credential additional = runtime.caService()
                    .issueIntermediateCertificate(new IntermediateCertIssueCommand(runtime.framework().formatId(),
                            rootCaId, intermediateCaId, "intermediate-ca", Optional.empty(), approved));
            X509CertificateHolder additionalHolder = new X509CertificateHolder(runtime.credentialBytes(additional));
            assertEquals("CN=Intermediate", additionalHolder.getSubject().toString());
            assertArrayEquals(intermediateKey.getPublic().getEncoded(),
                    additionalHolder.getSubjectPublicKeyInfo().getEncoded());
        }

        System.out.println("caProofGatesVerifyRootAndManagedIntermediateKeys...ok");
    }

    @Test
    void caIssuerImportAndWorkflowFailuresLeaveNoDurableSideEffects(@TempDir Path tempDir) throws Exception {
        System.out.println("caIssuerImportAndWorkflowFailuresLeaveNoDurableSideEffects");

        KeyPair rootKey = generateRsa();
        KeyPair replacementRootKey = generateRsa();
        KeyPair intermediateKey = generateRsa();
        KeyPair subjectKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef intermediateKeyRef = new KeyRef("kref:v1:keyring:test:intermediate");

        Path issuerDir = tempDir.resolve("issuer-mismatch");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(issuerDir, issuerDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey, intermediateKeyRef, intermediateKey))) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            assertEquals(2, runtime.submittedSignCount());
            runtime.replaceManagedKey(rootKeyRef, replacementRootKey);
            assertThrows(PkiException.class,
                    () -> runtime.caService()
                            .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootCaId,
                                    new SubjectRef("CN=Intermediate"), "intermediate-ca",
                                    Optional.of(intermediateKeyRef), new SimpleAttributeSet())));
            assertEquals(4, runtime.submittedSignCount());
            assertEquals(1, runtime.store().listCas().size());
            assertTrue(runtime.store().listWorkflowStates().isEmpty());
            assertEquals("ISSUER_MANAGED_KEY_MISMATCH", runtime.auditSink().snapshot()
                    .get(runtime.auditSink().snapshot().size() - 1).details().get("code"));
        }

        Path additionalDir = tempDir.resolve("additional-issuer-mismatch");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(additionalDir, additionalDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey, intermediateKeyRef, intermediateKey))) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            PkiId intermediateCaId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootCaId,
                            new SubjectRef("CN=Intermediate"), "intermediate-ca", Optional.of(intermediateKeyRef),
                            new SimpleAttributeSet()));
            assertEquals(5, runtime.submittedSignCount());
            runtime.replaceManagedKey(rootKeyRef, replacementRootKey);
            assertThrows(PkiException.class,
                    () -> runtime.caService()
                            .issueIntermediateCertificate(new IntermediateCertIssueCommand(
                                    runtime.framework().formatId(), rootCaId, intermediateCaId, "intermediate-ca",
                                    Optional.empty(), new SimpleAttributeSet())));
            assertEquals(7, runtime.submittedSignCount());
            assertEquals(1, runtime.caService().getCa(intermediateCaId).issuerIds().size());
            assertTrue(runtime.store().listWorkflowStates().isEmpty());
        }

        byte[] rootCertificate;
        byte[] intermediateCertificate;
        byte[] leafCertificate;
        Path sourceDir = tempDir.resolve("import-source");
        try (PkiTestRuntime source = PkiTestRuntime.create(sourceDir, sourceDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey, intermediateKeyRef, intermediateKey))) {
            PkiId rootCaId = source.caService().createRoot(new CaCreateCommand(source.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            rootCertificate = source
                    .credentialBytes(source.caCredential(source.caService().getCa(rootCaId), 0)).clone();
            PkiId intermediateCaId = source.caService()
                    .createIntermediate(new IntermediateCreateCommand(source.framework().formatId(), rootCaId,
                            new SubjectRef("CN=Intermediate"), "intermediate-ca", Optional.of(intermediateKeyRef),
                            new SimpleAttributeSet()));
            intermediateCertificate = source
                    .credentialBytes(source.caCredential(source.caService().getCa(intermediateCaId), 0)).clone();
            ParsedCertificationRequest leaf = parse(source, makeCsr(subjectKey, subjectKey, "CN=Leaf"));
            leafCertificate = source.credentialBytes(source.issuanceService()
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, leaf, "default", Optional.empty()))
                    .credential()).clone();
        }
        Path importDir = tempDir.resolve("import-mismatch");
        try (PkiTestRuntime target = PkiTestRuntime.create(importDir, importDir.resolve("bus.log"),
                Map.of(rootKeyRef, replacementRootKey))) {
            CaImportCommand command = new CaImportCommand(target.framework().formatId(), new SubjectRef("CN=Root"),
                    "root-ca", rootKeyRef, target.stageCredential(rootCertificate), new SimpleAttributeSet());
            assertThrows(PkiException.class, () -> target.caService().importRoot(command));
            assertTrue(target.store().listCas().isEmpty());
            assertTrue(target.store().listWorkflowStates().isEmpty());
            assertEquals("ROOT_MANAGED_KEY_MISMATCH",
                    target.auditSink().snapshot().get(target.auditSink().snapshot().size() - 1).details().get("code"));
        }

        Path mutationDir = tempDir.resolve("import-mutation");
        byte[] callerOwnedCertificate = rootCertificate.clone();
        byte[] expectedImportedCertificate = rootCertificate.clone();
        try (PkiTestRuntime target = PkiTestRuntime.create(mutationDir, mutationDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            target.onPublicKeyResolve(() -> callerOwnedCertificate[callerOwnedCertificate.length - 1] ^= 0x01);
            PkiId importedCaId = target.caService()
                    .importRoot(new CaImportCommand(target.framework().formatId(), new SubjectRef("CN=Root"), "root-ca",
                            rootKeyRef, target.stageCredential(callerOwnedCertificate),
                            new SimpleAttributeSet()));
            assertTrue(target.caCredential(target.caService().getCa(importedCaId), 0)
                    .profileBinding() instanceof CaProfileBinding);
            assertArrayEquals(expectedImportedCertificate,
                    target.credentialBytes(target.caCredential(target.caService().getCa(importedCaId), 0)));
        }

        assertInvalidRootImport(tempDir.resolve("import-leaf"), rootKeyRef, rootKey, leafCertificate, "CN=Leaf");
        assertInvalidRootImport(tempDir.resolve("import-non-self"), intermediateKeyRef, intermediateKey,
                intermediateCertificate, "CN=Intermediate");
        assertInvalidRootImport(tempDir.resolve("import-subject"), rootKeyRef, rootKey, rootCertificate, "CN=Wrong");
        byte[] invalidSelfSignature = rootCertificate.clone();
        invalidSelfSignature[invalidSelfSignature.length - 1] ^= 0x01;
        assertInvalidRootImport(tempDir.resolve("import-signature"), rootKeyRef, rootKey, invalidSelfSignature,
                "CN=Root");

        Path signingFailureDir = tempDir.resolve("signing-failure");
        try (PkiTestRuntime signingFailure = PkiTestRuntime.create(signingFailureDir,
                signingFailureDir.resolve("bus.log"), Map.of())) {
            assertThrows(PkiException.class,
                    () -> signingFailure.caService()
                            .createRoot(new CaCreateCommand(signingFailure.framework().formatId(),
                                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef),
                                    new SimpleAttributeSet())));
            assertTrue(signingFailure.store().listCas().isEmpty());
            assertTrue(signingFailure.store().listWorkflowStates().isEmpty());
            assertTrue(signingFailure.store().listSignRecords().isEmpty());
            try (zeroecho.pki.api.publication.PublicationCursor cursor =
                    signingFailure.store().openPublicationRecords()) {
                assertTrue(cursor.next(zeroecho.core.io.CancellationSignal.NONE).isEmpty());
            }
            assertFalse(signingFailure.hasRunningSignatureOperations());
            assertEquals(0, signingFailure.submittedSignCount());
            assertEquals("MANAGED_KEY_UNAVAILABLE", signingFailure.auditSink().snapshot()
                    .get(signingFailure.auditSink().snapshot().size() - 1).details().get("code"));
        }

        System.out.println("caIssuerImportAndWorkflowFailuresLeaveNoDurableSideEffects...ok");
    }

    private static void assertInvalidRootImport(Path rootDir, KeyRef keyRef, KeyPair keyPair, byte[] certificate,
            String subject) throws Exception {
        try (PkiTestRuntime runtime = PkiTestRuntime.create(rootDir, rootDir.resolve("bus.log"),
                Map.of(keyRef, keyPair))) {
            CaImportCommand command = new CaImportCommand(runtime.framework().formatId(), new SubjectRef(subject),
                    "root-ca", keyRef, runtime.stageCredential(certificate), new SimpleAttributeSet());
            assertThrows(PkiException.class, () -> runtime.caService().importRoot(command));
            assertTrue(runtime.store().listCas().isEmpty());
            assertEquals(0, runtime.submittedSignCount());
            assertEquals("ROOT_CREDENTIAL_INVALID", runtime.auditSink().snapshot()
                    .get(runtime.auditSink().snapshot().size() - 1).details().get("code"));
        }
    }

    @Test
    void endEntityPostconditionsAndAuditFailureRejectBeforePersistence(@TempDir Path tempDir) throws Exception {
        System.out.println("endEntityPostconditionsAndAuditFailureRejectBeforePersistence");

        KeyPair rootKey = generateRsa();
        KeyPair subjectKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        Path runtimeDir = tempDir.resolve("runtime");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(runtimeDir, runtimeDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            ParsedCertificationRequest subject = parse(runtime, makeCsr(subjectKey, subjectKey, "CN=Subject"));
            ParsedCertificationRequest substitute = parse(runtime, makeCsr(subjectKey, subjectKey, "CN=Substitute"));
            AtomicReference<CredentialBundle> substitutedBundle = new AtomicReference<>();
            CredentialIssuerBackend delegateBackend = runtime.issuerBackend();
            CredentialIssuerBackend throwingBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    throw new IllegalStateException("DO_NOT_LOG_SIGNATURE_SENTINEL");
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    throw new IllegalStateException("DO_NOT_LOG_SIGNATURE_SENTINEL");
                }
            };
            DefaultIssuanceService throwingBackendService = new DefaultIssuanceService(runtime.store(),
                    runtime.framework(), throwingBackend, runtime.auditSink(), runtime.statusResolver(),
                    runtime.profileService(), Clock.systemUTC(), runtime.revocationService());
            PkiException backendRejection = assertThrows(PkiException.class, () -> throwingBackendService
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, subject, "default", Optional.empty())));
            assertThrowableRedacted(backendRejection, "DO_NOT_LOG_SIGNATURE_SENTINEL");

            CredentialIssuerBackend maliciousBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    CredentialBundle bundle = delegateBackend.issueEndEntity(candidate, issuerCertificate, issuerKeyRef,
                            serial);
                    Credential raw = bundle.credential();
                    Credential forgedMetadata = new Credential(raw.credentialId(), raw.formatId(), raw.issuerRef(),
                            substitute.subjectRef(), raw.validity(), raw.serialOrUniqueId(), raw.publicKeyId(),
                            raw.profileBinding(), raw.status(), raw.content(), raw.attributes());
                    bundle = new CredentialBundle(forgedMetadata, bundle.supportingObjects());
                    substitutedBundle.set(bundle);
                    return bundle;
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    return delegateBackend.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                }
            };
            DefaultIssuanceService service = new DefaultIssuanceService(runtime.store(), runtime.framework(),
                    maliciousBackend, runtime.auditSink(), runtime.statusResolver(), runtime.profileService(),
                    Clock.systemUTC(), runtime.revocationService());
            assertThrows(PkiException.class, () -> service
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, subject, "default", Optional.empty())));
            Credential substitutedCredential = substitutedBundle.get().credential();
            assertTrue(runtime.store().getCredential(substitutedCredential.credentialId()).isEmpty());
            assertEquals("BACKEND_CREDENTIAL_MISMATCH", runtime.auditSink().snapshot()
                    .get(runtime.auditSink().snapshot().size() - 1).details().get("code"));

            AtomicReference<Credential> wrongBindingCredential = new AtomicReference<>();
            CredentialIssuerBackend wrongEndEntityBindingBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    CredentialBundle rawBundle = delegateBackend.issueEndEntity(candidate, issuerCertificate,
                            issuerKeyRef, serial);
                    Credential raw = rawBundle.credential();
                    Credential wrongBinding = copyWithBinding(raw, new CaProfileBinding(candidate.profileReference()));
                    wrongBindingCredential.set(wrongBinding);
                    return new CredentialBundle(wrongBinding, rawBundle.supportingObjects());
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    return delegateBackend.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                }
            };
            DefaultIssuanceService wrongBindingService = new DefaultIssuanceService(runtime.store(),
                    runtime.framework(), wrongEndEntityBindingBackend, runtime.auditSink(), runtime.statusResolver(),
                    runtime.profileService(), Clock.systemUTC(), runtime.revocationService());
            PkiException wrongBinding = assertThrows(PkiException.class, () -> wrongBindingService
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, subject, "default", Optional.empty())));
            assertTrue(wrongBinding.getMessage().contains("CREDENTIAL_PROFILE_BINDING_MISMATCH"));
            assertTrue(runtime.store().getCredential(wrongBindingCredential.get().credentialId()).isEmpty());

            CredentialIssuerBackend invalidSignatureBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    CredentialBundle rawBundle = delegateBackend.issueEndEntity(candidate, issuerCertificate,
                            issuerKeyRef, serial);
                    Credential raw = rawBundle.credential();
                    byte[] invalid = credentialBytes(runtime, raw).clone();
                    invalid[invalid.length - 1] ^= 0x01;
                    Credential invalidCredential = new Credential(raw.credentialId(), raw.formatId(), raw.issuerRef(),
                            raw.subjectRef(), raw.validity(), raw.serialOrUniqueId(), raw.publicKeyId(),
                            raw.profileBinding(), raw.status(), stageCredential(runtime, invalid),
                            raw.attributes());
                    return new CredentialBundle(invalidCredential, rawBundle.supportingObjects());
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    return delegateBackend.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                }
            };
            DefaultIssuanceService invalidSignatureService = new DefaultIssuanceService(runtime.store(),
                    runtime.framework(), invalidSignatureBackend, runtime.auditSink(), runtime.statusResolver(),
                    runtime.profileService(), Clock.systemUTC(), runtime.revocationService());
            assertThrows(PkiException.class, () -> invalidSignatureService
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, subject, "default", Optional.empty())));

            AtomicReference<CredentialBundle> rawBundle = new AtomicReference<>();
            CredentialIssuerBackend mutableBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    CredentialBundle raw = delegateBackend.issueEndEntity(candidate, issuerCertificate, issuerKeyRef,
                            serial);
                    rawBundle.set(raw);
                    return raw;
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    return delegateBackend.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                }
            };
            DefaultIssuanceService snapshotService = new DefaultIssuanceService(runtime.store(), runtime.framework(),
                    mutableBackend, runtime.auditSink(), runtime.statusResolver(), runtime.profileService(),
                    Clock.systemUTC(), runtime.revocationService());
            CredentialBundle returned = snapshotService
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, subject, "default", Optional.empty()));
            byte[] expectedLeaf = runtime.credentialBytes(returned.credential()).clone();
            assertEquals(rawBundle.get().credential().content(), returned.credential().content());
            assertEquals(rawBundle.get().supportingObjects(), returned.supportingObjects());
            assertArrayEquals(expectedLeaf, runtime.credentialBytes(returned.credential()));
            assertArrayEquals(expectedLeaf, runtime.credentialBytes(
                    runtime.store().getCredential(returned.credential().credentialId()).orElseThrow()));

            CaRecord root = runtime.caService().getCa(rootCaId);
            Credential original = runtime.caCredential(root, 0);
            Credential revoked = new Credential(new PkiId(original.credentialId().value() + ":revoked"),
                    original.formatId(), original.issuerRef(),
                    original.subjectRef(), original.validity(), original.serialOrUniqueId(), original.publicKeyId(),
                    original.profileBinding(), CredentialStatus.REVOKED, original.content(), original.attributes());
            runtime.store().putCredential(revoked);
            runtime.selectIssuerCredential(root, revoked, true);
            int before = runtime.submittedSignCount();
            assertThrows(PkiException.class, () -> runtime.issuanceService()
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, subject, "default", Optional.empty())));
            assertEquals(before, runtime.submittedSignCount());

            Validity expiredValidity = new Validity(Instant.now().minus(Duration.ofDays(2)),
                    Instant.now().minus(Duration.ofDays(1)));
            Credential expired = new Credential(new PkiId(original.credentialId().value() + ":expired"),
                    original.formatId(), original.issuerRef(), original.subjectRef(), expiredValidity,
                    original.serialOrUniqueId(), original.publicKeyId(), original.profileBinding(),
                    CredentialStatus.ISSUED, original.content(), original.attributes());
            runtime.store().putCredential(expired);
            runtime.selectIssuerCredential(root, expired, true);
            assertThrows(PkiException.class, () -> runtime.issuanceService()
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, subject, "default", Optional.empty())));
            assertEquals(before, runtime.submittedSignCount());

            runtime.caService().selectIssuancePath(root.caId(), root.currentIssuanceIssuerId(),
                    root.issuanceChainPathId(), "restore explicit test selection");
            ParsedCertificationRequest missing = withAttributes(subject, new SimpleAttributeSet());
            AttributeSet hostileAttributes = new AttributeSet() {
                @Override
                public Set<zeroecho.pki.api.attr.AttributeId> ids() {
                    return Set.of();
                }

                @Override
                public Optional<AttributeValue> get(zeroecho.pki.api.attr.AttributeId id) {
                    throw new IllegalStateException("DO_NOT_LOG_CSR_SENTINEL");
                }

                @Override
                public List<AttributeValue> getAll(zeroecho.pki.api.attr.AttributeId id) {
                    return List.of();
                }
            };
            PkiException parserRejection = assertThrows(PkiException.class,
                    () -> runtime.issuanceService().issueEndEntity(new IssueEndEntityCommand(rootCaId,
                            withAttributes(subject, hostileAttributes), "default", Optional.empty())));
            assertThrowableRedacted(parserRejection, "DO_NOT_LOG_CSR_SENTINEL");

            DefaultIssuanceService failingAudit = new DefaultIssuanceService(runtime.store(), runtime.framework(),
                    runtime.issuerBackend(), event -> {
                        throw new IllegalStateException("DO_NOT_LOG_PAYLOAD_SENTINEL");
                    }, runtime.statusResolver(), runtime.profileService(), Clock.systemUTC(), runtime.revocationService());
            PkiException rejection = assertThrows(PkiException.class, () -> failingAudit
                    .issueEndEntity(new IssueEndEntityCommand(rootCaId, missing, "default", Optional.empty())));
            assertTrue(rejection.getMessage().contains("CSR_MISSING"));
            assertThrowableRedacted(rejection, "DO_NOT_LOG_PAYLOAD_SENTINEL");
        }

        System.out.println("endEntityPostconditionsAndAuditFailureRejectBeforePersistence...ok");
    }

    @Test
    void intermediateBackendOutputIsValidatedAndSnapshotted(@TempDir Path tempDir) throws Exception {
        KeyPair rootKey = generateRsa();
        KeyPair intermediateKey = generateRsa();
        KeyPair wrongKey = generateRsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:test:root");
        KeyRef intermediateKeyRef = new KeyRef("kref:v1:keyring:test:intermediate");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey, intermediateKeyRef, intermediateKey))) {
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootKeyRef), new SimpleAttributeSet()));
            assertTrue(runtime.caCredential(runtime.caService().getCa(rootCaId), 0)
                    .profileBinding() instanceof CaProfileBinding);
            CredentialIssuerBackend delegate = runtime.issuerBackend();
            for (BindingVariantMutation mutation : BindingVariantMutation.values()) {
                AtomicReference<Credential> produced = new AtomicReference<>();
                CaService wrongBindingService = runtime.caService(bindingMutationBackend(delegate, mutation, produced));
                PkiException rejected = assertThrows(PkiException.class,
                        () -> wrongBindingService
                                .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(),
                                        rootCaId, new SubjectRef("CN=BindingRejectedIntermediate"), "intermediate-ca",
                                        Optional.of(intermediateKeyRef), new SimpleAttributeSet())),
                        mutation.name());
                assertTrue(rejected.getMessage().contains("CREDENTIAL_PROFILE_BINDING_MISMATCH"), mutation.name());
                assertEquals(1, runtime.store().listCas().size(), mutation.name());
                if (produced.get() != null) {
                    assertTrue(runtime.store().getCredential(produced.get().credentialId()).isEmpty(), mutation.name());
                }
            }
            CredentialIssuerBackend wrongKeyBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    Credential raw = delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                    return rebuildIntermediateIdentity(runtime, raw, rootKey, Optional.of(wrongKey.getPublic()),
                            Optional.empty());
                }
            };
            CaService wrongKeyService = runtime.caService(wrongKeyBackend);
            assertThrows(PkiException.class,
                    () -> wrongKeyService.createIntermediate(new IntermediateCreateCommand(
                            runtime.framework().formatId(), rootCaId, new SubjectRef("CN=Intermediate"),
                            "intermediate-ca", Optional.of(intermediateKeyRef), new SimpleAttributeSet())));
            assertEquals(1, runtime.store().listCas().size());

            PkiId intermediateCaId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootCaId,
                            new SubjectRef("CN=Intermediate"), "intermediate-ca", Optional.of(intermediateKeyRef),
                            new SimpleAttributeSet()));
            for (BindingVariantMutation mutation : BindingVariantMutation.values()) {
                AtomicReference<Credential> produced = new AtomicReference<>();
                CaService wrongBindingService = runtime.caService(bindingMutationBackend(delegate, mutation, produced));
                PkiException rejected = assertThrows(PkiException.class,
                        () -> wrongBindingService.issueIntermediateCertificate(new IntermediateCertIssueCommand(
                                runtime.framework().formatId(), rootCaId, intermediateCaId, "intermediate-ca",
                                Optional.empty(), new SimpleAttributeSet())),
                        mutation.name());
                assertTrue(rejected.getMessage().contains("CREDENTIAL_PROFILE_BINDING_MISMATCH"), mutation.name());
                assertEquals(1, runtime.caService().getCa(intermediateCaId).issuerIds().size(), mutation.name());
                if (produced.get() != null) {
                    assertTrue(runtime.store().getCredential(produced.get().credentialId()).isEmpty(), mutation.name());
                }
            }
            CredentialIssuerBackend wrongSubjectBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    Credential raw = delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                    return rebuildIntermediateIdentity(runtime, raw, rootKey, Optional.empty(),
                            Optional.of("CN=WrongIntermediate"));
                }
            };
            CaService wrongSubjectService = runtime.caService(wrongSubjectBackend);
            assertThrows(PkiException.class,
                    () -> wrongSubjectService.issueIntermediateCertificate(
                            new IntermediateCertIssueCommand(runtime.framework().formatId(), rootCaId, intermediateCaId,
                                    "intermediate-ca", Optional.empty(), new SimpleAttributeSet())));
            assertEquals(1, runtime.caService().getCa(intermediateCaId).issuerIds().size());

            CredentialIssuerBackend invalidSignatureBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    Credential raw = delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                    byte[] invalid = credentialBytes(runtime, raw).clone();
                    invalid[invalid.length - 1] ^= 0x01;
                    return new Credential(raw.credentialId(), raw.formatId(), raw.issuerRef(), raw.subjectRef(),
                            raw.validity(), raw.serialOrUniqueId(), raw.publicKeyId(), raw.profileBinding(),
                            raw.status(), stageCredential(runtime, invalid), raw.attributes());
                }
            };
            CaService invalidSignatureService = runtime.caService(invalidSignatureBackend);
            assertThrows(PkiException.class,
                    () -> invalidSignatureService.issueIntermediateCertificate(
                            new IntermediateCertIssueCommand(runtime.framework().formatId(), rootCaId, intermediateCaId,
                                    "intermediate-ca", Optional.empty(), new SimpleAttributeSet())));
            assertEquals(1, runtime.caService().getCa(intermediateCaId).issuerIds().size());

            for (IntermediateExtensionVariant variant : IntermediateExtensionVariant.values()) {
                CaService maliciousExtensionService = runtime
                        .caService(extensionVariantBackend(runtime, delegate, rootKey, variant));
                assertThrows(PkiException.class,
                        () -> maliciousExtensionService.issueIntermediateCertificate(new IntermediateCertIssueCommand(
                                runtime.framework().formatId(), rootCaId, intermediateCaId, "intermediate-ca",
                                Optional.empty(), new SimpleAttributeSet())),
                        variant.name());
                assertEquals(1, runtime.caService().getCa(intermediateCaId).issuerIds().size(), variant.name());
            }

            AtomicReference<Credential> rawCredential = new AtomicReference<>();
            CredentialIssuerBackend mutableBackend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                    return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                        zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                    Credential raw = delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                    rawCredential.set(raw);
                    return raw;
                }
            };
            CaService snapshotService = runtime.caService(mutableBackend);
            Credential returned = snapshotService
                    .issueIntermediateCertificate(new IntermediateCertIssueCommand(runtime.framework().formatId(),
                            rootCaId, intermediateCaId, "intermediate-ca", Optional.empty(), new SimpleAttributeSet()));
            byte[] expected = runtime.credentialBytes(returned).clone();
            assertEquals(rawCredential.get().content(), returned.content());
            assertArrayEquals(expected, runtime.credentialBytes(returned));
            assertArrayEquals(expected,
                    runtime.credentialBytes(runtime.store().getCredential(returned.credentialId()).orElseThrow()));
        }
    }

    private enum IntermediateExtensionVariant {
        ABSENT_BASIC_CONSTRAINTS, NONCRITICAL_BASIC_CONSTRAINTS, UNLIMITED_BASIC_CONSTRAINTS, ABSENT_KEY_USAGE,
        NONCRITICAL_KEY_USAGE, INCOMPATIBLE_KEY_USAGE
    }

    private enum BindingVariantMutation {
        END_ENTITY_SAME_ID, END_ENTITY_OTHER_ID, CA_OTHER_ID, NULL_CREDENTIAL
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

    private static CredentialIssuerBackend extensionVariantBackend(PkiTestRuntime runtime,
            CredentialIssuerBackend delegate, KeyPair issuerKey, IntermediateExtensionVariant variant) {
        return new CredentialIssuerBackend() {
            @Override
            public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                    zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
            }

            @Override
            public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                    zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                Credential credential = delegate.issueIntermediateCertificate(issuance, issuerCertificate,
                        issuerKeyRef);
                return rebuildIntermediateExtensions(runtime, credential, issuerKey, variant);
            }
        };
    }

    private static CredentialIssuerBackend bindingMutationBackend(CredentialIssuerBackend delegate,
            BindingVariantMutation mutation, AtomicReference<Credential> produced) {
        return new CredentialIssuerBackend() {
            @Override
            public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                    zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
            }

            @Override
            public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                    zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                Credential raw = delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
                produced.set(raw);
                if (mutation == BindingVariantMutation.NULL_CREDENTIAL) {
                    return null;
                }
                return copyWithBinding(raw, bindingFor(mutation, issuance.profileReference()));
            }
        };
    }

    private static CredentialProfileBinding bindingFor(BindingVariantMutation mutation,
            CertificateProfileRef profileReference) {
        return switch (mutation) {
            case END_ENTITY_SAME_ID ->
                new EndEntityProfileBinding(new CertificateProfileRef(profileReference.profileId(), 1,
                        new byte[CertificateProfileRef.HASH_BYTES]));
            case END_ENTITY_OTHER_ID -> new EndEntityProfileBinding(
                    new CertificateProfileRef("other", 1, new byte[CertificateProfileRef.HASH_BYTES]));
            case CA_OTHER_ID ->
                new CaProfileBinding(new CertificateProfileRef("other", 1, new byte[CertificateProfileRef.HASH_BYTES]));
            case NULL_CREDENTIAL -> throw new IllegalStateException("null credential has no binding");
        };
    }

    private static Credential copyWithBinding(Credential credential, CredentialProfileBinding binding) {
        return new Credential(credential.credentialId(), credential.formatId(), credential.issuerRef(),
                credential.subjectRef(), credential.validity(), credential.serialOrUniqueId(), credential.publicKeyId(),
                binding, credential.status(), credential.content(), credential.attributes());
    }

    private static Credential rebuildIntermediateIdentity(PkiTestRuntime runtime, Credential credential,
            KeyPair issuerKey, Optional<PublicKey> subjectPublicKey, Optional<String> subjectName) {
        try {
            X509CertificateHolder original = new X509CertificateHolder(runtime.credentialBytes(credential));
            X500Name subject = subjectName.map(X500Name::new).orElse(original.getSubject());
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo publicKeyInfo = subjectPublicKey
                    .map(key -> org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(key.getEncoded()))
                    .orElse(original.getSubjectPublicKeyInfo());
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(original.getIssuer(),
                    original.getSerialNumber(), original.getNotBefore(), original.getNotAfter(), subject,
                    publicKeyInfo);
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate());
            byte[] encoded = builder.build(signer).getEncoded();
            return new Credential(new PkiId("x509:" + sha256Hex(encoded)), credential.formatId(),
                    credential.issuerRef(), new SubjectRef(subject.toString()), credential.validity(),
                    credential.serialOrUniqueId(), new PkiId("spki:" + sha256Hex(publicKeyInfo.getEncoded())),
                    credential.profileBinding(), credential.status(), runtime.stageCredential(encoded),
                    credential.attributes());
        } catch (Exception ex) {
            throw new PkiException("Failed to create adversarial intermediate identity", ex);
        }
    }

    private static Credential rebuildIntermediateExtensions(PkiTestRuntime runtime, Credential credential,
            KeyPair issuerKey, IntermediateExtensionVariant variant) {
        try {
            X509CertificateHolder original = new X509CertificateHolder(runtime.credentialBytes(credential));
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(original.getIssuer(),
                    original.getSerialNumber(), original.getNotBefore(), original.getNotAfter(), original.getSubject(),
                    original.getSubjectPublicKeyInfo());
            if (variant != IntermediateExtensionVariant.ABSENT_BASIC_CONSTRAINTS) {
                boolean critical = variant != IntermediateExtensionVariant.NONCRITICAL_BASIC_CONSTRAINTS;
                BasicConstraints constraints = variant == IntermediateExtensionVariant.UNLIMITED_BASIC_CONSTRAINTS
                        ? new BasicConstraints(true)
                        : new BasicConstraints(0);
                builder.addExtension(Extension.basicConstraints, critical, constraints);
            }
            if (variant != IntermediateExtensionVariant.ABSENT_KEY_USAGE) {
                boolean critical = variant != IntermediateExtensionVariant.NONCRITICAL_KEY_USAGE;
                int usages = KeyUsage.keyCertSign | KeyUsage.cRLSign;
                if (variant == IntermediateExtensionVariant.INCOMPATIBLE_KEY_USAGE) {
                    usages |= KeyUsage.digitalSignature;
                }
                builder.addExtension(Extension.keyUsage, critical, new KeyUsage(usages));
            }
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate());
            byte[] encoded = builder.build(signer).getEncoded();
            return new Credential(new PkiId("x509:" + sha256Hex(encoded)), credential.formatId(),
                    credential.issuerRef(), credential.subjectRef(), credential.validity(),
                    credential.serialOrUniqueId(), credential.publicKeyId(), credential.profileBinding(),
                    credential.status(), runtime.stageCredential(encoded), credential.attributes());
        } catch (Exception ex) {
            throw new PkiException("Failed to create adversarial intermediate certificate", ex);
        }
    }

    private static byte[] credentialBytes(PkiTestRuntime runtime, Credential credential) {
        try {
            return runtime.credentialBytes(credential);
        } catch (java.io.IOException exception) {
            throw new PkiException("Failed to read adversarial credential fixture", exception);
        }
    }

    private static zeroecho.pki.api.content.DurableContentReference stageCredential(PkiTestRuntime runtime,
            byte[] encoded) {
        try {
            return runtime.stageCredential(encoded);
        } catch (java.io.IOException exception) {
            throw new PkiException("Failed to stage adversarial credential fixture", exception);
        }
    }

    private static ParsedCertificationRequest parse(PkiTestRuntime runtime, PKCS10CertificationRequest csr)
            throws Exception {
        return runtime.certificationRequestService().parse(new CertificationRequest(runtime.framework().formatId(),
                new EncodedObject(Encoding.DER, csr.getEncoded())));
    }

    private static PKCS10CertificationRequest makeCsr(KeyPair publicKeyPair, KeyPair signingKeyPair, String dn)
            throws Exception {
        return makeCsr(publicKeyPair, signingKeyPair, dn, "SHA256withRSA");
    }

    private static PKCS10CertificationRequest makeCsr(KeyPair publicKeyPair, KeyPair signingKeyPair, String dn,
            String algorithm) throws Exception {
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(dn),
                publicKeyPair.getPublic());
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(algorithm);
        if ("SHA256withRSAandMGF1".equals(algorithm)) {
            signerBuilder.setProvider(new BouncyCastleProvider());
        }
        ContentSigner signer = signerBuilder.build(signingKeyPair.getPrivate());
        return builder.build(signer);
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static byte[] csrDer(ParsedCertificationRequest request) {
        return ((AttributeValue.BytesValue) request.attributes().get(BcX509Attributes.CSR_DER).orElseThrow()).value();
    }

    private static BcX509ProofOfPossessionVerifier standaloneBcVerifier() {
        zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor executor =
                new zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor();
        zeroecho.pki.impl.framework.x509.X509AlgorithmResolver.Policy policy = (suite, direction) -> true;
        zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot authority =
                zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot.compose(List.of(), List.of(executor),
                        List.of(zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot.bindExecutor(
                                zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor.IMPLEMENTATION_ID,
                                zeroecho.core.spi.AlgorithmExecutionCapability.Direction.VERIFY, executor)),
                        policy);
        return new BcX509ProofOfPossessionVerifier(authority, executor);
    }

    private static ParsedCertificationRequest withCsr(ParsedCertificationRequest source, byte[] csrDer) {
        AttributeSet attributes = SimpleAttributeSet.builder()
                .put(BcX509Attributes.CSR_DER, new AttributeValue.BytesValue(csrDer)).build();
        return withAttributes(source, attributes);
    }

    private static ParsedCertificationRequest withAttributes(ParsedCertificationRequest source,
            AttributeSet attributes) {
        return new ParsedCertificationRequest(source.requestId(), source.formatId(), source.subjectRef(),
                source.publicKeyInfo(), source.requestedValidity(), source.requestedProfileId(), attributes);
    }

    private static void assertRejected(PkiTestRuntime runtime, PkiId issuerCaId, ParsedCertificationRequest request,
            String code) {
        int before = runtime.auditSink().snapshot().size();
        assertThrows(PkiException.class, () -> issue(runtime, issuerCaId, request));
        assertEquals(before + 1, runtime.auditSink().snapshot().size());
        assertEquals(code, runtime.auditSink().snapshot().get(before).details().get("code"));
    }

    private static void issue(PkiTestRuntime runtime, PkiId issuerCaId, ParsedCertificationRequest request) {
        runtime.issuanceService()
                .issueEndEntity(new IssueEndEntityCommand(issuerCaId, request, "default", Optional.empty()));
    }

    private static AttributeSet hostileIntermediateAttributes(PublicKey wrongPublicKey) {
        return SimpleAttributeSet.builder()
                .put(BcX509Attributes.ISSUER_CERT_DER, new AttributeValue.BytesValue(new byte[] { 0x01 }))
                .put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue("attacker-key"))
                .put(BcX509Attributes.SUBJECT_SPKI_DER, new AttributeValue.BytesValue(wrongPublicKey.getEncoded()))
                .put(BcX509Attributes.SUBJECT_DN, new AttributeValue.StringValue("CN=Attacker")).build();
    }

    private static void assertThrowableRedacted(Throwable failure, String sentinel) {
        Throwable current = failure;
        while (current != null) {
            assertFalse(String.valueOf(current.getMessage()).contains(sentinel));
            for (Throwable suppressed : current.getSuppressed()) {
                assertThrowableRedacted(suppressed, sentinel);
            }
            current = current.getCause();
        }
    }
}
