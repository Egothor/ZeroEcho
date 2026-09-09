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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.impl.core.DefaultIssuanceService;
import zeroecho.pki.impl.core.ValidatedCaCertificateRequest;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.testkit.H7ProfileDocuments;
import zeroecho.pki.testkit.PkiTestRuntime;

/**
 * Real signed-CSR rejection evidence for the closed H7 SAN and extension
 * grammar.
 */
final class H7EndEntityCsrRejectionE2eTest {
    private static final int DNS_AND_IP_REJECTION_CASE_COUNT = 11;
    private static final int URI_AND_RFC822_REJECTION_CASE_COUNT = 17;
    private static final int CSR_STRUCTURE_REJECTION_CASE_COUNT = 10;
    private static final int CSR_REJECTION_CASE_COUNT = 38;
    private static final String REDACTION_SENTINEL = "DO-NOT-LOG-H7-CSR-SENTINEL";

    @Test
    void signedDnsAndIpInvalidMatrixRejectsWithoutIssuanceSideEffects(@TempDir Path tempDir) throws Exception {
        try (RejectionFixture fixture = RejectionFixture.create(tempDir)) {
            List<SignedCsrCase> parserCases = List
                    .of(sanCase("dns-trailing-dot", dns(REDACTION_SENTINEL + ".example."), "SAN_MALFORMED"),
                            sanCase("dns-partial-wildcard", dns("www*.example.com"), "SAN_MALFORMED"),
                            sanCase("dns-multiple-wildcard", dns("*.*.example.com"), "SAN_MALFORMED"),
                            sanCase("dns-ip-literal", dns("192.0.2.1"), "SAN_MALFORMED"),
                            sanCase("dns-duplicate-lowercase", List.of(dns("Example.COM"), dns("example.com")),
                                    "SAN_DUPLICATE"),
                            sanCase("ip-invalid-length", ip(new byte[] { 1, 2, 3, 4, 5 }), "SAN_MALFORMED"),
                            sanCase("ip-duplicate",
                                    List.of(ip(new byte[] { (byte) 192, 0, 2, 1 }),
                                            ip(new byte[] { (byte) 192, 0, 2, 1 })),
                                    "SAN_DUPLICATE"),
                            sanCase("ip-address-invalid-length", ip(new byte[15]), "SAN_MALFORMED"));
            assertParserCases(fixture, parserCases);

            fixture.assertProfileRejected("dns-wildcard-disabled", "h7-dns",
                    signedSanCsr(fixture.leafKey(), new X500Name("CN=Leaf"), List.of(dns("*.example.com"))),
                    "SAN_WILDCARD_FORBIDDEN");
            fixture.assertProfileRejected(
                    "ipv6-forbidden-by-ipv4-profile", "h7-ipv4", signedSanCsr(fixture.leafKey(),
                            new X500Name("CN=Leaf"), List.of(ip(hex("20010db8000000000000000000000001")))),
                    "SAN_IP_FAMILY_FORBIDDEN");
            fixture.assertProfileRejected(
                    "ipv4-forbidden-by-ipv6-profile", "h7-ipv6", signedSanCsr(fixture.leafKey(),
                            new X500Name("CN=Leaf"), List.of(ip(new byte[] { (byte) 192, 0, 2, 2 }))),
                    "SAN_IP_FAMILY_FORBIDDEN");
            assertEquals(CSR_REJECTION_CASE_COUNT, DNS_AND_IP_REJECTION_CASE_COUNT + URI_AND_RFC822_REJECTION_CASE_COUNT
                    + CSR_STRUCTURE_REJECTION_CASE_COUNT);
            assertEquals(DNS_AND_IP_REJECTION_CASE_COUNT, fixture.assertedCaseCount());
        }
    }

    @Test
    void signedUriAndRfc822InvalidMatrixRejectsWithoutIssuanceSideEffects(@TempDir Path tempDir) throws Exception {
        try (RejectionFixture fixture = RejectionFixture.create(tempDir)) {
            String oversizedUri = "https://oversize.example.com/" + "a".repeat(2050);
            List<SignedCsrCase> parserCases = List.of(sanCase("uri-relative", uri("/relative/path"), "SAN_MALFORMED"),
                    sanCase("uri-missing-host", uri("https:///missing-host"), "SAN_MALFORMED"),
                    sanCase("uri-opaque", uri("mailto:user@example.com"), "SAN_MALFORMED"),
                    sanCase("uri-userinfo", uri("https://user@example.com/path"), "SAN_MALFORMED"),
                    sanCase("uri-fragment", uri("https://example.com/path#fragment"), "SAN_MALFORMED"),
                    sanCase("uri-duplicate", List.of(uri("HTTPS://Example.COM/path"), uri("https://example.com/path")),
                            "SAN_DUPLICATE"),
                    sanCase("uri-oversize", uri(oversizedUri), "SAN_MALFORMED"),
                    sanCase("rfc822-display-name", rfc822("Display <user@example.com>"), "SAN_MALFORMED"),
                    sanCase("rfc822-comments", rfc822("user(comment)@example.com"), "SAN_MALFORMED"),
                    sanCase("rfc822-whitespace", rfc822("user @example.com"), "SAN_MALFORMED"),
                    sanCase("rfc822-multiple-at", rfc822("user@@example.com"), "SAN_MALFORMED"),
                    sanCase("rfc822-empty-local", rfc822("@example.com"), "SAN_MALFORMED"),
                    sanCase("rfc822-empty-domain", rfc822("user@"), "SAN_MALFORMED"),
                    sanCase("rfc822-invalid-domain", rfc822("user@-example.com"), "SAN_MALFORMED"),
                    sanCase("rfc822-duplicate", List.of(rfc822("Local@Example.COM"), rfc822("Local@example.com")),
                            "SAN_DUPLICATE"));
            assertParserCases(fixture, parserCases);

            fixture.assertProfileRejected("uri-forbidden-scheme", "h7-uri",
                    signedSanCsr(fixture.leafKey(), new X500Name("CN=Leaf"), List.of(uri("http://example.com/path"))),
                    "SAN_URI_SCHEME_FORBIDDEN");
            PKCS10CertificationRequest subjectEmail = signedCsr(fixture.leafKey(),
                    new X500Name("CN=Leaf,E=user@example.com"), List.of());
            fixture.assertProfileRejected("subject-email-does-not-replace-rfc822-san", "h7-subject-email-rfc822",
                    subjectEmail, "SAN_COUNT_INVALID");
            assertEquals(URI_AND_RFC822_REJECTION_CASE_COUNT, fixture.assertedCaseCount());
        }
    }

    @Test
    void signedCsrExtensionStructureMatrixRejectsBeforeBackendAndPersistence(@TempDir Path tempDir) throws Exception {
        try (RejectionFixture fixture = RejectionFixture.create(tempDir)) {
            Extension san = sanExtension(false, List.of(dns("structure.example.com")));
            Extension keyUsage = new Extension(Extension.keyUsage, true,
                    new DEROctetString(new KeyUsage(KeyUsage.digitalSignature).getEncoded()));
            Extension basicConstraints = new Extension(Extension.basicConstraints, true,
                    new DEROctetString(new BasicConstraints(false).getEncoded()));
            Extension unknownCritical = new Extension(new ASN1ObjectIdentifier("1.2.3.4.10"), true,
                    new DEROctetString(DERNull.INSTANCE.getEncoded()));
            Extension unknownNoncritical = new Extension(new ASN1ObjectIdentifier("1.2.3.4.11"), false,
                    new DEROctetString(DERNull.INSTANCE.getEncoded()));
            Extension criticalSan = sanExtension(true, List.of(dns("critical-request.example.com")));
            Extension emptySan = new Extension(Extension.subjectAlternativeName, false,
                    new DEROctetString(new DERSequence().getEncoded()));
            Extension otherName = sanExtension(false,
                    List.of(new GeneralName(GeneralName.otherName, new DERUTF8String(REDACTION_SENTINEL))));
            Extension directoryName = sanExtension(false,
                    List.of(new GeneralName(GeneralName.directoryName, new X500Name("CN=Nested"))));
            DERSequence duplicateSan = new DERSequence(new ASN1Encodable[] { san, san });

            List<SignedCsrCase> cases = List.of(
                    extensionCase("san-plus-key-usage", new DERSequence(new ASN1Encodable[] { san, keyUsage }),
                            "EXTENSION_UNSUPPORTED"),
                    extensionCase("san-plus-basic-constraints",
                            new DERSequence(new ASN1Encodable[] { san, basicConstraints }), "EXTENSION_UNSUPPORTED"),
                    extensionCase("unknown-critical", new Extensions(unknownCritical), "EXTENSION_UNSUPPORTED"),
                    extensionCase("unknown-noncritical", new Extensions(unknownNoncritical), "EXTENSION_UNSUPPORTED"),
                    extensionCase("two-san-extensions", duplicateSan, "EXTENSION_REQUEST_MALFORMED"),
                    new SignedCsrCase("two-extension-request-attributes", new X500Name("CN=Leaf"),
                            List.of(new Extensions(san), new Extensions(san)), "CSR_ATTRIBUTE_UNSUPPORTED"),
                    extensionCase("empty-san", new Extensions(emptySan), "SAN_COUNT_INVALID"),
                    extensionCase("other-name", new Extensions(otherName), "SAN_MALFORMED"),
                    extensionCase("directory-name", new Extensions(directoryName), "SAN_TYPE_UNSUPPORTED"),
                    extensionCase("criticality-mismatch", new Extensions(criticalSan), "SAN_CRITICALITY_REQUESTED"));
            assertParserCases(fixture, cases);
            assertEquals(CSR_STRUCTURE_REJECTION_CASE_COUNT, fixture.assertedCaseCount());
        }
    }

    private static void assertParserCases(RejectionFixture fixture, List<SignedCsrCase> cases) throws Exception {
        for (SignedCsrCase testCase : cases) {
            PKCS10CertificationRequest csr = signedCsr(fixture.leafKey(), testCase.subject(),
                    testCase.extensionRequests());
            fixture.assertParserAndGateRejected(testCase.name(), csr, testCase.parserCode());
        }
    }

    private static SignedCsrCase sanCase(String name, GeneralName nameValue, String code) throws Exception {
        return sanCase(name, List.of(nameValue), code);
    }

    private static SignedCsrCase sanCase(String name, List<GeneralName> names, String code) throws Exception {
        return extensionCase(name, new Extensions(sanExtension(false, names)), code);
    }

    private static SignedCsrCase extensionCase(String name, ASN1Encodable extensionRequest, String code) {
        return new SignedCsrCase(name, new X500Name("CN=Leaf"), List.of(extensionRequest), code);
    }

    private static PKCS10CertificationRequest signedSanCsr(KeyPair keyPair, X500Name subject, List<GeneralName> names)
            throws Exception {
        return signedCsr(keyPair, subject, List.of(new Extensions(sanExtension(false, names))));
    }

    private static PKCS10CertificationRequest signedCsr(KeyPair keyPair, X500Name subject,
            List<? extends ASN1Encodable> extensionRequests) throws Exception {
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject,
                keyPair.getPublic());
        for (ASN1Encodable extensionRequest : extensionRequests) {
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionRequest);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return builder.build(signer);
    }

    private static Extension sanExtension(boolean critical, List<GeneralName> names) throws Exception {
        return new Extension(Extension.subjectAlternativeName, critical,
                new DEROctetString(new GeneralNames(names.toArray(GeneralName[]::new)).getEncoded()));
    }

    private static GeneralName dns(String value) {
        return new GeneralName(GeneralName.dNSName, value);
    }

    private static GeneralName ip(byte[] value) {
        return new GeneralName(GeneralName.iPAddress, new DEROctetString(value));
    }

    private static GeneralName uri(String value) {
        return new GeneralName(GeneralName.uniformResourceIdentifier, value);
    }

    private static GeneralName rfc822(String value) {
        return new GeneralName(GeneralName.rfc822Name, value);
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }

    private record SignedCsrCase(String name, X500Name subject, List<ASN1Encodable> extensionRequests,
            String parserCode) {
        private SignedCsrCase {
            extensionRequests = List.copyOf(extensionRequests);
        }
    }

    private static final class RejectionFixture implements AutoCloseable {
        private final PkiTestRuntime runtime;
        private final KeyPair leafKey;
        private final PkiId rootCaId;
        private final ParsedCertificationRequest validTemplate;
        private int assertedCases;

        private RejectionFixture(PkiTestRuntime runtime, KeyPair leafKey, PkiId rootCaId,
                ParsedCertificationRequest validTemplate) {
            this.runtime = runtime;
            this.leafKey = leafKey;
            this.rootCaId = rootCaId;
            this.validTemplate = validTemplate;
            this.assertedCases = 0;
        }

        private static RejectionFixture create(Path tempDir) throws Exception {
            KeyPair rootKey = rsa();
            KeyPair leafKey = rsa();
            KeyRef rootRef = new KeyRef("kref:v1:keyring:h7-csr-rejection:root");
            PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"),
                    Map.of(rootRef, rootKey));
            runtime.importAndActivate(H7ProfileDocuments.dnsProfile());
            runtime.importAndActivate(H7ProfileDocuments.ipv4Profile());
            runtime.importAndActivate(H7ProfileDocuments.ipv6Profile());
            runtime.importAndActivate(H7ProfileDocuments.uriProfile());
            runtime.importAndActivate(H7ProfileDocuments.subjectEmailAndRfc822Profile());
            PkiId rootCaId = runtime.caService()
                    .createRoot(new CaCreateCommand(runtime.framework().formatId(),
                            new SubjectRef("CN=H7 CSR Rejection Root"), "root-ca", Optional.of(rootRef),
                            new SimpleAttributeSet()));
            PKCS10CertificationRequest valid = signedSanCsr(leafKey, new X500Name("CN=Template"),
                    List.of(dns("template.example.com")));
            ParsedCertificationRequest template = parse(runtime, valid);
            return new RejectionFixture(runtime, leafKey, rootCaId, template);
        }

        private KeyPair leafKey() {
            return leafKey;
        }

        private int assertedCaseCount() {
            return assertedCases;
        }

        private void assertParserAndGateRejected(String name, PKCS10CertificationRequest csr, String parserCode)
                throws Exception {
            assertTrue(
                    csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo())),
                    name);
            int signsBefore = runtime.submittedSignCount();
            int auditBefore = runtime.auditSink().snapshot().size();
            PkiException parserRejection = assertThrows(PkiException.class, () -> parse(runtime, csr), name);
            assertTrue(parserRejection.getMessage().contains(parserCode), name);
            assertRedacted(parserRejection);
            assertEquals(signsBefore, runtime.submittedSignCount(), name);
            assertEquals(auditBefore, runtime.auditSink().snapshot().size(), name);

            ParsedCertificationRequest supplied = withCsr(validTemplate, csr.getEncoded());
            assertGateRejected(name, supplied, "default", "CSR_MALFORMED", signsBefore, auditBefore);
            assertedCases++;
        }

        private void assertProfileRejected(String name, String profileId, PKCS10CertificationRequest csr, String code)
                throws Exception {
            assertTrue(
                    csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo())),
                    name);
            ParsedCertificationRequest parsed = parse(runtime, csr);
            int signsBefore = runtime.submittedSignCount();
            int auditBefore = runtime.auditSink().snapshot().size();
            assertGateRejected(name, parsed, profileId, code, signsBefore, auditBefore);
            assertedCases++;
        }

        private void assertGateRejected(String name, ParsedCertificationRequest request, String profileId, String code,
                int signsBefore, int auditBefore) {
            AtomicInteger backendCalls = new AtomicInteger();
            AtomicInteger persistenceCalls = new AtomicInteger();
            CredentialIssuerBackend backend = countingBackend(runtime.issuerBackend(), backendCalls);
            PkiStore trackingStore = trackingStore(runtime.store(), persistenceCalls);
            DefaultIssuanceService service = new DefaultIssuanceService(trackingStore, runtime.framework(), backend,
                    runtime.auditSink(), runtime.statusResolver(), runtime.profileService(), Clock.systemUTC(),
                    runtime.revocationService());

            PkiException rejection = assertThrows(PkiException.class,
                    () -> service
                            .issueEndEntity(new IssueEndEntityCommand(rootCaId, request, profileId, Optional.empty())),
                    name);

            assertTrue(rejection.getMessage().contains(code), name);
            assertRedacted(rejection);
            assertEquals(0, backendCalls.get(), name);
            assertEquals(0, persistenceCalls.get(), name);
            assertEquals(signsBefore, runtime.submittedSignCount(), name);
            List<AuditEvent> events = runtime.auditSink().snapshot();
            assertEquals(auditBefore + 1, events.size(), name);
            AuditEvent event = events.get(auditBefore);
            assertEquals("ISSUE_END_ENTITY_REJECTED", event.action(), name);
            assertEquals(code, event.details().get("code"), name);
            assertFalse(events.toString().contains(REDACTION_SENTINEL), name);
        }

        @Override
        public void close() throws Exception {
            runtime.close();
        }
    }

    private static ParsedCertificationRequest parse(PkiTestRuntime runtime, PKCS10CertificationRequest csr)
            throws Exception {
        return runtime.certificationRequestService().parse(new CertificationRequest(runtime.framework().formatId(),
                new EncodedObject(Encoding.DER, csr.getEncoded())));
    }

    private static ParsedCertificationRequest withCsr(ParsedCertificationRequest source, byte[] csrDer) {
        AttributeSet attributes = SimpleAttributeSet.builder()
                .put(BcX509Attributes.CSR_DER, new AttributeValue.BytesValue(csrDer)).build();
        return new ParsedCertificationRequest(source.requestId(), source.formatId(), source.subjectRef(),
                source.publicKeyInfo(), source.requestedValidity(), source.requestedProfileId(), source.subjectRdns(),
                source.subjectAlternativeNames(), source.subjectAlternativeNamePresent(), attributes);
    }

    private static CredentialIssuerBackend countingBackend(CredentialIssuerBackend delegate,
            AtomicInteger backendCalls) {
        return new CredentialIssuerBackend() {
            @Override
            public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                    zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef, java.math.BigInteger serial) {
                backendCalls.incrementAndGet();
                return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
            }

            @Override
            public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance,
                    zeroecho.pki.api.content.DurableContentReference issuerCertificate, KeyRef issuerKeyRef) {
                return delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
            }
        };
    }

    private static PkiStore trackingStore(PkiStore delegate, AtomicInteger persistenceCalls) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if ("putCredential".equals(method.getName())) {
                        persistenceCalls.incrementAndGet();
                    }
                    try {
                        return method.invoke(delegate, arguments);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                });
    }

    private static void assertRedacted(Throwable failure) {
        assertFalse(String.valueOf(failure.getMessage()).contains(REDACTION_SENTINEL));
        for (Throwable suppressed : failure.getSuppressed()) {
            assertRedacted(suppressed);
        }
        if (failure.getCause() != null) {
            assertRedacted(failure.getCause());
        }
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
