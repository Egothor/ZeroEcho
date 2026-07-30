/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.e2e;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
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
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.impl.core.ValidatedCaCertificateRequest;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.testkit.H7ProfileDocuments;
import zeroecho.pki.testkit.PkiTestRuntime;

/**
 * End-to-end H7 acceptance evidence from signed PKCS#10 requests through durable
 * real X.509 leaf certificates.
 */
final class H7EndEntityAcceptanceE2eTest {
    private static final int POSITIVE_ISSUANCE_CASE_COUNT = 16;
    private static final int MAIN_BACKEND_MUTATION_CASE_COUNT = 61;
    private static final int BACKEND_MUTATION_CASE_COUNT = 63;
    private static final String REDACTION_SENTINEL = "DO-NOT-LOG-H7-SENTINEL";
    private static final Set<ASN1ObjectIdentifier> LEAF_EXTENSION_OIDS = Set.of(
            Extension.basicConstraints, Extension.keyUsage, Extension.extendedKeyUsage,
            Extension.subjectAlternativeName);

    @Test
    void everyBuiltInTemplateRequiresImportAndActivationBeforeRealIssuance(@TempDir Path tempDir)
            throws Exception {
        KeyPair rootKey = rsa();
        KeyPair leafKey = rsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:h7-built-in:root");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            List<BuiltInCertificateProfileTemplate> templates = BuiltInCertificateProfileCatalog.load(
                    H7EndEntityAcceptanceE2eTest.class.getClassLoader());
            assertEquals(6, templates.size());
            for (BuiltInCertificateProfileTemplate template : templates) {
                String profileId = template.definition().profileId();
                assertTrue(runtime.profileService().getImportedVersion(profileId, 1).isEmpty());
            }
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=H7 Built-in Root"), "root-ca", Optional.of(rootKeyRef),
                    new SimpleAttributeSet()));
            for (BuiltInCertificateProfileTemplate template : templates.stream()
                    .filter(template -> template.definition().certificateType()
                            == zeroecho.pki.api.profile.CertificateProfileKind.END_ENTITY)
                    .toList()) {
                String profileId = template.definition().profileId();
                CertificateProfileRef imported = runtime.profileService().importBuiltIn(template);
                assertTrue(runtime.profileService().getActiveReference(profileId).isEmpty());
                assertThrows(PkiException.class, () -> runtime.profileService().requireActiveProfile(profileId));
                assertEquals(imported, runtime.profileService().activateProfile(profileId, 1));

                GeneralName identity = builtInIdentity(profileId);
                ParsedCertificationRequest request = parse(runtime, leafKey,
                        new X500Name("CN=" + profileId), List.of(identity));
                Credential issued = runtime.issuanceService().issueEndEntity(new IssueEndEntityCommand(rootCaId,
                        request, profileId, Optional.empty())).credential();
                EndEntityProfileBinding binding = (EndEntityProfileBinding) issued.profileBinding();
                assertEquals(imported, binding.reference());
                X509CertificateHolder holder = new X509CertificateHolder(issued.encoded().bytes());
                GeneralName[] names = GeneralNames.fromExtensions(holder.getExtensions(),
                        Extension.subjectAlternativeName).getNames();
                assertEquals(1, names.length);
                assertEquals(identity.getTagNo(), names[0].getTagNo());
            }
        }
    }

    private static GeneralName builtInIdentity(String profileId) {
        return switch (profileId) {
            case "server-tls", "vpn-server" ->
                new GeneralName(GeneralName.dNSName, profileId + ".example.com");
            case "vpn-client" ->
                new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://example.test/workload");
            case "email-signing" ->
                new GeneralName(GeneralName.rfc822Name, "Signer@example.com");
            default -> throw new IllegalArgumentException("unexpected built-in profile");
        };
    }

    @Test
    void realSignedCsrMatrixIssuesExactProfilesAndSurvivesReopen(@TempDir Path tempDir) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair leafKey = rsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:h7-acceptance:root");
        Path busFile = tempDir.resolve("bus.log");
        Map<PkiId, PersistedExpectation> durableCredentials = new LinkedHashMap<>();
        List<BigInteger> allocatedSerials = new ArrayList<>();

        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, busFile, Map.of(rootKeyRef, rootKey))) {
            List<byte[]> profiles = acceptanceProfileDocuments();
            profiles.forEach(runtime::importAndActivate);
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=H7 Acceptance Root"), "root-ca", Optional.of(rootKeyRef),
                    new SimpleAttributeSet()));

            CredentialIssuerBackend serialCapturingBackend = serialCapturingBackend(runtime.issuerBackend(),
                    allocatedSerials);
            List<IssuanceCase> cases = List.of(
                    new IssuanceCase("h7-dns", new X500Name("CN=DNS Leaf"), false,
                            List.of(new GeneralName(GeneralName.dNSName, "WWW.Example.COM")),
                            List.of("2:www.example.com")),
                    new IssuanceCase("h7-dns-multiple", new X500Name("CN=Multiple DNS Leaf"), false,
                            List.of(new GeneralName(GeneralName.dNSName, "one.example.com"),
                                    new GeneralName(GeneralName.dNSName, "two.example.com"),
                                    new GeneralName(GeneralName.dNSName, "three.example.com")),
                            List.of("2:one.example.com", "2:two.example.com", "2:three.example.com")),
                    new IssuanceCase("h7-wildcard", new X500Name("CN=Wildcard Leaf"), false,
                            List.of(new GeneralName(GeneralName.dNSName, "*.Example.COM")),
                            List.of("2:*.example.com")),
                    new IssuanceCase("h7-dns-empty", new X500Name(""), true,
                            List.of(new GeneralName(GeneralName.dNSName, "empty.example.com")),
                            List.of("2:empty.example.com")),
                    new IssuanceCase("h7-dns-critical", new X500Name("CN=Critical DNS Leaf"), true,
                            List.of(new GeneralName(GeneralName.dNSName, "critical.example.com")),
                            List.of("2:critical.example.com")),
                    new IssuanceCase("h7-ip", new X500Name("CN=IPv4 Leaf"), false,
                            List.of(ipName(new byte[] { (byte) 192, 0, 2, 10 })),
                            List.of("7:c000020a")),
                    new IssuanceCase("h7-ip", new X500Name("CN=IPv6 Leaf"), false,
                            List.of(ipName(HexFormat.of().parseHex("20010db8000000000000000000000001"))),
                            List.of("7:20010db8000000000000000000000001")),
                    new IssuanceCase("h7-ip-mixed", new X500Name("CN=Mixed IP Leaf"), false,
                            List.of(ipName(new byte[] { (byte) 192, 0, 2, 11 }),
                                    ipName(HexFormat.of().parseHex("20010db8000000000000000000000002"))),
                            List.of("7:c000020b", "7:20010db8000000000000000000000002")),
                    new IssuanceCase("h7-ip-empty", new X500Name(""), true,
                            List.of(ipName(new byte[] { (byte) 192, 0, 2, 12 })),
                            List.of("7:c000020c")),
                    new IssuanceCase("h7-uri", new X500Name("CN=URI Leaf"), false,
                            List.of(new GeneralName(GeneralName.uniformResourceIdentifier,
                                    "HTTPS://Service.Example.COM/a%2Fb?q=%2F")),
                            List.of("6:https://service.example.com/a%2Fb?q=%2F")),
                    new IssuanceCase("h7-uri-multiple", new X500Name("CN=Multiple URI Leaf"), false,
                            List.of(new GeneralName(GeneralName.uniformResourceIdentifier,
                                            "https://one.example.com/a"),
                                    new GeneralName(GeneralName.uniformResourceIdentifier,
                                            "HTTPS://Two.Example.COM/b%2Fc?q=%2F")),
                            List.of("6:https://one.example.com/a",
                                    "6:https://two.example.com/b%2Fc?q=%2F")),
                    new IssuanceCase("h7-uri-empty", new X500Name(""), true,
                            List.of(new GeneralName(GeneralName.uniformResourceIdentifier,
                                    "https://empty.example.com/service")),
                            List.of("6:https://empty.example.com/service")),
                    new IssuanceCase("h7-rfc822", new X500Name("CN=Mail Leaf"), false,
                            List.of(new GeneralName(GeneralName.rfc822Name, "Local@Example.COM")),
                            List.of("1:Local@example.com")),
                    new IssuanceCase("h7-rfc822-multiple", new X500Name("CN=Multiple Mail Leaf"), false,
                            List.of(new GeneralName(GeneralName.rfc822Name, "First@Example.COM"),
                                    new GeneralName(GeneralName.rfc822Name, "second@Example.COM")),
                            List.of("1:First@example.com", "1:second@example.com")),
                    new IssuanceCase("h7-rfc822-empty", new X500Name(""), true,
                            List.of(new GeneralName(GeneralName.rfc822Name, "Empty@Example.COM")),
                            List.of("1:Empty@example.com")),
                    new IssuanceCase("h7-mixed", new X500Name("CN=Mixed Leaf"), false,
                            List.of(new GeneralName(GeneralName.dNSName, "mixed.example.com"),
                                    ipName(new byte[] { (byte) 198, 51, 100, 7 }),
                                    new GeneralName(GeneralName.uniformResourceIdentifier,
                                            "https://mixed.example.com/service"),
                                    new GeneralName(GeneralName.rfc822Name, "Mixed@Example.COM")),
                            List.of("2:mixed.example.com", "7:c6336407",
                                    "6:https://mixed.example.com/service", "1:Mixed@example.com")));
            assertEquals(POSITIVE_ISSUANCE_CASE_COUNT, cases.size());

            for (IssuanceCase issuanceCase : cases) {
                Credential credential = issue(runtime, serialCapturingBackend, rootCaId, leafKey, issuanceCase);
                BigInteger allocatedSerial = allocatedSerials.get(allocatedSerials.size() - 1);
                PersistedExpectation expectation = new PersistedExpectation(issuanceCase, allocatedSerial,
                        credential.validity(), credential.publicKeyId());
                assertExactLeaf(credential, rootKey, leafKey, expectation);
                durableCredentials.put(credential.credentialId(), expectation);
            }
        }

        assertEquals(durableCredentials.size(), allocatedSerials.size());
        for (BigInteger serial : allocatedSerials) {
            assertTrue(serial.signum() > 0);
            assertTrue(serial.toByteArray().length <= 20);
        }
        assertEquals(List.of("issuerCaId", "request", "profileId", "validityOverride"),
                Arrays.stream(IssueEndEntityCommand.class.getRecordComponents())
                        .map(component -> component.getName()).toList());

        try (PkiTestRuntime reopened = PkiTestRuntime.create(tempDir, busFile, Map.of(rootKeyRef, rootKey))) {
            for (Map.Entry<PkiId, PersistedExpectation> entry : durableCredentials.entrySet()) {
                Credential persisted = reopened.store().getCredential(entry.getKey()).orElseThrow();
                assertExactLeaf(persisted, rootKey, leafKey, entry.getValue());
            }
        }
    }

    @Test
    void realSignedCsrProfileViolationsRejectBeforeBackendPersistenceOrSuccessAudit(@TempDir Path tempDir)
            throws Exception {
        KeyPair rootKey = rsa();
        KeyPair leafKey = rsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:h7-rejection:root");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            acceptanceProfileDocuments().forEach(runtime::importAndActivate);
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=H7 Rejection Root"), "root-ca", Optional.of(rootKeyRef),
                    new SimpleAttributeSet()));

            assertProfileRejected(runtime, rootCaId, leafKey, "h7-dns",
                    List.of(new GeneralName(GeneralName.dNSName, "*.example.com")),
                    "SAN_WILDCARD_FORBIDDEN");
            assertProfileRejected(runtime, rootCaId, leafKey, "h7-ip",
                    List.of(new GeneralName(GeneralName.dNSName, "wrong-type.example.com")),
                    "SAN_TYPE_FORBIDDEN");
            assertProfileRejected(runtime, rootCaId, leafKey, "h7-ipv4",
                    List.of(ipName(HexFormat.of().parseHex("20010db8000000000000000000000001"))),
                    "SAN_IP_FAMILY_FORBIDDEN");
            assertProfileRejected(runtime, rootCaId, leafKey, "h7-ipv6",
                    List.of(ipName(new byte[] { (byte) 192, 0, 2, 20 })),
                    "SAN_IP_FAMILY_FORBIDDEN");
            assertProfileRejected(runtime, rootCaId, leafKey, "h7-uri",
                    List.of(new GeneralName(GeneralName.uniformResourceIdentifier,
                            "http://service.example.com/path")),
                    "SAN_URI_SCHEME_FORBIDDEN");
            assertProfileRejected(runtime, rootCaId, leafKey, "h7-rfc822",
                    List.of(new GeneralName(GeneralName.dNSName, "mail.example.com")),
                    "SAN_TYPE_FORBIDDEN");
            assertProfileRejected(runtime, rootCaId, leafKey, "h7-mixed",
                    List.of(new GeneralName(GeneralName.dNSName, "mixed.example.com"),
                            ipName(new byte[] { (byte) 198, 51, 100, 8 }),
                            new GeneralName(GeneralName.uniformResourceIdentifier,
                                    "https://mixed.example.com/service")),
                    "SAN_COUNT_INVALID");
        }
    }

    @Test
    void maliciousRealDerMutationMatrixRejectsEveryLeafPostcondition(@TempDir Path tempDir) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair leafKey = rsa();
        KeyPair substituteKey = rsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:h7-mutation:root");
        CollectingLogHandler logHandler = new CollectingLogHandler();
        Logger rootLogger = Logger.getLogger("");
        rootLogger.addHandler(logHandler);
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"),
                Map.of(rootKeyRef, rootKey))) {
            runtime.importAndActivate(H7ProfileDocuments.backendMutationProfile());
            runtime.importAndActivate(H7ProfileDocuments.noSanOrEkuProfile());
            PkiId rootCaId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=H7 Mutation Root"), "root-ca", Optional.of(rootKeyRef),
                    new SimpleAttributeSet()));
            ParsedCertificationRequest request = parse(runtime, leafKey,
                    new X500Name("CN=Mutation Leaf,O=Example"),
                    List.of(new GeneralName(GeneralName.dNSName, "base.example.com"),
                            ipName(new byte[] { (byte) 203, 0, 113, 9 }),
                            new GeneralName(GeneralName.uniformResourceIdentifier,
                                    "https://base.example.com/service"),
                            new GeneralName(GeneralName.rfc822Name, "Base@example.com")));

            assertEquals(BACKEND_MUTATION_CASE_COUNT, LeafMutation.values().length);
            assertEquals(MAIN_BACKEND_MUTATION_CASE_COUNT,
                    Arrays.stream(LeafMutation.values()).filter(LeafMutation::mainProfile).count());
            for (LeafMutation mutation : LeafMutation.values()) {
                if (mutation.mainProfile()) {
                    assertMaliciousMutationRejected(runtime, rootCaId, request, "h7-backend-mutation",
                            rootKey, substituteKey, mutation);
                }
            }
            ParsedCertificationRequest noExtensions = parseWithoutExtensions(runtime, leafKey,
                    new X500Name("CN=No Extensions Leaf"));
            assertMaliciousMutationRejected(runtime, rootCaId, noExtensions, "h7-no-san-eku",
                    rootKey, substituteKey, LeafMutation.SUBJECT_ALTERNATIVE_NAME_ADDED_WHEN_FORBIDDEN);
            assertMaliciousMutationRejected(runtime, rootCaId, noExtensions, "h7-no-san-eku",
                    rootKey, substituteKey, LeafMutation.EXTENDED_KEY_USAGE_ADDED_WHEN_FORBIDDEN);
            assertFalse(logHandler.messages().contains(REDACTION_SENTINEL));
        } finally {
            rootLogger.removeHandler(logHandler);
        }
    }

    @Test
    void bcConstructionCannotEmitDuplicateCertificateExtensionOids() throws Exception {
        for (ASN1ObjectIdentifier oid : LEAF_EXTENSION_OIDS) {
            ExtensionsGenerator generator = new ExtensionsGenerator();
            ASN1Encodable value = extensionValue(oid);
            generator.addExtension(oid, true, value);
            try {
                generator.addExtension(oid, false, value);
                assertEquals(1, Arrays.stream(generator.generate().getExtensionOIDs())
                        .filter(oid::equals).count(), oid::getId);
            } catch (RuntimeException expectedRejection) {
                assertFalse(String.valueOf(expectedRejection.getMessage()).isBlank(), oid::getId);
            }
        }
    }

    private static ASN1Encodable extensionValue(ASN1ObjectIdentifier oid) {
        if (Extension.basicConstraints.equals(oid)) {
            return new BasicConstraints(false);
        }
        if (Extension.keyUsage.equals(oid)) {
            return new KeyUsage(KeyUsage.digitalSignature);
        }
        if (Extension.extendedKeyUsage.equals(oid)) {
            return new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
        }
        return new GeneralNames(new GeneralName(GeneralName.dNSName, "duplicate.example.com"));
    }

    private static List<byte[]> acceptanceProfileDocuments() {
        return List.of(H7ProfileDocuments.dnsProfile(), H7ProfileDocuments.multipleDnsProfile(),
                H7ProfileDocuments.wildcardDnsProfile(), H7ProfileDocuments.emptySubjectDnsProfile(),
                H7ProfileDocuments.criticalDnsProfile(), H7ProfileDocuments.ipProfile(),
                H7ProfileDocuments.mixedIpProfile(), H7ProfileDocuments.emptySubjectIpProfile(),
                H7ProfileDocuments.ipv4Profile(), H7ProfileDocuments.ipv6Profile(),
                H7ProfileDocuments.uriProfile(), H7ProfileDocuments.multipleUriProfile(),
                H7ProfileDocuments.emptySubjectUriProfile(), H7ProfileDocuments.rfc822Profile(),
                H7ProfileDocuments.multipleRfc822Profile(), H7ProfileDocuments.emptySubjectRfc822Profile(),
                H7ProfileDocuments.mixedSanProfile());
    }

    private static Credential issue(PkiTestRuntime runtime, CredentialIssuerBackend backend, PkiId rootCaId,
            KeyPair leafKey, IssuanceCase issuanceCase) throws Exception {
        ParsedCertificationRequest request = parse(runtime, leafKey, issuanceCase.subject(),
                issuanceCase.sans());
        CredentialBundle bundle = runtime.issuanceService(backend, runtime.statusResolver()).issueEndEntity(
                new IssueEndEntityCommand(rootCaId, request, issuanceCase.profileId(), Optional.empty()));
        return bundle.credential();
    }

    private static ParsedCertificationRequest parse(PkiTestRuntime runtime, KeyPair leafKey, String commonName,
            List<GeneralName> sans) throws Exception {
        return parse(runtime, leafKey, new X500Name("CN=" + commonName), sans);
    }

    private static ParsedCertificationRequest parse(PkiTestRuntime runtime, KeyPair leafKey, X500Name subject,
            List<GeneralName> sans) throws Exception {
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                subject, leafKey.getPublic());
        ExtensionsGenerator extensionGenerator = new ExtensionsGenerator();
        extensionGenerator.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(sans.toArray(GeneralName[]::new)));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionGenerator.generate());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(leafKey.getPrivate());
        PKCS10CertificationRequest csr = builder.build(signer);
        return runtime.certificationRequestService().parse(new CertificationRequest(runtime.framework().formatId(),
                new EncodedObject(Encoding.DER, csr.getEncoded())));
    }

    private static ParsedCertificationRequest parseWithoutExtensions(PkiTestRuntime runtime, KeyPair leafKey,
            X500Name subject) throws Exception {
        PKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, leafKey.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(leafKey.getPrivate());
        PKCS10CertificationRequest csr = builder.build(signer);
        return runtime.certificationRequestService().parse(new CertificationRequest(runtime.framework().formatId(),
                new EncodedObject(Encoding.DER, csr.getEncoded())));
    }

    private static CredentialIssuerBackend serialCapturingBackend(CredentialIssuerBackend delegate,
            List<BigInteger> allocatedSerials) {
        return new CredentialIssuerBackend() {
            @Override
            public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                    EncodedObject issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                allocatedSerials.add(serial);
                return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
            }

            @Override
            public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance, EncodedObject issuerCertificate, KeyRef issuerKeyRef) {
                return delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
            }
        };
    }

    private static void assertExactLeaf(Credential credential, KeyPair rootKey, KeyPair leafKey,
            PersistedExpectation expectation) throws Exception {
        assertEquals(Encoding.DER, credential.encoded().encoding());
        EndEntityProfileBinding binding = assertInstanceOf(EndEntityProfileBinding.class,
                credential.profileBinding());
        assertEquals(expectation.issuanceCase().profileId(), binding.reference().profileId());
        assertEquals(expectation.validity(), credential.validity());
        assertEquals(expectation.publicKeyId(), credential.publicKeyId());
        X509CertificateHolder holder = new X509CertificateHolder(credential.encoded().bytes());
        assertEquals(expectation.issuanceCase().subject(), holder.getSubject());
        SubjectRef expectedSubjectRef = expectation.issuanceCase().subject().getRDNs().length == 0
                ? new SubjectRef("x509:empty-subject")
                : new SubjectRef(holder.getSubject().toString());
        assertEquals(expectedSubjectRef, credential.subjectRef());
        assertEquals(expectation.issuanceCase().expectedSans(), encodedSans(holder));
        assertArrayEquals(leafKey.getPublic().getEncoded(), holder.getSubjectPublicKeyInfo().getEncoded());
        assertTrue(holder.isSignatureValid(new JcaContentVerifierProviderBuilder().build(rootKey.getPublic())));
        assertEquals(credential.serialOrUniqueId(), holder.getSerialNumber().toString());
        assertEquals(expectation.allocatedSerial(), holder.getSerialNumber());
        assertTrue(holder.getSerialNumber().signum() > 0);
        assertTrue(holder.getSerialNumber().toByteArray().length <= 20);
        assertEquals(credential.validity().notBefore().getEpochSecond(),
                holder.getNotBefore().toInstant().getEpochSecond());
        assertEquals(credential.validity().notAfter().getEpochSecond(),
                holder.getNotAfter().toInstant().getEpochSecond());

        assertEquals(LEAF_EXTENSION_OIDS, Arrays.stream(holder.getExtensions().getExtensionOIDs()).collect(
                java.util.stream.Collectors.toUnmodifiableSet()));
        Extension basicConstraints = holder.getExtension(Extension.basicConstraints);
        assertTrue(basicConstraints.isCritical());
        assertFalse(BasicConstraints.getInstance(basicConstraints.getParsedValue()).isCA());
        Extension keyUsage = holder.getExtension(Extension.keyUsage);
        assertTrue(keyUsage.isCritical());
        KeyUsage usages = KeyUsage.getInstance(keyUsage.getParsedValue());
        assertTrue(usages.hasUsages(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        assertFalse(usages.hasUsages(KeyUsage.keyCertSign));
        Extension extendedKeyUsage = holder.getExtension(Extension.extendedKeyUsage);
        assertFalse(extendedKeyUsage.isCritical());
        assertArrayEquals(new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth },
                ExtendedKeyUsage.getInstance(extendedKeyUsage.getParsedValue()).getUsages());
        assertEquals(expectation.issuanceCase().sanCritical(),
                holder.getExtension(Extension.subjectAlternativeName).isCritical());
    }

    private static List<String> encodedSans(X509CertificateHolder holder) {
        GeneralName[] names = GeneralNames.fromExtensions(holder.getExtensions(),
                Extension.subjectAlternativeName).getNames();
        List<String> encoded = new ArrayList<>(names.length);
        for (GeneralName name : names) {
            if (name.getTagNo() == GeneralName.iPAddress) {
                encoded.add(name.getTagNo() + ":" + HexFormat.of().formatHex(
                        DEROctetString.getInstance(name.getName()).getOctets()));
            } else {
                encoded.add(name.getTagNo() + ":" + DERIA5String.getInstance(name.getName()).getString());
            }
        }
        return List.copyOf(encoded);
    }

    private static GeneralName ipName(byte[] address) {
        return new GeneralName(GeneralName.iPAddress, new DEROctetString(address));
    }

    private static void assertProfileRejected(PkiTestRuntime runtime, PkiId rootCaId, KeyPair leafKey,
            String profileId, List<GeneralName> sans, String code) throws Exception {
        ParsedCertificationRequest request = parse(runtime, leafKey, "Rejected Leaf", sans);
        AtomicInteger backendCalls = new AtomicInteger();
        CredentialIssuerBackend backend = countingBackend(runtime.issuerBackend(), backendCalls);
        int auditBefore = runtime.auditSink().snapshot().size();
        int signsBefore = runtime.submittedSignCount();

        PkiException rejection = assertThrows(PkiException.class,
                () -> runtime.issuanceService(backend, runtime.statusResolver()).issueEndEntity(
                        new IssueEndEntityCommand(rootCaId, request, profileId, Optional.empty())));

        assertTrue(rejection.getMessage().contains(code), profileId);
        assertEquals(0, backendCalls.get(), profileId);
        assertEquals(signsBefore, runtime.submittedSignCount(), profileId);
        assertSingleRejectionAudit(runtime, auditBefore, code);
    }

    private static CredentialIssuerBackend countingBackend(CredentialIssuerBackend delegate,
            AtomicInteger backendCalls) {
        return new CredentialIssuerBackend() {
            @Override
            public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                    EncodedObject issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                backendCalls.incrementAndGet();
                return delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef, serial);
            }

            @Override
            public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance, EncodedObject issuerCertificate, KeyRef issuerKeyRef) {
                return delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
            }
        };
    }

    private static void assertMaliciousMutationRejected(PkiTestRuntime runtime, PkiId rootCaId,
            ParsedCertificationRequest request, String profileId, KeyPair rootKey, KeyPair substituteKey,
            LeafMutation mutation) throws Exception {
        AtomicReference<Credential> maliciousCredential = new AtomicReference<>();
        AtomicReference<Credential> baselineCredential = new AtomicReference<>();
        AtomicReference<BigInteger> deliveredSerial = new AtomicReference<>();
        AtomicInteger backendCalls = new AtomicInteger();
        CredentialIssuerBackend backend = mutatingBackend(runtime.issuerBackend(), rootKey, substituteKey,
                mutation, baselineCredential, maliciousCredential, deliveredSerial, backendCalls);
        int auditBefore = runtime.auditSink().snapshot().size();

        PkiException rejection = assertThrows(PkiException.class,
                () -> runtime.issuanceService(backend, runtime.statusResolver()).issueEndEntity(
                        new IssueEndEntityCommand(rootCaId, request, profileId, Optional.empty())),
                mutation.name());

        String expectedCode = mutation == LeafMutation.PROFILE_ID_METADATA
                ? "CREDENTIAL_PROFILE_BINDING_MISMATCH" : "BACKEND_CREDENTIAL_MISMATCH";
        assertTrue(rejection.getMessage().contains(expectedCode), mutation.name());
        assertEquals(1, backendCalls.get(), mutation.name());
        assertTrue(deliveredSerial.get().signum() > 0, mutation.name());
        assertTrue(deliveredSerial.get().toByteArray().length <= 20, mutation.name());
        assertTrue(runtime.store().getCredential(maliciousCredential.get().credentialId()).isEmpty(),
                mutation.name());
        assertTrue(runtime.store().getCredential(baselineCredential.get().credentialId()).isEmpty(),
                mutation.name());
        assertSingleRejectionAudit(runtime, auditBefore, expectedCode);
        assertRedacted(rejection, REDACTION_SENTINEL);
        assertFalse(runtime.auditSink().snapshot().toString().contains(REDACTION_SENTINEL), mutation.name());
    }

    private static CredentialIssuerBackend mutatingBackend(CredentialIssuerBackend delegate, KeyPair rootKey,
            KeyPair substituteKey, LeafMutation mutation, AtomicReference<Credential> baselineCredential,
            AtomicReference<Credential> maliciousCredential, AtomicReference<BigInteger> deliveredSerial,
            AtomicInteger backendCalls) {
        return new CredentialIssuerBackend() {
            @Override
            public CredentialBundle issueEndEntity(ValidatedCertificateRequest candidate,
                    EncodedObject issuerCertificate, KeyRef issuerKeyRef, BigInteger serial) {
                backendCalls.incrementAndGet();
                deliveredSerial.set(serial);
                CredentialBundle baseline = delegate.issueEndEntity(candidate, issuerCertificate, issuerKeyRef,
                        serial);
                baselineCredential.set(baseline.credential());
                Credential mutated = mutateCredential(baseline.credential(), rootKey, substituteKey, mutation);
                maliciousCredential.set(mutated);
                return new CredentialBundle(mutated, baseline.supportingObjects());
            }

            @Override
            public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest issuance, EncodedObject issuerCertificate, KeyRef issuerKeyRef) {
                return delegate.issueIntermediateCertificate(issuance, issuerCertificate, issuerKeyRef);
            }
        };
    }

    private static Credential mutateCredential(Credential credential, KeyPair rootKey, KeyPair substituteKey,
            LeafMutation mutation) {
        try {
            X509CertificateHolder original = new X509CertificateHolder(credential.encoded().bytes());
            X500Name issuer = mutation == LeafMutation.ISSUER
                    ? new X500Name("CN=Wrong H7 Issuer") : original.getIssuer();
            X500Name subject = mutatedSubject(original.getSubject(), mutation);
            SubjectPublicKeyInfo publicKeyInfo = mutation == LeafMutation.PUBLIC_KEY
                    ? SubjectPublicKeyInfo.getInstance(substituteKey.getPublic().getEncoded())
                    : original.getSubjectPublicKeyInfo();
            BigInteger serial = switch (mutation) {
                case SERIAL -> original.getSerialNumber().add(BigInteger.ONE);
                case SERIAL_ZERO -> BigInteger.ZERO;
                case SERIAL_NEGATIVE -> BigInteger.ONE.negate();
                default -> original.getSerialNumber();
            };
            Date notBefore = mutation == LeafMutation.NOT_BEFORE_MOVED
                    ? Date.from(original.getNotBefore().toInstant().plusSeconds(60)) : original.getNotBefore();
            Date notAfter = switch (mutation) {
                case NOT_AFTER_EXTENDED -> Date.from(original.getNotAfter().toInstant().plusSeconds(60));
                case VALIDITY_SHORTENED -> Date.from(original.getNotAfter().toInstant().minusSeconds(60));
                case VALIDITY_EXCEEDS_ISSUER -> Date.from(java.time.Instant.parse("2099-01-01T00:00:00Z"));
                default -> original.getNotAfter();
            };
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter,
                    subject, publicKeyInfo);
            addMutatedExtensions(builder, original, mutation);
            KeyPair signingKey = mutation == LeafMutation.SIGNED_BY_OTHER_KEY ? substituteKey : rootKey;
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey.getPrivate());
            byte[] der = builder.build(signer).getEncoded();
            if (mutation == LeafMutation.CORRUPT_SIGNATURE) {
                der[der.length - 1] ^= 0x01;
            }
            X509CertificateHolder mutated = new X509CertificateHolder(der);
            byte[] spki = mutated.getSubjectPublicKeyInfo().getEncoded();
            Validity validity = new Validity(mutated.getNotBefore().toInstant(), mutated.getNotAfter().toInstant());
            PkiId credentialId = mutation == LeafMutation.CREDENTIAL_ID_METADATA
                    ? new PkiId("x509:wrong-metadata") : new PkiId("x509:" + sha256Hex(der));
            FormatId formatId = mutation == LeafMutation.FORMAT_METADATA
                    ? new FormatId("wrong-format") : credential.formatId();
            IssuerRef issuerRef = mutation == LeafMutation.ISSUER_REF_METADATA
                    ? new IssuerRef(new PkiId("ca:wrong-metadata")) : credential.issuerRef();
            SubjectRef subjectRef = mutated.getSubject().getRDNs().length == 0
                    ? new SubjectRef("x509:empty-subject") : new SubjectRef(mutated.getSubject().toString());
            if (mutation == LeafMutation.SUBJECT_REF_METADATA) {
                subjectRef = new SubjectRef("CN=Wrong Metadata Subject");
            }
            Validity metadataValidity = mutation == LeafMutation.VALIDITY_METADATA
                    ? new Validity(validity.notBefore().plusSeconds(1), validity.notAfter()) : validity;
            String metadataSerial = mutation == LeafMutation.SERIAL_METADATA
                    ? original.getSerialNumber().add(BigInteger.TEN).toString()
                    : mutated.getSerialNumber().toString();
            PkiId publicKeyId = mutation == LeafMutation.PUBLIC_KEY_ID_METADATA
                    ? new PkiId("spki:wrong-metadata") : new PkiId("spki:" + sha256Hex(spki));
            EndEntityProfileBinding originalBinding = (EndEntityProfileBinding) credential.profileBinding();
            CertificateProfileRef originalRef = originalBinding.reference();
            EndEntityProfileBinding profileBinding = mutation == LeafMutation.PROFILE_ID_METADATA
                    ? new EndEntityProfileBinding(new CertificateProfileRef("wrong-profile",
                            originalRef.profileVersion(), originalRef.canonicalSha256()))
                    : originalBinding;
            CredentialStatus status = mutation == LeafMutation.STATUS_METADATA
                    ? CredentialStatus.REVOKED : credential.status();
            Encoding encoding = mutation == LeafMutation.ENCODING_METADATA ? Encoding.PEM : Encoding.DER;
            return new Credential(credentialId, formatId, issuerRef, subjectRef, metadataValidity,
                    metadataSerial, publicKeyId, profileBinding, status, new EncodedObject(encoding, der),
                    credential.attributes());
        } catch (Exception exception) {
            throw new IllegalStateException("Failed to build controlled H7 mutation " + mutation.name());
        }
    }

    private static X500Name mutatedSubject(X500Name original, LeafMutation mutation) {
        RDN[] rdns = original.getRDNs();
        if (mutation == LeafMutation.SUBJECT_REPLACED) {
            return new X500Name("CN=" + REDACTION_SENTINEL + ",O=Example");
        }
        if (mutation == LeafMutation.SUBJECT_REMOVED) {
            return new X500Name(Arrays.copyOf(rdns, rdns.length - 1));
        }
        if (mutation == LeafMutation.SUBJECT_ADDED) {
            RDN[] added = Arrays.copyOf(rdns, rdns.length + 1);
            added[rdns.length] = new RDN(BCStyle.OU, new DERUTF8String("Unexpected"));
            return new X500Name(added);
        }
        if (mutation == LeafMutation.SUBJECT_DUPLICATED) {
            RDN[] duplicated = Arrays.copyOf(rdns, rdns.length + 1);
            duplicated[rdns.length] = rdns[0];
            return new X500Name(duplicated);
        }
        if (mutation == LeafMutation.SUBJECT_REORDERED) {
            RDN[] reordered = rdns.clone();
            for (int index = 0; index < reordered.length / 2; index++) {
                RDN swap = reordered[index];
                reordered[index] = reordered[reordered.length - index - 1];
                reordered[reordered.length - index - 1] = swap;
            }
            return new X500Name(reordered);
        }
        return original;
    }

    private static void addMutatedExtensions(X509v3CertificateBuilder builder, X509CertificateHolder original,
            LeafMutation mutation) throws Exception {
        Extension originalBasicConstraints = original.getExtension(Extension.basicConstraints);
        if (mutation != LeafMutation.BASIC_CONSTRAINTS_ABSENT) {
            if (mutation == LeafMutation.BASIC_CONSTRAINTS_MALFORMED) {
                builder.addExtension(Extension.basicConstraints, true, DERNull.INSTANCE);
            } else {
                boolean critical = mutation == LeafMutation.BASIC_CONSTRAINTS_NONCRITICAL
                        ? false : originalBasicConstraints.isCritical();
                BasicConstraints value = switch (mutation) {
                    case BASIC_CONSTRAINTS_CA -> new BasicConstraints(true);
                    case BASIC_CONSTRAINTS_PATH_LENGTH -> new BasicConstraints(0);
                    default -> BasicConstraints.getInstance(originalBasicConstraints.getParsedValue());
                };
                builder.addExtension(Extension.basicConstraints, critical, value);
            }
        }

        Extension originalKeyUsage = original.getExtension(Extension.keyUsage);
        if (mutation != LeafMutation.KEY_USAGE_ABSENT) {
            if (mutation == LeafMutation.KEY_USAGE_MALFORMED) {
                builder.addExtension(Extension.keyUsage, true, DERNull.INSTANCE);
            } else {
                boolean critical = mutation == LeafMutation.KEY_USAGE_NONCRITICAL
                        ? false : originalKeyUsage.isCritical();
                KeyUsage value = switch (mutation) {
                    case KEY_USAGE_ADD -> new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                            | KeyUsage.dataEncipherment);
                    case KEY_USAGE_REMOVE -> new KeyUsage(KeyUsage.digitalSignature);
                    case KEY_USAGE_REPLACE -> new KeyUsage(KeyUsage.keyAgreement);
                    default -> KeyUsage.getInstance(originalKeyUsage.getParsedValue());
                };
                builder.addExtension(Extension.keyUsage, critical, value);
            }
        }

        Extension originalExtendedKeyUsage = original.getExtension(Extension.extendedKeyUsage);
        if (mutation == LeafMutation.EXTENDED_KEY_USAGE_ADDED_WHEN_FORBIDDEN) {
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        } else if (originalExtendedKeyUsage != null && mutation != LeafMutation.EXTENDED_KEY_USAGE_ABSENT) {
            if (mutation == LeafMutation.EXTENDED_KEY_USAGE_MALFORMED) {
                builder.addExtension(Extension.extendedKeyUsage, false, DERNull.INSTANCE);
            } else {
                boolean critical = mutation == LeafMutation.EXTENDED_KEY_USAGE_CRITICAL
                        || originalExtendedKeyUsage.isCritical();
                KeyPurposeId[] usages;
                if (mutation == LeafMutation.EXTENDED_KEY_USAGE_ADD) {
                    usages = new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth,
                            KeyPurposeId.id_kp_codeSigning };
                } else if (mutation == LeafMutation.EXTENDED_KEY_USAGE_REMOVE) {
                    usages = new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth };
                } else if (mutation == LeafMutation.EXTENDED_KEY_USAGE_REPLACE) {
                    usages = new KeyPurposeId[] { KeyPurposeId.id_kp_codeSigning };
                } else if (mutation == LeafMutation.EXTENDED_KEY_USAGE_DUPLICATE) {
                    usages = new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth,
                            KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth };
                } else {
                    usages = ExtendedKeyUsage.getInstance(originalExtendedKeyUsage.getParsedValue()).getUsages();
                }
                builder.addExtension(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(usages));
            }
        }

        Extension originalSan = original.getExtension(Extension.subjectAlternativeName);
        if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_ADDED_WHEN_FORBIDDEN) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "forbidden.example.com")));
        } else if (originalSan != null && mutation != LeafMutation.SUBJECT_ALTERNATIVE_NAME_ABSENT) {
            if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_MALFORMED) {
                builder.addExtension(Extension.subjectAlternativeName, false, DERNull.INSTANCE);
            } else {
                GeneralName[] names = GeneralNames.fromExtensions(original.getExtensions(),
                        Extension.subjectAlternativeName).getNames();
                if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_ADD_ONE) {
                    GeneralName[] added = Arrays.copyOf(names, names.length + 1);
                    added[names.length] = new GeneralName(GeneralName.dNSName, "added.example.com");
                    names = added;
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_REMOVE_ONE) {
                    names = Arrays.copyOf(names, names.length - 1);
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_REPLACE) {
                    names[0] = new GeneralName(GeneralName.dNSName,
                            REDACTION_SENTINEL.toLowerCase(java.util.Locale.ROOT) + ".example.com");
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_CHANGE_TYPE) {
                    names[0] = new GeneralName(GeneralName.rfc822Name, "Changed@example.com");
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_DUPLICATE) {
                    GeneralName[] duplicate = Arrays.copyOf(names, names.length + 1);
                    duplicate[names.length] = names[0];
                    names = duplicate;
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_DNS_CASE) {
                    names[0] = new GeneralName(GeneralName.dNSName, "BASE.Example.COM");
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_IP_BYTES) {
                    names[1] = ipName(new byte[] { (byte) 203, 0, 113, 10 });
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_URI_VALUE) {
                    names[2] = new GeneralName(GeneralName.uniformResourceIdentifier,
                            "https://" + REDACTION_SENTINEL.toLowerCase(java.util.Locale.ROOT) + ".example.com/");
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_RFC822_VALUE) {
                    names[3] = new GeneralName(GeneralName.rfc822Name,
                            REDACTION_SENTINEL + "@example.com");
                } else if (mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_REORDERED) {
                    GeneralName first = names[0];
                    names[0] = names[1];
                    names[1] = first;
                }
                boolean critical = mutation == LeafMutation.SUBJECT_ALTERNATIVE_NAME_CRITICAL
                        || originalSan.isCritical();
                builder.addExtension(Extension.subjectAlternativeName, critical, new GeneralNames(names));
            }
        }

        if (mutation == LeafMutation.UNKNOWN_NONCRITICAL_EXTENSION) {
            builder.addExtension(new ASN1ObjectIdentifier("1.2.3.4.5.6.7"), false, DERNull.INSTANCE);
        } else if (mutation == LeafMutation.UNKNOWN_CRITICAL_EXTENSION) {
            builder.addExtension(new ASN1ObjectIdentifier("1.2.3.4.5.6.8"), true, DERNull.INSTANCE);
        } else if (mutation == LeafMutation.SUBJECT_KEY_IDENTIFIER_EXTENSION) {
            builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(new byte[20]));
        } else if (mutation == LeafMutation.AUTHORITY_KEY_IDENTIFIER_EXTENSION) {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(new byte[20]));
        }
    }

    private static void assertSingleRejectionAudit(PkiTestRuntime runtime, int auditBefore, String code) {
        List<AuditEvent> events = runtime.auditSink().snapshot();
        assertEquals(auditBefore + 1, events.size(), code);
        AuditEvent event = events.get(auditBefore);
        assertEquals("ISSUE_END_ENTITY_REJECTED", event.action());
        assertEquals(code, event.details().get("code"));
    }

    private static void assertRedacted(Throwable failure, String sentinel) {
        Throwable current = failure;
        while (current != null) {
            assertFalse(String.valueOf(current.getMessage()).contains(sentinel));
            for (Throwable suppressed : current.getSuppressed()) {
                assertRedacted(suppressed, sentinel);
            }
            current = current.getCause();
        }
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String sha256Hex(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private record IssuanceCase(String profileId, X500Name subject, boolean sanCritical, List<GeneralName> sans,
            List<String> expectedSans) {
        private IssuanceCase {
            sans = List.copyOf(sans);
            expectedSans = List.copyOf(expectedSans);
        }
    }

    private record PersistedExpectation(IssuanceCase issuanceCase, BigInteger allocatedSerial,
            Validity validity, PkiId publicKeyId) {
    }

    private enum LeafMutation {
        SUBJECT_REPLACED,
        SUBJECT_REMOVED,
        SUBJECT_ADDED,
        SUBJECT_DUPLICATED,
        SUBJECT_REORDERED,
        SUBJECT_ALTERNATIVE_NAME_ADD_ONE,
        SUBJECT_ALTERNATIVE_NAME_REMOVE_ONE,
        SUBJECT_ALTERNATIVE_NAME_REPLACE,
        SUBJECT_ALTERNATIVE_NAME_CHANGE_TYPE,
        SUBJECT_ALTERNATIVE_NAME_DUPLICATE,
        SUBJECT_ALTERNATIVE_NAME_DNS_CASE,
        SUBJECT_ALTERNATIVE_NAME_IP_BYTES,
        SUBJECT_ALTERNATIVE_NAME_URI_VALUE,
        SUBJECT_ALTERNATIVE_NAME_RFC822_VALUE,
        SUBJECT_ALTERNATIVE_NAME_REORDERED,
        SUBJECT_ALTERNATIVE_NAME_CRITICAL,
        SUBJECT_ALTERNATIVE_NAME_ABSENT,
        SUBJECT_ALTERNATIVE_NAME_MALFORMED,
        SUBJECT_ALTERNATIVE_NAME_ADDED_WHEN_FORBIDDEN(false),
        PUBLIC_KEY,
        ISSUER,
        SERIAL,
        SERIAL_ZERO,
        SERIAL_NEGATIVE,
        NOT_BEFORE_MOVED,
        NOT_AFTER_EXTENDED,
        VALIDITY_SHORTENED,
        VALIDITY_EXCEEDS_ISSUER,
        PROFILE_ID_METADATA,
        CREDENTIAL_ID_METADATA,
        FORMAT_METADATA,
        ISSUER_REF_METADATA,
        SUBJECT_REF_METADATA,
        VALIDITY_METADATA,
        SERIAL_METADATA,
        PUBLIC_KEY_ID_METADATA,
        STATUS_METADATA,
        ENCODING_METADATA,
        BASIC_CONSTRAINTS_ABSENT,
        BASIC_CONSTRAINTS_CA,
        BASIC_CONSTRAINTS_PATH_LENGTH,
        BASIC_CONSTRAINTS_NONCRITICAL,
        BASIC_CONSTRAINTS_MALFORMED,
        KEY_USAGE_ABSENT,
        KEY_USAGE_ADD,
        KEY_USAGE_REMOVE,
        KEY_USAGE_REPLACE,
        KEY_USAGE_NONCRITICAL,
        KEY_USAGE_MALFORMED,
        EXTENDED_KEY_USAGE_ABSENT,
        EXTENDED_KEY_USAGE_ADD,
        EXTENDED_KEY_USAGE_REMOVE,
        EXTENDED_KEY_USAGE_REPLACE,
        EXTENDED_KEY_USAGE_DUPLICATE,
        EXTENDED_KEY_USAGE_CRITICAL,
        EXTENDED_KEY_USAGE_MALFORMED,
        EXTENDED_KEY_USAGE_ADDED_WHEN_FORBIDDEN(false),
        UNKNOWN_NONCRITICAL_EXTENSION,
        UNKNOWN_CRITICAL_EXTENSION,
        SUBJECT_KEY_IDENTIFIER_EXTENSION,
        AUTHORITY_KEY_IDENTIFIER_EXTENSION,
        CORRUPT_SIGNATURE,
        SIGNED_BY_OTHER_KEY;

        private final boolean mainProfile;

        LeafMutation() {
            this(true);
        }

        LeafMutation(boolean mainProfile) {
            this.mainProfile = mainProfile;
        }

        private boolean mainProfile() {
            return mainProfile;
        }
    }

    private static final class CollectingLogHandler extends Handler {
        private final List<String> messages = java.util.Collections.synchronizedList(new ArrayList<>());

        @Override
        public void publish(LogRecord record) {
            if (record == null) {
                return;
            }
            messages.add(String.valueOf(record.getMessage()));
            Object[] parameters = record.getParameters();
            if (parameters != null) {
                for (Object parameter : parameters) {
                    messages.add(String.valueOf(parameter));
                }
            }
            if (record.getThrown() != null) {
                collectThrowable(record.getThrown());
            }
        }

        private void collectThrowable(Throwable failure) {
            Throwable current = failure;
            while (current != null) {
                messages.add(String.valueOf(current.getMessage()));
                for (Throwable suppressed : current.getSuppressed()) {
                    collectThrowable(suppressed);
                }
                current = current.getCause();
            }
        }

        private String messages() {
            synchronized (messages) {
                return String.join("\n", messages);
            }
        }

        @Override
        public void flush() {
            // No buffered destination.
        }

        @Override
        public void close() {
            messages.clear();
        }
    }
}
