/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialProfileBinding;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.LeafCertificatePolicy;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.profile.SubjectAlternativeNamePolicy;
import zeroecho.pki.api.profile.SubjectAlternativeNameRule;
import zeroecho.pki.api.profile.SubjectAlternativeNameType;
import zeroecho.pki.api.profile.SubjectPolicy;
import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.framework.x509.bc.BcX509CertificationRequestParser;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.testkit.H7ProfileDocuments;
import zeroecho.pki.testkit.PkiTestRuntime;

/**
 * Focused H7 profile, parser, validator, and postcondition regression evidence.
 */
final class H7ProfileEnforcementTest {
    private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");

    @Test
    void sanCanonicalizationPreservesTypedIdentityAndRawUriEscapes() {
        assertEquals("www.example.com", new SubjectAlternativeName.DnsName("WWW.Example.COM").value());
        assertArrayEquals(new byte[] { 127, 0, 0, 1 },
                new SubjectAlternativeName.IpAddress(new byte[] { 127, 0, 0, 1 }).bytes());
        assertEquals("https://example.com/a%2Fb?q=%2F",
                new SubjectAlternativeName.UriName("HTTPS://Example.COM/a%2Fb?q=%2F").value());
        assertEquals("Local@example.com", new SubjectAlternativeName.Rfc822Name("Local@Example.COM").value());

        assertThrows(IllegalArgumentException.class, () -> new SubjectAlternativeName.DnsName("127.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> new SubjectAlternativeName.DnsName("bad.example."));
        assertThrows(IllegalArgumentException.class, () -> new SubjectAlternativeName.IpAddress(new byte[5]));
        assertThrows(IllegalArgumentException.class, () -> new SubjectAlternativeName.UriName("mailto:a@example.com"));
        assertThrows(IllegalArgumentException.class,
                () -> new SubjectAlternativeName.UriName("https://user@example.com/path"));
        assertThrows(IllegalArgumentException.class,
                () -> new SubjectAlternativeName.Rfc822Name("Display <a@example.com>"));
    }

    @Test
    void profileConstructionRejectsUnsatisfiableAndOpenPolicy() {
        SubjectAlternativeNameRule dns = new SubjectAlternativeNameRule(SubjectAlternativeNameType.DNS_NAME, 0, 1,
                false, false);
        assertThrows(IllegalArgumentException.class,
                () -> new SubjectAlternativeNamePolicy(2, 2, List.of(dns), false, Set.of(), false, false, false));
        assertThrows(IllegalArgumentException.class,
                () -> new SubjectAlternativeNamePolicy(0, 1, List.of(), false, Set.of(), false, true, false));
        assertThrows(IllegalArgumentException.class, () -> new SubjectAlternativeNamePolicy(0, 1, List.of(dns), false,
                Set.of("https"), false, false, false));
        assertThrows(IllegalArgumentException.class,
                () -> leaf(Set.of(LeafKeyUsage.ENCIPHER_ONLY), Set.of("RSA"), Set.of()));
        assertThrows(IllegalArgumentException.class,
                () -> leaf(Set.of(LeafKeyUsage.DIGITAL_SIGNATURE), Set.of("rsa"), Set.of()));
        assertThrows(IllegalArgumentException.class, () -> new ExtendedKeyUsageId("1.40.1"));
        assertEquals("1.3.6.1.5.5.7.3.1", new ExtendedKeyUsageId("1.3.6.1.5.5.7.3.1").oid());
    }

    @Test
    void parserUsesLogicalSubjectStringsAndFourClosedSanTypes() throws Exception {
        KeyPair keyPair = rsa();
        X500NameBuilder subject = new X500NameBuilder(BCStyle.INSTANCE);
        subject.addRDN(BCStyle.CN, new DERUTF8String("#literal\\name"));
        Extensions extensions = extensions(false, new GeneralName(GeneralName.dNSName, "WWW.Example.COM"),
                new GeneralName(GeneralName.iPAddress, new DEROctetString(new byte[] { 10, 0, 0, 1 })),
                new GeneralName(GeneralName.uniformResourceIdentifier, "HTTPS://Example.COM/a%2Fb"),
                new GeneralName(GeneralName.rfc822Name, "Local@Example.COM"));

        ParsedCertificationRequest parsed = parse(csr(keyPair, subject.build(), List.of(extensions)));

        assertEquals(List.of(new SubjectRdn(SubjectRdnType.COMMON_NAME, "#literal\\name")), parsed.subjectRdns());
        assertEquals(BcX509ProfileSupport.subject(parsed.subjectRdns()).toString(), parsed.subjectRef().value());
        assertEquals(List.of(new SubjectAlternativeName.DnsName("www.example.com"),
                new SubjectAlternativeName.IpAddress(new byte[] { 10, 0, 0, 1 }),
                new SubjectAlternativeName.UriName("https://example.com/a%2Fb"),
                new SubjectAlternativeName.Rfc822Name("Local@example.com")), parsed.subjectAlternativeNames());
    }

    @Test
    void parserRejectsUnsupportedSubjectAndCsrExtensionShapes() throws Exception {
        KeyPair keyPair = rsa();
        X500NameBuilder unsupportedSubject = new X500NameBuilder(BCStyle.INSTANCE);
        unsupportedSubject.addRDN(BCStyle.CN, new DERBMPString("unsupported"));
        assertCode("SUBJECT_VALUE_UNSUPPORTED", () -> parse(csr(keyPair, unsupportedSubject.build(), List.of())));

        Extensions unknown = new Extensions(
                new Extension(new ASN1ObjectIdentifier("1.2.3.4"), false, new byte[] { 0x05, 0x00 }));
        assertCode("EXTENSION_UNSUPPORTED", () -> parse(csr(keyPair, new X500Name("CN=Leaf"), List.of(unknown))));

        Extensions criticalSan = extensions(true, new GeneralName(GeneralName.dNSName, "example.com"));
        assertCode("SAN_CRITICALITY_REQUESTED",
                () -> parse(csr(keyPair, new X500Name("CN=Leaf"), List.of(criticalSan))));

        Extensions san = extensions(false, new GeneralName(GeneralName.dNSName, "example.com"));
        assertCode("CSR_ATTRIBUTE_UNSUPPORTED", () -> parse(csr(keyPair, new X500Name("CN=Leaf"), List.of(san, san))));

        Extension sanExtension = san.getExtension(Extension.subjectAlternativeName);
        DERSequence duplicateSan = new DERSequence(new ASN1Encodable[] { sanExtension, sanExtension });
        assertCode("EXTENSION_REQUEST_MALFORMED",
                () -> parse(csr(keyPair, new X500Name("CN=Leaf"), List.of(duplicateSan))));

        Extensions unsupportedName = extensions(false,
                new GeneralName(GeneralName.directoryName, new X500Name("CN=Nested")));
        assertCode("SAN_TYPE_UNSUPPORTED",
                () -> parse(csr(keyPair, new X500Name("CN=Leaf"), List.of(unsupportedName))));
    }

    @Test
    void validatorRequiresCanonicalSupportedSpkiParametersAndDerivesFinalSubject() throws Exception {
        for (String algorithm : List.of("RSA", "ECDSA", "Ed25519", "Ed448")) {
            KeyPair pair = keyPair(algorithm);
            ValidatedCertificateRequest validated = validate(pair.getPublic().getEncoded(), algorithm,
                    policyWithFixedOrganization(algorithm));
            assertTrue(validated.subjectRef().value().contains("O=Profile Fixed"));
        }

        KeyPair rsa = rsa();
        SubjectPublicKeyInfo original = SubjectPublicKeyInfo.getInstance(rsa.getPublic().getEncoded());
        SubjectPublicKeyInfo missingNull = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), original.getPublicKeyData().getBytes());
        assertCode("SUBJECT_KEY_PARAMETERS_UNSUPPORTED",
                () -> validate(missingNull.getEncoded(), "RSA", policyWithFixedOrganization("RSA")));

        SubjectPublicKeyInfo ed = SubjectPublicKeyInfo.getInstance(keyPair("Ed25519").getPublic().getEncoded());
        SubjectPublicKeyInfo edWithNull = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(ed.getAlgorithm().getAlgorithm(), DERNull.INSTANCE),
                ed.getPublicKeyData().getBytes());
        assertCode("SUBJECT_KEY_PARAMETERS_UNSUPPORTED",
                () -> validate(edWithNull.getEncoded(), "Ed25519", policyWithFixedOrganization("Ed25519")));
    }

    @Test
    void postconditionRejectsDuplicateEkuAndUnknownExtensions() throws Exception {
        KeyPair pair = rsa();
        ValidatedCertificateRequest request = validatedRequest(pair);
        X509CertificateHolder exact = certificate(pair, request, false, false);
        X509CertificateHolder duplicateEku = certificate(pair, request, true, false);
        X509CertificateHolder unknownExtension = certificate(pair, request, false, true);

        assertTrue(BcX509ProfileSupport.matchesLeafExtensions(exact, request));
        assertFalse(BcX509ProfileSupport.matchesLeafExtensions(duplicateEku, request));
        assertFalse(BcX509ProfileSupport.matchesLeafExtensions(unknownExtension, request));
    }

    @Test
    void activeProfileCannotSubstitutePolicyForItsCanonicalReference() {
        CertificateProfileDefinition definition = CertificateProfileDocumentCodec
                .parse(H7ProfileDocuments.defaultProfile());
        CertificateProfileRef substituted = new CertificateProfileRef(definition.profileId(),
                definition.profileVersion(), new byte[CertificateProfileRef.HASH_BYTES]);

        assertThrows(IllegalArgumentException.class, () -> new ActiveCertificateProfile(substituted, definition));
    }

    @Test
    void credentialProfileBindingVariantsAreClosedAndExact() {
        CertificateProfileRef reference = new CertificateProfileRef("shared-profile", 1,
                new byte[CertificateProfileRef.HASH_BYTES]);
        EndEntityProfileBinding endEntity = new EndEntityProfileBinding(reference);
        CaProfileBinding ca = new CaProfileBinding(reference);

        assertTrue(CredentialProfileBinding.class.isSealed());
        assertEquals(Set.of(EndEntityProfileBinding.class, CaProfileBinding.class),
                Set.of(CredentialProfileBinding.class.getPermittedSubclasses()));
        assertTrue(java.util.Arrays.stream(CredentialProfileBinding.class.getMethods())
                .noneMatch(method -> method.getName().equals("profileId")));
        assertTrue(java.util.Arrays.stream(Credential.class.getMethods())
                .noneMatch(method -> method.getName().equals("profileId")));

        CredentialProfileBindings.requireEndEntityBinding(endEntity, reference);
        CredentialProfileBindings.requireCaBinding(ca, reference);
        assertCode(CredentialProfileBindings.MISMATCH_CODE,
                () -> CredentialProfileBindings.requireEndEntityBinding(ca, reference));
        assertCode(CredentialProfileBindings.MISMATCH_CODE,
                () -> CredentialProfileBindings.requireCaBinding(endEntity, reference));
        assertCode(CredentialProfileBindings.MISMATCH_CODE, () -> CredentialProfileBindings.requireCaBinding(
                new CaProfileBinding(new CertificateProfileRef("other", 1, new byte[32])), reference));
        assertCode(CredentialProfileBindings.MISMATCH_CODE,
                () -> CredentialProfileBindings.requireCaBinding(null, reference));
    }

    @Test
    void profileResolutionFailuresPrecedeSigningAndPersistence(@TempDir Path tempDir) throws Exception {
        KeyPair root = rsa();
        KeyPair leaf = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:h7:root");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(tempDir, tempDir.resolve("bus.log"),
                Map.of(rootRef, root))) {
            PkiId caId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            ParsedCertificationRequest request = runtime.certificationRequestService().parse(new CertificationRequest(
                    runtime.framework().formatId(),
                    new EncodedObject(Encoding.DER, csr(leaf, new X500Name("CN=Leaf"), List.of()).getEncoded())));
            int signs = runtime.submittedSignCount();

            assertRejectedWithoutSideEffects(runtime, caId, request, "missing", Optional.empty(), signs);

            runtime.profileService().importProfile(H7ProfileDocuments.inactiveProfile());
            assertRejectedWithoutSideEffects(runtime, caId, request, "inactive", Optional.empty(), signs);

            runtime.importAndActivate(H7ProfileDocuments.wrongFormatProfile());
            assertRejectedWithoutSideEffects(runtime, caId, request, "wrong-format", Optional.empty(), signs);

            runtime.importAndActivate(H7ProfileDocuments.excessiveValidityProfile());
            Validity tooLong = new Validity(NOW, NOW.plus(Duration.ofDays(366)));
            assertRejectedWithoutSideEffects(runtime, caId, request, "too-long", Optional.of(tooLong), signs);

            ProfileService mismatched = mismatchedProfileService(runtime.profileService());
            DefaultIssuanceService service = new DefaultIssuanceService(runtime.store(), runtime.framework(),
                    runtime.issuerBackend(), runtime.auditSink(), runtime.statusResolver(), mismatched,
                    Clock.systemUTC());
            assertThrows(PkiException.class, () -> service
                    .issueEndEntity(new IssueEndEntityCommand(caId, request, "requested", Optional.empty())));
            assertEquals(signs, runtime.submittedSignCount());

            assertEquals(List.of("issuerCaId", "request", "profileId", "validityOverride"),
                    java.util.Arrays.stream(IssueEndEntityCommand.class.getRecordComponents())
                            .map(component -> component.getName()).toList());
        }
    }

    private static void assertRejectedWithoutSideEffects(PkiTestRuntime runtime, PkiId caId,
            ParsedCertificationRequest request, String profileId, Optional<Validity> validity, int signs) {
        assertThrows(PkiException.class, () -> runtime.issuanceService()
                .issueEndEntity(new IssueEndEntityCommand(caId, request, profileId, validity)));
        assertEquals(signs, runtime.submittedSignCount());
    }

    private static ProfileService mismatchedProfileService(ProfileService delegate) {
        return (ProfileService) Proxy.newProxyInstance(ProfileService.class.getClassLoader(),
                new Class<?>[] { ProfileService.class }, (proxy, method, args) -> {
                    if ("requireActiveProfile".equals(method.getName())) {
                        CertificateProfileDefinition definition = CertificateProfileDocumentCodec
                                .parse(H7ProfileDocuments.defaultProfile());
                        return new ActiveCertificateProfile(profileRef(definition), definition);
                    }
                    try {
                        return method.invoke(delegate, args);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                });
    }

    private static CertificateProfileRef profileRef(CertificateProfileDefinition definition) {
        try {
            byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
            return new CertificateProfileRef(definition.profileId(), definition.profileVersion(),
                    MessageDigest.getInstance("SHA-256").digest(canonical));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static ValidatedCertificateRequest validate(byte[] encoded, String algorithm, CertificateProfile profile) {
        ParsedCertificationRequest request = parsedRequest(encoded);
        IssueEndEntityCommand command = new IssueEndEntityCommand(new PkiId("ca:h7"), request, profile.profileId(),
                Optional.empty());
        VerifiedIssuanceCandidate candidate = new VerifiedIssuanceCandidate(request, request.requestId(),
                request.publicKeyInfo(), ProofOfPossessionStatus.VERIFIED, command);
        CertificateProfileRef reference = new CertificateProfileRef(profile.profileId(), 1,
                new byte[CertificateProfileRef.HASH_BYTES]);
        return CertificateProfileValidator.validate(candidate, profile, reference, issuerCredential(), NOW);
    }

    private static ParsedCertificationRequest parsedRequest(byte[] encoded) {
        AttributeSet attributes = SimpleAttributeSet.builder()
                .put(BcX509Attributes.CSR_DER, new AttributeValue.BytesValue(new byte[] { 1 })).build();
        return new ParsedCertificationRequest(new PkiId("csr:h7"), BcX509CredentialFramework.FORMAT_ID,
                new SubjectRef("CN=Leaf"), new EncodedObject(Encoding.DER, encoded), Optional.empty(), Optional.empty(),
                List.of(new SubjectRdn(SubjectRdnType.COMMON_NAME, "Leaf")), List.of(), false, attributes);
    }

    private static Credential issuerCredential() {
        return new Credential(new PkiId("credential:issuer"), BcX509CredentialFramework.FORMAT_ID,
                new IssuerRef(new PkiId("ca:issuer")), new SubjectRef("CN=Issuer"),
                new Validity(NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(1000))), "1",
                new PkiId("spki:issuer"), new CaProfileBinding(new CertificateProfileRef("root", 1, new byte[32])),
                CredentialStatus.ISSUED, new EncodedObject(Encoding.DER, new byte[] { 1 }), new SimpleAttributeSet());
    }

    private static CertificateProfile policyWithFixedOrganization(String algorithm) {
        SubjectPolicy subject = new SubjectPolicy(false, List.of(
                new SubjectRdnRule(SubjectRdnType.COMMON_NAME, 1, 1, 256, Optional.empty(), true),
                new SubjectRdnRule(SubjectRdnType.ORGANIZATION_NAME, 1, 1, 256, Optional.of("Profile Fixed"), false)));
        SubjectAlternativeNamePolicy sans = new SubjectAlternativeNamePolicy(0, 0, List.of(), false, Set.of(), false,
                false, false);
        LeafCertificatePolicy leaf = new LeafCertificatePolicy(sans, Set.of(LeafKeyUsage.DIGITAL_SIGNATURE), Set.of(),
                true, false, true, Set.of(algorithm));
        return new CertificateProfile("h7", BcX509CredentialFramework.FORMAT_ID, "H7", Duration.ofDays(365), subject,
                leaf);
    }

    private static LeafCertificatePolicy leaf(Set<LeafKeyUsage> usages, Set<String> algorithms,
            Set<ExtendedKeyUsageId> ekus) {
        return new LeafCertificatePolicy(
                new SubjectAlternativeNamePolicy(1, 1,
                        List.of(new SubjectAlternativeNameRule(SubjectAlternativeNameType.DNS_NAME, 1, 1, false,
                                false)),
                        false, Set.of(), false, true, false),
                usages, ekus, true, false, true, algorithms);
    }

    private static ParsedCertificationRequest parse(PKCS10CertificationRequest request) throws Exception {
        CertificationRequest input = new CertificationRequest(BcX509CredentialFramework.FORMAT_ID,
                new EncodedObject(Encoding.DER, request.getEncoded()));
        return new BcX509CertificationRequestParser().parse(input);
    }

    private static PKCS10CertificationRequest csr(KeyPair pair, X500Name subject,
            List<? extends ASN1Encodable> extensionRequests) throws Exception {
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
        for (ASN1Encodable extensions : extensionRequests) {
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        return builder.build(signer);
    }

    private static Extensions extensions(boolean critical, GeneralName... names) throws Exception {
        GeneralNames generalNames = new GeneralNames(names);
        return new Extensions(new Extension(Extension.subjectAlternativeName, critical,
                new DEROctetString(generalNames.getEncoded())));
    }

    private static KeyPair rsa() throws Exception {
        return keyPair("RSA");
    }

    private static KeyPair keyPair(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA".equals(algorithm) ? "EC" : algorithm);
        if ("RSA".equals(algorithm)) {
            generator.initialize(2048);
        } else if ("ECDSA".equals(algorithm)) {
            generator.initialize(new ECGenParameterSpec("secp256r1"));
        }
        return generator.generateKeyPair();
    }

    private static ValidatedCertificateRequest validatedRequest(KeyPair pair) {
        return new ValidatedCertificateRequest(new PkiId("ca:h7"),
                new CertificateProfileRef("h7", 1, new byte[CertificateProfileRef.HASH_BYTES]),
                new SubjectRef("CN=Leaf"), List.of(new SubjectRdn(SubjectRdnType.COMMON_NAME, "Leaf")),
                List.of(new SubjectAlternativeName.DnsName("example.com")), false,
                new EncodedObject(Encoding.DER, pair.getPublic().getEncoded()),
                new Validity(NOW, NOW.plus(Duration.ofDays(1))), Set.of(LeafKeyUsage.DIGITAL_SIGNATURE),
                Set.of(new ExtendedKeyUsageId(KeyPurposeId.id_kp_serverAuth.getId())), true, false, true);
    }

    private static X509CertificateHolder certificate(KeyPair pair, ValidatedCertificateRequest request,
            boolean duplicateEku, boolean unknownExtension) throws Exception {
        X500Name subject = BcX509ProfileSupport.subject(request.subjectRdns());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(subject, BigInteger.ONE,
                Date.from(request.validity().notBefore()), Date.from(request.validity().notAfter()), subject,
                SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        KeyPurposeId[] usages = duplicateEku
                ? new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_serverAuth }
                : new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth };
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(usages));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")));
        if (unknownExtension) {
            builder.addExtension(new ASN1ObjectIdentifier("1.2.3.4"), false, DERNull.INSTANCE);
        }
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate()));
    }

    private static void assertCode(String code, ThrowingAction action) {
        PkiException exception = assertThrows(PkiException.class, action::run);
        assertTrue(exception.getMessage().contains(code));
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
