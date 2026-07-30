/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.framework.x509.bc;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;

import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;

/**
 * Exact X.509 representation and postcondition helpers for validated leaf
 * profiles.
 */
public final class BcX509ProfileSupport {
    private BcX509ProfileSupport() {
    }

    /**
     * Builds the exact ordered subject name.
     *
     * @param rdns validated ordered RDNs
     * @return exact X.509 name
     */
    // ASN.1 value construction is necessarily one object per approved RDN.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public static X500Name subject(List<SubjectRdn> rdns) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        for (SubjectRdn rdn : rdns) {
            builder.addRDN(new ASN1ObjectIdentifier(rdn.type().oid()), subjectValue(rdn));
        }
        return builder.build();
    }

    private static org.bouncycastle.asn1.ASN1Encodable subjectValue(SubjectRdn rdn) {
        return switch (rdn.type()) {
            case COUNTRY_NAME, SERIAL_NUMBER -> new DERPrintableString(rdn.value(), true);
            case EMAIL_ADDRESS -> new DERIA5String(rdn.value(), true);
            case COMMON_NAME, ORGANIZATION_NAME, ORGANIZATIONAL_UNIT_NAME, STATE_OR_PROVINCE_NAME, LOCALITY_NAME,
                    PSEUDONYM ->
                new DERUTF8String(rdn.value());
        };
    }

    /**
     * Verifies the complete allowed leaf extension set and exact values.
     *
     * @param holder  issued certificate
     * @param request validated request
     * @return {@code true} only when every extension matches
     */
    // Malformed post-signing ASN.1 is a false postcondition, not an exposed parser
    // failure.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public static boolean matchesLeafExtensions(X509CertificateHolder holder, ValidatedCertificateRequest request) {
        try {
            Set<ASN1ObjectIdentifier> expectedOids = new LinkedHashSet<>();
            expectedOids.add(Extension.basicConstraints);
            if (!request.keyUsages().isEmpty()) {
                expectedOids.add(Extension.keyUsage);
            }
            if (!request.extendedKeyUsages().isEmpty()) {
                expectedOids.add(Extension.extendedKeyUsage);
            }
            if (!request.subjectAlternativeNames().isEmpty()) {
                expectedOids.add(Extension.subjectAlternativeName);
            }
            ASN1ObjectIdentifier[] encodedOids = holder.getExtensions().getExtensionOIDs();
            Set<ASN1ObjectIdentifier> actualOids = new LinkedHashSet<>(Arrays.asList(encodedOids));
            if (actualOids.size() != encodedOids.length || !actualOids.equals(expectedOids)) {
                return false;
            }
            Extension basic = holder.getExtension(Extension.basicConstraints);
            if (basic == null || basic.isCritical() != request.basicConstraintsCritical()
                    || BasicConstraints.getInstance(basic.getParsedValue()).isCA()) {
                return false;
            }
            if (!matchesKeyUsage(holder, request) || !matchesExtendedKeyUsage(holder, request)) {
                return false;
            }
            return matchesSubjectAlternativeNames(holder, request);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private static boolean matchesKeyUsage(X509CertificateHolder holder, ValidatedCertificateRequest request) {
        Extension extension = holder.getExtension(Extension.keyUsage);
        if (request.keyUsages().isEmpty()) {
            return extension == null;
        }
        if (extension == null || extension.isCritical() != request.keyUsageCritical()) {
            return false;
        }
        KeyUsage actual = KeyUsage.getInstance(extension.getParsedValue());
        KeyUsage expected = new KeyUsage(toKeyUsageBits(request.keyUsages()));
        return Arrays.equals(actual.getBytes(), expected.getBytes()) && actual.getPadBits() == expected.getPadBits();
    }

    private static boolean matchesExtendedKeyUsage(X509CertificateHolder holder, ValidatedCertificateRequest request) {
        Extension extension = holder.getExtension(Extension.extendedKeyUsage);
        if (request.extendedKeyUsages().isEmpty()) {
            return extension == null;
        }
        if (extension == null || extension.isCritical() != request.extendedKeyUsageCritical()) {
            return false;
        }
        ExtendedKeyUsage actual = ExtendedKeyUsage.getInstance(extension.getParsedValue());
        KeyPurposeId[] actualUsages = actual.getUsages();
        Set<String> actualOids = new LinkedHashSet<>();
        for (KeyPurposeId purpose : actualUsages) {
            actualOids.add(purpose.getId());
        }
        Set<String> expectedOids = new LinkedHashSet<>();
        request.extendedKeyUsages().forEach(value -> expectedOids.add(value.oid()));
        return actualOids.size() == actualUsages.length && actualOids.equals(expectedOids);
    }

    private static boolean matchesSubjectAlternativeNames(X509CertificateHolder holder,
            ValidatedCertificateRequest request) {
        Extension extension = holder.getExtension(Extension.subjectAlternativeName);
        if (request.subjectAlternativeNames().isEmpty()) {
            return extension == null;
        }
        if (extension == null || extension.isCritical() != request.subjectAlternativeNameCritical()) {
            return false;
        }
        GeneralName[] names = GeneralNames.getInstance(extension.getParsedValue()).getNames();
        if (names.length != request.subjectAlternativeNames().size()) {
            return false;
        }
        for (int index = 0; index < names.length; index++) {
            if (!parse(names[index]).equals(request.subjectAlternativeNames().get(index))) {
                return false;
            }
        }
        return true;
    }

    private static SubjectAlternativeName parse(GeneralName name) {
        return switch (name.getTagNo()) {
            case GeneralName.dNSName -> new SubjectAlternativeName.DnsName(((ASN1String) name.getName()).getString());
            case GeneralName.iPAddress ->
                new SubjectAlternativeName.IpAddress(ASN1OctetString.getInstance(name.getName()).getOctets());
            case GeneralName.uniformResourceIdentifier ->
                new SubjectAlternativeName.UriName(((ASN1String) name.getName()).getString());
            case GeneralName.rfc822Name ->
                new SubjectAlternativeName.Rfc822Name(((ASN1String) name.getName()).getString());
            default -> throw new IllegalArgumentException("Unsupported SAN type");
        };
    }

    private static int toKeyUsageBits(Set<LeafKeyUsage> usages) {
        int bits = 0;
        for (LeafKeyUsage usage : usages) {
            bits |= switch (usage) {
                case DIGITAL_SIGNATURE -> KeyUsage.digitalSignature;
                case CONTENT_COMMITMENT -> KeyUsage.nonRepudiation;
                case KEY_ENCIPHERMENT -> KeyUsage.keyEncipherment;
                case DATA_ENCIPHERMENT -> KeyUsage.dataEncipherment;
                case KEY_AGREEMENT -> KeyUsage.keyAgreement;
                case ENCIPHER_ONLY -> KeyUsage.encipherOnly;
                case DECIPHER_ONLY -> KeyUsage.decipherOnly;
            };
        }
        return bits;
    }
}
