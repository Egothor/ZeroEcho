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
package zeroecho.pki.impl.framework.x509.bc;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.DirectoryStringType;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.RelativeDistinguishedName;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;

/**
 * Exact X.509 representation and postcondition helpers for validated leaf
 * profiles, expressed in terms of the ZeroEcho PKIX library and standard JDK
 * certificate accessors.
 */
// Dotted literals in this class are ASN.1 object identifiers, never network endpoints.
@SuppressWarnings("PMD.AvoidUsingHardCodedIP")
public final class BcX509ProfileSupport {

    private static final String OID_BASIC_CONSTRAINTS = "2.5.29.19";
    private static final String OID_KEY_USAGE = "2.5.29.15";
    private static final String OID_EXTENDED_KEY_USAGE = "2.5.29.37";
    private static final String OID_SUBJECT_ALTERNATIVE_NAME = "2.5.29.17";

    private static final int SAN_RFC822 = 1;
    private static final int SAN_DNS = 2;
    private static final int SAN_URI = 6;
    private static final int SAN_IP = 7;

    private BcX509ProfileSupport() {
    }

    /**
     * Builds the exact ordered subject name.
     *
     * @param rdns validated ordered RDNs
     * @return exact X.500 name
     */
    // ASN.1 value construction is necessarily one object per approved RDN.
    public static X500Principal subject(List<SubjectRdn> rdns) {
        List<RelativeDistinguishedName> converted = new ArrayList<>(rdns.size());
        for (SubjectRdn rdn : rdns) {
            converted.add(new RelativeDistinguishedName(rdn.type().oid(), rdn.value(), stringType(rdn)));
        }
        return Pkix.distinguishedName(converted);
    }

    /**
     * Renders the ordered subject name as its canonical string form, matching the
     * representation used for {@code SubjectRef} identity throughout the runtime.
     *
     * @param rdns validated ordered RDNs
     * @return the canonical distinguished-name string
     */
    public static String subjectRefString(List<SubjectRdn> rdns) {
        List<RelativeDistinguishedName> converted = new ArrayList<>(rdns.size());
        for (SubjectRdn rdn : rdns) {
            converted.add(new RelativeDistinguishedName(rdn.type().oid(), rdn.value(), stringType(rdn)));
        }
        return Pkix.distinguishedNameString(converted);
    }

    private static DirectoryStringType stringType(SubjectRdn rdn) {
        return switch (rdn.type()) {
            case COUNTRY_NAME, SERIAL_NUMBER -> DirectoryStringType.PRINTABLE;
            case EMAIL_ADDRESS -> DirectoryStringType.IA5;
            case COMMON_NAME, ORGANIZATION_NAME, ORGANIZATIONAL_UNIT_NAME, STATE_OR_PROVINCE_NAME, LOCALITY_NAME,
                    PSEUDONYM ->
                DirectoryStringType.UTF8;
        };
    }

    /**
     * Verifies the complete allowed leaf extension set and exact values.
     *
     * @param certificate issued certificate
     * @param request     validated request
     * @return {@code true} only when every extension matches
     */
    // Malformed post-signing structure is a false postcondition, not an exposed
    // parser failure.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    public static boolean matchesLeafExtensions(X509Certificate certificate, ValidatedCertificateRequest request) {
        try {
            Set<String> expectedOids = new LinkedHashSet<>();
            expectedOids.add(OID_BASIC_CONSTRAINTS);
            if (!request.keyUsages().isEmpty()) {
                expectedOids.add(OID_KEY_USAGE);
            }
            if (!request.extendedKeyUsages().isEmpty()) {
                expectedOids.add(OID_EXTENDED_KEY_USAGE);
            }
            if (!request.subjectAlternativeNames().isEmpty()) {
                expectedOids.add(OID_SUBJECT_ALTERNATIVE_NAME);
            }
            Set<String> actualOids = new LinkedHashSet<>();
            if (certificate.getCriticalExtensionOIDs() != null) {
                actualOids.addAll(certificate.getCriticalExtensionOIDs());
            }
            if (certificate.getNonCriticalExtensionOIDs() != null) {
                actualOids.addAll(certificate.getNonCriticalExtensionOIDs());
            }
            if (!actualOids.equals(expectedOids)) {
                return false;
            }
            // basicConstraints present, matching criticality, non-CA.
            if (certificate.getBasicConstraints() != -1
                    || isCritical(certificate, OID_BASIC_CONSTRAINTS) != request.basicConstraintsCritical()) {
                return false;
            }
            return matchesKeyUsage(certificate, request) && matchesExtendedKeyUsage(certificate, request)
                    && matchesSubjectAlternativeNames(certificate, request);
        } catch (RuntimeException | java.security.cert.CertificateParsingException exception) {
            return false;
        }
    }

    private static boolean isCritical(X509Certificate certificate, String oid) {
        Set<String> critical = certificate.getCriticalExtensionOIDs();
        return critical != null && critical.contains(oid);
    }

    private static boolean matchesKeyUsage(X509Certificate certificate, ValidatedCertificateRequest request) {
        boolean[] actual = certificate.getKeyUsage();
        if (request.keyUsages().isEmpty()) {
            return actual == null;
        }
        if (actual == null || isCritical(certificate, OID_KEY_USAGE) != request.keyUsageCritical()) {
            return false;
        }
        boolean[] expected = new boolean[9];
        for (LeafKeyUsage usage : request.keyUsages()) {
            expected[keyUsageBit(usage)] = true;
        }
        for (int index = 0; index < 9; index++) {
            boolean present = index < actual.length && actual[index];
            if (present != expected[index]) {
                return false;
            }
        }
        // Reject any usage bit beyond bit 8.
        for (int index = 9; index < actual.length; index++) {
            if (actual[index]) {
                return false;
            }
        }
        return true;
    }

    private static int keyUsageBit(LeafKeyUsage usage) {
        return switch (usage) {
            case DIGITAL_SIGNATURE -> 0;
            case CONTENT_COMMITMENT -> 1;
            case KEY_ENCIPHERMENT -> 2;
            case DATA_ENCIPHERMENT -> 3;
            case KEY_AGREEMENT -> 4;
            case ENCIPHER_ONLY -> 7;
            case DECIPHER_ONLY -> 8;
        };
    }

    private static boolean matchesExtendedKeyUsage(X509Certificate certificate, ValidatedCertificateRequest request)
            throws java.security.cert.CertificateParsingException {
        List<String> actual = certificate.getExtendedKeyUsage();
        if (request.extendedKeyUsages().isEmpty()) {
            return actual == null;
        }
        if (actual == null || isCritical(certificate, OID_EXTENDED_KEY_USAGE) != request.extendedKeyUsageCritical()) {
            return false;
        }
        Set<String> actualOids = new LinkedHashSet<>(actual);
        Set<String> expectedOids = new LinkedHashSet<>();
        request.extendedKeyUsages().forEach(value -> expectedOids.add(value.oid()));
        return actualOids.size() == actual.size() && actualOids.equals(expectedOids);
    }

    private static boolean matchesSubjectAlternativeNames(X509Certificate certificate,
            ValidatedCertificateRequest request) throws java.security.cert.CertificateParsingException {
        java.util.Collection<List<?>> names = certificate.getSubjectAlternativeNames();
        if (request.subjectAlternativeNames().isEmpty()) {
            return names == null;
        }
        if (names == null || isCritical(certificate, OID_SUBJECT_ALTERNATIVE_NAME)
                != request.subjectAlternativeNameCritical()) {
            return false;
        }
        List<SubjectAlternativeName> actual = new ArrayList<>(names.size());
        for (List<?> entry : names) {
            actual.add(parse(entry));
        }
        return actual.equals(request.subjectAlternativeNames());
    }

    private static SubjectAlternativeName parse(List<?> entry) {
        int type = ((Number) entry.get(0)).intValue();
        Object value = entry.get(1);
        return switch (type) {
            case SAN_DNS -> new SubjectAlternativeName.DnsName((String) value);
            case SAN_URI -> new SubjectAlternativeName.UriName((String) value);
            case SAN_RFC822 -> new SubjectAlternativeName.Rfc822Name((String) value);
            case SAN_IP -> new SubjectAlternativeName.IpAddress(ipOctets((String) value));
            default -> throw new IllegalArgumentException("Unsupported SAN type");
        };
    }

    private static byte[] ipOctets(String literal) {
        try {
            return InetAddress.getByName(literal).getAddress();
        } catch (UnknownHostException exception) {
            throw new IllegalArgumentException("Malformed IP SAN literal", exception);
        }
    }
}
