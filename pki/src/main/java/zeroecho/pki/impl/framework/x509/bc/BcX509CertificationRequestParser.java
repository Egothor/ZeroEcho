/* *****************************************************************************
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

import zeroecho.pkix.cmp.CrmfRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pkix.Pkix;
import zeroecho.pkix.RelativeDistinguishedName;
import zeroecho.pkix.UnsupportedDirectoryStringException;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.framework.CertificationRequestParser;

/**
 * Parser for X.509 PKCS#10 certification requests, routed through the ZeroEcho
 * PKIX library.
 *
 * <p>
 * This parser converts an incoming {@link CertificationRequest} in the X.509
 * framework format into a normalized {@link ParsedCertificationRequest} used by
 * the PKI core. It supports CSR input encoded either directly as DER or as PEM
 * carrying a PKCS#10 object that can be converted to DER.
 * </p>
 *
 * <p>
 * This class does not verify proof of possession and does not evaluate issuance
 * policy. Those responsibilities are delegated to other framework components.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is stateless and thread-safe.
 * </p>
 */
// PMD cannot infer the redaction boundary or the explicit closed parsing grammar.
@SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.CyclomaticComplexity", "PMD.AvoidUsingHardCodedIP" })
public final class BcX509CertificationRequestParser implements CertificationRequestParser {
    private static final int MAXIMUM_SUBJECT_DER_BYTES = 16 * 1024;
    private static final int MAXIMUM_SAN_DER_BYTES = 32 * 1024;
    /* default */ static final int MAXIMUM_CSR_DER_BYTES = 1024 * 1024;
    private static final int MAXIMUM_CSR_ENCODED_BYTES = 2 * 1024 * 1024;
    private static final int MAXIMUM_SUBJECT_RDNS = 32;
    private static final int SINGLE_ATTRIBUTE_VALUE = 1;
    private static final int MAXIMUM_SAN_ENTRIES = 64;
    private static final String EXTENSION_REQUEST_OID = "1.2.840.113549.1.9.14";
    private static final String SUBJECT_ALTERNATIVE_NAME_OID = "2.5.29.17";
    private static final String CERTIFICATE_REQUEST = "CERTIFICATE REQUEST";
    private static final String NEW_CERTIFICATE_REQUEST = "NEW CERTIFICATE REQUEST";
    private static final String CSR_PEM_INVALID = "Invalid PEM: code=CSR_PEM_INVALID";

    /** Creates a stateless PKCS#10 request parser. */
    public BcX509CertificationRequestParser() {
        // Stateless.
    }

    /**
     * Parses an explicitly typed original X.509 enrollment request.
     * CRMF requires signing-key PoP over its complete subject/key CertRequest;
     * parsing retains the proof but does not verify it.
     * @param request bounded immutable original payload
     * @return normalized request with one syntax-specific transport attribute
     * @throws PkiException if the request or supported subject/SAN grammar is invalid
     */
    @Override
    public ParsedCertificationRequest parseX509(X509EnrollmentPayload request) {
        Objects.requireNonNull(request, "request");
        if (request.kind() == X509EnrollmentPayload.Kind.PKCS10) {
            return parse(new CertificationRequest(BcX509CredentialFramework.FORMAT_ID,
                    new EncodedObject(Encoding.DER, request.der())));
        }
        byte[] der = request.der();
        try {
            new StreamingDerReader().validate(der, MAXIMUM_CSR_DER_BYTES);
            CrmfRequest crmf = CrmfRequest.parse(der);
            List<SubjectRdn> subject = parseSubject(crmf.subject());
            List<SubjectAlternativeName> sans = parseRequestedExtensions(crmf.requestedExtensions());
            return new ParsedCertificationRequest(new PkiId("crmf:" + sha256Hex(der)),
                    BcX509CredentialFramework.FORMAT_ID, subjectReference(subject),
                    new EncodedObject(Encoding.DER, crmf.subjectPublicKeyInfo()), Optional.empty(), Optional.empty(),
                    subject, sans, !sans.isEmpty(), SimpleAttributeSet.builder()
                            .put(BcX509Attributes.CRMF_DER, new AttributeValue.BytesValue(der.clone())).build());
        } catch (java.io.IOException | IllegalArgumentException malformed) {
            throw new PkiException("Invalid CRMF certification request: code=CRMF_MALFORMED");
        } finally {
            java.util.Arrays.fill(der, (byte) 0);
        }
    }

    /**
     * Parses a PKCS#10 certification request into the normalized PKI request
     * representation.
     *
     * @param request certification request to parse; must not be {@code null}
     * @return normalized parsed certification request
     * @throws IllegalArgumentException if {@code request} is {@code null}, if its
     *                                  format identifier does not match, or if its
     *                                  encoding is unsupported
     * @throws PkiException             if the PKCS#10 request is structurally
     *                                  invalid or its public key cannot be extracted
     */
    @Override
    public ParsedCertificationRequest parse(CertificationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        if (!BcX509CredentialFramework.FORMAT_ID.equals(request.formatId())) {
            throw new IllegalArgumentException("Unsupported request formatId: " + request.formatId().value());
        }

        EncodedObject enc = request.encoded();
        byte[] csrDer;
        try {
            csrDer = toDer(enc);
        } catch (IllegalArgumentException exception) {
            if (enc.encoding() != Encoding.DER && enc.encoding() != Encoding.PEM) {
                throw exception;
            }
            throw new PkiException("Invalid PKCS#10 certification request: code=CSR_MALFORMED");
        }
        byte[] spki = null;
        try {
            zeroecho.pkix.csr.CertificationRequest csr;
            try {
                new StreamingDerReader().validate(csrDer, MAXIMUM_CSR_DER_BYTES);
                csr = Pkix.parseCertificationRequest(csrDer);
            } catch (Exception ex) {
                throw new PkiException("Invalid PKCS#10 certification request: code=CSR_MALFORMED");
            }

            List<SubjectRdn> subjectRdns = parseSubject(csr.subject());
            SubjectRef subjectRef = subjectReference(subjectRdns);
            List<SubjectAlternativeName> subjectAlternativeNames = parseSubjectAlternativeNames(csr);

            try {
                spki = csr.subjectPublicKeyInfo();
            } catch (Exception ex) {
                throw new PkiException("Failed to extract CSR SPKI: code=CSR_SPKI_INVALID");
            }
            EncodedObject publicKeyInfo = new EncodedObject(Encoding.DER, spki);

            PkiId requestId = new PkiId("csr:" + sha256Hex(csrDer));

            SimpleAttributeSet attrs = SimpleAttributeSet.builder()
                    .put(BcX509Attributes.CSR_DER, new AttributeValue.BytesValue(csrDer.clone())).build();

            return new ParsedCertificationRequest(requestId, request.formatId(), subjectRef, publicKeyInfo,
                    Optional.empty(), Optional.empty(), subjectRdns, subjectAlternativeNames,
                    !subjectAlternativeNames.isEmpty(), attrs);
        } finally {
            java.util.Arrays.fill(csrDer, (byte) 0);
            if (spki != null) {
                java.util.Arrays.fill(spki, (byte) 0);
            }
        }
    }

    /**
     * Reconstructs a certification request from an already-issued certificate for
     * renewal or reissue, where no fresh PKCS#10 request exists.
     *
     * @param certificate already-issued certificate to reconstruct from
     * @param formatId    active framework format identifier
     * @return reconstructed request with no CSR transport attribute
     */
    // Certificate provider accessors may throw provider-specific runtime exceptions at this validation boundary.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public static ParsedCertificationRequest reconstructForRenewal(X509Certificate certificate, FormatId formatId) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(formatId, "formatId");
        List<SubjectRdn> subjectRdns = parseSubject(certificate.getSubjectX500Principal());
        SubjectRef subjectRef = subjectReference(subjectRdns);
        List<SubjectAlternativeName> subjectAlternativeNames = reconstructSubjectAlternativeNames(certificate);
        byte[] spki;
        byte[] certificateDer;
        try {
            spki = Pkix.subjectPublicKeyInfo(certificate);
            certificateDer = certificate.getEncoded();
        } catch (RuntimeException | java.security.cert.CertificateEncodingException ex) {
            throw new PkiException("Failed to read certificate for reconstruction: code=CSR_SPKI_INVALID");
        }
        try {
            EncodedObject publicKeyInfo = new EncodedObject(Encoding.DER, spki.clone());
            PkiId requestId = new PkiId("renew:" + sha256Hex(certificateDer));
            return new ParsedCertificationRequest(requestId, formatId, subjectRef, publicKeyInfo,
                    Optional.empty(), Optional.empty(), subjectRdns, subjectAlternativeNames,
                    !subjectAlternativeNames.isEmpty(), new SimpleAttributeSet());
        } finally {
            java.util.Arrays.fill(spki, (byte) 0);
        }
    }

    private static List<SubjectAlternativeName> reconstructSubjectAlternativeNames(X509Certificate certificate) {
        java.util.Collection<List<?>> names;
        try {
            names = certificate.getSubjectAlternativeNames();
        } catch (java.security.cert.CertificateParsingException exception) {
            throw new PkiException("Certificate SAN rejected: code=SAN_MALFORMED");
        }
        if (names == null) {
            return List.of();
        }
        if (names.isEmpty() || names.size() > MAXIMUM_SAN_ENTRIES) {
            throw new PkiException("Certificate SAN rejected: code=SAN_COUNT_INVALID");
        }
        try {
            List<SubjectAlternativeName> result = new ArrayList<>(names.size());
            Set<SubjectAlternativeName> unique = new HashSet<>();
            for (List<?> entry : names) {
                SubjectAlternativeName parsed = parseJdkGeneralName(entry);
                if (!unique.add(parsed)) {
                    throw new PkiException("Certificate SAN rejected: code=SAN_DUPLICATE");
                }
                result.add(parsed);
            }
            return List.copyOf(result);
        } catch (IllegalArgumentException | IllegalStateException exception) {
            throw new PkiException("Certificate SAN rejected: code=SAN_MALFORMED");
        }
    }

    // Each approved RDN requires one immutable typed value; providers use several malformed-name exceptions.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static List<SubjectRdn> parseSubject(javax.security.auth.x500.X500Principal subject) {
        byte[] encoded = subject.getEncoded();
        if (encoded.length > MAXIMUM_SUBJECT_DER_BYTES) {
            throw new PkiException("CSR subject rejected: code=SUBJECT_TOO_LARGE");
        }
        List<RelativeDistinguishedName> rdns;
        try {
            rdns = Pkix.parseDistinguishedName(encoded);
        } catch (UnsupportedDirectoryStringException unsupported) {
            throw new PkiException("CSR subject rejected: code=SUBJECT_VALUE_UNSUPPORTED");
        } catch (RuntimeException exception) {
            throw new PkiException("CSR subject rejected: code=SUBJECT_MALFORMED");
        }
        if (rdns.size() > MAXIMUM_SUBJECT_RDNS) {
            throw new PkiException("CSR subject rejected: code=SUBJECT_TOO_MANY_RDNS");
        }
        List<SubjectRdn> result = new ArrayList<>(rdns.size());
        for (RelativeDistinguishedName rdn : rdns) {
            SubjectRdnType type;
            try {
                type = SubjectRdnType.fromOid(rdn.attributeTypeOid());
            } catch (IllegalArgumentException exception) {
                throw new PkiException("CSR subject rejected: code=SUBJECT_RDN_UNSUPPORTED");
            }
            result.add(new SubjectRdn(type, rdn.value()));
        }
        return List.copyOf(result);
    }

    private static SubjectRef subjectReference(List<SubjectRdn> rdns) {
        return new SubjectRef(rdns.isEmpty() ? "x509:empty-subject" : BcX509ProfileSupport.subjectRefString(rdns));
    }

    // The branches enforce the closed PKCS#10 extensionRequest grammar.
    @SuppressWarnings("PMD.CyclomaticComplexity")
    private static List<SubjectAlternativeName> parseSubjectAlternativeNames(
            zeroecho.pkix.csr.CertificationRequest csr) {
        List<zeroecho.pkix.csr.CsrAttribute> extensionRequests = new ArrayList<>();
        boolean otherAttributePresent = false;
        boolean challengePresent = false;
        boolean estKeygenAttributes = false;
        for (zeroecho.pkix.csr.CsrAttribute attribute : csr.rawAttributes()) {
            if (EXTENSION_REQUEST_OID.equals(attribute.oid())) {
                extensionRequests.add(attribute);
            } else if ("1.2.840.113549.1.9.7".equals(attribute.oid()) && !challengePresent) {
                try { attribute.challengePassword(); }
                catch (IllegalArgumentException invalid) { throw new PkiException("CSR attributes rejected: code=CSR_ATTRIBUTE_MALFORMED"); }
                challengePresent = true;
            } else if (zeroecho.pkix.EstKeygen.CAPABILITIES_OID.equals(attribute.oid())
                    || zeroecho.pkix.EstKeygen.RECIPIENT_KEY_ID_OID.equals(attribute.oid())) {
                estKeygenAttributes = true;
            } else {
                otherAttributePresent = true;
            }
        }
        if (extensionRequests.size() > 1 || otherAttributePresent) {
            throw new PkiException("CSR attributes rejected: code=CSR_ATTRIBUTE_UNSUPPORTED");
        }
        if (estKeygenAttributes) {
            try { zeroecho.pkix.EstKeygen.requireAttributes(csr.encoded()); }
            catch (IllegalArgumentException malformed) { throw new PkiException("CSR attributes rejected: code=CSR_ATTRIBUTE_MALFORMED"); }
        }
        if (extensionRequests.isEmpty()) {
            return List.of();
        }
        List<byte[]> values = extensionRequests.get(0).derValues();
        if (values.size() != SINGLE_ATTRIBUTE_VALUE) {
            throw new PkiException("CSR extensions rejected: code=EXTENSION_REQUEST_MALFORMED");
        }
        List<zeroecho.pkix.CertificateExtension> extensions;
        try {
            extensions = Pkix.parseExtensions(values.get(0));
        } catch (IllegalArgumentException exception) {
            throw new PkiException("CSR extensions rejected: code=EXTENSION_REQUEST_MALFORMED");
        }
        if (extensions.isEmpty()) {
            throw new PkiException("CSR extensions rejected: code=EXTENSION_UNSUPPORTED");
        }
        return parseRequestedExtensions(extensions);
    }

    private static List<SubjectAlternativeName> parseRequestedExtensions(List<zeroecho.pkix.CertificateExtension> extensions) {
        if (extensions.isEmpty()) {
            return List.of();
        }
        if (extensions.size() != 1 || !SUBJECT_ALTERNATIVE_NAME_OID.equals(extensions.get(0).oid())) {
            throw new PkiException("CSR extensions rejected: code=EXTENSION_UNSUPPORTED");
        }
        zeroecho.pkix.CertificateExtension sanExtension = extensions.get(0);
        if (sanExtension.critical()) {
            throw new PkiException("CSR extensions rejected: code=SAN_CRITICALITY_REQUESTED");
        }
        byte[] sanValue = sanExtension.derValue();
        if (sanValue.length > MAXIMUM_SAN_DER_BYTES) {
            throw new PkiException("CSR extensions rejected: code=SAN_TOO_LARGE");
        }
        List<zeroecho.pkix.GeneralName> names;
        try {
            names = Pkix.parseGeneralNames(sanValue);
        } catch (IllegalArgumentException exception) {
            throw new PkiException("CSR extensions rejected: code=SAN_MALFORMED");
        }
        if (names.isEmpty() || names.size() > MAXIMUM_SAN_ENTRIES) {
            throw new PkiException("CSR extensions rejected: code=SAN_COUNT_INVALID");
        }
        List<SubjectAlternativeName> result = new ArrayList<>(names.size());
        Set<SubjectAlternativeName> unique = new HashSet<>();
        try {
            for (zeroecho.pkix.GeneralName name : names) {
                SubjectAlternativeName parsed = parseGeneralName(name);
                if (!unique.add(parsed)) {
                    throw new PkiException("CSR extensions rejected: code=SAN_DUPLICATE");
                }
                result.add(parsed);
            }
        } catch (IllegalArgumentException | IllegalStateException exception) {
            throw new PkiException("CSR extensions rejected: code=SAN_MALFORMED");
        }
        return List.copyOf(result);
    }

    private static SubjectAlternativeName parseGeneralName(zeroecho.pkix.GeneralName name) {
        return switch (name) {
            case zeroecho.pkix.GeneralName.DnsName dns -> new SubjectAlternativeName.DnsName(dns.value());
            case zeroecho.pkix.GeneralName.IpAddress ip -> new SubjectAlternativeName.IpAddress(ipOctets(ip.value()));
            case zeroecho.pkix.GeneralName.UniformResourceIdentifier uri ->
                new SubjectAlternativeName.UriName(uri.value());
            case zeroecho.pkix.GeneralName.Rfc822Name email -> new SubjectAlternativeName.Rfc822Name(email.value());
            case zeroecho.pkix.GeneralName.OtherName ignored ->
                throw new PkiException("CSR extensions rejected: code=SAN_MALFORMED");
            default -> throw new PkiException("CSR extensions rejected: code=SAN_TYPE_UNSUPPORTED");
        };
    }

    private static SubjectAlternativeName parseJdkGeneralName(List<?> entry) {
        int type = ((Number) entry.get(0)).intValue();
        Object value = entry.get(1);
        return switch (type) {
            case 2 -> new SubjectAlternativeName.DnsName((String) value);
            case 6 -> new SubjectAlternativeName.UriName((String) value);
            case 1 -> new SubjectAlternativeName.Rfc822Name((String) value);
            case 7 -> new SubjectAlternativeName.IpAddress(ipOctets((String) value));
            default -> throw new PkiException("Certificate SAN rejected: code=SAN_TYPE_UNSUPPORTED");
        };
    }

    private static byte[] ipOctets(String literal) {
        try {
            return InetAddress.getByName(literal).getAddress();
        } catch (UnknownHostException exception) {
            throw new IllegalArgumentException("Malformed IP SAN literal", exception);
        }
    }

    /**
     * Converts the supplied encoded object to DER form.
     *
     * @param obj encoded object to convert; must not be {@code null}
     * @return DER-form bytes corresponding to the supplied object
     * @throws NullPointerException     if {@code obj} is {@code null}
     * @throws IllegalArgumentException if the encoding is unsupported or PEM
     *                                  decoding fails
     */
    private static byte[] toDer(EncodedObject obj) {
        Objects.requireNonNull(obj, "obj");
        byte[] encoded = obj.bytes();
        if (obj.encoding() == Encoding.DER) {
            return requireDecodedLimit(encoded);
        }
        try {
            if (encoded.length > MAXIMUM_CSR_ENCODED_BYTES) {
                throw new IllegalArgumentException("CSR encoding exceeds element limit");
            }
            return switch (obj.encoding()) {
                case DER -> throw new IllegalStateException("DER handled before PEM conversion");
                case PEM -> readPemContentOrThrow(encoded);
                default -> throw new IllegalArgumentException("Unsupported CSR encoding: " + obj.encoding());
            };
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Reads the binary content of a PEM object.
     *
     * @param pemBytes PEM-encoded input bytes; must not be {@code null}
     * @return decoded binary content of the PEM object
     * @throws NullPointerException     if {@code pemBytes} is {@code null}
     * @throws IllegalArgumentException if the PEM input cannot be parsed
     */
    @SuppressWarnings("PMD.AvoidThrowingNewInstanceOfSameException")
    private static byte[] readPemContentOrThrow(byte[] pemBytes) {
        Objects.requireNonNull(pemBytes, "pemBytes");
        for (byte value : pemBytes) {
            if (value < 0) {
                throw new IllegalArgumentException(CSR_PEM_INVALID);
            }
        }
        String text = new String(pemBytes, java.nio.charset.StandardCharsets.US_ASCII);
        int begin = skipWhitespace(text, 0);
        String label;
        String certificateRequestBegin = "-----BEGIN " + CERTIFICATE_REQUEST + "-----";
        String newCertificateRequestBegin = "-----BEGIN " + NEW_CERTIFICATE_REQUEST + "-----";
        if (text.startsWith(certificateRequestBegin, begin)) {
            label = CERTIFICATE_REQUEST;
        } else if (text.startsWith(newCertificateRequestBegin, begin)) {
            label = NEW_CERTIFICATE_REQUEST;
        } else {
            throw new IllegalArgumentException(CSR_PEM_INVALID);
        }
        int bodyStart = begin + "-----BEGIN ".length() + label.length() + "-----".length();
        if (bodyStart >= text.length() || text.charAt(bodyStart) != '\n'
                && (text.charAt(bodyStart) != '\r' || bodyStart + 1 >= text.length()
                        || text.charAt(bodyStart + 1) != '\n')) {
            throw new IllegalArgumentException(CSR_PEM_INVALID);
        }
        String endMarker = "-----END " + label + "-----";
        int end = text.indexOf(endMarker, bodyStart);
        if (end <= bodyStart || text.charAt(end - 1) != '\n'
                || skipWhitespace(text, end + endMarker.length()) != text.length()) {
            throw new IllegalArgumentException(CSR_PEM_INVALID);
        }
        StringBuilder compact = new StringBuilder(end - bodyStart);
        for (int index = bodyStart; index < end; index++) {
            char value = text.charAt(index);
            if (isWhitespace(value)) {
                continue;
            }
            if (isBase64(value) || value == '=') {
                compact.append(value);
            } else {
                throw new IllegalArgumentException(CSR_PEM_INVALID);
            }
        }
        if (compact.isEmpty() || (compact.length() + 3L) / 4L * 3L > MAXIMUM_CSR_DER_BYTES + 2L) {
            throw new IllegalArgumentException(CSR_PEM_INVALID);
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(compact.toString());
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(CSR_PEM_INVALID);
        }
        if (!Base64.getEncoder().encodeToString(decoded).contentEquals(compact)) {
            java.util.Arrays.fill(decoded, (byte) 0);
            throw new IllegalArgumentException(CSR_PEM_INVALID);
        }
        return requireDecodedLimit(decoded);
    }

    private static byte[] requireDecodedLimit(byte[] decoded) {
        if (decoded.length > MAXIMUM_CSR_DER_BYTES) {
            java.util.Arrays.fill(decoded, (byte) 0);
            throw new IllegalArgumentException("CSR DER exceeds element limit");
        }
        return decoded;
    }

    private static int skipWhitespace(String value, int offset) {
        int index = offset;
        while (index < value.length() && isWhitespace(value.charAt(index))) {
            index++;
        }
        return index;
    }

    private static boolean isWhitespace(char value) {
        return value == ' ' || value == '\t' || value == '\r' || value == '\n';
    }

    private static boolean isBase64(char value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
                || value >= '0' && value <= '9' || value == '+' || value == '/';
    }

    /**
     * Computes the SHA-256 digest of the supplied bytes as a lowercase hex string.
     *
     * @param in input bytes; must not be {@code null}
     * @return hexadecimal SHA-256 digest
     * @throws IllegalStateException if SHA-256 is unavailable
     */
    private static String sha256Hex(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(in);
            try {
                return HexFormat.of().formatHex(d);
            } finally {
                java.util.Arrays.fill(d, (byte) 0);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 unavailable: code=DIGEST_UNAVAILABLE");
        }
    }
}
