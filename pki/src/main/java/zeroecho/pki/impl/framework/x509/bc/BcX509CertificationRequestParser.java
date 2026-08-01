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

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.spi.framework.CertificationRequestParser;

/**
 * Bouncy Castle backed parser for X.509 PKCS#10 certification requests.
 *
 * <p>
 * This parser converts an incoming {@link CertificationRequest} in the X.509
 * framework format into a normalized {@link ParsedCertificationRequest} used by
 * the PKI core. It supports CSR input encoded either directly as DER or as PEM
 * carrying a PKCS#10 object that can be converted to DER.
 * </p>
 *
 * <p>
 * The parser performs structural decoding and extraction of the key request
 * properties needed by the PKI runtime:
 * </p>
 * <ul>
 * <li>the CSR subject as {@link SubjectRef},</li>
 * <li>the subject public key information as DER-encoded
 * {@link EncodedObject},</li>
 * <li>a deterministic request identifier derived from the SHA-256 digest of the
 * CSR DER bytes,</li>
 * <li>framework-specific attributes containing the original CSR DER
 * payload.</li>
 * </ul>
 *
 * <p>
 * This class does not verify proof of possession and does not evaluate issuance
 * policy. Those responsibilities are delegated to other framework components.
 * The parser is concerned only with decoding and normalizing the PKCS#10
 * request content.
 * </p>
 *
 * <h2>Supported encodings</h2>
 * <ul>
 * <li>{@link Encoding#DER} - consumed directly,</li>
 * <li>{@link Encoding#PEM} - decoded to the enclosed DER content.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>The parsed CSR bytes are carried forward as
 * {@link BcX509Attributes#CSR_DER} for downstream framework use.</li>
 * <li>This parser must not be treated as successful proof-of-possession
 * validation.</li>
 * <li>Malformed, truncated, or semantically invalid PKCS#10 objects are
 * rejected with explicit exceptions.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is stateless and thread-safe.
 * </p>
 */
// PMD cannot infer the redaction boundary or the explicit closed parsing grammar.
@SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.CyclomaticComplexity" })
public final class BcX509CertificationRequestParser implements CertificationRequestParser {
    private static final int MAXIMUM_SUBJECT_DER_BYTES = 16 * 1024;
    private static final int MAXIMUM_SAN_DER_BYTES = 32 * 1024;
    private static final int MAXIMUM_SUBJECT_RDNS = 32;
    private static final int SINGLE_ATTRIBUTE_VALUE = 1;

    /**
     * Parses a PKCS#10 certification request into the normalized PKI request
     * representation.
     *
     * <p>
     * The supplied request must use the X.509 credential framework format
     * identifier. The encoded request is converted to DER if necessary, parsed as a
     * PKCS#10 structure, and normalized into a {@link ParsedCertificationRequest}.
     * </p>
     *
     * <p>
     * The returned parsed request contains:
     * </p>
     * <ul>
     * <li>a request id of the form {@code csr:&lt;sha256-of-csr-der&gt;},</li>
     * <li>the subject distinguished name derived from the CSR subject,</li>
     * <li>the subject public key info encoded as DER,</li>
     * <li>an attribute set containing the original CSR DER bytes under
     * {@link BcX509Attributes#CSR_DER},</li>
     * <li>empty optional issuer and profile information, because those are not
     * carried by this parser.</li>
     * </ul>
     *
     * @param request certification request to parse; must not be {@code null}
     * @return normalized parsed certification request
     * @throws IllegalArgumentException if {@code request} is {@code null}, if its
     *                                  format identifier does not match the X.509
     *                                  framework format, or if its encoding is
     *                                  unsupported
     * @throws PkiException             if the PKCS#10 request is structurally
     *                                  invalid or if the subject public key
     *                                  information cannot be extracted
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
        byte[] csrDer = toDer(enc);
        byte[] spki = null;
        try {
            PKCS10CertificationRequest csr;
            try {
                BcX509AlgorithmAdapter.requireCanonicalDer(csrDer);
                csr = new PKCS10CertificationRequest(csrDer);
            } catch (Exception ex) {
                throw new PkiException("Invalid PKCS#10 certification request: code=CSR_MALFORMED");
            }

            X500Name subject = csr.getSubject();
            List<SubjectRdn> subjectRdns = parseSubject(subject);
            SubjectRef subjectRef = subjectReference(subjectRdns);
            List<SubjectAlternativeName> subjectAlternativeNames = parseSubjectAlternativeNames(csr);

            try {
                spki = csr.getSubjectPublicKeyInfo().getEncoded();
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

    // Each approved RDN requires one immutable typed value and round-trip check.
    @SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.AvoidInstantiatingObjectsInLoops" })
    private static List<SubjectRdn> parseSubject(X500Name subject) {
        try {
            if (subject.getEncoded().length > MAXIMUM_SUBJECT_DER_BYTES) {
                throw new PkiException("CSR subject rejected: code=SUBJECT_TOO_LARGE");
            }
            RDN[] rdns = subject.getRDNs();
            if (rdns.length > MAXIMUM_SUBJECT_RDNS) {
                throw new PkiException("CSR subject rejected: code=SUBJECT_TOO_MANY_RDNS");
            }
            List<SubjectRdn> result = new ArrayList<>(rdns.length);
            for (RDN rdn : rdns) {
                if (rdn == null || rdn.isMultiValued() || rdn.getFirst() == null) {
                    throw new PkiException("CSR subject rejected: code=SUBJECT_MULTIVALUED");
                }
                SubjectRdnType type;
                try {
                    type = SubjectRdnType.fromOid(rdn.getFirst().getType().getId());
                } catch (IllegalArgumentException exception) {
                    throw new PkiException("CSR subject rejected: code=SUBJECT_RDN_UNSUPPORTED");
                }
                ASN1Encodable encodedValue = rdn.getFirst().getValue();
                if (!(encodedValue instanceof DERUTF8String || encodedValue instanceof DERPrintableString
                        || encodedValue instanceof DERIA5String) || !(encodedValue instanceof ASN1String stringValue)) {
                    throw new PkiException("CSR subject rejected: code=SUBJECT_VALUE_UNSUPPORTED");
                }
                SubjectRdn parsed = new SubjectRdn(type, stringValue.getString());
                X500Name rebuilt = BcX509ProfileSupport.subject(List.of(parsed));
                ASN1Encodable rebuiltValue = rebuilt.getRDNs()[0].getFirst().getValue();
                if (!(rebuiltValue instanceof ASN1String rebuiltString)
                        || !rebuiltString.getString().equals(parsed.value())) {
                    throw new PkiException("CSR subject rejected: code=SUBJECT_VALUE_AMBIGUOUS");
                }
                result.add(parsed);
            }
            return List.copyOf(result);
        } catch (PkiException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new PkiException("CSR subject rejected: code=SUBJECT_MALFORMED");
        }
    }

    private static SubjectRef subjectReference(List<SubjectRdn> rdns) {
        return new SubjectRef(rdns.isEmpty() ? "x509:empty-subject" : BcX509ProfileSupport.subject(rdns).toString());
    }

    // The branches enforce the closed PKCS#10 extensionRequest grammar.
    @SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.AvoidRethrowingException" })
    private static List<SubjectAlternativeName> parseSubjectAlternativeNames(PKCS10CertificationRequest csr) {
        Attribute[] allAttributes = csr.getAttributes();
        Attribute[] extensionRequests = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (extensionRequests.length > 1 || allAttributes.length != extensionRequests.length) {
            throw new PkiException("CSR attributes rejected: code=CSR_ATTRIBUTE_UNSUPPORTED");
        }
        if (extensionRequests.length == 0) {
            return List.of();
        }
        Attribute request = extensionRequests[0];
        if (request.getAttrValues().size() != SINGLE_ATTRIBUTE_VALUE) {
            throw new PkiException("CSR extensions rejected: code=EXTENSION_REQUEST_MALFORMED");
        }
        Extensions extensions;
        try {
            extensions = Extensions.getInstance(request.getAttrValues().getObjectAt(0));
        } catch (IllegalArgumentException exception) {
            throw new PkiException("CSR extensions rejected: code=EXTENSION_REQUEST_MALFORMED");
        }
        org.bouncycastle.asn1.ASN1ObjectIdentifier[] identifiers = extensions.getExtensionOIDs();
        if (identifiers.length != 1 || !Extension.subjectAlternativeName.equals(identifiers[0])) {
            throw new PkiException("CSR extensions rejected: code=EXTENSION_UNSUPPORTED");
        }
        Extension sanExtension = extensions.getExtension(Extension.subjectAlternativeName);
        if (sanExtension == null || sanExtension.isCritical()) {
            throw new PkiException("CSR extensions rejected: code=SAN_CRITICALITY_REQUESTED");
        }
        try {
            if (sanExtension.getEncoded().length > MAXIMUM_SAN_DER_BYTES) {
                throw new PkiException("CSR extensions rejected: code=SAN_TOO_LARGE");
            }
            GeneralName[] names = GeneralNames.getInstance(sanExtension.getParsedValue()).getNames();
            if (names.length == 0 || names.length > 64) {
                throw new PkiException("CSR extensions rejected: code=SAN_COUNT_INVALID");
            }
            List<SubjectAlternativeName> result = new ArrayList<>(names.length);
            Set<SubjectAlternativeName> unique = new HashSet<>();
            for (GeneralName name : names) {
                SubjectAlternativeName parsed = parseGeneralName(name);
                if (!unique.add(parsed)) {
                    throw new PkiException("CSR extensions rejected: code=SAN_DUPLICATE");
                }
                result.add(parsed);
            }
            return List.copyOf(result);
        } catch (PkiException exception) {
            throw exception;
        } catch (IllegalArgumentException | IllegalStateException | java.io.IOException exception) {
            throw new PkiException("CSR extensions rejected: code=SAN_MALFORMED");
        }
    }

    private static SubjectAlternativeName parseGeneralName(GeneralName name) {
        return switch (name.getTagNo()) {
            case GeneralName.dNSName -> new SubjectAlternativeName.DnsName(asAsciiString(name.getName()));
            case GeneralName.iPAddress ->
                new SubjectAlternativeName.IpAddress(ASN1OctetString.getInstance(name.getName()).getOctets());
            case GeneralName.uniformResourceIdentifier ->
                new SubjectAlternativeName.UriName(asAsciiString(name.getName()));
            case GeneralName.rfc822Name -> new SubjectAlternativeName.Rfc822Name(asAsciiString(name.getName()));
            default -> throw new PkiException("CSR extensions rejected: code=SAN_TYPE_UNSUPPORTED");
        };
    }

    private static String asAsciiString(ASN1Encodable value) {
        if (!(value instanceof ASN1String stringValue)) {
            throw new PkiException("CSR extensions rejected: code=SAN_MALFORMED");
        }
        return stringValue.getString();
    }

    /**
     * Converts the supplied encoded object to DER form.
     *
     * <p>
     * This method accepts only encodings that can represent a certification request
     * in the current X.509 parsing flow. {@link Encoding#DER} input is returned
     * unchanged. {@link Encoding#PEM} input is parsed as an ASCII PEM container and
     * the enclosed binary content is returned.
     * </p>
     *
     * <p>
     * The method performs only encoding-level conversion. It does not validate that
     * the resulting DER bytes actually contain a well-formed PKCS#10 certification
     * request. Structural validation remains the responsibility of the downstream
     * parser.
     * </p>
     *
     * @param obj encoded object to convert; must not be {@code null}
     * @return DER-form bytes corresponding to the supplied object
     * @throws NullPointerException     if {@code obj} is {@code null}
     * @throws IllegalArgumentException if the encoding is unsupported, if the PEM
     *                                  payload is empty, or if PEM decoding fails
     */
    private static byte[] toDer(EncodedObject obj) {
        Objects.requireNonNull(obj, "obj");

        return switch (obj.encoding()) {
            case DER -> obj.bytes();
            case PEM -> pemToDer(obj);
            default -> throw new IllegalArgumentException("Unsupported CSR encoding: " + obj.encoding());
        };
    }

    private static byte[] pemToDer(EncodedObject obj) {
        byte[] pemBytes = obj.bytes();
        try {
            return readPemContentOrThrow(pemBytes);
        } finally {
            java.util.Arrays.fill(pemBytes, (byte) 0);
        }
    }

    /**
     * Reads the binary content of a PEM object.
     *
     * <p>
     * The input is interpreted as US-ASCII text and parsed using {@link PemReader}.
     * If the PEM container is syntactically valid and contains an object, the raw
     * decoded content of that object is returned.
     * </p>
     *
     * <p>
     * This method does not validate the semantic type of the PEM object. It only
     * extracts its binary payload.
     * </p>
     *
     * @param pemBytes PEM-encoded input bytes; must not be {@code null}
     * @return decoded binary content of the PEM object
     * @throws NullPointerException     if {@code pemBytes} is {@code null}
     * @throws IllegalArgumentException if the PEM input is empty or cannot be
     *                                  parsed
     */
    private static byte[] readPemContentOrThrow(byte[] pemBytes) {
        Objects.requireNonNull(pemBytes, "pemBytes");

        try (PemReader reader = new PemReader(
                new InputStreamReader(new ByteArrayInputStream(pemBytes), StandardCharsets.US_ASCII))) {

            PemObject pemObject = reader.readPemObject();
            if (pemObject == null) {
                throw new IllegalArgumentException("Empty PEM");
            }
            return pemObject.getContent();
        } catch (java.io.IOException ex) {
            throw new IllegalArgumentException("Invalid PEM: code=CSR_PEM_INVALID");
        }
    }

    /**
     * Computes the SHA-256 digest of the supplied bytes and returns it as a
     * lowercase hexadecimal string.
     *
     * @param in input bytes; must not be {@code null}
     * @return hexadecimal SHA-256 digest
     * @throws IllegalStateException if SHA-256 is unexpectedly unavailable in the
     *                               runtime
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
