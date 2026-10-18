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
package zeroecho.pkix;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

import javax.security.auth.x500.X500Principal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import zeroecho.pkix.cert.CertificateBuilder;
import zeroecho.pkix.crl.CrlBuilder;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.csr.CertificationRequestBuilder;
import zeroecho.pkix.csr.CsrAttribute;
import zeroecho.pkix.ct.PreCertificateResult;
import zeroecho.pkix.ct.SignedCertificateTimestamp;
import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.OcspRequest;
import zeroecho.pkix.ocsp.OcspResponse;
import zeroecho.pkix.ocsp.OcspResponseBuilder;
import zeroecho.pkix.sign.ContentSigner;
import zeroecho.pkix.sign.ContentVerifier;
import zeroecho.pkix.spi.PkixProvider;

/**
 * The entry point of the ZeroEcho PKIX API: certificate, CSR, CRL, and OCSP
 * builders and parsers plus content signing and verification, all in terms of
 * standard {@code java.security} types.
 *
 * <p>
 * All operations are delegated to a single {@link PkixProvider}, resolved once as
 * follows: a {@link ServiceLoader}-published provider if present, else the class
 * named by the {@code zeroecho.pkix.provider} system property, else the built-in
 * BouncyCastle-backed provider. This keeps the concrete cryptographic toolkit an
 * implementation detail confined to the {@code lib} module.
 * </p>
 */
// The established PKIX facade name is part of the exported source and binary API.
@SuppressWarnings("PMD.ShortClassName")
public final class Pkix {
    private static final String TEXT_ALGORITHM = "algorithm";


    private static final String DEFAULT_PROVIDER = "zeroecho.pkix.bc.BcPkixProvider";
    private static final String DER_PARAMETER = "der";

    /** Holds the lazily resolved process-wide provider. */
    private static final class Holder {
        private static final PkixProvider PROVIDER = resolve();

        private static PkixProvider resolve() {
            java.util.Iterator<PkixProvider> providers = ServiceLoader.load(PkixProvider.class).iterator();
            if (providers.hasNext()) {
                return providers.next();
            }
            String override = System.getProperty("zeroecho.pkix.provider", DEFAULT_PROVIDER);
            if (!override.startsWith("zeroecho.")) {
                throw new IllegalStateException("PKIX provider class must be in the zeroecho package: " + override);
            }
            try {
                return Class.forName(override).asSubclass(PkixProvider.class).getDeclaredConstructor()
                        .newInstance();
            } catch (ReflectiveOperationException failure) {
                throw new IllegalStateException("Cannot load PKIX provider: " + override, failure);
            }
        }
    }

    private Pkix() {
    }

    /**
     * Returns the resolved PKIX provider.
     *
     * @return the active provider
     */
    public static PkixProvider provider() {
        return Holder.PROVIDER;
    }

    /**
     * Creates a certificate builder.
     *
     * @return a fresh certificate builder
     */
    public static CertificateBuilder certificateBuilder() {
        return provider().certificateBuilder();
    }

    /**
     * Verifies a certificate's standardized alternative signature against an
     * explicitly trusted issuer alternative key. The subject alternative key
     * extension does not establish issuer trust. No primary signature, validity
     * interval or certification path is validated by this method.
     * @param certificate nonnull certificate with all three alternative extensions
     * @param issuerAlternativeKey nonnull expected issuer alternative public key
     * @return false for absent, malformed or invalid alternative signatures
     * @throws NullPointerException if an argument is null
     * @throws UnsupportedOperationException if the provider lacks this capability
     */
    public static boolean verifyAlternativeSignature(X509Certificate certificate, PublicKey issuerAlternativeKey) {
        return provider().verifyAlternativeSignature(Objects.requireNonNull(certificate, "certificate"),
                Objects.requireNonNull(issuerAlternativeKey, "issuerAlternativeKey"));
    }

    /**
     * Parses a DER-encoded X.509 certificate.
     *
     * @param der the certificate DER
     * @return the parsed certificate
     */
    public static X509Certificate parseCertificate(byte[] der) {
        return provider().parseCertificate(Objects.requireNonNull(der, DER_PARAMETER));
    }

    /**
     * Creates a certification-request builder.
     *
     * @return a fresh CSR builder
     */
    public static CertificationRequestBuilder certificationRequestBuilder() {
        return provider().certificationRequestBuilder();
    }

    /**
     * Parses a DER-encoded PKCS#10 certification request.
     *
     * @param der the request DER
     * @return the parsed request
     */
    public static CertificationRequest parseCertificationRequest(byte[] der) {
        return provider().parseCertificationRequest(Objects.requireNonNull(der, DER_PARAMETER));
    }

    /**
     * Creates a CRL builder.
     *
     * @return a fresh CRL builder
     */
    public static CrlBuilder crlBuilder() {
        return provider().crlBuilder();
    }

    /**
     * Parses a DER-encoded X.509 CRL.
     *
     * @param der the CRL DER
     * @return the parsed CRL
     */
    public static X509CRL parseCrl(byte[] der) {
        return provider().parseCrl(Objects.requireNonNull(der, DER_PARAMETER));
    }

    /**
     * Creates an OCSP response builder.
     *
     * @return a fresh OCSP response builder
     */
    public static OcspResponseBuilder ocspResponseBuilder() {
        return provider().ocspResponseBuilder();
    }

    /**
     * Parses a DER-encoded OCSP request.
     *
     * @param der the request DER
     * @return the parsed request
     */
    public static OcspRequest parseOcspRequest(byte[] der) {
        return provider().parseOcspRequest(Objects.requireNonNull(der, DER_PARAMETER));
    }

    /**
     * Creates a content signer over a local private key.
     *
     * @param privateKey the signing private key
     * @param algorithm the signature algorithm identifier
     * @return a content signer
     * @throws zeroecho.core.err.UnsupportedRoleException if LMS/XMSS signing is
     *         requested; rejection precedes provider invocation
     */
    public static ContentSigner signer(PrivateKey privateKey, AlgorithmIdentifier algorithm) {
        zeroecho.core.alg.common.sig.StatefulSigningGuard.requireStateless(
                Objects.requireNonNull(algorithm, TEXT_ALGORITHM).oid(), privateKey);
        return provider().signer(Objects.requireNonNull(privateKey, "privateKey"),
                Objects.requireNonNull(algorithm, TEXT_ALGORITHM));
    }

    /**
     * Creates a content verifier over a public key.
     *
     * @param publicKey the verifying public key
     * @param algorithm the signature algorithm identifier
     * @return a content verifier
     */
    public static ContentVerifier verifier(PublicKey publicKey, AlgorithmIdentifier algorithm) {
        return provider().verifier(Objects.requireNonNull(publicKey, "publicKey"),
                Objects.requireNonNull(algorithm, TEXT_ALGORITHM));
    }

    /**
     * Creates a content verifier over a DER-encoded {@code SubjectPublicKeyInfo} and
     * a signature algorithm identifier, honouring any algorithm parameters carried by
     * the identifier.
     *
     * @param subjectPublicKeyInfoDer the SPKI DER of the verifying key
     * @param algorithm the signature algorithm identifier
     * @return a content verifier
     */
    public static ContentVerifier verifier(byte[] subjectPublicKeyInfoDer, AlgorithmIdentifier algorithm) {
        return provider().verifier(Objects.requireNonNull(subjectPublicKeyInfoDer, "spki"),
                Objects.requireNonNull(algorithm, TEXT_ALGORITHM));
    }

    /**
     * Computes the standard subject key identifier for a public key.
     *
     * @param publicKey the public key
     * @return the subject key identifier bytes
     */
    public static byte[] subjectKeyIdentifier(PublicKey publicKey) {
        return provider().subjectKeyIdentifier(Objects.requireNonNull(publicKey, "publicKey"));
    }

    /**
     * Computes an OCSP {@link CertId} for a certificate under a given issuer.
     *
     * @param issuer the issuer certificate
     * @param serialNumber the subject certificate serial number
     * @param digestAlgorithmOid the digest algorithm OID
     * @return the computed cert id
     */
    public static CertId computeCertId(X509Certificate issuer, BigInteger serialNumber,
            String digestAlgorithmOid) {
        return provider().computeCertId(Objects.requireNonNull(issuer, "issuer"),
                Objects.requireNonNull(serialNumber, "serialNumber"),
                Objects.requireNonNull(digestAlgorithmOid, "digestAlgorithmOid"));
    }

    /**
     * Builds a byte-exact distinguished name from typed relative distinguished names.
     *
     * @param relativeNames the ordered relative distinguished names
     * @return the distinguished name
     */
    public static X500Principal distinguishedName(List<RelativeDistinguishedName> relativeNames) {
        return provider().distinguishedName(relativeNames);
    }

    /**
     * Parses a DER-encoded X.509 {@code AlgorithmIdentifier}.
     *
     * @param der the algorithm-identifier DER
     * @return the parsed algorithm identifier
     */
    public static AlgorithmIdentifier parseAlgorithmIdentifier(byte[] der) {
        return provider().parseAlgorithmIdentifier(Objects.requireNonNull(der, DER_PARAMETER));
    }

    /**
     * Extracts the algorithm identifier from a DER-encoded {@code SubjectPublicKeyInfo}.
     *
     * @param subjectPublicKeyInfoDer the SPKI DER
     * @return the subject public key algorithm identifier
     */
    public static AlgorithmIdentifier subjectPublicKeyAlgorithm(byte[] subjectPublicKeyInfoDer) {
        return provider().subjectPublicKeyAlgorithm(Objects.requireNonNull(subjectPublicKeyInfoDer, "spki"));
    }

    /**
     * Recovers a public key from a DER-encoded {@code SubjectPublicKeyInfo}.
     *
     * @param subjectPublicKeyInfoDer the SPKI DER
     * @return the public key
     */
    public static PublicKey publicKeyFromSubjectPublicKeyInfo(byte[] subjectPublicKeyInfoDer) {
        return provider().publicKeyFromSubjectPublicKeyInfo(Objects.requireNonNull(subjectPublicKeyInfoDer, "spki"));
    }

    /**
     * Parses a DER-encoded OCSP response.
     *
     * @param der the response DER
     * @return the parsed response
     */
    public static OcspResponse parseOcspResponse(byte[] der) {
        return provider().parseOcspResponse(Objects.requireNonNull(der, DER_PARAMETER));
    }

    /**
     * Parses a DER-encoded X.500 {@code Name} into its ordered, single-valued
     * relative distinguished names, preserving each value's ASN.1 string type.
     *
     * @param nameDer the DER of an X.500 {@code Name}
     * @return the ordered relative distinguished names
     */
    public static List<RelativeDistinguishedName> parseDistinguishedName(byte[] nameDer) {
        return provider().parseDistinguishedName(Objects.requireNonNull(nameDer, "nameDer"));
    }

    /**
     * Parses a distinguished-name string into its ordered, single-valued relative
     * distinguished names, preserving the written order.
     *
     * @param name the distinguished-name string
     * @return the ordered relative distinguished names
     */
    public static List<RelativeDistinguishedName> parseDistinguishedNameString(String name) {
        return provider().parseDistinguishedNameString(Objects.requireNonNull(name, "name"));
    }

    /**
     * Returns the raw contents of the public-key {@code BIT STRING} of a DER-encoded
     * {@code SubjectPublicKeyInfo}.
     *
     * @param subjectPublicKeyInfoDer the SPKI DER
     * @return the public-key bit-string content bytes
     */
    public static byte[] subjectPublicKeyBytes(byte[] subjectPublicKeyInfoDer) {
        return provider().subjectPublicKeyBytes(Objects.requireNonNull(subjectPublicKeyInfoDer, "spki"));
    }

    /**
     * Returns the exact DER of the {@code SubjectPublicKeyInfo} embedded in a
     * certificate.
     *
     * @param certificate the certificate
     * @return the exact SPKI DER
     */
    public static byte[] subjectPublicKeyInfo(X509Certificate certificate) {
        return provider().subjectPublicKeyInfo(Objects.requireNonNull(certificate, "certificate"));
    }

    /**
     * Builds the DER of a {@code SubjectPublicKeyInfo} from an algorithm identifier
     * and the raw public-key {@code BIT STRING} contents.
     *
     * @param algorithm the subject public-key algorithm identifier
     * @param publicKeyBits the raw public-key bit-string content bytes
     * @return the SPKI DER
     */
    public static byte[] buildSubjectPublicKeyInfo(AlgorithmIdentifier algorithm, byte[] publicKeyBits) {
        return provider().buildSubjectPublicKeyInfo(Objects.requireNonNull(algorithm, TEXT_ALGORITHM),
                Objects.requireNonNull(publicKeyBits, "publicKeyBits"));
    }

    /**
     * Parses a DER-encoded X.509 {@code Extensions} sequence into typed extensions.
     *
     * @param der the DER of an {@code Extensions} sequence
     * @return the parsed extensions in order
     */
    public static List<CertificateExtension> parseExtensions(byte[] der) {
        return provider().parseExtensions(Objects.requireNonNull(der, DER_PARAMETER));
    }

    /**
     * Parses a DER-encoded {@code GeneralNames} sequence into typed general names.
     *
     * @param der the DER of a {@code GeneralNames} sequence
     * @return the parsed general names in order
     */
    public static List<GeneralName> parseGeneralNames(byte[] der) {
        return provider().parseGeneralNames(Objects.requireNonNull(der, DER_PARAMETER));
    }

    /**
     * Reassembles a signed certificate or CRL from its {@code tbs} bytes and a raw
     * signature, repeating the algorithm identifier embedded in the {@code tbs}.
     *
     * @param tbs the {@code tbsCertificate} or {@code tbsCertList} DER
     * @param signature the raw signature bytes
     * @param crl {@code true} for a CRL, {@code false} for a certificate
     * @return the DER of the assembled signed object
     */
    public static byte[] assembleCertificateOrCrl(byte[] tbs, byte[] signature, boolean crl) {
        return provider().assembleCertificateOrCrl(Objects.requireNonNull(tbs, "tbs"),
                Objects.requireNonNull(signature, "signature"), crl);
    }

    /**
     * Reassembles a successful {@code OCSPResponse} from its {@code tbsResponseData},
     * a DER-encoded signature algorithm identifier, and a raw signature.
     *
     * @param tbsResponseData the {@code tbsResponseData} DER
     * @param signatureAlgorithmDer the DER of the signature {@code AlgorithmIdentifier}
     * @param signature the raw signature bytes
     * @return the DER of the assembled OCSP response
     */
    public static byte[] assembleOcspResponse(byte[] tbsResponseData, byte[] signatureAlgorithmDer,
            byte[] signature) {
        return provider().assembleOcspResponse(Objects.requireNonNull(tbsResponseData, "tbsResponseData"),
                Objects.requireNonNull(signatureAlgorithmDer, "signatureAlgorithmDer"),
                Objects.requireNonNull(signature, "signature"));
    }

    /**
     * Reassembles a successful OCSP response from unsigned {@code ResponseData},
     * an encoded signature algorithm, a raw signature and an ordered certificate
     * chain. Certificates are embedded in the supplied order without sorting or
     * trust validation. An empty chain omits the optional {@code certs} field,
     * matching the three-argument overload. No signer is invoked and the raw
     * signature is not cryptographically verified by assembly.
     *
     * <p>Inputs remain caller-owned and are not retained. The returned DER array
     * is independent. Time and auxiliary memory are linear in response-data,
     * algorithm, signature and total embedded-certificate bytes. No aggregate
     * live-response size limit is introduced.</p>
     *
     * @param tbsResponseData nonnull DER-encoded unsigned {@code ResponseData}
     * @param signatureAlgorithmDer nonnull DER-encoded signature {@code AlgorithmIdentifier}
     * @param signature nonnull raw signature bytes
     * @param chain nonnull certificate list in exact embedding order, with no null elements
     * @return freshly encoded successful OCSP response DER
     * @throws NullPointerException if an argument or a chain element is null
     * @throws IllegalArgumentException if DER parsing or certificate encoding fails
     */
    public static byte[] assembleOcspResponse(byte[] tbsResponseData, byte[] signatureAlgorithmDer,
            byte[] signature, List<X509Certificate> chain) {
        return provider().assembleOcspResponse(Objects.requireNonNull(tbsResponseData, "tbsResponseData"),
                Objects.requireNonNull(signatureAlgorithmDer, "signatureAlgorithmDer"),
                Objects.requireNonNull(signature, "signature"), Objects.requireNonNull(chain, "chain"));
    }

    /**
     * Returns the DER encoding of an X.509 {@code AlgorithmIdentifier}.
     *
     * @param algorithm the algorithm identifier
     * @return the DER encoding
     */
    public static byte[] encodeAlgorithmIdentifier(AlgorithmIdentifier algorithm) {
        return provider().encodeAlgorithmIdentifier(Objects.requireNonNull(algorithm, TEXT_ALGORITHM));
    }

    /**
     * Renders a distinguished name, built from typed relative distinguished names,
     * as its canonical string form.
     *
     * @param relativeNames the ordered relative distinguished names
     * @return the string form of the distinguished name
     */
    public static String distinguishedNameString(List<RelativeDistinguishedName> relativeNames) {
        return provider().distinguishedNameString(Objects.requireNonNull(relativeNames, "relativeNames"));
    }

    // -------------------------------------------------------------------------
    // EST (RFC 7030) operations
    // -------------------------------------------------------------------------

    /**
     * Parses a PKCS#10 certification request from PEM or DER encoding, verifying the
     * proof-of-possession self-signature before returning.
     *
     * <p>PEM input is detected by the presence of a {@code -----BEGIN} header; all
     * other input is treated as DER. Base64-encoded DER without PEM headers is also
     * accepted via standard {@link Base64} decoding.</p>
     *
     * @param csrPemOrDer PEM or DER bytes of the certification request; must not be null
     * @return the parsed and verified certification request
     * @throws CertificationRequestException if the CSR cannot be parsed or its
     *         self-signature fails verification
     */
    public static CertificationRequest parseCsr(byte[] csrPemOrDer) throws CertificationRequestException {
        Objects.requireNonNull(csrPemOrDer, "csrPemOrDer");
        byte[] der;
        String pem = new String(csrPemOrDer, StandardCharsets.US_ASCII).trim();
        if (pem.startsWith("-----")) {
            String stripped = pem
                    .replaceAll("-----[^\n]*-----", "")
                    .replaceAll("\\s+", "");
            try {
                der = Base64.getDecoder().decode(stripped);
            } catch (IllegalArgumentException failure) {
                throw new CertificationRequestException("Invalid PEM base64 encoding", failure);
            }
        } else {
            der = csrPemOrDer;
        }
        CertificationRequest csr;
        try {
            csr = provider().parseCertificationRequest(der);
        } catch (IllegalArgumentException failure) {
            throw new CertificationRequestException("Cannot parse certification request", failure);
        }
        if (!csr.verifySelfSignature()) {
            throw new CertificationRequestException("Certification request self-signature is invalid");
        }
        return csr;
    }

    /**
     * Encodes a list of X.509 certificates as a CMS certs-only message, suitable for
     * EST {@code /cacerts} and {@code /simpleenroll} responses.
     *
     * @param chain ordered certificate list; must not be null or empty
     * @return DER-encoded CMS {@code ContentInfo} wrapping {@code SignedData}
     * @throws IllegalArgumentException if encoding fails
     */
    public static byte[] encodeCertsOnly(List<X509Certificate> chain) {
        return provider().encodeCertsOnly(Objects.requireNonNull(chain, "chain"));
    }

    /**
     * Encodes a list of CSR attributes as an RFC 7030 {@code CsrAttrs} DER structure,
     * suitable for EST {@code /csrattrs} responses.
     *
     * @param attributes the CSR attributes to encode; must not be null
     * @return DER-encoded {@code CsrAttrs} sequence
     * @throws IllegalArgumentException if encoding fails
     */
    public static byte[] encodeCsrAttrs(List<CsrAttribute> attributes) {
        return provider().encodeCsrAttrs(Objects.requireNonNull(attributes, "attributes"));
    }

    /**
     * Builds a new PKCS#10 CSR using a server-generated key pair, copying the subject
     * DN and attributes from the original CSR, for use in EST {@code /serverkeygen}.
     *
     * @param originalCsrDer      original PKCS#10 CSR DER (source of subject and attributes)
     * @param generatedPublicKey  server-generated public key
     * @param generatedPrivateKey server-generated private key
     * @return new PKCS#10 CSR DER self-signed with the generated key
     * @throws IllegalArgumentException if CSR construction or signing fails
     * @throws zeroecho.core.err.UnsupportedRoleException if the private key uses
     *         LMS/XMSS; rejection precedes provider invocation
     */
    public static byte[] buildServerKeygenCsr(byte[] originalCsrDer, PublicKey generatedPublicKey,
            PrivateKey generatedPrivateKey) {
        zeroecho.core.alg.common.sig.StatefulSigningGuard.requireStateless(null, generatedPrivateKey);
        return provider().buildServerKeygenCsr(
                Objects.requireNonNull(originalCsrDer, "originalCsrDer"),
                Objects.requireNonNull(generatedPublicKey, "generatedPublicKey"),
                Objects.requireNonNull(generatedPrivateKey, "generatedPrivateKey"));
    }

    /**
     * Encrypts a PKCS#8 private key for a single recipient using CMS
     * {@code EnvelopedData} with AES-256-GCM content encryption, for use in EST
     * {@code /serverkeygen} responses.
     *
     * @param pkcs8PrivateKeyDer   DER-encoded PKCS#8 private key to encrypt
     * @param recipientCertificate the recipient's certificate (public key used for wrap)
     * @return DER-encoded CMS {@code ContentInfo} wrapping the {@code EnvelopedData}
     * @throws IllegalArgumentException if encryption fails
     */
    public static byte[] encryptPrivateKeyForRecipient(byte[] pkcs8PrivateKeyDer,
            X509Certificate recipientCertificate) {
        return provider().encryptPrivateKeyForRecipient(
                Objects.requireNonNull(pkcs8PrivateKeyDer, "pkcs8PrivateKeyDer"),
                Objects.requireNonNull(recipientCertificate, "recipientCertificate"));
    }

    // -------------------------------------------------------------------------
    // Certificate Transparency (RFC 9162) operations
    // -------------------------------------------------------------------------

    /**
     * Builds a CT pre-certificate by adding the CT poison extension to a
     * {@code TBSCertificate} and signing it, ready for submission to CT logs.
     *
     * @param tbsCertificateDer DER-encoded {@code TBSCertificate}
     * @param issuerChainDer    DER-encoded issuer chain (issuer first, root last)
     * @param signer            configured signer for the issuing CA key
     * @return pre-certificate DER and its chain
     * @throws IllegalArgumentException if pre-certificate construction or signing fails
     */
    public static PreCertificateResult buildPreCertificate(byte[] tbsCertificateDer,
            List<byte[]> issuerChainDer, ContentSigner signer) {
        return provider().buildPreCertificate(
                Objects.requireNonNull(tbsCertificateDer, "tbsCertificateDer"),
                Objects.requireNonNull(issuerChainDer, "issuerChainDer"),
                Objects.requireNonNull(signer, "signer"));
    }

    /**
     * Embeds a list of SCTs into a {@code TBSCertificate} as the SCT list extension
     * (OID {@code 1.3.6.1.4.1.11129.2.4.2}), replacing any existing CT poison or SCT
     * list extension.
     *
     * @param tbsCertificateDer DER-encoded {@code TBSCertificate}
     * @param scts              verified SCTs to embed; must contain at least one entry
     * @return modified DER-encoded {@code TBSCertificate} with the SCT list extension
     * @throws IllegalArgumentException if embedding fails
     */
    public static byte[] embedScts(byte[] tbsCertificateDer,
            List<SignedCertificateTimestamp> scts) {
        return provider().embedScts(
                Objects.requireNonNull(tbsCertificateDer, "tbsCertificateDer"),
                Objects.requireNonNull(scts, "scts"));
    }

    /**
     * Parses a Signed Certificate Timestamp from the JSON response body returned by a
     * CT log's {@code add-pre-chain} or {@code add-chain} endpoint.
     *
     * @param jsonResponseBody raw response body bytes from the CT log; must not be {@code null}
     * @return the parsed SCT
     * @throws IllegalArgumentException if the JSON is malformed or the SCT structure is invalid
     */
    public static SignedCertificateTimestamp parseSct(byte[] jsonResponseBody) {
        return provider().parseSct(Objects.requireNonNull(jsonResponseBody, "jsonResponseBody"));
    }

    /**
     * Verifies an SCT's digital signature against a known CT log public key.
     *
     * @param sct            the SCT to verify; must not be {@code null}
     * @param ctLogPublicKey EC or RSA public key of the CT log; must not be {@code null}
     * @param preCertDer     DER-encoded pre-certificate that was submitted; must not be {@code null}
     * @return {@code true} if the signature is valid, {@code false} otherwise
     * @throws IllegalArgumentException if the algorithm is unsupported or the key is invalid
     */
    public static boolean verifySct(SignedCertificateTimestamp sct,
            PublicKey ctLogPublicKey, byte[] preCertDer) {
        return provider().verifySct(
                Objects.requireNonNull(sct, "sct"),
                Objects.requireNonNull(ctLogPublicKey, "ctLogPublicKey"),
                Objects.requireNonNull(preCertDer, "preCertDer"));
    }
}
