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

import zeroecho.pkix.cert.CertificateBuilder;
import zeroecho.pkix.crl.CrlBuilder;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.csr.CertificationRequestBuilder;
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
     */
    public static ContentSigner signer(PrivateKey privateKey, AlgorithmIdentifier algorithm) {
        return provider().signer(privateKey, algorithm);
    }

    /**
     * Creates a content verifier over a public key.
     *
     * @param publicKey the verifying public key
     * @param algorithm the signature algorithm identifier
     * @return a content verifier
     */
    public static ContentVerifier verifier(PublicKey publicKey, AlgorithmIdentifier algorithm) {
        return provider().verifier(publicKey, algorithm);
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
                Objects.requireNonNull(algorithm, "algorithm"));
    }

    /**
     * Computes the standard subject key identifier for a public key.
     *
     * @param publicKey the public key
     * @return the subject key identifier bytes
     */
    public static byte[] subjectKeyIdentifier(PublicKey publicKey) {
        return provider().subjectKeyIdentifier(publicKey);
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
        return provider().computeCertId(issuer, serialNumber, digestAlgorithmOid);
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
        return provider().buildSubjectPublicKeyInfo(Objects.requireNonNull(algorithm, "algorithm"),
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
     * Returns the DER encoding of an X.509 {@code AlgorithmIdentifier}.
     *
     * @param algorithm the algorithm identifier
     * @return the DER encoding
     */
    public static byte[] encodeAlgorithmIdentifier(AlgorithmIdentifier algorithm) {
        return provider().encodeAlgorithmIdentifier(Objects.requireNonNull(algorithm, "algorithm"));
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
}
