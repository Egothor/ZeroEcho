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
package zeroecho.pkix.spi;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.RelativeDistinguishedName;
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

/**
 * The service-provider contract that backs the ZeroEcho PKIX API.
 *
 * <p>
 * A provider supplies the concrete builders, parsers, and signing operators. The
 * default provider is implemented with BouncyCastle and is confined to the
 * {@code lib} module; a JDK-only or in-house provider can replace it in future
 * without any change to the public {@code zeroecho.pkix} API. Providers are
 * resolved by {@link zeroecho.pkix.Pkix}.
 * </p>
 */
public interface PkixProvider {

    /**
     * Returns the stable provider identifier (for diagnostics and selection).
     *
     * @return the provider id
     */
    String id();

    /**
     * Creates a new certificate builder.
     *
     * @return a fresh certificate builder
     */
    CertificateBuilder certificateBuilder();

    /**
     * Parses a DER-encoded X.509 certificate.
     *
     * @param der the certificate DER
     * @return the parsed certificate
     */
    X509Certificate parseCertificate(byte[] der);

    /**
     * Creates a new certification-request builder.
     *
     * @return a fresh CSR builder
     */
    CertificationRequestBuilder certificationRequestBuilder();

    /**
     * Parses a DER-encoded PKCS#10 certification request.
     *
     * @param der the request DER
     * @return the parsed request
     */
    CertificationRequest parseCertificationRequest(byte[] der);

    /**
     * Creates a new CRL builder.
     *
     * @return a fresh CRL builder
     */
    CrlBuilder crlBuilder();

    /**
     * Parses a DER-encoded X.509 CRL.
     *
     * @param der the CRL DER
     * @return the parsed CRL
     */
    X509CRL parseCrl(byte[] der);

    /**
     * Creates a new OCSP response builder.
     *
     * @return a fresh OCSP response builder
     */
    OcspResponseBuilder ocspResponseBuilder();

    /**
     * Parses a DER-encoded OCSP request.
     *
     * @param der the request DER
     * @return the parsed request
     */
    OcspRequest parseOcspRequest(byte[] der);

    /**
     * Creates a content signer over a local private key.
     *
     * @param privateKey the signing private key
     * @param algorithm the signature algorithm identifier
     * @return a content signer
     */
    ContentSigner signer(PrivateKey privateKey, AlgorithmIdentifier algorithm);

    /**
     * Creates a content verifier over a public key.
     *
     * @param publicKey the verifying public key
     * @param algorithm the signature algorithm identifier
     * @return a content verifier
     */
    ContentVerifier verifier(PublicKey publicKey, AlgorithmIdentifier algorithm);

    /**
     * Creates a content verifier over a DER-encoded {@code SubjectPublicKeyInfo} and
     * a signature algorithm identifier, honouring any algorithm parameters (such as
     * RSASSA-PSS parameters) carried by the identifier.
     *
     * @param subjectPublicKeyInfoDer the SPKI DER of the verifying key
     * @param algorithm the signature algorithm identifier
     * @return a content verifier
     */
    ContentVerifier verifier(byte[] subjectPublicKeyInfoDer, AlgorithmIdentifier algorithm);

    /**
     * Computes the standard subject key identifier (SHA-1 of the SPKI) for a key.
     *
     * @param publicKey the public key
     * @return the subject key identifier bytes
     */
    byte[] subjectKeyIdentifier(PublicKey publicKey);

    /**
     * Computes an OCSP {@link CertId} for a certificate under a given issuer.
     *
     * @param issuer the issuer certificate
     * @param serialNumber the subject certificate serial number
     * @param digestAlgorithmOid the digest algorithm OID for the hashes
     * @return the computed cert id
     */
    CertId computeCertId(X509Certificate issuer, BigInteger serialNumber, String digestAlgorithmOid);

    /**
     * Builds a byte-exact distinguished name from typed relative distinguished names.
     *
     * @param relativeNames the ordered relative distinguished names
     * @return the distinguished name
     */
    X500Principal distinguishedName(List<RelativeDistinguishedName> relativeNames);

    /**
     * Parses a DER-encoded X.509 {@code AlgorithmIdentifier}.
     *
     * @param der the algorithm-identifier DER
     * @return the parsed algorithm identifier
     */
    AlgorithmIdentifier parseAlgorithmIdentifier(byte[] der);

    /**
     * Extracts the algorithm identifier from a DER-encoded {@code SubjectPublicKeyInfo}.
     *
     * @param subjectPublicKeyInfoDer the SPKI DER
     * @return the subject public key algorithm identifier
     */
    AlgorithmIdentifier subjectPublicKeyAlgorithm(byte[] subjectPublicKeyInfoDer);

    /**
     * Recovers a public key from a DER-encoded {@code SubjectPublicKeyInfo}.
     *
     * @param subjectPublicKeyInfoDer the SPKI DER
     * @return the public key
     */
    PublicKey publicKeyFromSubjectPublicKeyInfo(byte[] subjectPublicKeyInfoDer);

    /**
     * Parses a DER-encoded OCSP response.
     *
     * @param der the response DER
     * @return the parsed response
     */
    OcspResponse parseOcspResponse(byte[] der);

    /**
     * Parses a DER-encoded X.500 {@code Name} into its ordered, single-valued
     * relative distinguished names, preserving the ASN.1 string type of each value.
     *
     * @param nameDer the DER encoding of an X.500 {@code Name}
     * @return the ordered relative distinguished names
     */
    List<RelativeDistinguishedName> parseDistinguishedName(byte[] nameDer);

    /**
     * Parses a distinguished-name string (as produced by
     * {@link #distinguishedNameString(java.util.List)}) into its ordered,
     * single-valued relative distinguished names, preserving the written order.
     *
     * @param name the distinguished-name string
     * @return the ordered relative distinguished names
     */
    List<RelativeDistinguishedName> parseDistinguishedNameString(String name);

    /**
     * Returns the raw contents of the public-key {@code BIT STRING} of a DER-encoded
     * {@code SubjectPublicKeyInfo} (the bytes after the unused-bits octet).
     *
     * @param subjectPublicKeyInfoDer the SPKI DER
     * @return the public-key bit-string content bytes
     */
    byte[] subjectPublicKeyBytes(byte[] subjectPublicKeyInfoDer);

    /**
     * Returns the exact DER of the {@code SubjectPublicKeyInfo} embedded in a
     * certificate, byte-for-byte as encoded in the certificate.
     *
     * @param certificate the certificate
     * @return the exact SPKI DER
     */
    byte[] subjectPublicKeyInfo(X509Certificate certificate);

    /**
     * Builds the DER of a {@code SubjectPublicKeyInfo} from an algorithm identifier
     * and the raw public-key {@code BIT STRING} contents.
     *
     * @param algorithm the subject public-key algorithm identifier
     * @param publicKeyBits the raw public-key bit-string content bytes
     * @return the SPKI DER
     */
    byte[] buildSubjectPublicKeyInfo(AlgorithmIdentifier algorithm, byte[] publicKeyBits);

    /**
     * Parses a DER-encoded X.509 {@code Extensions} sequence into typed extensions.
     *
     * @param der the DER of an {@code Extensions} sequence
     * @return the parsed extensions in order
     */
    List<zeroecho.pkix.CertificateExtension> parseExtensions(byte[] der);

    /**
     * Parses a DER-encoded {@code GeneralNames} sequence into typed general names.
     *
     * @param der the DER of a {@code GeneralNames} sequence
     * @return the parsed general names in order
     */
    List<zeroecho.pkix.GeneralName> parseGeneralNames(byte[] der);

    /**
     * Reassembles a signed certificate or CRL from its {@code tbs} bytes and a raw
     * signature, repeating the algorithm identifier embedded in the {@code tbs} as
     * the outer {@code signatureAlgorithm}, and validates that the result parses.
     *
     * @param tbs the {@code tbsCertificate} or {@code tbsCertList} DER
     * @param signature the raw signature bytes
     * @param crl {@code true} for a CRL, {@code false} for a certificate
     * @return the DER of the assembled signed object
     */
    byte[] assembleCertificateOrCrl(byte[] tbs, byte[] signature, boolean crl);

    /**
     * Reassembles a successful {@code OCSPResponse} wrapping a {@code BasicOCSPResponse}
     * from its {@code tbsResponseData}, a DER-encoded signature algorithm identifier,
     * and a raw signature, and validates that the result parses as successful.
     *
     * @param tbsResponseData the {@code tbsResponseData} DER
     * @param signatureAlgorithmDer the DER of the signature {@code AlgorithmIdentifier}
     * @param signature the raw signature bytes
     * @return the DER of the assembled OCSP response
     */
    byte[] assembleOcspResponse(byte[] tbsResponseData, byte[] signatureAlgorithmDer, byte[] signature);

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
    byte[] assembleOcspResponse(byte[] tbsResponseData, byte[] signatureAlgorithmDer, byte[] signature,
            java.util.List<X509Certificate> chain);

    /**
     * Returns the DER encoding of an X.509 {@code AlgorithmIdentifier}.
     *
     * @param algorithm the algorithm identifier
     * @return the DER encoding
     */
    byte[] encodeAlgorithmIdentifier(AlgorithmIdentifier algorithm);

    /**
     * Renders a distinguished name, built from typed relative distinguished names,
     * as its canonical string form (attribute short names, most-significant first).
     *
     * @param relativeNames the ordered relative distinguished names
     * @return the string form of the distinguished name
     */
    String distinguishedNameString(List<RelativeDistinguishedName> relativeNames);
}
