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
package zeroecho.pkix.cert;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.ExtendedKeyUsage;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.sign.ContentSigner;

/**
 * A fluent builder for an unsigned X.509 v3 certificate body or a signed standard
 * {@link X509Certificate}.
 *
 * <p>
 * The builder collects the certificate fields and extensions, then produces the
 * final certificate by streaming the {@code tbsCertificate} through a caller
 * supplied {@link ContentSigner} — so the private key never enters the builder.
 * Typed setters are provided for the common extensions; arbitrary extensions can
 * be added with {@link #addExtension(CertificateExtension)}.
 * For deferred signing, {@link #buildTbs(AlgorithmIdentifier)} returns the exact
 * canonical unsigned body without a signer invocation.
 * </p>
 *
 * <p>
 * Instances are single-use and not thread-safe.
 * </p>
 */
public interface CertificateBuilder {

    /**
     * Sets the certificate serial number (required, positive).
     *
     * @param serialNumber the serial number
     * @return this builder
     */
    CertificateBuilder serialNumber(BigInteger serialNumber);

    /**
     * Sets the subject distinguished name (required).
     *
     * @param subject the subject DN
     * @return this builder
     */
    CertificateBuilder subject(X500Principal subject);

    /**
     * Sets the issuer distinguished name (required).
     *
     * @param issuer the issuer DN
     * @return this builder
     */
    CertificateBuilder issuer(X500Principal issuer);

    /**
     * Sets the validity window (required).
     *
     * @param notBefore inclusive start of validity
     * @param notAfter inclusive end of validity
     * @return this builder
     */
    CertificateBuilder validity(Instant notBefore, Instant notAfter);

    /**
     * Sets the subject public key (required, unless {@link #publicKeyInfo(byte[])} is used).
     *
     * @param subjectPublicKey the subject public key
     * @return this builder
     */
    CertificateBuilder publicKey(PublicKey subjectPublicKey);

    /**
     * Sets the subject public key from the exact DER of a {@code SubjectPublicKeyInfo},
     * preserving the original encoding byte-for-byte (required, unless
     * {@link #publicKey(PublicKey)} is used).
     *
     * @param subjectPublicKeyInfoDer the exact SPKI DER
     * @return this builder
     */
    CertificateBuilder publicKeyInfo(byte[] subjectPublicKeyInfoDer);

    /**
     * Adds a {@code BasicConstraints} extension.
     *
     * @param basicConstraints the basic-constraints value
     * @param critical whether the extension is critical
     * @return this builder
     */
    CertificateBuilder basicConstraints(BasicConstraints basicConstraints, boolean critical);

    /**
     * Adds a {@code KeyUsage} extension.
     *
     * @param keyUsage the set of key-usage bits
     * @param critical whether the extension is critical
     * @return this builder
     */
    CertificateBuilder keyUsage(Set<KeyUsage> keyUsage, boolean critical);

    /**
     * Adds an {@code ExtendedKeyUsage} extension.
     *
     * @param extendedKeyUsage the extended key usage value
     * @param critical whether the extension is critical
     * @return this builder
     */
    CertificateBuilder extendedKeyUsage(ExtendedKeyUsage extendedKeyUsage, boolean critical);

    /**
     * Adds a {@code SubjectAlternativeName} extension.
     *
     * @param names the general names
     * @param critical whether the extension is critical
     * @return this builder
     */
    CertificateBuilder subjectAlternativeNames(List<GeneralName> names, boolean critical);

    /**
     * Adds a {@code SubjectKeyIdentifier} derived from the subject public key.
     *
     * @return this builder
     */
    CertificateBuilder subjectKeyIdentifier();

    /**
     * Adds an {@code AuthorityKeyIdentifier} carrying the given key identifier.
     *
     * @param keyIdentifier the issuer subject-key-identifier bytes
     * @return this builder
     */
    CertificateBuilder authorityKeyIdentifier(byte[] keyIdentifier);

    /**
     * Adds an arbitrary extension.
     *
     * @param extension the extension to add
     * @return this builder
     */
    CertificateBuilder addExtension(CertificateExtension extension);

    /**
     * Encodes the configured unsigned X.509 v3 {@code TBSCertificate} as canonical DER.
     * The supplied identifier is embedded exactly as the certificate signature
     * algorithm. This method performs no signing and invokes no content signer.
     *
     * <p>Required fields and extensions are the same as for {@link #build(ContentSigner)}.
     * Local time and auxiliary memory are linear in the resulting TBS byte size.</p>
     *
     * @param signatureAlgorithm exact signature algorithm and parameter representation
     * @return newly allocated canonical DER of the unsigned certificate body
     * @throws NullPointerException if the algorithm or a required field is missing
     * @throws IllegalArgumentException if fields or extensions cannot form a certificate body
     * @throws IllegalStateException if DER encoding fails
     */
    byte[] buildTbs(AlgorithmIdentifier signatureAlgorithm);

    /**
     * Encodes the standardized alternative-signature input, omitting both the
     * {@code TBSCertificate.signature} field and the {@code AltSignatureValue}
     * extension. Other configured fields and extension order are preserved.
     * The alternative algorithm and subject alternative public key extensions
     * must be supplied by the caller. No signer is invoked.
     * Time and auxiliary memory are linear in the encoded body size.
     * @return newly allocated canonical DER pre-TBS sequence
     * @throws UnsupportedOperationException if this provider lacks this capability
     * @throws IllegalArgumentException if configured fields or extensions are invalid
     * @throws NullPointerException if a required field is missing
     * @throws IllegalStateException if encoding fails
     */
    default byte[] buildAlternativeSignatureTbs() {
        throw new UnsupportedOperationException("Alternative-signature pre-TBS is unavailable");
    }

    /**
     * Signs the assembled {@code tbsCertificate} with the given signer and returns
     * the resulting certificate.
     *
     * @param signer the content signer supplying the signature and algorithm
     * @return the signed certificate
     */
    X509Certificate build(ContentSigner signer);
}
