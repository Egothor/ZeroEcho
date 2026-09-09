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
package zeroecho.pkix.csr;

import java.security.PublicKey;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.sign.ContentVerifier;

/**
 * A parsed PKCS#10 certification request (RFC 2986).
 *
 * <p>
 * The type exposes the request's subject, public key, and requested extensions in
 * ZeroEcho PKIX terms, and gives access to the exact signed bytes so that proof of
 * possession can be verified either with the request's own key
 * ({@link #verifySelfSignature()}) or with an externally supplied
 * {@link ContentVerifier} over {@link #certificationRequestInfo()} — the latter is
 * how a signing service re-verifies a request without holding the key locally.
 * </p>
 */
public interface CertificationRequest {

    /**
     * Returns the requested subject distinguished name.
     *
     * @return the subject DN
     */
    X500Principal subject();

    /**
     * Returns the subject public key carried by the request.
     *
     * @return the subject public key
     */
    PublicKey publicKey();

    /**
     * Returns the signature algorithm identifier of the request self-signature.
     *
     * @return the signature algorithm identifier
     */
    AlgorithmIdentifier signatureAlgorithm();

    /**
     * Returns the requested subject alternative names, if any.
     *
     * @return the requested SANs (possibly empty)
     */
    List<GeneralName> requestedSubjectAlternativeNames();

    /**
     * Returns the requested v3 extensions, if any.
     *
     * @return the requested extensions (possibly empty)
     */
    List<CertificateExtension> requestedExtensions();

    /**
     * Returns the request attributes (excluding the extension-request attribute,
     * which is surfaced via {@link #requestedExtensions()}).
     *
     * @return the request attributes (possibly empty)
     */
    List<CsrAttribute> attributes();

    /**
     * Returns every PKCS#10 attribute, including the extension-request attribute,
     * as raw {@code (oid, DER values)} pairs without interpreting any extension.
     *
     * <p>
     * This gives callers that enforce a strict request grammar full control over
     * attribute cardinality and shape without depending on the toolkit's own
     * extension parsing.
     * </p>
     *
     * @return the raw attributes (possibly empty)
     */
    List<CsrAttribute> rawAttributes();

    /**
     * Returns the exact DER of the {@code SubjectPublicKeyInfo} carried by the
     * request, byte-for-byte as encoded in the request.
     *
     * @return the exact SPKI DER
     */
    byte[] subjectPublicKeyInfo();

    /**
     * Returns the exact DER of the {@code certificationRequestInfo} (the
     * to-be-signed portion of the request).
     *
     * @return the to-be-signed DER
     */
    byte[] certificationRequestInfo();

    /**
     * Returns the request self-signature bytes.
     *
     * @return the signature bytes
     */
    byte[] signature();

    /**
     * Returns the exact DER encoding of the whole request.
     *
     * @return the request DER
     */
    byte[] encoded();

    /**
     * Verifies proof of possession by checking the request self-signature against
     * the request's own public key.
     *
     * @return {@code true} if the self-signature is valid
     */
    boolean verifySelfSignature();
}
