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
package zeroecho.pkix.ocsp;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import zeroecho.pkix.AlgorithmIdentifier;

/**
 * A parsed OCSP request (RFC 6960).
 *
 * <p>
 * Exposes the requested certificate identifiers and optional nonce, and — for
 * signed requests — the exact to-be-signed bytes, signature, and any embedded
 * signer certificates, so the request signature can be verified.
 * </p>
 */
public interface OcspRequest {

    /**
     * Returns the requested certificate identifiers.
     *
     * @return the requested cert ids (non-empty)
     */
    List<CertId> requestedCertificates();

    /**
     * Returns the request nonce, if present.
     *
     * @return the nonce bytes, or empty
     */
    Optional<byte[]> nonce();

    /**
     * Indicates whether the request carries an optional signature.
     *
     * @return {@code true} if the request is signed
     */
    boolean isSigned();

    /**
     * Returns the request signature algorithm identifier, for a signed request.
     *
     * @return the signature algorithm, or empty
     */
    Optional<AlgorithmIdentifier> signatureAlgorithm();

    /**
     * Returns the exact DER of the {@code tbsRequest} (the signed portion).
     *
     * @return the to-be-signed DER, or empty for an unsigned request
     */
    Optional<byte[]> toBeSigned();

    /**
     * Returns the request signature, for a signed request.
     *
     * @return the signature bytes, or empty
     */
    Optional<byte[]> signature();

    /**
     * Returns the signer certificates embedded in a signed request, if any.
     *
     * @return the signer certificates (possibly empty)
     */
    List<X509Certificate> signerCertificates();

    /**
     * Verifies the request signature against the given public key.
     *
     * @param signerKey the public key to verify with
     * @return {@code true} if the request is signed and the signature is valid
     */
    boolean verifySignature(PublicKey signerKey);
}
