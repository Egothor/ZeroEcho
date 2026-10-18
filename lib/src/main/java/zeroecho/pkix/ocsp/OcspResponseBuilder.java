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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import zeroecho.pkix.sign.ContentSigner;

/**
 * A fluent builder for unsigned OCSP {@code ResponseData} or a successful,
 * signed OCSP response (RFC 6960) carrying a {@code BasicOCSPResponse}.
 *
 * <p>
 * The {@code tbsResponseData} is signed by a caller supplied {@link ContentSigner};
 * the result is the DER of the whole {@code OCSPResponse} with
 * {@code responseStatus = successful}.
 * </p>
 *
 * <p>
 * Instances are single-use and not thread-safe.
 * </p>
 */
public interface OcspResponseBuilder {

    /**
     * Sets the responder identity (required).
     *
     * @param responderId the responder id
     * @return this builder
     */
    OcspResponseBuilder responderId(ResponderId responderId);

    /**
     * Sets {@code producedAt} (required).
     *
     * @param producedAt the response production time
     * @return this builder
     */
    OcspResponseBuilder producedAt(Instant producedAt);

    /**
     * Adds a single certificate-status response.
     *
     * @param certId the requested certificate id
     * @param status the certificate status
     * @param thisUpdate the time the status is known to be correct
     * @param nextUpdate the time newer information will be available (nullable)
     * @return this builder
     */
    OcspResponseBuilder addResponse(CertId certId, CertStatus status, Instant thisUpdate, Instant nextUpdate);

    /**
     * Adds a response nonce (echoing the request nonce).
     *
     * @param nonce the nonce bytes
     * @return this builder
     */
    OcspResponseBuilder nonce(byte[] nonce);

    /**
     * Encodes the exact unsigned {@code ResponseData} that a signer must sign.
     * Preserves response insertion order, responder identity, status/time fields
     * and the optional response nonce. The returned DER contains no signature,
     * signature algorithm, outer response envelope or certificate chain. This
     * method neither invokes a signer nor mutates the configured fields.
     *
     * <p>The returned array is independently owned by the caller. Time and
     * auxiliary memory are linear in the encoded response-data size. Response
     * count and total response size retain the builder's existing caller-managed
     * limits; this method adds no live-response size policy.</p>
     *
     * @return freshly encoded unsigned {@code ResponseData} DER
     * @throws NullPointerException if required responder, production time or response fields are missing
     * @throws IllegalStateException if response data cannot be encoded
     */
    byte[] buildTbs();

    /**
     * Signs the assembled {@code tbsResponseData} and returns the DER of the whole
     * successful {@code OCSPResponse}.
     *
     * @param signer the content signer supplying the signature and algorithm
     * @param chain nonnull responder certificate chain in embedding order; empty omits the optional certificates field
     * @return the DER-encoded OCSP response
     * @throws NullPointerException if a required field, signer, chain or certificate is null
     * @throws IllegalStateException if encoding or signing fails
     */
    byte[] build(ContentSigner signer, List<X509Certificate> chain);
}
