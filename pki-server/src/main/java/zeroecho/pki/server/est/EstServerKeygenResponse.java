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
package zeroecho.pki.server.est;

import java.util.Objects;

/**
 * Structured result of a successful {@code /serverkeygen} EST operation.
 *
 * <p>The private key is PKCS#7 EnvelopedData encrypted for the requesting client's
 * certificate (AES-256-GCM). The key bytes must never be logged or stored unencrypted.</p>
 *
 * <p>Construction copies both input arrays, but the generated record accessors
 * return the retained arrays directly. This is not a deeply immutable value:
 * consumers must coordinate access and avoid modifying buffers while another
 * consumer is encoding the response. No automatic buffer clearing is provided.</p>
 *
 * @param encryptedPrivateKeyDer  PKCS#7 EnvelopedData wrapping the private key (DER)
 * @param certificateChainDer     issued certificate and chain as
 *                                {@code application/pkcs7-mime; smime-type=certs-only} (DER)
 * @param multipartBoundary       MIME multipart boundary token
 *
 * @since 1.0
 */
public record EstServerKeygenResponse(byte[] encryptedPrivateKeyDer, byte[] certificateChainDer,
        String multipartBoundary) {

    /** Validates that all components are non-null and non-empty. */
    public EstServerKeygenResponse {
        Objects.requireNonNull(encryptedPrivateKeyDer, "encryptedPrivateKeyDer");
        Objects.requireNonNull(certificateChainDer, "certificateChainDer");
        Objects.requireNonNull(multipartBoundary, "multipartBoundary");
        if (encryptedPrivateKeyDer.length == 0) { throw new IllegalArgumentException("encryptedPrivateKeyDer is empty"); }
        if (certificateChainDer.length == 0) { throw new IllegalArgumentException("certificateChainDer is empty"); }
        if (multipartBoundary.isBlank()) { throw new IllegalArgumentException("multipartBoundary is blank"); }
        // Isolate the input arrays; the generated accessors still expose the retained buffers.
        encryptedPrivateKeyDer = encryptedPrivateKeyDer.clone();
        certificateChainDer = certificateChainDer.clone();
    }
}
