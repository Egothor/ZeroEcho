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
package zeroecho.pki.server.est;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import zeroecho.pkix.CertificationRequestException;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.csr.CsrAttribute;

/**
 * CMS encode/decode bridge between the EST protocol and the {@link Pkix} facade.
 *
 * <p>All BouncyCastle CMS operations are confined to the {@code lib} module via
 * {@link Pkix}; this class never imports {@code org.bouncycastle}.</p>
 */
final class EstCmsCodec {

    /* default */ static final String CONTENT_TYPE_PKCS10 = "application/pkcs10";
    /* default */ static final String CONTENT_TYPE_CERTS_ONLY = "application/pkcs7-mime; smime-type=certs-only";
    /* default */ static final String CONTENT_TYPE_CSRATTRS = "application/csrattrs";

    private static final Base64.Encoder MIME_B64 =
            Base64.getMimeEncoder(76, "\r\n".getBytes(StandardCharsets.US_ASCII));

    private EstCmsCodec() {
    }

    /**
     * Parses a PKCS#10 CSR from DER or base64-encoded DER and verifies the self-signature.
     *
     * @param body raw request body bytes
     * @return verified certification request
     * @throws CertificationRequestException if the CSR is malformed or the self-signature is invalid
     */
    /* default */ static CertificationRequest parsePkcs10(byte[] body) throws CertificationRequestException {
        return Pkix.parseCsr(body);
    }

    /**
     * Encodes a certificate chain as a CMS certs-only message, MIME-base64-encoded.
     *
     * @param chain ordered certificate list (issuer first or leaf first — preserved as-is)
     * @return base64-encoded DER CMS ContentInfo
     */
    /* default */ static byte[] encodeCertsOnly(List<X509Certificate> chain) {
        return MIME_B64.encode(Pkix.encodeCertsOnly(chain));
    }

    /**
     * Encodes CSR attributes as an RFC 7030 {@code CsrAttrs} DER sequence, MIME-base64-encoded.
     *
     * @param attributes the CSR attributes to encode
     * @return base64-encoded DER CsrAttrs sequence
     */
    /* default */ static byte[] encodeCsrAttrs(List<CsrAttribute> attributes) {
        return MIME_B64.encode(Pkix.encodeCsrAttrs(attributes));
    }

}
