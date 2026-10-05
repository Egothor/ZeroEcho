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

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

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
    /* default */ static final String CONTENT_TYPE_PKCS8 = "application/pkcs8";

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

    /**
     * Encrypts a PKCS#8 private key for the recipient using CMS EnvelopedData with AES-256-GCM.
     *
     * @param pkcs8Der      DER-encoded PKCS#8 private key (caller must zero after this returns)
     * @param recipientCert the recipient's certificate (public key used to wrap the content key)
     * @return base64-encoded DER CMS ContentInfo wrapping EnvelopedData
     */
    /* default */ static byte[] encryptPrivateKey(byte[] pkcs8Der, X509Certificate recipientCert) {
        return MIME_B64.encode(Pkix.encryptPrivateKeyForRecipient(pkcs8Der, recipientCert));
    }

    /**
     * Builds a {@code multipart/mixed} response body for POST {@code /serverkeygen}.
     *
     * <p>Part 1: encrypted private key ({@code application/pkcs8}, base64). <br>
     * Part 2: issued certificate chain ({@code application/pkcs7-mime; smime-type=certs-only}, base64).</p>
     *
     * @param encryptedKeyBase64  MIME-base64 CMS EnvelopedData bytes (from {@link #encryptPrivateKey})
     * @param certsCmsBase64      MIME-base64 CMS certs-only bytes (from {@link #encodeCertsOnly})
     * @return two-element array: {@code [0]} = body bytes, {@code [1]} = boundary bytes
     */
    /* default */ static byte[][] buildServerKeygenMultipart(byte[] encryptedKeyBase64, byte[] certsCmsBase64) {
        String boundary = "estboundary-" + UUID.randomUUID().toString().replace("-", "");
        String crlf = "\r\n";
        StringBuilder sb = new StringBuilder(256);
        sb.append("--").append(boundary).append(crlf)
                .append("Content-Type: ").append(CONTENT_TYPE_PKCS8).append(crlf)
                .append("Content-Transfer-Encoding: base64").append(crlf).append(crlf)
                .append(new String(encryptedKeyBase64, StandardCharsets.US_ASCII)).append(crlf)
                .append("--").append(boundary).append(crlf)
                .append("Content-Type: ").append(CONTENT_TYPE_CERTS_ONLY).append(crlf)
                .append("Content-Transfer-Encoding: base64").append(crlf).append(crlf)
                .append(new String(certsCmsBase64, StandardCharsets.US_ASCII)).append(crlf)
                .append("--").append(boundary).append("--").append(crlf);
        return new byte[][]{
                sb.toString().getBytes(StandardCharsets.US_ASCII),
                boundary.getBytes(StandardCharsets.US_ASCII)
        };
    }
}
