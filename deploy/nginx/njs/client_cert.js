/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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

/*
 * ZeroEcho PKI edge — RFC 9440 client-certificate forwarding helper (njs).
 *
 * nginx exposes the verified browser client certificate only as PEM in the
 * (deprecated) $ssl_client_cert variable. RFC 9440 requires the `Client-Cert`
 * header value to be a Structured-Fields Byte Sequence: a colon, base64 of the
 * DER certificate, and a closing colon. The base64 body of a single PEM
 * certificate IS base64(DER); we simply strip the armor and all whitespace and
 * wrap the result in colons. This yields the canonical, newline-free base64 that
 * pki-server's strict parser requires (it re-encodes and compares for equality).
 *
 * If no client certificate is present (should not happen while
 * ssl_verify_client is `on`), we return an empty string so nginx omits the
 * header rather than forwarding a malformed value.
 *
 * NOTE: nginx does not expose the intermediate chain the client presented as a
 * variable, so `Client-Cert-Chain` is intentionally NOT produced here. The
 * server treats a missing chain header as "no chain"; admin identity is matched
 * on the leaf's SPKI/certificate commitment, so the leaf alone is sufficient.
 */

function rfc9440Leaf(r) {
    var pem = r.variables.ssl_client_cert;
    if (!pem) {
        return '';
    }
    var body = pem
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
    if (body.length === 0) {
        return '';
    }
    return ':' + body + ':';
}

export default { rfc9440Leaf };
