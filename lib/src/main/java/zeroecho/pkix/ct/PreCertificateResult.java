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
package zeroecho.pkix.ct;

import java.util.List;
import java.util.Objects;

/**
 * The result of building a CT pre-certificate: a signed pre-cert and its issuer chain,
 * ready for submission to a Certificate Transparency log.
 *
 * <p>A pre-certificate is a certificate with the same {@code TBSCertificate} content as
 * the intended final certificate, except that it carries the CT poison extension
 * (OID {@code 1.3.6.1.4.1.11129.2.4.3}) marked critical, and lacks the SCT list
 * extension. CT logs return SCTs in response to pre-certificate submissions; those SCTs
 * are embedded into the final certificate before signing.</p>
 *
 * <p>All arrays are defensively copied; the record is immutable and thread-safe.</p>
 *
 * @param preCertDer DER-encoded pre-certificate (signed by the issuing CA key)
 * @param chainDer   DER-encoded issuer chain in submission order (issuer first, root last)
 * @since 1.0
 */
public record PreCertificateResult(byte[] preCertDer, List<byte[]> chainDer) {

    /** Validates and defensively copies all contents. */
    public PreCertificateResult {
        Objects.requireNonNull(preCertDer, "preCertDer");
        Objects.requireNonNull(chainDer, "chainDer");
        if (preCertDer.length == 0) {
            throw new IllegalArgumentException("preCertDer must not be empty");
        }
        preCertDer = preCertDer.clone();
        chainDer = chainDer.stream()
                .map(cert -> {
                    Objects.requireNonNull(cert, "chain element must not be null");
                    return cert.clone();
                })
                .toList();
    }

    /**
     * Returns an independent copy of the pre-certificate DER.
     *
     * @return pre-certificate DER bytes
     */
    @Override
    public byte[] preCertDer() {
        return preCertDer.clone();
    }

    /**
     * Returns an immutable list of independent copies of the issuer chain DER.
     *
     * @return issuer chain DER, issuer first
     */
    @Override
    public List<byte[]> chainDer() {
        return chainDer.stream().map(byte[]::clone).toList();
    }
}
