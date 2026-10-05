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
package zeroecho.pki.server.ct;

import java.util.List;
import java.util.Objects;

import zeroecho.pkix.Pkix;
import zeroecho.pkix.ct.PreCertificateResult;
import zeroecho.pkix.sign.ContentSigner;

/**
 * Builds a CT pre-certificate from a {@code TBSCertificate} by adding the CT poison
 * extension and signing it with the CA's key, ready for submission to CT logs.
 *
 * <p>This class delegates entirely to {@link Pkix#buildPreCertificate}; it exists as a
 * named collaborator so the issuance pipeline can treat pre-certificate construction as
 * an injected strategy rather than a direct static call.</p>
 *
 * <h2>Thread safety</h2>
 * <p>This class is stateless and thread-safe.</p>
 *
 * @since 1.0
 */
public final class PreCertificateBuilder {

    /** Prevents instantiation; all methods are static. */
    private PreCertificateBuilder() {
        // utility class
    }

    /**
     * Builds a CT pre-certificate from a {@code TBSCertificate} using the CA's content signer.
     *
     * <p>The returned {@link PreCertificateResult} contains the DER-encoded pre-certificate
     * (with the CT poison extension added and signed with the CA key) and the issuer chain.
     * The pre-certificate is ready for submission to one or more CT logs via
     * {@link CtLogSubmitter#submitAll}.</p>
     *
     * @param tbsCertificateDer DER-encoded {@code TBSCertificate}; must not be {@code null}
     * @param issuerChainDer    DER-encoded issuer certificate chain, issuer first; must not be {@code null}
     * @param signer            content signer configured for the issuing CA key; must not be {@code null}
     * @return pre-certificate DER and its chain
     * @throws IllegalArgumentException if pre-certificate construction or signing fails
     * @throws NullPointerException     if any argument is {@code null}
     * @since 1.0
     */
    public static PreCertificateResult build(byte[] tbsCertificateDer, List<byte[]> issuerChainDer,
            ContentSigner signer) {
        Objects.requireNonNull(tbsCertificateDer, "tbsCertificateDer");
        Objects.requireNonNull(issuerChainDer, "issuerChainDer");
        Objects.requireNonNull(signer, "signer");
        return Pkix.buildPreCertificate(tbsCertificateDer, issuerChainDer, signer);
    }
}
