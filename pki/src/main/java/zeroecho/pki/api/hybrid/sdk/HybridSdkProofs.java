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
package zeroecho.pki.api.hybrid.sdk;

import java.time.Instant;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.impl.framework.x509.bc.BcHybridSdkProofVerifier;
import zeroecho.pki.impl.framework.x509.bc.BcX509CertificationRequestParser;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;

/** Public fixed-suite SDK proof boundary without exposing framework implementation packages. */
public final class HybridSdkProofs {
    private HybridSdkProofs() { }

    /**
     * Parses canonical PKCS#10 and verifies its original primary SUBJECT-key proof.
     * @param originalDer bounded complete original request DER
     * @return verified original-request view; fresh dual proof remains required
     * @throws PkiException if the original request, key suite or primary proof is invalid
     */
    public static ParsedHybridSdkRequest parse(byte[] originalDer) {
        if (originalDer == null || originalDer.length < 1 || originalDer.length > 1048576) throw new PkiException("SDK_REQUEST_SIZE_INVALID");
        return new BcX509CertificationRequestParser().parseHybridSdk(new CertificationRequest(
                BcX509CredentialFramework.FORMAT_ID, new EncodedObject(Encoding.DER, originalDer)));
    }

    /**
     * Verifies both fresh subject-key proofs, without granting issuance authority.
     * @param request verified original request view
     * @param primaryFrame exact retained F1 challenge
     * @param primaryProof canonical ECDSA-with-SHA384 signature
     * @param alternativeProof pure ML-DSA-87 signature with empty context
     * @param now authoritative acceptance time
     * @return sha512-prefixed F3 commitment for the exact verified proofs
     * @throws PkiException if request, time, key bindings or either proof fails
     */
    public static String verify(ParsedHybridSdkRequest request, HybridSdkFrame primaryFrame,
            byte[] primaryProof, byte[] alternativeProof, Instant now) {
        return new BcHybridSdkProofVerifier().verify(request, primaryFrame, primaryProof, alternativeProof, now);
    }
}
