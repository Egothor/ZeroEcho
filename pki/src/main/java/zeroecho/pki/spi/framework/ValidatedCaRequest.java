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
package zeroecho.pki.spi.framework;

import java.math.BigInteger;
import java.util.List;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.profile.CaCertificatePolicy;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.core.ValidatedCaCertificateRequest;

/**
 * Read-only gate-produced validated certificate request.
 *
 * <p>Only the trusted hidden implementation may implement this contract. Its
 * construction and authority checks remain internal to the PKI runtime.</p>
 */
public sealed interface ValidatedCaRequest permits ValidatedCaCertificateRequest {

    /**
     * Returns the credential format.
     *
     * @return exact format identifier
     */
    FormatId formatId();

    /**
     * Returns the issuing CA identifier.
     *
     * @return exact issuer authority
     */
    PkiId issuerCaId();

    /**
     * Returns the subject CA identifier.
     *
     * @return exact subject authority
     */
    PkiId subjectCaId();

    /**
     * Returns the exact active profile reference.
     *
     * @return immutable profile reference
     */
    CertificateProfileRef profileReference();

    /**
     * Returns the required certificate kind.
     *
     * @return exact profile certificate kind
     */
    CertificateProfileKind certificateType();

    /**
     * Returns the canonical subject reference.
     *
     * @return exact inventory subject
     */
    SubjectRef subjectRef();

    /**
     * Returns the ordered canonical subject components.
     *
     * @return immutable subject RDNs
     */
    List<SubjectRdn> subjectRdns();

    /**
     * Returns a defensive copy of the proof-bound public key.
     *
     * @return exact SPKI copy
     */
    EncodedObject exactPublicKey();

    /**
     * Returns the approved exact validity.
     *
     * @return credential validity interval
     */
    Validity validity();

    /**
     * Returns the issuer-controlled serial.
     *
     * @return positive canonical serial
     */
    BigInteger serial();

    /**
     * Returns the exact profile-derived CA policy.
     *
     * @return immutable CA policy
     */
    CaCertificatePolicy policy();

    /**
     * Returns the X.509 representation selection.
     *
     * @return exact immutable binding policy
     */
    X509AlgorithmBindingPolicy algorithmBindingPolicy();
}
