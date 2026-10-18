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

import java.util.List;
import java.util.Set;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;

/**
 * Read-only gate-produced validated certificate request.
 *
 * <p>Only the trusted hidden implementation may implement this contract. Its
 * construction and authority checks remain internal to the PKI runtime.</p>
 */
public sealed interface ValidatedLeafRequest permits ValidatedCertificateRequest {

    /**
     * Returns the authoritative issuer CA identifier.
     *
     * @return exact logical authority identifier
     */
    PkiId issuerCaId();

    /**
     * Returns the selected exact profile reference, active or frozen by issuance intent.
     *
     * @return exact immutable profile reference
     */
    CertificateProfileRef profileReference();

    /**
     * Returns the selected logical profile identifier.
     *
     * @return nonblank profile identifier
     */
    String profileId();

    /**
     * Returns the canonical inventory subject reference.
     *
     * @return exact subject reference
     */
    SubjectRef subjectRef();

    /**
     * Returns the approved subject name.
     *
     * @return ordered immutable subject RDNs
     */
    List<SubjectRdn> subjectRdns();

    /**
     * Returns the approved subject alternative names.
     *
     * @return ordered immutable SAN entries
     */
    List<SubjectAlternativeName> subjectAlternativeNames();

    /**
     * Returns the profile-derived SAN criticality.
     *
     * @return whether SAN is critical
     */
    boolean subjectAlternativeNameCritical();

    /**
     * Returns the exact proof-bound public key.
     *
     * @return defensive copy of the SPKI
     */
    EncodedObject exactPublicKey();

    /**
     * Returns the approved issuer-time validity.
     *
     * @return exact validity interval
     */
    Validity validity();

    /**
     * Returns the profile-derived key usages.
     *
     * @return immutable key-usage set
     */
    Set<LeafKeyUsage> keyUsages();

    /**
     * Returns the profile-derived extended key usages.
     *
     * @return immutable extended-key-usage set
     */
    Set<ExtendedKeyUsageId> extendedKeyUsages();

    /**
     * Returns the KeyUsage extension criticality.
     *
     * @return whether KeyUsage is critical
     */
    boolean keyUsageCritical();

    /**
     * Returns the ExtendedKeyUsage extension criticality.
     *
     * @return whether ExtendedKeyUsage is critical
     */
    boolean extendedKeyUsageCritical();

    /**
     * Returns the leaf BasicConstraints criticality.
     *
     * @return whether BasicConstraints is critical
     */
    boolean basicConstraintsCritical();

    /**
     * Returns the X.509 representation selection.
     *
     * @return exact immutable binding policy
     */
    X509AlgorithmBindingPolicy algorithmBindingPolicy();
}
