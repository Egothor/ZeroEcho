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
package zeroecho.pki.api.request;

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Normalized representation of a certification request.
 *
 * <p>
 * This record is produced by a framework-specific request parser. It contains a
 * minimal set of mandatory core fields required by the PKI runtime, plus a
 * universal typed {@link AttributeSet} that carries additional request
 * attributes in a framework-neutral manner.
 * </p>
 *
 * <p>
 * The PKI runtime is expected to apply policy and profile constraints before
 * issuance.
 * </p>
 *
 * @param requestId                     stable identifier for the request
 *                                      (typically derived from the request
 *                                      payload fingerprint)
 * @param formatId                      framework/format identifier
 * @param subjectRef                    normalized subject reference for policy
 *                                      and inventory correlation
 * @param publicKeyInfo                 requested public key information (SPKI
 *                                      DER preferred where applicable)
 * @param requestedValidity             optional validity requested by the
 *                                      subject; policy may override or deny
 * @param requestedProfileId            optional profile hint; policy may
 *                                      override or deny
 * @param subjectRdns                   ordered typed single-valued subject
 *                                      components
 * @param subjectAlternativeNames       ordered typed SAN entries
 * @param subjectAlternativeNamePresent whether one valid SAN extension was
 *                                      present
 * @param attributes                    proof-carrying parser attributes;
 *                                      issuance policy rejects all attributes
 *                                      except the canonical CSR transport
 *                                      attribute
 */
// The SAN-presence component name is an exported accessor and distinguishes presence from content.
@SuppressWarnings("PMD.LongVariable")
public record ParsedCertificationRequest(PkiId requestId, FormatId formatId, SubjectRef subjectRef,
        EncodedObject publicKeyInfo, Optional<Validity> requestedValidity, Optional<String> requestedProfileId,
        List<SubjectRdn> subjectRdns, List<SubjectAlternativeName> subjectAlternativeNames,
        boolean subjectAlternativeNamePresent, AttributeSet attributes) {

    /**
     * Creates a diagnostic request without typed X.509 identity semantics.
     *
     * <p>
     * The authoritative X.509 issuance path reparses the signed CSR and requires
     * exact typed-semantic equality, so instances built through this convenience
     * constructor cannot bypass typed subject or SAN validation.
     * </p>
     *
     * @param requestId          request identifier
     * @param formatId           format identifier
     * @param subjectRef         diagnostic subject reference
     * @param publicKeyInfo      public-key information
     * @param requestedValidity  requested validity
     * @param requestedProfileId requested profile
     * @param attributes         diagnostic attributes
     */
    public ParsedCertificationRequest(PkiId requestId, FormatId formatId, SubjectRef subjectRef,
            EncodedObject publicKeyInfo, Optional<Validity> requestedValidity, Optional<String> requestedProfileId,
            AttributeSet attributes) {
        this(requestId, formatId, subjectRef, publicKeyInfo, requestedValidity, requestedProfileId, List.of(),
                List.of(), false, attributes);
    }

    /**
     * Creates a parsed certification request.
     *
     * @param requestId          stable request id
     * @param formatId           format id
     * @param subjectRef         normalized subject reference
     * @param publicKeyInfo      requested public key info
     * @param requestedValidity  optional requested validity
     * @param requestedProfileId optional requested profile id
     * @param attributes         extracted attributes
     * @throws IllegalArgumentException if mandatory inputs are null or optional
     *                                  containers are null
     */
    public ParsedCertificationRequest {
        if (requestId == null) {
            throw new IllegalArgumentException("requestId must not be null");
        }
        if (formatId == null) {
            throw new IllegalArgumentException("formatId must not be null");
        }
        if (subjectRef == null) {
            throw new IllegalArgumentException("subjectRef must not be null");
        }
        if (publicKeyInfo == null) {
            throw new IllegalArgumentException("publicKeyInfo must not be null");
        }
        if (requestedValidity == null) {
            throw new IllegalArgumentException("requestedValidity must not be null");
        }
        if (requestedProfileId == null) {
            throw new IllegalArgumentException("requestedProfileId must not be null");
        }
        if (subjectRdns == null || subjectAlternativeNames == null) {
            throw new IllegalArgumentException("Typed identity collections must not be null");
        }
        subjectRdns = List.copyOf(subjectRdns);
        subjectAlternativeNames = List.copyOf(subjectAlternativeNames);
        if (subjectRdns.stream().anyMatch(java.util.Objects::isNull)
                || subjectAlternativeNames.stream().anyMatch(java.util.Objects::isNull)) {
            throw new IllegalArgumentException("Typed identity collections must not contain null");
        }
        if (subjectRdns.size() > 32 || subjectAlternativeNames.size() > 64) {
            throw new IllegalArgumentException("Typed identity collection exceeds the hard limit");
        }
        if (subjectAlternativeNamePresent != !subjectAlternativeNames.isEmpty()) {
            throw new IllegalArgumentException("SAN extension presence is inconsistent");
        }
        if (attributes == null) {
            throw new IllegalArgumentException("attributes must not be null");
        }
    }
}
