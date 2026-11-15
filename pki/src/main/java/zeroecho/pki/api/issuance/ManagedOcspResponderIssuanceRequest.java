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

package zeroecho.pki.api.issuance;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.request.SubjectRdn;

/**
 * Frozen request to provision a dedicated managed OCSP responder certificate.
 * It grants no key generation, signing, profile or issuer authority. Caller intent
 * identifiers are not provisioning uniqueness keys; actual public SPKIs determine the slot.
 * @param authorityId logical authority @param primaryKeyRef existing managed primary subject key
 * @param alternativeKeyRef existing managed alternative subject key @param subject ordered subject RDNs
 * @param validity absolute requested validity @param intent exact issuer/profile/path selection
 * @param expectedPredecessorCredentialId explicit same-slot renewal predecessor, absent initially
 */
public record ManagedOcspResponderIssuanceRequest(PkiId authorityId, KeyRef primaryKeyRef, KeyRef alternativeKeyRef,
        List<SubjectRdn> subject, Validity validity, IssuanceIntent intent, Optional<PkiId> expectedPredecessorCredentialId) {
    /** Validates bounded immutable inputs without resolving keys or admitting an operation. */
    public ManagedOcspResponderIssuanceRequest {
        Objects.requireNonNull(authorityId, "authorityId");
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(authorityId.value());
        Objects.requireNonNull(primaryKeyRef, "primaryKeyRef"); Objects.requireNonNull(alternativeKeyRef, "alternativeKeyRef");
        for (KeyRef key : List.of(primaryKeyRef, alternativeKeyRef)) {
            if (key.value().getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 1_048_576) throw new IllegalArgumentException("Managed key reference exceeds bound");
        }
        if (primaryKeyRef.equals(alternativeKeyRef)) throw new IllegalArgumentException("Responder roles require distinct keys");
        subject = List.copyOf(subject);
        if (subject.isEmpty() || subject.size() > 32) throw new IllegalArgumentException("Responder subject exceeds bound");
        Objects.requireNonNull(validity, "validity"); Objects.requireNonNull(intent, "intent");
        expectedPredecessorCredentialId = Objects.requireNonNull(expectedPredecessorCredentialId, "expectedPredecessorCredentialId");
        expectedPredecessorCredentialId.ifPresent(id -> CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(id.value()));
    }
    /**
     * Preserves initial provisioning without an explicit renewal predecessor.
     * @param authorityId logical authority @param primaryKeyRef existing primary key
     * @param alternativeKeyRef existing alternative key @param subject ordered RDNs
     * @param validity absolute validity @param intent exact immutable selection
     */
    public ManagedOcspResponderIssuanceRequest(PkiId authorityId, KeyRef primaryKeyRef, KeyRef alternativeKeyRef,
            List<SubjectRdn> subject, Validity validity, IssuanceIntent intent) {
        this(authorityId, primaryKeyRef, alternativeKeyRef, subject, validity, intent, Optional.empty());
    }
    /** @return redacted diagnostic without key or subject coordinates */
    @Override public String toString() { return "ManagedOcspResponderIssuanceRequest[redacted]"; }
}
