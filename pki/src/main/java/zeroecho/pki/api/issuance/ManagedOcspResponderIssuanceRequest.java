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
 * Captures the requested certificate for an existing pair of managed OCSP responder keys.
 *
 * <p>The request contains key references, not private key material. Creating it neither
 * generates keys nor grants signing, profile or issuer authority. Provisioning resolves
 * the actual public keys to determine the uniqueness slot; an intent identifier is not
 * a substitute for that public-key identity.
 *
 * <p>The subject list is copied on construction and exposed as an unmodifiable list.
 * Issuer, profile, path and key eligibility are checked by the issuance workflow,
 * separately from the structural validation performed by this record.
 *
 * @param authorityId logical issuer authority; must not be {@code null}
 * @param primaryKeyRef existing managed primary subject key; must not be {@code null}
 * @param alternativeKeyRef existing managed alternative subject key, distinct from the
 *        primary reference; must not be {@code null}
 * @param subject ordered subject RDNs, containing between 1 and 32 non-null entries
 * @param validity absolute requested validity; must not be {@code null}
 * @param intent exact issuer, profile and path selection; must not be {@code null}
 * @param expectedPredecessorCredentialId same-slot renewal predecessor, or an empty
 *        optional for initial provisioning; the optional must not be {@code null}
 */
public record ManagedOcspResponderIssuanceRequest(PkiId authorityId, KeyRef primaryKeyRef, KeyRef alternativeKeyRef,
        List<SubjectRdn> subject, Validity validity, IssuanceIntent intent, Optional<PkiId> expectedPredecessorCredentialId) {
    /**
     * Validates request structure and takes an immutable snapshot of the subject list.
     *
     * <p>No managed key is resolved and no operation is admitted. Each key reference is
     * limited to 1,048,576 UTF-8 bytes; authority and predecessor identifiers use the
     * bounded issuance-identifier contract.
     *
     * @throws NullPointerException if a required component or subject entry is null
     * @throws IllegalArgumentException if an identifier is invalid, the key references
     *         are equal or oversized, or the subject count is outside 1 through 32
     * @param authorityId logical issuer authority; must not be {@code null}
     * @param primaryKeyRef existing managed primary subject key; must not be {@code null}
     * @param alternativeKeyRef existing managed alternative subject key, distinct from the primary reference; must not be {@code null}
     * @param subject ordered subject RDNs, containing between 1 and 32 non-null entries
     * @param validity absolute requested validity; must not be {@code null}
     * @param intent exact issuer, profile and path selection; must not be {@code null}
     * @param expectedPredecessorCredentialId same-slot renewal predecessor, or an empty optional for initial provisioning; the optional must not be {@code null}
     */
    public ManagedOcspResponderIssuanceRequest {
        Objects.requireNonNull(authorityId, "authorityId");
        CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(authorityId.value());
        Objects.requireNonNull(primaryKeyRef, "primaryKeyRef");
        Objects.requireNonNull(alternativeKeyRef, "alternativeKeyRef");
        for (KeyRef key : List.of(primaryKeyRef, alternativeKeyRef)) {
            if (key.value().getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 1_048_576) {
                throw new IllegalArgumentException("Managed key reference exceeds bound");
            }
        }
        if (primaryKeyRef.equals(alternativeKeyRef)) {
            throw new IllegalArgumentException("Responder roles require distinct keys");
        }
        subject = List.copyOf(subject);
        if (subject.isEmpty() || subject.size() > 32) {
            throw new IllegalArgumentException("Responder subject exceeds bound");
        }
        Objects.requireNonNull(validity, "validity");
        Objects.requireNonNull(intent, "intent");
        expectedPredecessorCredentialId = Objects.requireNonNull(expectedPredecessorCredentialId, "expectedPredecessorCredentialId");
        expectedPredecessorCredentialId.ifPresent(id -> CorrelatedEndEntityIssuanceRequest.requireBoundedIdentifier(id.value()));
    }
    /**
     * Creates an initial-provisioning request without a renewal predecessor.
     *
     * @param authorityId logical issuer authority; must not be {@code null}
     * @param primaryKeyRef existing managed primary subject key; must not be {@code null}
     * @param alternativeKeyRef distinct existing managed alternative subject key;
     *        must not be {@code null}
     * @param subject ordered subject RDNs, containing between 1 and 32 non-null entries
     * @param validity absolute requested validity; must not be {@code null}
     * @param intent exact issuer, profile and path selection; must not be {@code null}
     * @throws NullPointerException if a required component or subject entry is null
     * @throws IllegalArgumentException if an identifier, key reference or subject count
     *         violates the canonical constructor's bounds
     */
    public ManagedOcspResponderIssuanceRequest(PkiId authorityId, KeyRef primaryKeyRef, KeyRef alternativeKeyRef,
            List<SubjectRdn> subject, Validity validity, IssuanceIntent intent) {
        this(authorityId, primaryKeyRef, alternativeKeyRef, subject, validity, intent, Optional.empty());
    }
    /**
     * Returns a diagnostic label without exposing key, issuer or subject coordinates.
     *
     * @return the fixed redacted request label
     */
    @Override
    public String toString() {
        return "ManagedOcspResponderIssuanceRequest[redacted]";
    }
}
