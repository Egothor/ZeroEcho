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
package zeroecho.pki.api.ca;

import java.util.List;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;

/**
 * Represents one logical CA authority and its explicit issuer generations.
 *
 * <p>
 * A CA entity may have multiple CA credentials to support:
 * </p>
 * <ul>
 * <li>cross-signing (multiple issuers for the same subject key),</li>
 * <li>credential rollover (new CA credential with the same key),</li>
 * <li>key rotation (new CA key with a new set of credentials).</li>
 * </ul>
 *
 * @param caId          CA identifier
 * @param kind          CA kind (root or intermediate)
 * @param state         operational state
 * @param issuerKeyRef  key reference used for issuing operations (private key
 *                      reference)
 * @param subjectRef    normalized subject reference
 * @param issuerIds canonical issuer-generation identifiers owned by the authority
 * @param currentIssuanceIssuerId exact generation selected for new issuance
 * @param issuanceChainPathId exact chain path selected for issuance bundles
 */
public record CaRecord(PkiId caId, CaKind kind, CaState state, KeyRef issuerKeyRef, SubjectRef subjectRef,
        List<PkiId> issuerIds, PkiId currentIssuanceIssuerId, PkiId issuanceChainPathId) {

    /**
     * Creates a CA record.
     *
     * @throws IllegalArgumentException if a mandatory input or credential
     *                                  identifier is {@code null}, or if a
     *                                  credential identifier is duplicated
     */
    public CaRecord {
        if (caId == null) {
            throw new IllegalArgumentException("caId must not be null");
        }
        if (kind == null) {
            throw new IllegalArgumentException("kind must not be null");
        }
        if (state == null) {
            throw new IllegalArgumentException("state must not be null");
        }
        if (issuerKeyRef == null) {
            throw new IllegalArgumentException("issuerKeyRef must not be null");
        }
        if (subjectRef == null) {
            throw new IllegalArgumentException("subjectRef must not be null");
        }
        if (issuerIds == null || issuerIds.isEmpty()) {
            throw new IllegalArgumentException("issuerIds must not be null/empty");
        }
        if (issuerIds.stream().anyMatch(java.util.Objects::isNull)
                || issuerIds.size() != new java.util.HashSet<>(issuerIds).size()) {
            throw new IllegalArgumentException("issuerIds must contain unique non-null identifiers");
        }
        if (currentIssuanceIssuerId == null || !issuerIds.contains(currentIssuanceIssuerId)) {
            throw new IllegalArgumentException("currentIssuanceIssuerId must identify an owned generation");
        }
        if (issuanceChainPathId == null) {
            throw new IllegalArgumentException("issuanceChainPathId must not be null");
        }
        issuerIds = List.copyOf(issuerIds);
    }
}
