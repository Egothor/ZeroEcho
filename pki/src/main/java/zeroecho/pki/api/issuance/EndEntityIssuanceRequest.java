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

package zeroecho.pki.api.issuance;

import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;

/**
 * Immutable input for end-entity issuance from an exact DER PKCS#10 request.
 * Construction bounds and snapshots the input; cryptographic proof, issuer and
 * profile validation belong to semantic preparation. Thread-safe.
 *
 * @param issuerCaId logical issuing authority; the current generation is selected by the store
 * @param csrDer exact DER request, between one byte and one MiB inclusive
 * @param profileId nonblank active profile identifier
 * @param validityOverride optional requested duration, evaluated against issuer time and policy
 */
public record EndEntityIssuanceRequest(PkiId issuerCaId, byte[] csrDer, String profileId,
        Optional<Validity> validityOverride) {
    /** Maximum encoded request size, checked before allocating its defensive copy. */
    public static final int MAXIMUM_CSR_DER_BYTES = 1024 * 1024;

    /**
     * Validates and snapshots the request in linear time and auxiliary memory in its byte size.
     *
     * @throws IllegalArgumentException if an argument is null, the profile is blank,
     *         or the request is empty or exceeds the size limit
     */
    public EndEntityIssuanceRequest {
        if (issuerCaId == null || csrDer == null || profileId == null || profileId.isBlank()
                || validityOverride == null || csrDer.length == 0 || csrDer.length > MAXIMUM_CSR_DER_BYTES) {
            throw new IllegalArgumentException("Invalid end-entity issuance request");
        }
        csrDer = csrDer.clone();
    }

    /**
     * Returns the immutable request payload as a caller-owned snapshot.
     *
     * @return a defensive copy of the exact DER request
     */
    @Override public byte[] csrDer() {
        return csrDer.clone();
    }

    /**
     * Returns a safe diagnostic representation.
     *
     * @return a redacted description without requester or authority information
     */
    @Override public String toString() {
        return "EndEntityIssuanceRequest[redacted]";
    }
}
