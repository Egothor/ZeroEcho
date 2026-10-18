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

import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.request.X509EnrollmentPayload;

/**
 * Immutable input for end-entity issuance from an explicitly typed X.509 request.
 * Construction bounds and snapshots the input; cryptographic proof, issuer and
 * profile validation belong to semantic preparation. Thread-safe.
 *
 * @param issuerCaId logical issuing authority; the current generation is selected by the store
 * @param payload exact typed DER request, between one byte and one MiB inclusive
 * @param profileId nonblank active profile identifier
 * @param validityOverride optional requested duration, evaluated against issuer time and policy
 */
public record EndEntityIssuanceRequest(PkiId issuerCaId, X509EnrollmentPayload payload, String profileId,
        Optional<Validity> validityOverride) {
    /** Maximum encoded request size, checked before allocating its defensive copy. */
    public static final int MAXIMUM_CSR_DER_BYTES = 1024 * 1024;

    /**
     * Validates references and reuses the already immutable payload in constant time and memory.
     *
     * @throws IllegalArgumentException if an argument is null, the profile is blank,
     *         or the request is empty or exceeds the size limit
     */
    public EndEntityIssuanceRequest {
        if (issuerCaId == null || payload == null || profileId == null || profileId.isBlank()
                || validityOverride == null) {
            throw new IllegalArgumentException("Invalid end-entity issuance request");
        }
    }

    /**
     * Constructs a PKCS#10 issuance request using the established convenience API.
     * @param issuerCaId logical issuing authority
     * @param csrDer bounded exact PKCS#10 DER, defensively copied
     * @param profileId active certificate profile identity
     * @param validityOverride optional requested validity
     */
    public EndEntityIssuanceRequest(PkiId issuerCaId, byte[] csrDer, String profileId,
            Optional<Validity> validityOverride) {
        this(issuerCaId, new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, csrDer), profileId, validityOverride);
    }

    /**
     * Returns the immutable request payload as a caller-owned snapshot.
     *
     * @return a defensive copy of the exact PKCS#10 DER request
     * @throws IllegalStateException if this request carries CRMF rather than PKCS#10
     */
    public byte[] csrDer() {
        if (payload.kind() != X509EnrollmentPayload.Kind.PKCS10) {
            throw new IllegalStateException("The enrollment request is not PKCS#10");
        }
        return payload.der();
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
