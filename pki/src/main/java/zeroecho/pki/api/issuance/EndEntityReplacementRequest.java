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

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.request.X509EnrollmentPayload;

/**
 * Immutable, thread-safe replacement input with a fresh, explicitly typed request.
 * Preparation verifies proof of possession and the selected active profile. The
 * predecessor's logical authority is retained. Reusing its SPKI is permitted only
 * when it is neither held nor permanently revoked; a different verified key may
 * replace either status. Construction alone does not validate the CSR or policy.
 *
 * @param existingCredentialId authoritative predecessor identifier
 * @param payload exact typed request, from one byte through one MiB inclusive
 * @param profileId nonblank selected logical profile identifier
 */
public record EndEntityReplacementRequest(PkiId existingCredentialId, X509EnrollmentPayload payload, String profileId) {
    /** Maximum CSR size, checked before creating a defensive copy. */
    public static final int MAXIMUM_CSR_DER_BYTES = EndEntityIssuanceRequest.MAXIMUM_CSR_DER_BYTES;

    /**
     * Validates coordinates and retains the immutable payload in constant time and memory.
     * @throws IllegalArgumentException if an argument is null, the profile is blank,
     *         or the CSR is empty or exceeds the size limit
     */
    public EndEntityReplacementRequest {
        if (existingCredentialId == null || payload == null || profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException("Invalid end-entity replacement request");
        }
    }

    /**
     * Creates a replacement from a bounded PKCS#10 request, defensively copied.
     * @param existingCredentialId authoritative predecessor identity
     * @param csrDer exact PKCS#10 DER
     * @param profileId selected certificate profile
     */
    public EndEntityReplacementRequest(PkiId existingCredentialId, byte[] csrDer, String profileId) {
        this(existingCredentialId, new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, csrDer), profileId);
    }

    /**
     * Returns the original PKCS#10 request.
     * @return a caller-owned defensive DER copy
     * @throws IllegalStateException if the payload is CRMF
     */
    public byte[] csrDer() {
        if (payload.kind() != X509EnrollmentPayload.Kind.PKCS10) {
            throw new IllegalStateException("Request is not PKCS#10");
        }
        return payload.der();
    }

    /** {@return a redacted diagnostic representation} */
    @Override public String toString() { return "EndEntityReplacementRequest[redacted]"; }
}
