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
package zeroecho.pki.spi.crypto;

import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.KeyRef;

/** Provider-owned, generate-only capability; results never contain private material. */
public interface ManagedKeyGeneration {
    /** Closed explicit asymmetric generation choices; no provider default is selected. */
    enum Parameters {
        /** NIST P-384 key pair. */ ECDSA_P384,
        /** RSA 4096-bit modulus and public exponent 65537. */ RSA_4096,
        /** Pure ML-DSA-87 parameter set. */ ML_DSA_87
    }

    /**
     * Public observation of one generated pair.
     * @param keyRef provider-owned private signing-key reference
     * @param parameters exact generation parameters
     * @param subjectPublicKeyInfo public DER SubjectPublicKeyInfo
     */
    record Result(KeyRef keyRef, Parameters parameters, EncodedObject subjectPublicKeyInfo) {
        /** Validates the immutable public result. */
        public Result {
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(parameters, "parameters");
            Objects.requireNonNull(subjectPublicKeyInfo, "subjectPublicKeyInfo");
        }
    }

    /**
     * Generates a new pair once into an unused reservation-derived provider slot.
     * The caller must durably claim the reservation before invoking this method.
     * @param reservationId lowercase SHA-256 reservation identity, not a caller alias
     * @param parameters explicit supported parameters
     * @return public result after durable encrypted pair publication
     * @throws IllegalStateException if generation/publication fails or the slot is occupied
     */
    Result generate(String reservationId, Parameters parameters);

    /**
     * Observes a previously reserved slot without performing cryptography.
     * @param reservationId exact reservation identity
     * @param parameters expected immutable parameters
     * @return public result if the complete matching pair exists, otherwise empty
     * @throws IllegalStateException if material is inconsistent or inaccessible
     */
    Optional<Result> observe(String reservationId, Parameters parameters);
}
