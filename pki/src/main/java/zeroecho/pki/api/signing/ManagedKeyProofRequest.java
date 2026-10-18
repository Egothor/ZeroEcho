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

package zeroecho.pki.api.signing;

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;

/**
 * Immutable, thread-safe coordinates for a managed private-key possession proof.
 * These values grant no authorization and perform no store lookup or algorithm
 * selection. All identifiers must be nonblank strict UTF-8: PKI identifiers are
 * limited to 4,096 bytes, profile identifiers to 256 bytes and key references to
 * 1,048,576 bytes. The encoded command has its own aggregate size limit.
 * Construction takes linear time in the supplied text and constant auxiliary memory.
 */
public sealed interface ManagedKeyProofRequest {
    /**
     * Returns the exact managed key to prove.
     * @return immutable key reference, never private key material
     */
    KeyRef keyRef();

    /**
     * Proof coordinates for a CA subject key.
     * @param issuerAuthorityId logical authority authorizing the subject-key proof
     * @param subjectAuthorityId target authority when already identified, otherwise empty
     * @param profileId selected logical CA profile
     * @param keyRef managed subject key whose possession is to be proved
     */
    record CaSubject(PkiId issuerAuthorityId, Optional<PkiId> subjectAuthorityId,
            String profileId, KeyRef keyRef) implements ManagedKeyProofRequest {
        /**
         * Validates the bounded coordinates without resolving them.
         * @throws NullPointerException if an argument is null
         * @throws IllegalArgumentException if text is blank, oversized or contains an unpaired surrogate
         */
        public CaSubject {
            ManagedKeyProofInputs.identifier(issuerAuthorityId);
            subjectAuthorityId = Objects.requireNonNull(subjectAuthorityId, "subjectAuthorityId");
            subjectAuthorityId.ifPresent(ManagedKeyProofInputs::identifier);
            ManagedKeyProofInputs.text(profileId, 256);
            ManagedKeyProofInputs.text(Objects.requireNonNull(keyRef, "keyRef").value(), 1_048_576);
        }

        /** Returns a diagnostic representation without privileged coordinates. */
        @Override public String toString() { return "ManagedKeyProofRequest.CaSubject[redacted]"; }
    }

    /**
     * Proof coordinates for a managed OCSP responder key.
     * @param authorityId logical authority served by the responder
     * @param responderCredentialId exact responder credential
     * @param keyRef managed responder key whose possession is to be proved
     */
    record OcspResponder(PkiId authorityId, PkiId responderCredentialId,
            KeyRef keyRef) implements ManagedKeyProofRequest {
        /**
         * Validates the bounded coordinates without resolving them.
         * @throws NullPointerException if an argument is null
         * @throws IllegalArgumentException if text is oversized or contains an unpaired surrogate
         */
        public OcspResponder {
            ManagedKeyProofInputs.identifier(authorityId);
            ManagedKeyProofInputs.identifier(responderCredentialId);
            ManagedKeyProofInputs.text(Objects.requireNonNull(keyRef, "keyRef").value(), 1_048_576);
        }

        /** Returns a diagnostic representation without privileged coordinates. */
        @Override public String toString() { return "ManagedKeyProofRequest.OcspResponder[redacted]"; }
    }
}
