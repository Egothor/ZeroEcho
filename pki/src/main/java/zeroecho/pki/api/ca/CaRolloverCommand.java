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

import java.util.Optional;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Command to roll over a CA credential while keeping the same key reference.
 *
 * <p>
 * Profile selection comes from authoritative CA state. Construction validates
 * structural inputs only: it neither verifies possession nor authorizes rollover.
 * Historical credentials remain accessible for audit and chain selection.
 * </p>
 *
 */
public sealed interface CaRolloverCommand {
    /** {@return CA entity identifier} */
    PkiId caId();
    /** {@return optional requested validity; policy may override or deny it} */
    Optional<Validity> requestedValidity();
    /** {@return immutable universal attributes} */
    AttributeSet attributes();

    /**
     * Root rollover using the authoritative current key. Execution must separately
     * authorize rollover and verify a fresh self-signature against the same frozen
     * canonical SubjectPublicKeyInfo used for the new credential. A retained proof
     * or historical self-signature cannot replace that verification.
     * @param caId root CA identifier, strict UTF-8 at most 4,096 bytes
     * @param requestedValidity optional requested validity
     * @param attributes immutable universal attributes, possibly empty
     */
    record Root(PkiId caId, Optional<Validity> requestedValidity, AttributeSet attributes) implements CaRolloverCommand {
        /**
         * Validates local structure without resolving authority state.
         * @throws IllegalArgumentException if a component is null or the CA identifier is invalid
         */
        public Root {
            CaCommandInputs.identifier(caId);
            CaCommandInputs.required(requestedValidity);
            CaCommandInputs.required(attributes);
        }
        /** {@return a diagnostic representation without command coordinates or attributes} */
        @Override public String toString() { return "CaRolloverCommand.Root[redacted]"; }
    }

    /**
     * Intermediate rollover with an expected current subject key. Execution must
     * match the key and profile to authoritative CA state, authorize separately,
     * and complete a fresh internal subject-key proof within the same durable admission.
     * @param caId intermediate CA identifier, strict UTF-8 at most 4,096 bytes
     * @param issuerCaId issuer CA identifier, strict UTF-8 at most 4,096 bytes
     * @param keyRef expected current key, strict UTF-8 at most 1,048,576 bytes
     * @param requestedValidity optional requested validity
     * @param attributes immutable universal attributes, possibly empty
     */
    record Intermediate(PkiId caId, PkiId issuerCaId, KeyRef keyRef,
            Optional<Validity> requestedValidity, AttributeSet attributes) implements CaRolloverCommand {
        /**
         * Validates local structure without resolving authority state.
         * @throws IllegalArgumentException if any component is null, bounded text is invalid
         */
        public Intermediate {
            CaCommandInputs.identifier(caId);
            CaCommandInputs.identifier(issuerCaId);
            CaCommandInputs.key(keyRef);
                CaCommandInputs.required(requestedValidity);
            CaCommandInputs.required(attributes);
        }
        /** {@return a diagnostic representation without command coordinates or attributes} */
        @Override public String toString() { return "CaRolloverCommand.Intermediate[redacted]"; }
    }
}
