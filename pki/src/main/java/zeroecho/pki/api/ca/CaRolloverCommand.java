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
    /**
     * Identifies the authority whose credential will be rolled over.
     *
     * @return the logical CA identifier
     */
    PkiId caId();
    /**
     * Returns the requested validity before authoritative policy is applied.
     *
     * @return the requested bounds, or an empty optional when policy selects them;
     *         policy may override or deny a supplied request
     */
    Optional<Validity> requestedValidity();
    /**
     * Returns the universal attributes carried by the rollover request.
     *
     * @return immutable attributes, possibly empty
     */
    AttributeSet attributes();
    /**
     * Returns the selected head against which execution must be checked.
     *
     * @return the exact original head, present after normalization and otherwise possibly empty
     */
    Optional<CaHeadSnapshot> expectedHead();

    /**
     * Root rollover using the authoritative current key. Execution must separately
     * authorize rollover and verify a fresh self-signature against the same frozen
     * canonical SubjectPublicKeyInfo used for the new credential. A retained proof
     * or historical self-signature cannot replace that verification.
     * @param caId root CA identifier, strict UTF-8 at most 4,096 bytes
     * @param requestedValidity optional requested validity
     * @param attributes immutable universal attributes, possibly empty
     * @param expectedHead optional expected original selected head
     */
    record Root(PkiId caId, Optional<Validity> requestedValidity, AttributeSet attributes,
            Optional<CaHeadSnapshot> expectedHead) implements CaRolloverCommand {
        /**
         * Validates local structure without resolving authority state.
         * @throws IllegalArgumentException if a component is null or the CA identifier is invalid
         * @param caId root CA identifier, strict UTF-8 at most 4,096 bytes
         * @param requestedValidity optional requested validity
         * @param attributes immutable universal attributes, possibly empty
         * @param expectedHead optional expected original selected head
         */
        public Root {
            CaCommandInputs.identifier(caId);
            CaCommandInputs.required(requestedValidity);
            CaCommandInputs.required(attributes);
            CaCommandInputs.required(expectedHead);
        }
        /**
         * Creates a same-key root rollover before capturing the expected head.
         *
         * <p>The empty expected-head optional must be normalized from authoritative
         * state before approval. This constructor performs only local structural checks;
         * it neither authorizes rollover nor obtains the required fresh self-signature.
         *
         * @param caId root authority identifier using bounded strict UTF-8
         * @param requestedValidity requested bounds, or an empty optional; must not be null
         * @param attributes immutable universal attributes, possibly empty; must not be null
         * @throws IllegalArgumentException if a component is null or the CA identifier is invalid
         */
        public Root(PkiId caId, Optional<Validity> requestedValidity, AttributeSet attributes) {
            this(caId, requestedValidity, attributes, Optional.empty());
        }
        /**
         * Returns a diagnostic label without disclosing rollover coordinates or attributes.
         *
         * @return the fixed redacted root-rollover label
         */
        @Override
        public String toString() {
            return "CaRolloverCommand.Root[redacted]";
        }
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
     * @param expectedHead optional expected original selected head
     */
    record Intermediate(PkiId caId, PkiId issuerCaId, KeyRef keyRef,
            Optional<Validity> requestedValidity, AttributeSet attributes, Optional<CaHeadSnapshot> expectedHead) implements CaRolloverCommand {
        /**
         * Validates local structure without resolving authority state.
         * @throws IllegalArgumentException if any component is null, bounded text is invalid
         * @param caId intermediate CA identifier, strict UTF-8 at most 4,096 bytes
         * @param issuerCaId issuer CA identifier, strict UTF-8 at most 4,096 bytes
         * @param keyRef expected current key, strict UTF-8 at most 1,048,576 bytes
         * @param requestedValidity optional requested validity
         * @param attributes immutable universal attributes, possibly empty
         * @param expectedHead optional expected original selected head
         */
        public Intermediate {
            CaCommandInputs.identifier(caId);
            CaCommandInputs.identifier(issuerCaId);
            CaCommandInputs.key(keyRef);
            CaCommandInputs.required(requestedValidity);
            CaCommandInputs.required(attributes);
            CaCommandInputs.required(expectedHead);
        }
        /**
         * Creates a same-key intermediate rollover before capturing the expected subject head.
         *
         * <p>The workflow must subsequently match the expected key to authoritative
         * subject state, normalize the head, authorize both authorities' use and obtain
         * the fresh subject-key proof. Construction does not perform those operations.
         *
         * @param caId intermediate authority identifier using bounded strict UTF-8
         * @param issuerCaId independently selected parent authority identifier
         * @param keyRef expected current managed subject-key reference
         * @param requestedValidity requested bounds, or an empty optional; must not be null
         * @param attributes immutable universal attributes, possibly empty; must not be null
         * @throws IllegalArgumentException if a component is null or a bounded coordinate is invalid
         */
        public Intermediate(PkiId caId, PkiId issuerCaId, KeyRef keyRef,
                Optional<Validity> requestedValidity, AttributeSet attributes) {
            this(caId, issuerCaId, keyRef, requestedValidity, attributes, Optional.empty());
        }
        /**
         * Returns a diagnostic label without disclosing rollover coordinates or attributes.
         *
         * @return the fixed redacted intermediate-rollover label
         */
        @Override
        public String toString() {
            return "CaRolloverCommand.Intermediate[redacted]";
        }
    }
}
