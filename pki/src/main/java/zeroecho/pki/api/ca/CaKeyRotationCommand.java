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
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Requests explicit changes to a CA's outgoing signing roles and corresponding credentials.
 *
 * <p>
 * Each selected role can change its managed key reference, its signature algorithm,
 * or both. Unspecified members retain the exact authoritative issuer binding;
 * an algorithm-only selection therefore need not replace key material. Historical
 * key references and credentials remain necessary for audit and validation of
 * previously issued credentials.
 * Profile selection comes from authoritative CA state. Construction validates
 * structure only; it neither generates keys nor proves possession or authorizes
 * rotation.
 * </p>
 *
 */
public sealed interface CaKeyRotationCommand {
    /**
     * Identifies the authority whose outgoing subject-key roles will be rotated.
     *
     * @return the logical CA identifier
     */
    PkiId caId();
    /**
     * Returns the explicitly requested primary and alternative role changes.
     *
     * @return the immutable role selection, normalized before approval
     */
    CaRotationSelection selection();
    /**
     * Returns the original selected head against which execution must be checked.
     *
     * @return the expected head, present after normalization and otherwise possibly empty
     */
    Optional<CaHeadSnapshot> expectedHead();
    /**
     * Projects the primary managed key for the existing primary-only API.
     * @return explicit primary key reference
     * @throws IllegalStateException if a partial/alternative-only selector has not been normalized
     */
    default KeyRef newKeyRef() {
        return selection().primary().flatMap(CaRotationSelection.RoleChange::keyRef)
                .orElseThrow(() -> new IllegalStateException("Primary rotation selection is not normalized"));
    }
    /**
     * Returns the universal attributes carried by the rotation request.
     *
     * @return the immutable attributes, possibly empty
     */
    AttributeSet attributes();

    /**
     * Root rotation with an explicitly provisioned new key. Execution must
     * separately authorize rotation and verify a fresh self-signature against the
     * same frozen canonical SubjectPublicKeyInfo of the new key used for the new
     * credential. A retained proof or historical self-signature is not a substitute.
     * @param caId root CA identifier, strict UTF-8 at most 4,096 bytes
     * @param selection explicit outgoing role changes, normalized before approval
     * @param expectedHead exact expected original head, or empty before normalization
     * @param attributes immutable universal attributes, possibly empty
     */
    record Root(PkiId caId, CaRotationSelection selection, Optional<CaHeadSnapshot> expectedHead,
            AttributeSet attributes) implements CaKeyRotationCommand {
        /**
         * Validates local structure without resolving authority state.
         * @throws IllegalArgumentException if any component is null or bounded text is invalid
         * @param caId root CA identifier, strict UTF-8 at most 4,096 bytes
         * @param selection explicit outgoing role changes, normalized before approval
         * @param expectedHead exact expected original head, or empty before normalization
         * @param attributes immutable universal attributes, possibly empty
         */
        public Root {
            CaCommandInputs.identifier(caId);
            CaCommandInputs.required(selection);
            CaCommandInputs.required(expectedHead);
            CaCommandInputs.required(attributes);
        }
        /**
         * Creates a primary-key-only root rotation without selecting a new algorithm.
         *
         * <p>The expected head is initially empty and must be captured during
         * normalization. This constructor neither generates the key nor authorizes
         * rotation or verifies the required fresh possession proof.
         *
         * @param caId exact root authority identifier
         * @param newKeyRef explicitly provisioned managed primary key
         * @param attributes immutable universal attributes, possibly empty
         * @throws NullPointerException if the managed key reference is null
         * @throws IllegalArgumentException if a required component or bounded identifier is invalid
         */
        public Root(PkiId caId, KeyRef newKeyRef, AttributeSet attributes) {
            this(caId, CaRotationSelection.primaryKey(newKeyRef), Optional.empty(), attributes);
        }
        /**
         * Returns a diagnostic label without exposing rotation coordinates or attributes.
         *
         * @return the fixed redacted root-rotation label
         */
        @Override
        public String toString() {
            return "CaKeyRotationCommand.Root[redacted]";
        }
    }

    /**
     * Intermediate rotation with a new managed key. Execution must separately
     * authorize rotation and complete a fresh internal proof for the target key
     * within the same durable admission.
     * @param caId intermediate CA identifier, strict UTF-8 at most 4,096 bytes
     * @param selection explicit outgoing subject role changes
     * @param issuerCaId independently selected parent authority
     * @param expectedHead exact original subject head, or empty before normalization
     * @param attributes immutable universal attributes, possibly empty
     */
    record Intermediate(PkiId caId, CaRotationSelection selection, PkiId issuerCaId,
            Optional<CaHeadSnapshot> expectedHead, AttributeSet attributes) implements CaKeyRotationCommand {
        /**
         * Validates local structure without resolving authority state.
         * @throws IllegalArgumentException if any component is null, bounded text is invalid
         * @param caId intermediate CA identifier, strict UTF-8 at most 4,096 bytes
         * @param selection explicit outgoing subject role changes
         * @param issuerCaId independently selected parent authority
         * @param expectedHead exact original subject head, or empty before normalization
         * @param attributes immutable universal attributes, possibly empty
         */
        public Intermediate {
            CaCommandInputs.identifier(caId);
            CaCommandInputs.required(selection);
            CaCommandInputs.identifier(issuerCaId);
            CaCommandInputs.required(expectedHead);
            CaCommandInputs.required(attributes);
        }
        /**
         * Creates a primary-key-only intermediate rotation with an explicit parent authority.
         *
         * <p>The expected subject head is initially empty and must be captured during
         * normalization. Parent selection remains independent of the new subject key;
         * construction does not authorize either authority's use or perform a key proof.
         *
         * @param caId exact intermediate authority identifier
         * @param newKeyRef explicitly provisioned managed primary subject key
         * @param issuerCaId independently selected parent authority identifier
         * @param attributes immutable universal attributes, possibly empty
         * @throws NullPointerException if the managed key reference is null
         * @throws IllegalArgumentException if a required component or bounded identifier is invalid
         */
        public Intermediate(PkiId caId, KeyRef newKeyRef, PkiId issuerCaId, AttributeSet attributes) {
            this(caId, CaRotationSelection.primaryKey(newKeyRef), issuerCaId, Optional.empty(), attributes);
        }
        /**
         * Returns a diagnostic label without exposing rotation coordinates or attributes.
         *
         * @return the fixed redacted intermediate-rotation label
         */
        @Override
        public String toString() {
            return "CaKeyRotationCommand.Intermediate[redacted]";
        }
    }
}
