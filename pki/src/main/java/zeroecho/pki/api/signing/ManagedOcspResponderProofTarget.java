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
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole;

/**
 * Binds a managed responder possession proof to a frozen pre-certificate candidate.
 *
 * <p>The parent signing identity and intent distinguish the enclosing issuance from
 * its child key proofs. The target commitment binds the final TBS, profile, issuer
 * and public keys. Possessing this value is neither a credential nor an authority grant.
 *
 * @param parentOperationId exact parent signing-submission identity; must not be {@code null}
 * @param parentIntentCommitment {@code ocsp-intent:v1:} followed by 64 lowercase
 *        hexadecimal characters
 * @param frozenTargetCommitment final candidate's SHA-256 commitment as 64 lowercase
 *        hexadecimal characters
 * @param role subject-key role proved by the child operation; must not be {@code null}
 */
public record ManagedOcspResponderProofTarget(PkiId parentOperationId, String parentIntentCommitment,
        String frozenTargetCommitment, SubjectKeyRole role) {
    /**
     * Validates the signing identity, commitment encodings and required subject role.
     *
     * <p>No provider or store is consulted. The enclosing workflow must still validate
     * the relationship between the parent operation and the child proof operation.
     *
     * @throws NullPointerException if the parent identity or role is null
     * @throws IllegalArgumentException if the parent identifier is invalid or either
     *         commitment is null or has an invalid representation
     * @param parentOperationId exact parent signing-submission identity; must not be {@code null}
     * @param parentIntentCommitment {@code ocsp-intent:v1:} followed by 64 lowercase hexadecimal characters
     * @param frozenTargetCommitment final candidate's SHA-256 commitment as 64 lowercase hexadecimal characters
     * @param role subject-key role proved by the child operation; must not be {@code null}
     */
    public ManagedOcspResponderProofTarget {
        ManagedKeyProofInputs.identifier(parentOperationId);
        SigningSubmissionId parent = SigningSubmissionId.parse(parentOperationId);
        if (!parent.id().equals(parentOperationId) || parentIntentCommitment == null
                || !parentIntentCommitment.matches("ocsp-intent:v1:[0-9a-f]{64}") || frozenTargetCommitment == null
                || !frozenTargetCommitment.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Responder proof target invalid");
        }
        Objects.requireNonNull(role, "role");
    }
}
