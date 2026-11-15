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
 * Pre-certificate managed responder proof context; it is not a credential or authority grant.
 * @param parentOperationId exact parent signing identity @param parentIntentCommitment ocsp-intent:v1 digest
 * @param frozenTargetCommitment SHA256 frozen final TBS/profile/issuer/public-key target @param role exact subject role
 */
public record ManagedOcspResponderProofTarget(PkiId parentOperationId, String parentIntentCommitment,
        String frozenTargetCommitment, SubjectKeyRole role) {
    /** Validates finite canonical context without a provider or store. */
    public ManagedOcspResponderProofTarget {
        ManagedKeyProofInputs.identifier(parentOperationId);
        var parent = SigningSubmissionId.parse(parentOperationId);
        if (!parent.id().equals(parentOperationId) || parentIntentCommitment == null
                || !parentIntentCommitment.matches("ocsp-intent:v1:[0-9a-f]{64}") || frozenTargetCommitment == null
                || !frozenTargetCommitment.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Responder proof target invalid");
        Objects.requireNonNull(role, "role");
    }
}
