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
package zeroecho.pki.impl.core.continuation;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaHeadSnapshot;

import java.util.Objects;
import java.util.Optional;

/**
 * Exact expected predecessor for one guarded CA lifecycle publication.
 * @param version context version, one
 * @param operation exact lifecycle kind
 * @param expectedHead original selected generation/path and monotonic epoch
 * @param originalCredentialId exact original CA credential
 * @param originalCertificateSha256 lowercase original certificate DER SHA-256
 * @param transitionId root candidate transition identity, absent for immediate publication
 */
public record CaLifecycleContext(int version, Operation operation, CaHeadSnapshot expectedHead,
        PkiId originalCredentialId, String originalCertificateSha256, Optional<PkiId> transitionId) {
    /**
     * Closed lifecycle kinds; creation uses its existing distinct command.
     */
    public enum Operation {
        /**
         * Same-key/same-algorithm root credential rollover.
         */ ROOT_ROLLOVER,
        /**
         * Root key or outgoing algorithm change, pending separate activation.
         */ ROOT_CANDIDATE,
        /**
         * New credential/path for an existing intermediate authority.
         */ INTERMEDIATE_ISSUE,
        /**
         * Same-key intermediate rollover.
         */ INTERMEDIATE_ROLLOVER,
        /**
         * Explicit intermediate outgoing role rotation.
         */ INTERMEDIATE_ROTATION
    }

    /**
     * Rejects partial evidence and a transition identity on a noncandidate operation.
     *
     * @param version context version, one
     * @param operation exact lifecycle kind
     * @param expectedHead original selected generation/path and monotonic epoch
     * @param originalCredentialId exact original CA credential
     * @param originalCertificateSha256 lowercase original certificate DER SHA-256
     * @param transitionId root candidate transition identity, absent for immediate publication
     * @throws NullPointerException if operation, expectedHead, originalCredentialId, transitionId
     *     is null
     * @throws IllegalArgumentException if the version, certificate commitment or lifecycle metadata
     *     violates the canonical context contract
     */
    public CaLifecycleContext {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(expectedHead, "expectedHead");
        Objects.requireNonNull(originalCredentialId, "originalCredentialId");
        Objects.requireNonNull(transitionId, "transitionId");
        if (version != 1
                || originalCertificateSha256 == null
                || !originalCertificateSha256.matches("[0-9a-f]{64}")
                || transitionId.isPresent() != (operation == Operation.ROOT_CANDIDATE)) {
            throw new IllegalArgumentException("Invalid CA lifecycle context");
        }
    }
}
