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

package zeroecho.pki.application;

import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;

/**
 * Shared semantic command preparation and safe completed-result projection.
 *
 * <p>Instances borrow their session's lifetime and support concurrent calls while
 * that session is open. They own no resources and perform no authentication or
 * authorization. The caller supplies its established access context and optional
 * issuance evidence; neither is inferred from the other.</p>
 */
public interface PkiSigningCommands {
    /**
     * Prepares a command using the existing semantic signing service.
     *
     * <p>This may stage durable content but does not accept the operation or dispatch
     * a signing operation. The caller owns the prepared request until it discards
     * it or transfers custody through semantic signing acceptance. Existing profile,
     * key, issuer, and content validation remain applicable. Issuance evidence is
     * passed unchanged to end-entity preparation and is not synthesized here.</p>
     *
     * @param operation immutable command inputs
     * @param access established caller context
     * @param evidence optional server-established issuance evidence
     * @param cancellation cooperative preparation cancellation
     * @return prepared request awaiting acceptance or discard
     * @throws NullPointerException if any argument is null
     * @throws IllegalStateException if the owning session is closed
     * @throws java.util.NoSuchElementException if a referenced object is absent
     * @throws UnsupportedOperationException if a required request service is absent
     * @throws IllegalArgumentException if command inputs or the requested format are invalid
     * @throws zeroecho.pki.api.PkiException if existing preparation policy rejects the command
     */
    PreparedSemanticSigningRequest prepare(PkiSigningOperation operation,
            AccessContext access, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation);

    /**
     * Projects an authoritative completed semantic observation to stable safe metadata.
     *
     * <p>The result contains the operation identity, kind, encoding, SHA-256 digest,
     * and applicable credential or status-object identity. It contains no encoded
     * payload, caller identity, or authorization decision. Projection takes O(D)
     * time and O(D) transient memory for the existing defensive snapshot of D
     * encoded result bytes, plus existing bounded status-result decoding costs.</p>
     *
     * @param operation authoritative semantic observation with completed outer state
     * @return immutable result named {@code signing.operation}
     * @throws NullPointerException if the observation is null
     * @throws IllegalArgumentException if its outer state is not completed
     * @throws IllegalStateException if the owning session is closed
     */
    PkiOperationResult completedResult(SemanticSigningOperation operation);
}
