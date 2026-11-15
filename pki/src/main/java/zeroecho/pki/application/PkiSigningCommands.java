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
     * Resolves omitted creation selectors before command commitment or approval.
     * @param operation caller-selected immutable command
     * @return creation command with explicit configured default, or unchanged other command
     * @throws UnsupportedOperationException if creation normalization is unavailable
     */
    default PkiSigningOperation normalizeCreation(PkiSigningOperation operation) {
        throw new UnsupportedOperationException("Creation normalization unavailable");
    }

    /**
     * Freezes rotation role selections and the expected head before approval/hash capture.
     * @param operation immutable selected operation
     * @return normalized lifecycle command, or unchanged other command
     * @throws UnsupportedOperationException if required normalization is unavailable
     */
    default PkiSigningOperation normalizeLifecycle(PkiSigningOperation operation) {
        throw new UnsupportedOperationException("Lifecycle normalization unavailable");
    }

    /**
     * Checks known CA creation, CA lifecycle and ordinary leaf issuance/lifecycle
     * inputs without staging content, allocating a serial, signing, accepting work
     * or publishing metadata. Status-generation commands fail explicitly.
     * Execution repeats checks because profiles, keys and issuer state may change.
     *
     * @param operation immutable CA or leaf issuance/lifecycle command
     * @param access separately authenticated and authorized caller context
     * @param evidence optional trusted issuance evidence, never inferred
     * @param cancellation cooperative validation cancellation
     * @throws UnsupportedOperationException if this command has no pure validator
     * @throws NullPointerException if an argument is null
     * @throws zeroecho.pki.api.PkiException if known profile, subject or key policy rejects input
     * @throws IllegalArgumentException if a binding or input encoding is invalid
     */
    default void validate(PkiSigningOperation operation, AccessContext access,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("Pure signing input validation unavailable");
    }

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
     * Evaluates a dual-subject SDK request without signing, serial allocation or staging.
     * @param operation selected logical issuer and active profile
     * @param access independently authorized invocation context
     * @param request parsed exact client request; both client keys remain public
     * @param frozenValidity empty for initial evaluation, exact absolute bounds for revalidation
     * @param cancellation cooperative cancellation
     * @return exact public policy and issuer coordinates for F7
     * @throws UnsupportedOperationException if this service lacks SDK issuance
     * @throws zeroecho.pki.api.PkiException if input or frozen policy is invalid
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(PkiSigningOperation.IssueCredential operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            Optional<zeroecho.pki.api.Validity> frozenValidity, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK preview unavailable");
    }

    /**
     * Revalidates retained dual proof and freezes the same absolute validity before staging.
     * @param operation immutable issuer/profile/request selection
     * @param access separately authenticated and authorized invocation context
     * @param request exact parsed SDK request
     * @param approval trusted retained approval context; independently reverified
     * @param evidence optional trusted publication evidence
     * @param cancellation cooperative cancellation
     * @return caller-owned prepared request awaiting adoption or discard
     * @throws UnsupportedOperationException if this service lacks SDK issuance
     * @throws zeroecho.pki.api.PkiException if proof or frozen policy differs
     */
    default PreparedSemanticSigningRequest prepareSdk(PkiSigningOperation.IssueCredential operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        throw new UnsupportedOperationException("SDK preparation unavailable");
    }

    /**
     * Purely evaluates only issue, renewal, reissue or replacement SDK operations.
     * @param operation restricted leaf operation @param access authorized caller
     * @param request exact parsed client request @param frozenValidity absolute retained bounds, or empty initially
     * @param cancellation cooperative cancellation @return frozen public subject/issuer/lifecycle coordinates
     * @throws UnsupportedOperationException for another operation or an unavailable lifecycle service
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            Optional<zeroecho.pki.api.Validity> frozenValidity, CancellationSignal cancellation) {
        if (operation instanceof PkiSigningOperation.IssueCredential issue) return previewSdk(issue, access, request, frozenValidity, cancellation);
        throw new UnsupportedOperationException("SDK lifecycle preview unavailable");
    }

    /**
     * Prepares only issue, renewal, reissue or replacement using fresh accepted dual client proof.
     * @param operation restricted leaf operation @param access authorized caller
     * @param request exact client request @param approval retained proof and signed target
     * @param evidence trusted publication evidence @param cancellation cooperative cancellation
     * @return caller-owned staged request awaiting acceptance or discard
     * @throws UnsupportedOperationException for another operation or an unavailable lifecycle service
     */
    default PreparedSemanticSigningRequest prepareSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        if (operation instanceof PkiSigningOperation.IssueCredential issue) return prepareSdk(issue, access, request, approval, evidence, cancellation);
        throw new UnsupportedOperationException("SDK lifecycle preparation unavailable");
    }

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

    /**
     * Evaluates an explicitly bound native enrollment target without fabricating authority.
     * @param operation supported leaf operation @param access authorized invocation
     * @param request proof-bound original request @param frozenValidity retained absolute validity
     * @param enrollmentTarget trusted native enrollment coordinates, or empty for administrative use
     * @param cancellation cooperative cancellation @return immutable public preview
     * @throws UnsupportedOperationException if enrollment-target evaluation is unavailable
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(enrollmentTarget, "enrollmentTarget");
        if (enrollmentTarget.isPresent()) throw new UnsupportedOperationException("SDK enrollment preview unavailable");
        return previewSdk(operation, access, request, frozenValidity, cancellation);
    }
}
