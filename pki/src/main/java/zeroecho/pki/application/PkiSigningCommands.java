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
     * Resolves creation defaults and canonical managed-responder selection before approval.
     *
     * <p>Creation algorithms become explicit before command commitment. A managed
     * responder selection uses its canonical public-key provisioning binding;
     * neither normalization generates keys nor accepts an issuance operation.
     *
     * @param operation caller-selected immutable command
     * @return normalized creation or responder command, or an unchanged operation of another kind
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
     * <p>This may stage durable content but does not durably accept the primary
     * signing operation. Explicitly supported hybrid preparation may produce and
     * verify an alternative signature according to its semantic-service contract.
     * The caller owns the prepared request until it discards
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
     *
     * <p>The preview binds the exact requested keys, issuer/profile selection and
     * effective policy. Supplied absolute validity is retained during revalidation;
     * a public preview neither consumes a proof nor grants permission to issue.
     *
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
     *
     * <p>Proof lifetime is evaluated at its retained acceptance time. Current permitted
     * use and the actual selected target are checked before alternative signing;
     * returned staged content remains caller-owned until acceptance or discard.
     * This preparation does not durably accept the primary signing operation.
     *
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
     *
     * <p>The selected lifecycle predecessor and both subject keys contribute to
     * the public target. No proof is consumed, no serial allocated and no content
     * staged. The default handles issuance through the narrow overload and rejects
     * lifecycle operations unless the implementation explicitly supports them.
     *
     * @param operation supported immutable leaf operation
     * @param access authenticated and separately authorized invocation context
     * @param request exact original parsed dual-subject request
     * @param frozenValidity absolute retained bounds, or an empty optional initially
     * @param cancellation cooperative validation cancellation signal
     * @return frozen public subject, issuer and applicable lifecycle coordinates
     * @throws UnsupportedOperationException for another operation or an unavailable lifecycle service
     * @throws zeroecho.pki.api.PkiException if predecessor, keys, policy or frozen target is invalid
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            Optional<zeroecho.pki.api.Validity> frozenValidity, CancellationSignal cancellation) {
        if (operation instanceof PkiSigningOperation.IssueCredential issue) {
            return previewSdk(issue, access, request, frozenValidity, cancellation);
        }
        throw new UnsupportedOperationException("SDK lifecycle preview unavailable");
    }

    /**
     * Prepares only issue, renewal, reissue or replacement using fresh accepted dual client proof.
     *
     * <p>The retained accepted proof must match the current permitted use and exact
     * frozen target. Hybrid alternative signing can occur during preparation, but
     * primary durable acceptance remains separate. The default delegates issuance
     * to the narrow overload and rejects unsupported lifecycle operations.
     *
     * @param operation supported immutable leaf operation
     * @param access authenticated and separately authorized invocation context
     * @param request exact original parsed dual-subject request
     * @param approval retained accepted proof and frozen target
     * @param evidence trusted publication evidence, or an empty optional for embedded use
     * @param cancellation cooperative pre-acceptance cancellation signal
     * @return caller-owned staged request awaiting acceptance or discard
     * @throws UnsupportedOperationException for another operation or an unavailable lifecycle service
     * @throws zeroecho.pki.api.PkiException if proof, predecessor, policy, target or staging validation fails
     */
    default PreparedSemanticSigningRequest prepareSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval approval,
            Optional<IssuanceExecutionEvidence> evidence, CancellationSignal cancellation) {
        if (operation instanceof PkiSigningOperation.IssueCredential issue) {
            return prepareSdk(issue, access, request, approval, evidence, cancellation);
        }
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
     *
     * <p>A native target must match the supported operation mapping and original
     * request kind; the existence of a lifecycle overload does not enable every
     * carrier/profile combination. The default rejects present native targets and
     * delegates an empty target to administrative preview. No proof is consumed,
     * serial allocated, signature produced or content staged by evaluation.
     *
     * @param operation supported immutable leaf operation
     * @param access authenticated and separately authorized invocation context
     * @param request exact proof-bound original dual-subject request
     * @param frozenValidity retained absolute validity, or an empty optional initially
     * @param enrollmentTarget trusted native enrollment coordinates, or empty for administrative use
     * @param cancellation cooperative validation cancellation signal
     * @return immutable public preview including any supported native target
     * @throws NullPointerException if the enrollment-target optional is null
     * @throws UnsupportedOperationException if enrollment-target evaluation is unavailable
     * @throws zeroecho.pki.api.PkiException if native request, operation mapping or target coordinates differ
     */
    default zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview previewSdk(PkiSigningOperation operation,
            AccessContext access, zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest request,
            Optional<zeroecho.pki.api.Validity> frozenValidity,
            Optional<zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget> enrollmentTarget,
            CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(enrollmentTarget, "enrollmentTarget");
        if (enrollmentTarget.isPresent()) {
            throw new UnsupportedOperationException("SDK enrollment preview unavailable");
        }
        return previewSdk(operation, access, request, frozenValidity, cancellation);
    }
}
