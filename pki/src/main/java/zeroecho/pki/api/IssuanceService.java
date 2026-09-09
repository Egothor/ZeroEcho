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
package zeroecho.pki.api;

import zeroecho.core.io.CancellationSignal;

import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.issuance.BundleCommand;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.ReissueCommand;
import zeroecho.pki.api.issuance.RenewCommand;
import zeroecho.pki.api.issuance.ReplaceCommand;

/**
 * Issues, renews, replaces, and reissues credentials, and builds distributable
 * bundles.
 *
 * <p>
 * This service is framework-agnostic: concrete credential formats are
 * implemented by framework backends. The PKI runtime applies policy and profile
 * constraints before calling issuance backends.
 * </p>
 */
public interface IssuanceService {

    /**
     * Issues a new end-entity credential.
     *
     * <p>
     * Implementations must treat a supplied normalized request as untrusted
     * workflow state. Issuance reparses the original structural request, requires
     * proof of possession, and binds the exact request identity, subject, and
     * public key before privileged backend signing. Frameworks without verifiable
     * structural request evidence are not authorized by this operation.
     * </p>
     *
     * @param command issuance command
     * @return credential bundle (credential plus supporting artifacts)
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if issuance fails
     */
    CredentialBundle issueEndEntity(IssueEndEntityCommand command);

    /**
     * Issues a leaf credential with originating cancellation.
     * @param command validated issuance command
     * @param cancellation originating cooperative cancellation signal
     * @return issued credential bundle
     */
    default CredentialBundle issueEndEntity(IssueEndEntityCommand command, CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(cancellation, "cancellation");
        return issueEndEntity(command);
    }

    /**
     * Issues a leaf credential, co-committing server-derived issuance evidence into the credential's
     * universal attribute set in the same atomic durable write.
     *
     * <p>The evidence records the authenticated actor and authorization path (see
     * {@code IssuanceExecutionEvidence}); it is never trusted as issuance authority. The default
     * ignores the evidence for backends that do not co-commit it, preserving source compatibility.</p>
     *
     * @param command issuance command
     * @param evidence closed issuance-evidence attribute set (may be empty but not null)
     * @param cancellation originating cancellation
     * @return credential bundle
     */
    default CredentialBundle issueEndEntity(IssueEndEntityCommand command,
            zeroecho.pki.api.attr.AttributeSet evidence, CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(evidence, "evidence");
        return issueEndEntity(command, cancellation);
    }

    /**
     * Renews an existing credential according to policy-defined continuity
     * semantics.
     *
     * @param command renewal command
     * @return renewed credential bundle
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if renewal fails
     */
    CredentialBundle renew(RenewCommand command);

    /**
     * Renews a credential while carrying originating cancellation.
     * @param command validated renewal command
     * @param cancellation originating cooperative cancellation signal
     * @return renewed credential bundle
     */
    default CredentialBundle renew(RenewCommand command, CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(cancellation, "cancellation");
        return renew(command);
    }

    /**
     * Replaces an existing credential (e.g., after compromise or attribute
     * changes).
     *
     * @param command replacement command
     * @return replacement credential bundle
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if replacement fails
     */
    CredentialBundle replace(ReplaceCommand command);

    /**
     * Replaces a credential while carrying originating cancellation.
     * @param command validated replacement command
     * @param cancellation originating cooperative cancellation signal
     * @return replacement credential bundle
     */
    default CredentialBundle replace(ReplaceCommand command, CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(cancellation, "cancellation");
        return replace(command);
    }

    /**
     * Reissues based on a stored issuance record.
     *
     * @param command reissue command
     * @return reissued credential bundle
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if reissue fails
     */
    CredentialBundle reissue(ReissueCommand command);

    /**
     * Reissues a credential while carrying originating cancellation.
     * @param command validated reissue command
     * @param cancellation originating cooperative cancellation signal
     * @return reissued credential bundle
     */
    default CredentialBundle reissue(ReissueCommand command, CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(cancellation, "cancellation");
        return reissue(command);
    }

    /**
     * Builds a distributable bundle for an existing credential using chain
     * selection rules.
     *
     * @param command bundle command
     * @return bundle
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if bundle building fails
     */
    CredentialBundle buildBundle(BundleCommand command);
}
