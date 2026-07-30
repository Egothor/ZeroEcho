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
     * Reissues based on a stored issuance record.
     *
     * @param command reissue command
     * @return reissued credential bundle
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if reissue fails
     */
    CredentialBundle reissue(ReissueCommand command);

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
