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
package zeroecho.pki.api.profile;

/**
 * Closed multi-party approval requirement a certificate profile places on
 * end-entity issuance.
 *
 * <p>
 * This is the portable, deployment-neutral half of the approval control: the
 * profile states <em>whether</em> issuing a credential of this kind requires an
 * administrative approval and, if so, whether a single approval or a multi-party
 * threshold is mandated. The concrete approver identities, the exact threshold
 * count for {@link #THRESHOLD}, separation-of-duties, eligibility, and approval
 * lifetime are deployment concerns supplied by the server realm's approval
 * authority, never embedded in the transportable profile document.
 * </p>
 *
 * <p>Server deployments enforce the declared approval gate. In the standalone
 * local administrative mode, the explicitly configured local operator has root
 * authority: invoking the command approves it, including {@link #SINGLE} and
 * {@link #THRESHOLD}. This local authorization does not fabricate server approval
 * evidence and does not bypass cryptographic, profile, or consistency checks.</p>
 *
 * <p>
 * The value is deny-by-default oriented: it is always declared explicitly in the
 * canonical profile document and never inferred. Consumers branch on the
 * constant through an exhaustive {@code switch}; a new requirement cannot be
 * introduced without an explicit mapping decision at every enforcement site.
 * </p>
 */
public enum IssuanceApprovalRequirement {

    /** Issuance proceeds without any administrative approval. */
    NONE,

    /** Issuance requires exactly one attributable administrative approval. */
    SINGLE,

    /** Issuance requires a multi-party (M-of-N) approval threshold. */
    THRESHOLD;

    /**
     * Indicates whether server issuance under this requirement must be gated by
     * a durable administrative approval before the credential is signed.
     *
     * @return {@code true} unless the requirement is {@link #NONE}
     */
    public boolean requiresApproval() {
        return this != NONE;
    }
}
