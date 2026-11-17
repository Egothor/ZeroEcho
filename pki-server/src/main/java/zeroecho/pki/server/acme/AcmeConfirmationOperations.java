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
package zeroecho.pki.server.acme;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallengeRequest;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofResult;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;

/**
 * Provides confirmation operations for the ACME service.
 */
final class AcmeConfirmationOperations {
    private final AcmeService owner;
    /**
     * Creates an operation handler bound to the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmeConfirmationOperations(AcmeService owner) { this.owner = owner; }

    /**
     * Issues a credential-confirmation challenge for the authenticated account and order.
     */
    /* default */ CredentialConfirmationProofChallenge issueCredentialConfirmationChallenge(
            String accountId, String expectedAccountCommitment, String orderId){
        AcmeService.ConfirmationOrder confirmation = owner.operations.confirmation.requireConfirmationOrder(accountId, expectedAccountCommitment, orderId);
        CredentialConfirmationLifecycle lifecycle = owner.realm.session().confirmations()
                .get(confirmation.credentialId())
                .orElseThrow(() -> new IllegalStateException("ACME credential confirmation is unavailable"));
        owner.operations.confirmation.validateConfirmationLifecycle(confirmation, lifecycle);
        if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
            throw new IllegalStateException("ACME credential confirmation is not pending");
        }
        return owner.realm.session().confirmations().issueProofChallenge(
                new CredentialConfirmationProofChallengeRequest(confirmation.credentialId(),
                        lifecycle.revision(), lifecycle.recordCommitment()));
    }

    /**
     * Completes credential confirmation against the expected lifecycle revision and commitment.
     */
    /* default */ CredentialConfirmationProofResult completeCredentialConfirmation(
            String accountId, String expectedAccountCommitment, String orderId,
            long expectedLifecycleRevision, String lifecycleCommitment,
            String challengeCommitment, byte[] response){
        AcmeService.ConfirmationOrder confirmation = owner.operations.confirmation.requireConfirmationOrder(accountId, expectedAccountCommitment, orderId);
        CredentialConfirmationProofCas proofCas = new CredentialConfirmationProofCas(
                confirmation.credentialId(), expectedLifecycleRevision,
                lifecycleCommitment, challengeCommitment);
        return owner.realm.session().confirmations().verifyAndComplete(
                new CredentialConfirmationProofSubmission(proofCas, response));
    }

    /**
     * Resolves the authenticated order and its credential-confirmation context.
     */
    /* default */ AcmeService.ConfirmationOrder requireConfirmationOrder(String accountId,
            String expectedAccountCommitment, String orderId){
        AcmeState.Account account = owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Order order = owner.operations.shared.requireOrder(orderId);
        if (!order.accountId().equals(accountId) || order.status() != AcmeState.OrderStatus.VALID
                || order.credentialId().isEmpty()) {
            throw new IllegalArgumentException("ACME credential confirmation is unavailable");
        }
        AcmeState.Directory directory = owner.operations.shared.requireDirectory(order.directoryId());
        PkiId credentialId = order.credentialId().orElseThrow();
        owner.operations.shared.validatePublicationCorrelation(account, order, directory, credentialId);
        if (directory.confirmationPolicy().disclosurePolicy() == ConfirmationDisclosurePolicy.PUBLIC) {
            throw new IllegalArgumentException("ACME credential confirmation is not required");
        }
        return new AcmeService.ConfirmationOrder(directory, credentialId);
    }

    /**
     * Checks that the credential-confirmation lifecycle matches the selected order.
     */
    /* default */ void validateConfirmationLifecycle(AcmeService.ConfirmationOrder confirmation,
            CredentialConfirmationLifecycle lifecycle){
        AcmeState.Directory directory = confirmation.directory();
        if (!lifecycle.credentialId().equals(confirmation.credentialId())
                || !lifecycle.initialPolicyCommitment().equals(directory.confirmationPolicyCommitment())
                || !lifecycle.proofSuite().equals(directory.confirmationPolicy().proofSuite())
                || !lifecycle.confirmationRequired()) {
            throw new IllegalStateException("ACME credential confirmation binding differs");
        }
    }
}
