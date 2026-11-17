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

import java.util.List;
import java.util.Map;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.application.IssuanceExecutionEvidence;

/**
 * Provides enrollment operations for the ACME service.
 */
final class AcmeEnrollmentOperations {
    private final AcmeService owner;
    /**
     * Creates an operation handler bound to the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmeEnrollmentOperations(AcmeService owner) { this.owner = owner; }

    /**
     * Returns the enrollment coordinator owned by the realm.
     */
    /* default */ EnrollmentCoordinator enrollment(){
        return owner.realm.enrollmentCoordinator().orElseThrow(() -> new IllegalStateException("ACME enrollment coordinator is unavailable"));
    }

    /**
     * Tests whether the selected directory supports SDK enrollment.
     */
    /* default */ boolean hybridSdkAvailable(AcmeState.Directory directory){
        Optional<zeroecho.pki.server.enrollment.EnrollmentProfile> policy = owner.realm.enrollmentProfiles().find(directory.enrollmentProfileId());
        if (policy.isEmpty() || policy.orElseThrow().state() != zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE
                || policy.orElseThrow().sdkProfile().isEmpty() || owner.realm.enrollmentCoordinator().isEmpty()
                || owner.realm.session().semanticSigning().isEmpty()) { return false; }
        Optional<ImportedCertificateProfileVersion> profile = owner.realm.session().profiles().getImportedVersion(directory.profile().profileId(), directory.profile().profileVersion());
        return profile.isPresent() && profile.orElseThrow().definition().hybridMode() instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature alt
                && alt.subjectKeySource() == zeroecho.pki.api.hybrid.HybridCertificateMode.AlternativeSubjectKeySource.REQUEST;
    }

    /**
     * Creates an SDK proof challenge for the authenticated account and order.
     */
    /* default */ zeroecho.pki.server.enrollment.EnrollmentSdkAdmission.Challenge challengeSdk(String accountId,
            String expectedAccountCommitment, String orderId, byte[] csrDer, byte[] clientNonce, String canonicalOrigin){
        AcmeState.Account account = owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment); AcmeState.Order order = owner.operations.shared.requireOrder(orderId);
        if (!order.accountId().equals(accountId)) { throw new IllegalArgumentException("ACME order unavailable"); }
        return owner.operations.enrollment.enrollment().challengeSdk(owner.operations.bindings.sdkAdmission(account, order, csrDer, canonicalOrigin), clientNonce);
    }

    /**
     * Accepts SDK enrollment evidence for the selected account and order.
     */
    /* default */ AcmeState.Order acceptSdk(SdkAcceptance arguments) {
        String accountId = arguments.argument0();
        String expectedAccountCommitment = arguments.argument1();
        String orderId = arguments.argument2();
        byte[] csrDer = arguments.argument3();
        String intentId = arguments.argument4();
        String sdkRequestId = arguments.argument5();
        byte[] primaryProof = arguments.argument6();
        byte[] alternativeProof = arguments.argument7();
        String canonicalOrigin = arguments.argument8();
        CancellationSignal cancellation = arguments.argument9();

        AcmeState.Account account = owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment); AcmeState.Order order = owner.operations.shared.requireOrder(orderId);
        if (!order.accountId().equals(accountId)) { throw new IllegalArgumentException("ACME order unavailable"); }
        AcmeState.Directory directory = owner.operations.shared.requireDirectory(order.directoryId());
        zeroecho.pki.server.enrollment.EnrollmentSdkIntent retained = owner.operations.enrollment.enrollment().retainedSdkIntent(intentId).orElseThrow(() -> new IllegalArgumentException("SDK intent unavailable"));
        zeroecho.pki.server.enrollment.EnrollmentSdkAdmission old = retained.admission(); EnrollmentCoordinator.Admission original = old.admission();
        Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> authFields = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.decode(old.authenticationContext().field(5)).objectFields();
        if (original.protocol() != EnrollmentTransaction.Protocol.ACME || !original.endpointId().equals(directory.directoryId())
                || !old.target().endpointId().equals(directory.alias()) || !original.requester().actorId().equals(accountId)
                || !authFields.get("orderId").textValue().equals(orderId) || !original.transactionId().equals(owner.operations.shared.digest(orderId))
                || !canonicalOrigin.equals(old.canonicalOrigin()) || !java.util.Arrays.equals(original.payload().der(), csrDer)) {
            throw new IllegalArgumentException("SDK retained order differs");
        }
        if (retained.state() == zeroecho.pki.server.enrollment.EnrollmentSdkIntent.State.CONSUMED) {
            EnrollmentCoordinator.Admission readAdmission = new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.ACME, original.endpointId(), owner.operations.bindings.sdkRequester(account),
                    original.transactionId(), original.operation(), original.payload(), original.validity(), original.predecessorId(), original.protocolDeadline());
            zeroecho.pki.server.enrollment.EnrollmentSdkAdmission read = new zeroecho.pki.server.enrollment.EnrollmentSdkAdmission(readAdmission, old.expectedEndpointCommitment(), old.canonicalOrigin(), old.authenticationContext(), old.target(), Optional.empty());
            EnrollmentTransaction transaction = owner.operations.enrollment.enrollment().admitSdk(read, intentId, sdkRequestId, primaryProof, alternativeProof);
            return owner.operations.enrollment.attachSdkReceipt(order, transaction);
        }
        EnrollmentTransaction transaction = owner.operations.enrollment.enrollment().admitSdk(owner.operations.bindings.sdkAdmission(account, order, csrDer, canonicalOrigin), intentId, sdkRequestId, primaryProof, alternativeProof);
        owner.operations.bindings.requireEnrollmentBinding(order, directory, transaction);
        return owner.operations.enrollment.continueEnrollment(order, directory, account, transaction, cancellation);
        }


    /**
     * Attaches the enrollment receipt to the retained order.
     */
    /* default */ AcmeState.Order attachSdkReceipt(AcmeState.Order order, EnrollmentTransaction transaction){
        if (order.status() == AcmeState.OrderStatus.VALID) { return order; }
        RetainedIssuanceBinding binding = owner.operations.enrollment.enrollment().issuanceBinding(transaction.id());
        AcmeState.OrderStatus status = switch (transaction.state()) {
            case REJECTED, EXPIRED, FAILED -> AcmeState.OrderStatus.INVALID;
            default -> AcmeState.OrderStatus.PROCESSING;
        };
        Optional<PkiId> operation = transaction.receipt().map(zeroecho.pki.api.signing.SigningAcceptanceReceipt::operationId).or(order::signingOperationId);
        if (transaction.state() == EnrollmentTransaction.State.ISSUED) {
            SemanticSigningOperation signed = owner.realm.session().semanticSigning().orElseThrow().find(operation.orElseThrow()).orElseThrow();
            return owner.operations.enrollment.applySigningSnapshot(order, owner.operations.shared.requireDirectory(order.directoryId()), order.accountId(), signed);
        }
        if (order.status() == status && order.issuanceCommitment().equals(Optional.of(binding.effectiveCommitment())) && order.signingOperationId().equals(operation)) { return order; }
        return (AcmeState.Order) owner.store.replace(List.of(new AcmeControlStore.Replacement(order, owner.operations.shared.copyOrder(order, status, Optional.empty(), operation, Optional.of(binding.effectiveCommitment()))))).getFirst();
    }


    /**
     * Finds the enrollment transaction associated with the selected order and directory.
     */
    /* default */ Optional<EnrollmentTransaction> enrollmentFor(AcmeState.Order order, AcmeState.Directory directory){
        return owner.operations.enrollment.enrollment().find(EnrollmentTransaction.Protocol.ACME, directory.alias(), IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT,
                order.accountId(), owner.operations.shared.digest(order.orderId()), EnrollmentTransaction.Operation.ISSUE);
    }


    /**
     * Advances an existing enrollment transaction and projects its state onto the order.
     */
    /* default */ AcmeState.Order continueEnrollment(AcmeState.Order order, AcmeState.Directory directory, AcmeState.Account account,
            EnrollmentTransaction transaction, CancellationSignal cancellation){
        EnrollmentTransaction continued = owner.operations.enrollment.enrollment().dispatch(transaction.id(), cancellation);
        owner.operations.bindings.requireEnrollmentBinding(order, directory, continued);
        RetainedIssuanceBinding binding = owner.operations.enrollment.enrollment().issuanceBinding(continued.id());
        Optional<PkiId> operationId = switch (continued.state()) {
            case ACCEPTED, ISSUED, FAILED -> continued.receipt().map(zeroecho.pki.api.signing.SigningAcceptanceReceipt::operationId);
            default -> order.signingOperationId();
        };
        AcmeState.OrderStatus status = switch (continued.state()) {
            case REJECTED, EXPIRED, FAILED -> AcmeState.OrderStatus.INVALID;
            case ISSUED -> AcmeState.OrderStatus.VALID;
            default -> AcmeState.OrderStatus.PROCESSING;
        };
        if (continued.receipt().isPresent()) { AcmeService.tripFinalizeFault(AcmeService.FinalizeFaultPoint.BEFORE_SIGNING_ATTACHMENT); }
        if (status == AcmeState.OrderStatus.VALID) { return continueIssuedOrder(order, directory, account, continued, operationId, binding); }
        if (order.status() == status && order.issuanceCommitment().filter(binding.effectiveCommitment()::equals).isPresent()
                && order.signingOperationId().equals(operationId)) { return order; }
        AcmeState.Order updated = owner.operations.shared.copyOrder(order, status, Optional.empty(), operationId, Optional.of(binding.effectiveCommitment()));
        return (AcmeState.Order) owner.store.replace(List.of(new AcmeControlStore.Replacement(order, updated))).getFirst();
    }

    /**
     * Updates the order from the retained signing-operation snapshot.
     */
    /* default */ AcmeState.Order applySigningSnapshot(AcmeState.Order order, AcmeState.Directory directory,
            String accountId, SemanticSigningOperation snapshot){
        PkiId operationId = snapshot.submissionId().id();
        return switch (snapshot.state()) {
            case SIGNING, PUBLISHING -> {
                if (order.status() == AcmeState.OrderStatus.PROCESSING
                        && order.signingOperationId().filter(operationId::equals).isPresent()) { yield order; }
                AcmeState.Order processing = owner.operations.shared.copyOrder(order, AcmeState.OrderStatus.PROCESSING,
                        Optional.empty(), Optional.of(operationId));
                yield (AcmeState.Order) owner.store.replace(List.of(
                        new AcmeControlStore.Replacement(order, processing))).get(0);
            }
            case FAILED, EXPIRED -> {
                AcmeState.Order invalid = owner.operations.shared.copyOrder(order, AcmeState.OrderStatus.INVALID,
                        Optional.empty(), Optional.of(operationId));
                yield (AcmeState.Order) owner.store.replace(List.of(
                        new AcmeControlStore.Replacement(order, invalid))).get(0);
            }
            case COMPLETED -> owner.operations.enrollment.completeRecoveredOrder(order, directory, accountId, operationId, snapshot);
        };
    }

    /**
     * Completes a recovered order from its retained signing result.
     */
    /* default */ AcmeState.Order completeRecoveredOrder(AcmeState.Order order, AcmeState.Directory directory,
            String accountId, PkiId operationId, SemanticSigningOperation completed){
        PkiId credentialId = completed.completedCredentialId()
                .orElseThrow(() -> new IllegalStateException("Completed issuance lacks its publication identity"));
        zeroecho.pki.api.credential.Credential credential = owner.realm.session().repository()
                .credential(credentialId)
                .orElseThrow(() -> new IllegalStateException("Completed issuance publication is unavailable"));
        if (!credential.issuerRef().caId().equals(order.authorityId())
                || !credential.issuerRef().issuerId().equals(order.issuerId())
                || !credential.issuerRef().chainPathId().equals(order.issuancePathId())) {
            throw new IllegalStateException("Completed ACME issuance selection differs");
        }
        AcmeState.Account account = owner.operations.shared.requireAccount(accountId);
        owner.operations.shared.validatePublicationCorrelation(account, order, directory, credentialId);
        owner.operations.shared.registerPublication(credentialId, accountId);
        AcmeState.Order valid = owner.operations.shared.copyOrder(order, AcmeState.OrderStatus.VALID,
                Optional.of(credentialId), Optional.of(operationId));
        AcmeState.Order committed = (AcmeState.Order) owner.store.replace(List.of(
                new AcmeControlStore.Replacement(order, valid))).get(0);
        owner.operations.shared.audit("ACME_CERTIFICATE_ISSUED", accountId,
                Map.of("order", order.orderId(), "credential", credentialId.value()));
        return committed;
    }

    private AcmeState.Order continueIssuedOrder(AcmeState.Order order, AcmeState.Directory directory, AcmeState.Account account,
            EnrollmentTransaction continued, Optional<PkiId> operationId, RetainedIssuanceBinding binding) {

            if (order.status() == AcmeState.OrderStatus.VALID) {
                owner.operations.shared.validatePublicationCorrelation(account, order, directory, continued.credentialId().orElseThrow());
                owner.operations.shared.registerPublication(continued.credentialId().orElseThrow(), account.accountId());
                return order;
            }
            AcmeState.Order attached = owner.operations.shared.copyOrder(order, AcmeState.OrderStatus.PROCESSING, Optional.empty(), operationId, Optional.of(binding.effectiveCommitment()));
            AcmeState.Order observed = order;
            if (!order.issuanceCommitment().equals(attached.issuanceCommitment()) || !order.signingOperationId().equals(operationId)) {
                observed = (AcmeState.Order) owner.store.replace(List.of(new AcmeControlStore.Replacement(order, attached))).getFirst();
            }
            SemanticSigningOperation signed = owner.realm.session().semanticSigning().orElseThrow().find(operationId.orElseThrow()).orElseThrow();
            return owner.operations.enrollment.applySigningSnapshot(observed, directory, account.accountId(), signed);
            }


    /**
     * Borrowed arguments for one legacy facade call; byte arrays retain their original
     * ownership.
     */
    /* default */ record SdkAcceptance(String argument0, String argument1, String argument2, byte[] argument3, String argument4, String argument5, byte[] argument6, byte[] argument7, String argument8, CancellationSignal argument9) { }

}
