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
package zeroecho.pki.server;

import zeroecho.pki.application.PkiOperationResult;
import java.util.Map;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiOperation;

/**
 * Reconciles retained signing observations under the original control-store monitor.
 *
 * <p>Uses the control-store monitor shared with request processing to coordinate retained
 * state.
 */
final class AdministrativeRequestRecovery {
    private final ServerRealmContext realm;
    private final ServerControlStore control;
    private final java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService;
    private final AdministrativeRequestPolicy requestPolicy;
    private final AdministrativeRequestState requestState;

    /* default */ AdministrativeRequestRecovery(ServerRealmContext realm, ServerControlStore control,
            java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService,
            AdministrativeRequestPolicy requestPolicy, AdministrativeRequestState requestState) {
        this.realm=realm; this.control=control; this.signingService=signingService;
        this.requestPolicy=requestPolicy; this.requestState=requestState;
    }

    /* default */ AdministrativeRequest observationUnavailable(AdministrativeRequest current) {
        if(current.failureCode().filter("SIGNING_OBSERVATION_UNAVAILABLE"::equals).isPresent()) { return current; }
        AdministrativeRequest next=requestState.update(current,current.state(),current.receipt(),Optional.empty(),Optional.of("SIGNING_OBSERVATION_UNAVAILABLE"));
        requestState.write(current,next,Optional.empty(),Optional.empty());return next;
    }

    /* default */ Optional<PkiOperation.SelectIssuancePath> activationSelection(AdministrativeRequest retained) {
        if(!PkiOperation.SelectIssuancePath.NAME.equals(retained.operation())){ return Optional.empty(); }
        AdministrativeOperation operation=requestPolicy.request(retained).operation();
        if(operation instanceof AdministrativeOperation.Pki pki&&pki.operation() instanceof PkiOperation.SelectIssuancePath selected
                &&selected.transitionCommitment().isPresent()&&selected.distributionAcknowledged()){ return Optional.of(selected); }
        return Optional.empty();
    }

    /* default */ zeroecho.pki.api.ca.RootTrustAnchorActivation activationEvidence(AdministrativeRequest retained,PkiOperation.SelectIssuancePath selected) {
        ApprovalService.Request approval=realm.approvals().requireCurrent(retained.approvalId().orElseThrow());
        if(!approval.operationCommitment().equals(retained.operationCommitment())||!retained.policyCommitment().filter(approval.policyCommitment()::equals).isPresent()){ throw new SecurityException("Activation approval target differs"); }
        PkiOperationOutcome inspected=realm.session().operations().execute(new PkiOperation.InspectIssuerGeneration(selected.issuerId()),CancellationSignal.NONE);
        if(!(inspected instanceof PkiOperationOutcome.Completed complete)){ throw new IllegalStateException("Activation transition unavailable"); }
        Map<String,PkiOperationValue> fields=complete.result().fields();
        if(!LifecycleProjection.text(fields,"transitionCommitment").equals(selected.transitionCommitment().orElseThrow())){ throw new SecurityException("Activation transition differs"); }
        zeroecho.pki.api.ca.CaHeadSnapshot head=selected.expectedHead().orElseThrow();
        return new zeroecho.pki.api.ca.RootTrustAnchorActivation(1,new PkiId(LifecycleProjection.text(fields,"transitionId")),
                selected.transitionCommitment().orElseThrow(),head,selected.issuerId(),selected.pathId(),Math.addExact(head.epoch(),1),
                new PkiId(retained.requestId()),retained.actor().principalId(),retained.policyCommitment().orElseThrow(),
                retained.operationCommitment(),retained.createdAt(),true);
    }

    /* default */ AdministrativeRequest activationUnknown(AdministrativeRequest retained) {
        if(retained.state()==AdministrativeRequest.State.RECONCILIATION_REQUIRED){ return retained; }
        return finish(retained,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"ROOT_ACTIVATION_OUTCOME_UNKNOWN");
    }

    // Retain the original control-store monitor and exact admitted-request ordering.
    /* default */
    @SuppressWarnings({"PMD.AvoidSynchronizedStatement"})
    AdministrativeRequest reconcile(AdministrativeRequest current) {
        zeroecho.pki.api.SemanticSigningService service=signingService.get();
        SigningAcceptanceReceipt receipt=current.receipt().orElseThrow();
        SigningAcceptanceResolution resolution=service.resolve(receipt);
        if(resolution==SigningAcceptanceResolution.CONFLICT) { return finish(current,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SIGNING_RECEIPT_CONFLICT"); }
        if(resolution==SigningAcceptanceResolution.NOT_ACCEPTED) {
            if (OcspProvisioningSlot.OPERATION.equals(current.operation())) { return finish(current,
                    AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"OCSP_PROVISIONING_ACCEPTANCE_NOT_RETAINED"); }
            if(current.state()!=AdministrativeRequest.State.DISPATCHING) { return finish(current,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SIGNING_ACCEPTANCE_LOST"); }
            synchronized(control) {
                AdministrativeRequest exact=requestState.find(current.requestId()).orElseThrow();
                if(exact.revision()!=current.revision()) { return exact; }
                AdministrativeRequest next=requestState.update(exact,AdministrativeRequest.State.READY,Optional.empty(),Optional.empty(),Optional.empty());
                Optional<ApprovalService.Request> prior=exact.approvalId().map(realm.approvals()::requireCurrent);
                prior.ifPresent(v -> {
                    if (v.state()!=ApprovalService.State.EXECUTING
                            || !v.requesterPrincipalId().equals(exact.actor().principalId())
                            || !v.operationCommitment().equals(exact.operationCommitment())
                            || !v.scope().equals(exact.scope())
                            || !v.policyCommitment().equals(exact.policyCommitment().orElseThrow())) {
                        throw new IllegalStateException("Claimed approval differs from retained receipt");
                    }
                });
                Optional<ApprovalService.Request> approval=prior.map(v->AdministrativeRequestState.approvalState(v,ApprovalService.State.APPROVED,Optional.empty()));
                requestState.write(exact,next,prior,approval);return next;
            }
        }
        zeroecho.pki.api.signing.SemanticSigningOperation snapshot=service.find(receipt.operationId()).orElseThrow();
        return switch(snapshot.state()) {
            case SIGNING,PUBLISHING -> {
                if(current.state()==AdministrativeRequest.State.RUNNING) { yield current; }
                AdministrativeRequest next=requestState.update(current,AdministrativeRequest.State.RUNNING,current.receipt(),Optional.empty(),Optional.empty());requestState.write(current,next,Optional.empty(),Optional.empty());yield next;
            }
            case FAILED -> finish(current,AdministrativeRequest.State.FAILED,Optional.empty(),snapshot.detailCode().filter(AdministrativeRequestState::safeSigningCode).orElse("SIGNING_FAILED"));
            case EXPIRED -> finish(current,AdministrativeRequest.State.EXPIRED,Optional.empty(),"SIGNING_EXPIRED");
            case COMPLETED -> finish(current,AdministrativeRequest.State.SUCCEEDED,Optional.of(new PkiOperationValue.ObjectValue(
                    realm.session().signingCommands().orElseThrow().completedResult(snapshot).fields())),null);
        };
    }

    /* default */ AdministrativeRequest claim(AdministrativeRequest current,Optional<SigningAcceptanceReceipt> receipt) {
        Optional<ApprovalService.Request> prior=current.approvalId().map(realm.approvals()::requireCurrent);
        prior.ifPresent(v->{if(v.state()!=ApprovalService.State.APPROVED || !v.requesterPrincipalId().equals(current.actor().principalId())
                || !v.operationCommitment().equals(current.operationCommitment()) || !v.scope().equals(current.scope())
                || !v.policyCommitment().equals(current.policyCommitment().orElseThrow())) { throw new SecurityException("Approval does not bind request"); }});
        AdministrativeRequest next=requestState.update(current,AdministrativeRequest.State.DISPATCHING,receipt,Optional.empty(),Optional.empty());
        requestState.write(current,next,prior,prior.map(v->AdministrativeRequestState.approvalState(v,ApprovalService.State.EXECUTING,Optional.empty())));return next;
    }

    /* default */ AdministrativeRequest outcome(AdministrativeRequest current,PkiOperationOutcome outcome) {
        if(outcome instanceof PkiOperationOutcome.Completed completed) { return finish(current,AdministrativeRequest.State.SUCCEEDED,Optional.of(new PkiOperationValue.ObjectValue(completed.result().fields())),null); }
        if(outcome instanceof PkiOperationOutcome.Failed failed) {
            boolean uncertain = switch(failed.classification()) {
                case RECOVERY_REQUIRED,EXTERNAL_OUTCOME_UNKNOWN,RESOURCE_FAILURE,CANCELLED,INTERNAL_FAILURE -> true;
                default -> false;
            };
            return finish(current,uncertain?AdministrativeRequest.State.RECONCILIATION_REQUIRED:AdministrativeRequest.State.FAILED,Optional.empty(),failed.code());
        }
        return finish(current,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"UNRETAINED_PENDING_OUTCOME");
    }

    // Retain the original control-store monitor and exact admitted-request ordering.
    /* default */
    @SuppressWarnings({"PMD.AvoidSynchronizedStatement"})
    AdministrativeRequest finish(AdministrativeRequest current,AdministrativeRequest.State state,Optional<PkiOperationValue.ObjectValue> result,String code) {
        synchronized(control) {
            AdministrativeRequest exact=requestState.find(current.requestId()).orElseThrow(); if(exact.revision()!=current.revision()) { return exact; }
            AdministrativeRequest next=requestState.update(exact,state,exact.receipt(),result,Optional.ofNullable(code));
            Optional<ApprovalService.Request> prior=exact.approvalId().map(realm.approvals()::requireCurrent).filter(v->v.state()==ApprovalService.State.EXECUTING);
            requestState.write(exact,next,prior,prior.map(v->AdministrativeRequestState.approvalState(v,ApprovalService.State.EXECUTED,Optional.of(state.name()))));return next;
        }
    }

    /* default */ AdministrativeRequest failCurrent(String id,String code) { AdministrativeRequest v=requestState.find(id).orElseThrow();return finish(v,AdministrativeRequest.State.FAILED,Optional.empty(),code); }

    // Keep the original fail-closed or uncertain-outcome boundary for every runtime provider failure.
    @SuppressWarnings({"PMD.AvoidCatchingGenericException"})
    /* default */ AdministrativeRequest observeActivation(AdministrativeRequest current,
            PkiOperation.SelectIssuancePath activation) {
        try {
            Optional<PkiOperationResult> observed=realm.session().operations().observeRootActivation(activation,activationEvidence(current,activation),CancellationSignal.NONE);
            if(observed.isPresent()){ return outcome(current,new PkiOperationOutcome.Completed(observed.orElseThrow())); }
        } catch(RuntimeException unavailable) {
            return activationUnknown(current);
        }
        return activationUnknown(current);
    }

    /* default */ Optional<AdministrativeRequest> approvalOutcome(AdministrativeRequest current) {
        if(current.approvalId().isPresent()) {
            ApprovalService.Request approval=realm.approvals().requireCurrent(current.approvalId().orElseThrow());
            if(approval.state()==ApprovalService.State.REJECTED || approval.state()==ApprovalService.State.CANCELLED) { return Optional.of(finish(current,AdministrativeRequest.State.REJECTED,Optional.empty(),"APPROVAL_REJECTED")); }
            if(approval.state()==ApprovalService.State.EXPIRED) { return Optional.of(finish(current,AdministrativeRequest.State.EXPIRED,Optional.empty(),"APPROVAL_EXPIRED")); }
            if(approval.state()!=ApprovalService.State.APPROVED) { return Optional.of(current); }
        }
        return Optional.empty();
    }
}
