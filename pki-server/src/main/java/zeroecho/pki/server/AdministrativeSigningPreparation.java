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

import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.PkiSigningOperation;

/**
 * Prepares a single-use signing candidate or observes an existing managed-responder receipt.
 *
 * <p>Preparation returns either a candidate or a retained receipt; it does not authorize
 * execution.
 */
final class AdministrativeSigningPreparation {
    private final ServerRealmContext realm;
    private final java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService;
    private final HybridSdkAdmissionService sdkAdmission;
    private final OcspResponderProvisioningService ocspProvisioning;

    /* default */ AdministrativeSigningPreparation(ServerRealmContext realm,
            java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService,
            HybridSdkAdmissionService sdkAdmission, OcspResponderProvisioningService ocspProvisioning) {
        this.realm=realm; this.signingService=signingService;
        this.sdkAdmission=sdkAdmission; this.ocspProvisioning=ocspProvisioning;
    }

    /**
     * A prepared candidate or an already retained receipt; neither grants execution authority.
     */
    /* default */ sealed interface Result permits Candidate, Existing { }
    /**
     * Carries the same single-use candidate returned by the signing service.
     */
    /* default */ record Candidate(PreparedSemanticSigningRequest candidate) implements Result { }
    /**
     * Carries the exact observed managed-responder receipt without preparing new work.
     */
    /* default */ record Existing(SigningAcceptanceReceipt receipt) implements Result { }

    /* default */ Result prepare(AdministrativeRequest current, ServerOperationGateway.Request request,
            ServerOperationGateway.Admission admission, CancellationSignal cancellation,
            AdministrativeOperation.Signing signing) {
            AccessContext access=new AccessContext(new Principal("ADMIN_PRINCIPAL",request.principalId()),new Purpose(signing.operation().name()),Optional.empty(),Optional.empty());
            PreparedSemanticSigningRequest prepared;
            if (signing.operation() instanceof PkiSigningOperation.IssueOcspResponderCertificate provision) {
                ocspProvisioning.requireClaim(current);
                zeroecho.pki.api.issuance.CorrelatedIssuancePreparation correlated = signingService.get().prepareManagedOcspResponder(access,provision.request(),
                        realm.gateway().administrativeSigningEvidence(admission),cancellation);
                if (correlated instanceof zeroecho.pki.api.issuance.CorrelatedIssuancePreparation.Existing) {
                    SigningAcceptanceReceipt receipt = signingService.get().findManagedOcspResponderReceipt(provision.request())
                            .orElseThrow(() -> new IllegalStateException("OCSP retained receipt unavailable"));
                    return new Existing(receipt);
                }
                prepared = ((zeroecho.pki.api.issuance.CorrelatedIssuancePreparation.Prepared)correlated).prepared();
            } else if(current.sdkProof().isPresent()) {
                HybridSdkAdmissionService.Preparation input=sdkAdmission.preparation(current,request,current.envelope());
                PkiSigningOperation operation=HybridSdkIssuerResolver.issue(request);
                zeroecho.pki.application.PkiSigningCommands commands=realm.session().signingCommands().orElseThrow();
                zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview preview=commands.previewSdk(operation,access,input.subject(),Optional.of(HybridSdkIssuerResolver.frozenValidity(input.target())),cancellation);
                zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval proof=new zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval(preview,input.primaryFrame(),input.target(),
                        input.primaryProof(),input.alternativeProof(),input.proofCommitment(),input.acceptedAt());
                prepared=commands.prepareSdk(operation,access,input.subject(),proof,realm.gateway().administrativeSigningEvidence(admission),cancellation);
            } else {
                prepared=realm.session().signingCommands().orElseThrow().prepare(signing.operation(),access,
                        realm.gateway().administrativeSigningEvidence(admission),cancellation);
            }
            return new Candidate(prepared);
    }
}
