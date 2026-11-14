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

import java.util.Set;
import java.util.stream.Collectors;

/** Freezes the reviewed classification of every mutating catalog entry. */
final class AdministrativeRequestCoverage {
    private AdministrativeRequestCoverage() { }
    private static final Set<String> MUTATIONS = Set.of(
            "acme.account.deactivate",
            "acme.directory.activate",
            "acme.directory.deactivate",
            "acme.directory.register",
            "backup.export",
            "backup.restore",
            "backup.stream.acknowledge",
            "backup.stream.download",
            "backup.stream.export",
            "backup.stream.reserve",
            "backup.stream.restore",
            "backup.stream.upload",
            "backup.stream.verify",
            "ca.create",
            "ca.intermediate.create",
            "ca.intermediate.issue",
            "ca.rollover",
            "ca.rotate",
            "ca.transition",
            "certificate.publication.enroll",
            "cmp.endpoint.deregister",
            "cmp.endpoint.register",
            "credential.confirmation.challenge.issue",
            "credential.confirmation.pending.revoke",
            "credential.confirmation.proof.complete",
            "credential.hold",
            "credential.issue",
            "credential.reissue",
            "credential.renew",
            "credential.replace",
            "credential.revoke",
            "credential.unhold",
            "enrollment.profile.activate",
            "enrollment.profile.register",
            "enrollment.profile.suspend",
            "enrollment.profile.update",
            "enrollment.request.approve",
            "enrollment.request.reject",
            "est.endpoint.deregister",
            "est.endpoint.register",
            "issuer.path.register",
            "issuer.path.select",
            "ocsp.responder.activate",
            "ocsp.responder.deactivate",
            "ocsp.responder.register",
            "profile.activate",
            "profile.register",
            "publication.process",
            "publication.reconcile",
            "publication.register",
            "publication.retry",
            "repository.alias.remove",
            "repository.alias.set",
            "request.import",
            "scep.endpoint.deregister",
            "scep.endpoint.register",
            "security.approval.approve",
            "security.approval.cancel",
            "security.approval.reject",
            "security.approval.request",
            "security.break-glass.activate",
            "security.break-glass.create",
            "security.break-glass.revoke",
            "security.disclosure.capability.issue",
            "security.disclosure.capability.revoke",
            "security.disclosure.set",
            "security.grant.create",
            "security.grant.revoke",
            "security.principal.disable",
            "security.principal.enable",
            "security.principal.register",
            "security.role-assignment.create",
            "security.role-assignment.revoke",
            "status.generate",
            "status.schedule.set");
    private static final Set<String> DEDICATED = Set.of(
            "backup.export",
            "backup.restore",
            "backup.stream.acknowledge",
            "backup.stream.download",
            "backup.stream.export",
            "backup.stream.reserve",
            "backup.stream.restore",
            "backup.stream.upload",
            "backup.stream.verify",
            "credential.confirmation.challenge.issue",
            "credential.confirmation.proof.complete",
            "enrollment.request.approve",
            "enrollment.request.reject",
            "security.approval.approve",
            "security.approval.cancel",
            "security.approval.reject",
            "security.approval.request",
            "security.disclosure.capability.issue");

    static void verify() {
        var descriptors=new OperationSecurityDescriptors().descriptors().values();
        var actual=descriptors.stream().filter(OperationSecurityDescriptors.Descriptor::mutating)
                .map(OperationSecurityDescriptors.Descriptor::operationId).collect(Collectors.toSet());
        if(!actual.equals(MUTATIONS))throw new AssertionError("Catalog mutation coverage requires an explicit review");
        var catalog=new OperationSecurityDescriptors();
        var id=new zeroecho.pki.api.PkiId("synthetic-credential");
        var conditional=java.util.List.<zeroecho.pki.application.PkiOperation>of(
                new zeroecho.pki.application.PkiOperation.RevokeCredential(id,zeroecho.pki.api.revocation.RevocationReason.UNSPECIFIED),
                new zeroecho.pki.application.PkiOperation.HoldCredential(id),
                new zeroecho.pki.application.PkiOperation.UnholdCredential(id),
                new zeroecho.pki.application.PkiOperation.RevokePendingCredentialConfirmation(id));
        for(var operation:conditional) {
            var wrapped=new AdministrativeOperation.Pki(operation);
            if(catalog.approvalPolicyCategory(wrapped,true)!=OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK
                    ||catalog.approvalPolicyCategory(wrapped,false)!=OperationSecurityDescriptors.ApprovalCategory.NONE)throw new AssertionError("Conditional approval category changed: "+operation.name());
        }
        for(var descriptor:descriptors) {
            boolean expected=descriptor.mutating()&&!DEDICATED.contains(descriptor.operationId());
            if(AdministrativeRequestCoordinator.supports(descriptor)!=expected)throw new AssertionError("Incorrect durable boundary: "+descriptor.operationId());
        }
    }
}
