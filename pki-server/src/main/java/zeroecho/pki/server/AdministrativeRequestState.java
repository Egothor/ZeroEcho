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

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.PkiOperationValue;

/**
 * Reads and replaces durable administrative records without owning worker or session lifetime.
 *
 * <p>Worker and session lifetimes remain the responsibility of the calling coordinator.
 */
final class AdministrativeRequestState {
    private final ServerRealmContext realm;
    private final ServerControlStore control;
    private final Clock clock;
    private final OcspResponderProvisioningService ocspProvisioning;

    /* default */ AdministrativeRequestState(ServerRealmContext realm, ServerControlStore control, Clock clock,
            OcspResponderProvisioningService ocspProvisioning) {
        this.realm=realm; this.control=control; this.clock=clock; this.ocspProvisioning=ocspProvisioning;
    }
    /* default */ Optional<AdministrativeRequest> find(String id) { return control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,id).map(AdministrativeRequestCodec::decode); }

    /* default */ void write(AdministrativeRequest old,AdministrativeRequest next,Optional<ApprovalService.Request> prior,Optional<ApprovalService.Request> approval) {
        if (OcspProvisioningSlot.OPERATION.equals(old.operation())) {
            control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(next),Optional.of(AdministrativeRequestCodec.encode(old).commitment()),
                    prior,approval,Optional.empty(),Optional.of(ocspProvisioning.transition(old,next)));
        } else {
            control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(next),Optional.of(AdministrativeRequestCodec.encode(old).commitment()),prior,approval);
        }
        audit(next);
    }

    /* default */ void audit(AdministrativeRequest value) {
        try {
            realm.auditTransport("ADMINISTRATIVE_REQUEST_STATE",value.actor().principalId(),Map.of(
                    "requestId",value.requestId(),"operation",value.operation(),"state",value.state().name(),
                    "revision",Long.toString(value.revision()),"targetCommitment",value.targetCommitment()));
        } catch (IllegalStateException ignored) {
            // The durable private control record is authoritative; a closing audit projection cannot undo it.
        }
    }

    /* default */ AdministrativeRequest update(AdministrativeRequest old,AdministrativeRequest.State state,Optional<SigningAcceptanceReceipt> receipt,
            Optional<PkiOperationValue.ObjectValue> result,Optional<String> code) {
        return new AdministrativeRequest(old.requestId(),old.revision()+1,old.operation(),old.envelope(),old.actor(),old.scope(),old.operationCommitment(),old.profileCommitment(),old.targetCommitment(),state,old.createdAt(),now(),old.executionTimeoutMillis(),old.approvalId(),old.policyCommitment(),receipt,result,code,old.sdkProof());
    }

    /* default */ static ApprovalService.Request approvalState(ApprovalService.Request old,ApprovalService.State state,Optional<String> result) {
        return new ApprovalService.Request(old.approvalId(),old.operationId(),old.operationCommitment(),old.scope(),old.requesterPrincipalId(),old.createdAt(),old.expiresAt(),old.policy(),old.policyCommitment(),state,old.decisions(),result);
    }

    /* default */ Instant now() { return clock.instant().truncatedTo(ChronoUnit.MILLIS); }

    /* default */ static boolean safeSigningCode(String code) {
        return java.util.Arrays.stream(zeroecho.pki.spi.crypto.SigningProvider.DetailCode.values()).anyMatch(value -> value.name().equals(code))
                || java.util.Arrays.stream(zeroecho.pki.api.PkiFailureReason.values()).anyMatch(value -> value.externalSafe() && value.name().equals(code))
                || Set.of("CONTENT_INTEGRITY_FAILURE","PROVIDER_ID_MISMATCH","CANCELLED","EXPIRED").contains(code);
    }

    /* default */ static String safeDomainCode(PkiException failure) { return failure.failureReason().filter(zeroecho.pki.api.PkiFailureReason::externalSafe).map(Enum::name).orElse("PKI_POLICY_REJECTED"); }

    /* default */ static PkiOperationValue.Text text(String value) { return new PkiOperationValue.Text(value); }

    /* default */ PkiOperationValue.ObjectValue projection(AdministrativeRequest value,String viewer,boolean detail, AdministrativeRequestPolicy requestPolicy) {
        Map<String,PkiOperationValue> out=new LinkedHashMap<>();
        out.put("requestId",text(value.requestId()));out.put("operation",text(value.operation()));out.put("state",text(value.state().name()));
        out.put("requesterPrincipalId",text(value.actor().principalId()));out.put("createdAt",text(value.createdAt().toString()));out.put("updatedAt",text(value.updatedAt().toString()));
        out.put("executionTimeout",text(Duration.ofMillis(value.executionTimeoutMillis()).toString()));
        value.approvalId().ifPresent(v->out.put("approvalId",text(v)));value.receipt().ifPresent(v->out.put("signingOperationId",text(v.operationId().value())));
        value.failureCode().ifPresent(v->out.put("failureCode",text(v)));
        boolean content=requestPolicy.canReviewTarget(value,viewer);
        if(content && (detail || viewer.equals(value.actor().principalId()))) {
            PkiOperationValue.ObjectValue args=(PkiOperationValue.ObjectValue)value.envelope().fields().get("arguments");
            String summary=value.operation();
            if(args.fields().get("subjectRef") instanceof PkiOperationValue.Text subject) { summary += " — " + subject.value().substring(0,Math.min(256,subject.value().length())); }
            out.put("summary",text(summary));
        }
        if(detail && content) {
            Map<String,PkiOperationValue> target=new LinkedHashMap<>();target.put("arguments",value.envelope().fields().get("arguments"));
            Optional.ofNullable(value.envelope().fields().get("authorityId")).ifPresent(v->target.put("authorityId",v));
            out.put("target",new PkiOperationValue.ObjectValue(target));value.result().ifPresent(v->out.put("result",v));
        }
        return new PkiOperationValue.ObjectValue(out);
    }

    /* default */ ServerControlStore.Page<AdministrativeRequest> list(String viewer,int offset,int limit,
            Optional<AdministrativeRequest.State> state,Optional<String> requester,Optional<String> operation, AdministrativeRequestPolicy requestPolicy) {
        if(operation.filter(value -> !value.matches("[a-z][a-z0-9.-]{2,127}")).isPresent()) { throw new IllegalArgumentException("Invalid operation filter"); }
        if(offset<0 || limit<1 || limit>100) { throw new IllegalArgumentException("Invalid request page"); }
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page=control.protocolRecords(ServerControlStore.ADMINISTRATIVE_REQUEST,offset,limit);
        List<AdministrativeRequest> values=page.values().stream().map(AdministrativeRequestCodec::decode).filter(v->requestPolicy.canRead(v,viewer))
                .filter(v->state.map(v.state()::equals).orElse(true)).filter(v->requester.map(v.actor().principalId()::equals).orElse(true))
                .filter(v->operation.map(v.operation()::equals).orElse(true)).toList();
        return new ServerControlStore.Page<>(values,page.nextOffset(),page.hasMore());
    }
}
