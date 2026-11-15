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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.server.http.HttpOperationCodec;
import zeroecho.pki.server.http.StrictJson;

/**
 * Realm-owned durable administrative workflow and bounded recovery worker.
 *
 * <p>Submission retains an exact target and creates its required approval atomically. Human
 * decisions only change approval state; this worker resumes as the original requester. Signing
 * receipts precede acceptance and recovery never submits an uncertain replacement. Generic
 * synchronous mutations interrupted after their durable dispatch marker require reconciliation.</p>
 */
public final class AdministrativeRequestCoordinator implements AutoCloseable {
    private static final int MAXIMUM_RETAINED = 10000;
    private static final int MAXIMUM_PENDING = 1000;
    private static final int PAGE = 32;
    private static final String APPROVAL_PREFIX = "admin-request.";
    private final ServerRealmContext realm;
    private final ServerControlStore control;
    private final HybridSdkAdmissionService sdkAdmission;
    private final OcspResponderProvisioningService ocspProvisioning;
    private final Clock clock;
    private final java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService;
    private final Semaphore wake = new Semaphore(0);
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Set<String> inFlight = new java.util.HashSet<>();
    private volatile Thread worker;
    private volatile PkiServerConfiguration.Authentication authentication;
    private int scanOffset;

    AdministrativeRequestCoordinator(ServerRealmContext realm, ServerControlStore control, Clock clock) {
        this(realm, control, clock, () -> realm.session().semanticSigning().orElseThrow());
    }

    /** Composes the signing observation boundary without changing durable request authority. */
    AdministrativeRequestCoordinator(ServerRealmContext realm, ServerControlStore control, Clock clock,
            java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService) {
        this(realm,control,clock,signingService,"https://unconfigured.invalid:443",HybridSdkAdmissionService.unsupported());
    }

    /** Explicit internal SDK composition; public carrier activation remains a separate configured boundary. */
    AdministrativeRequestCoordinator(ServerRealmContext realm, ServerControlStore control, Clock clock, String sdkOrigin) {
        this(realm,control,clock,()->realm.session().semanticSigning().orElseThrow(),sdkOrigin,new HybridSdkIssuerResolver(realm));
    }

    /** Internal server-owned SDK resolver composition; the default constructor remains unsupported. */
    AdministrativeRequestCoordinator(ServerRealmContext realm, ServerControlStore control, Clock clock,
            java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService,
            String sdkOrigin, HybridSdkAdmissionService.Resolver sdkResolver) {
        this.realm=realm; this.control=control; this.clock=clock;
        this.signingService=java.util.Objects.requireNonNull(signingService,"signingService");
        this.sdkAdmission=new HybridSdkAdmissionService(control,clock,this,sdkOrigin,sdkResolver);
        this.ocspProvisioning=new OcspResponderProvisioningService(realm.configuration().realmId(),control,signingService);
    }

    HybridSdkAdmissionService sdkAdmission() { return sdkAdmission; }

    /**
     * Starts bounded startup recovery and decision-driven dispatch for the permanent server.
     * @param authentication current trusted authentication/mapping policy
     */
    public synchronized void start(PkiServerConfiguration.Authentication authentication) {
        if (closed.get()) throw new IllegalStateException("Administrative workflow is closed");
        this.authentication=java.util.Objects.requireNonNull(authentication,"authentication");
        if (worker != null) return;
        worker = new Thread(this::run, "zeroecho-administrative-requests"); worker.setDaemon(true); worker.start();
    }

    /** Coalesces advisory wakeups; durable state and periodic scans remain authoritative. */
    public void wake() { if (!closed.get() && wake.availablePermits()==0) wake.release(); }

    /**
     * Admits one exact authenticated target without executing it on the submitting connection.
     * @param requestId stable client identity reused after uncertain acknowledgements
     * @param request original trusted actor and decoded operation
     * @param envelope strict operation envelope containing only version, arguments and optional authority/deadline
     * @param executionTimeout bounded post-approval execution budget
     * @return original or newly retained authoritative request
     */
    public AdministrativeRequest submit(String requestId, ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, Duration executionTimeout) {
        if (request.operation() instanceof AdministrativeOperation.Signing signing
                && signing.operation() instanceof PkiSigningOperation.IssueOcspResponderCertificate selected) {
            var provisioning = ocspProvisioning.select(selected.request());
            var canonical = new ServerOperationGateway.Request(request.realmId(),request.principalId(),request.authenticationMode(),
                    request.transportPrincipalId(),request.credentialEvidence(),request.operation(),request.resource(),request.relationship(),
                    request.context(),request.approvalId(),provisioning.requestId());
            try {
                return submitInternal(provisioning.requestId(),canonical,envelope,executionTimeout,Optional.empty(),Optional.of(provisioning));
            } catch (OcspResponderProvisioningService.TargetConflict conflict) {
                var retained=find(conflict.canonicalRequestId()).orElseThrow(()->new SecurityException("Request unavailable"));
                if(!canReviewTarget(retained,request.principalId()))throw new SecurityException("Request unavailable");
                throw new ProvisioningConflict(retained.requestId());
            }
        }
        return submitInternal(requestId,request,envelope,executionTimeout,Optional.empty(),Optional.empty());
    }

    AdministrativeRequest submitSdk(String requestId, ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, Duration executionTimeout, HybridSdkAdmissionService.Acceptance proof) {
        return submitInternal(requestId,request,envelope,executionTimeout,Optional.of(proof),Optional.empty());
    }

    private AdministrativeRequest submitInternal(String requestId, ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, Duration executionTimeout, Optional<HybridSdkAdmissionService.Acceptance> proof,
            Optional<OcspResponderProvisioningService.Selection> provisioning) {
        if (requestId == null || !requestId.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}")) throw new IllegalArgumentException("Invalid request ID");
        var admission = proof.map(value->value.context().admission()).orElseGet(()->realm.gateway().assessAdministrativeRequest(request));
        if (!supports(realm.gateway().descriptor(admission.request().operation()))) throw new IllegalArgumentException("DURABLE_REQUEST_UNSUPPORTED");
        var retainedEnvelope=freezeCreationEnvelope(envelope,admission.request().operation());
        long timeout = executionTimeout.toMillis();
        if (timeout < 1 || timeout > 120000) throw new IllegalArgumentException("Invalid execution budget");
        String target = provisioning.map(OcspResponderProvisioningService.Selection::targetCommitment)
                .orElseGet(() -> ApprovalService.digest(admission.commitment() + '|' + timeout));
        synchronized (control) {
            if (provisioning.isPresent()) {
                var existing = ocspProvisioning.existing(provisioning.orElseThrow());
                if (existing.isPresent()) {
                    var retained = existing.orElseThrow();
                    if (!canReviewTarget(retained,request.principalId())) throw new SecurityException("Request unavailable");
                    return retained;
                }
                if (find(requestId).isPresent()) throw new IllegalStateException("OCSP provisioning request has no matching slot");
            }
            var old = find(requestId);
            if (old.isPresent()) {
                var retained=old.orElseThrow();
                if (!retained.actor().principalId().equals(request.principalId())) throw new SecurityException("Request unavailable");
                if (!retained.targetCommitment().equals(target) || !retained.sdkProof().equals(proof.map(HybridSdkAdmissionService.Acceptance::proof))) throw new Conflict();
                return retained;
            }
        }
        var validatedProfile = proof.map(value->sdkProfileCommitment(value.context().target())).orElseGet(()->profileCommitment(admission.request()));
        try { if(proof.isEmpty())validateBeforeApproval(admission); }
        catch(UnsupportedOperationException unsupported) { throw new ValidationFailure("PURE_VALIDATION_UNAVAILABLE"); }
        catch(IllegalStateException precondition) { throw new ValidationFailure("OPERATION_PRECONDITION_FAILED"); }
        if (proof.isEmpty() && !validatedProfile.equals(profileCommitment(admission.request()))) {
            throw new ValidationFailure("PROFILE_CHANGED");
        }
        Instant now = now();
        var actor = new AdministrativeRequest.Actor(request.principalId(),request.authenticationMode(),request.transportPrincipalId(),request.credentialEvidence());
        Optional<String> approvalId=admission.policy().map(v->APPROVAL_PREFIX+requestId);
        var retained = new AdministrativeRequest(requestId,0,request.operation().name(),retainedEnvelope,actor,admission.request().resource().scope(),
                admission.commitment(),validatedProfile,target,approvalId.isPresent()?AdministrativeRequest.State.WAITING_APPROVAL:AdministrativeRequest.State.READY,
                now,now,timeout,approvalId,admission.policy().map(ApprovalService.Policy::commitment),Optional.empty(),Optional.empty(),Optional.empty(),proof.map(HybridSdkAdmissionService.Acceptance::proof));
        if(proof.isPresent())validateActor(retained);
        Optional<ApprovalService.Request> approval=admission.policy().map(policy->new ApprovalService.Request(approvalId.orElseThrow(),request.operation().name(),
                admission.commitment(),admission.request().resource().scope(),request.principalId(),now,now.plus(policy.lifetime()),policy,policy.commitment(),
                ApprovalService.State.PENDING,List.of(),Optional.empty()));
        synchronized (control) {
            if (provisioning.isPresent()) {
                var existing = ocspProvisioning.existing(provisioning.orElseThrow());
                if (existing.isPresent()) {
                    if (!canReviewTarget(existing.orElseThrow(),request.principalId())) throw new SecurityException("Request unavailable");
                    return existing.orElseThrow();
                }
                if (find(requestId).isPresent()) throw new IllegalStateException("OCSP provisioning request has no matching slot");
            }
            var raced=find(requestId);
            if (raced.isPresent()) {
                if (!raced.orElseThrow().actor().principalId().equals(request.principalId())) throw new SecurityException("Request unavailable");
                if (!raced.orElseThrow().targetCommitment().equals(target) || !raced.orElseThrow().sdkProof().equals(proof.map(HybridSdkAdmissionService.Acceptance::proof))) throw new Conflict();
                return raced.orElseThrow();
            }
            int count=0,pending=0;
            try(var cursor=control.protocolSnapshot(ServerControlStore.ADMINISTRATIVE_REQUEST)) {
                Optional<ServerControlStore.ProtocolRecord> next;
                while((next=cursor.next()).isPresent()) {
                    count++; if(!AdministrativeRequestCodec.decode(next.orElseThrow()).terminal()) pending++;
                    if(count>=MAXIMUM_RETAINED || pending>=MAXIMUM_PENDING) throw new Capacity();
                }
            }
            control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(retained),Optional.empty(),Optional.empty(),approval,
                    proof.map(HybridSdkAdmissionService.Acceptance::consumption),
                    provisioning.map(value -> ocspProvisioning.claim(value,retained)));
        }
        audit(retained);
        wake(); return retained;
    }

    /**
     * Reads a retained request after caller-specific ownership or approval-read authorization.
     * @param requestId durable request identity
     * @param viewer authenticated current viewer
     * @return retained request, or a uniform unavailable failure
     */
    public AdministrativeRequest inspect(String requestId,String viewer) {
        var value=find(requestId).orElseThrow(()->new SecurityException("Request unavailable"));
        if(!canRead(value,viewer)) throw new SecurityException("Request unavailable");return value;
    }

    /**
     * Lists a bounded stable page of visible request metadata without arguments.
     * @param viewer authenticated current viewer
     * @param offset zero-based private-record offset
     * @param limit page size, from one through one hundred
     * @param state optional exact state filter
     * @param requester optional exact requesting identity filter
     * @param operation optional exact catalog operation filter
     * @return visible rows and continuation over the bounded private snapshot
     */
    public ServerControlStore.Page<AdministrativeRequest> list(String viewer,int offset,int limit,
            Optional<AdministrativeRequest.State> state,Optional<String> requester,Optional<String> operation) {
        if(operation.filter(value -> !value.matches("[a-z][a-z0-9.-]{2,127}")).isPresent()) throw new IllegalArgumentException("Invalid operation filter");
        if(offset<0 || limit<1 || limit>100) throw new IllegalArgumentException("Invalid request page");
        var page=control.protocolRecords(ServerControlStore.ADMINISTRATIVE_REQUEST,offset,limit);
        var values=page.values().stream().map(AdministrativeRequestCodec::decode).filter(v->canRead(v,viewer))
                .filter(v->state.map(v.state()::equals).orElse(true)).filter(v->requester.map(v.actor().principalId()::equals).orElse(true))
                .filter(v->operation.map(v.operation()::equals).orElse(true)).toList();
        return new ServerControlStore.Page<>(values,page.nextOffset(),page.hasMore());
    }

    /**
     * Projects approved metadata; detailed target/result disclosure requires current operation authority.
     * @param value already visible request
     * @param viewer current viewer
     * @param detail whether to consider original target and final result disclosure
     * @return bounded safe HTTP projection
     */
    public PkiOperationValue.ObjectValue projection(AdministrativeRequest value,String viewer,boolean detail) {
        Map<String,PkiOperationValue> out=new LinkedHashMap<>();
        out.put("requestId",text(value.requestId()));out.put("operation",text(value.operation()));out.put("state",text(value.state().name()));
        out.put("requesterPrincipalId",text(value.actor().principalId()));out.put("createdAt",text(value.createdAt().toString()));out.put("updatedAt",text(value.updatedAt().toString()));
        out.put("executionTimeout",text(Duration.ofMillis(value.executionTimeoutMillis()).toString()));
        value.approvalId().ifPresent(v->out.put("approvalId",text(v)));value.receipt().ifPresent(v->out.put("signingOperationId",text(v.operationId().value())));
        value.failureCode().ifPresent(v->out.put("failureCode",text(v)));
        boolean content=canReviewTarget(value,viewer);
        if(content && (detail || viewer.equals(value.actor().principalId()))) {
            var args=(PkiOperationValue.ObjectValue)value.envelope().fields().get("arguments");
            String summary=value.operation();
            if(args.fields().get("subjectRef") instanceof PkiOperationValue.Text subject) summary += " — " + subject.value().substring(0,Math.min(256,subject.value().length()));
            out.put("summary",text(summary));
        }
        if(detail && content) {
            Map<String,PkiOperationValue> target=new LinkedHashMap<>();target.put("arguments",value.envelope().fields().get("arguments"));
            Optional.ofNullable(value.envelope().fields().get("authorityId")).ifPresent(v->target.put("authorityId",v));
            out.put("target",new PkiOperationValue.ObjectValue(target));value.result().ifPresent(v->out.put("result",v));
        }
        return new PkiOperationValue.ObjectValue(out);
    }

    /**
     * Processes one retained request; useful for deterministic fixtures and bounded worker scans.
     * @param id retained request identity
     * @return latest authoritative state
     */
    public AdministrativeRequest process(String id) {
        synchronized(control) { if(closed.get() || !inFlight.add(id)) return find(id).orElseThrow(); }
        try {
            var current=find(id).orElseThrow();
            if (current.operation().equals(OcspProvisioningSlot.OPERATION)) ocspProvisioning.requireClaim(current);
            var activation=activationSelection(current);
            if(activation.isPresent()&&(current.state()==AdministrativeRequest.State.DISPATCHING
                    ||current.state()==AdministrativeRequest.State.RECONCILIATION_REQUIRED)) {
                try {
                    var observed=realm.session().operations().observeRootActivation(activation.orElseThrow(),activationEvidence(current,activation.orElseThrow()),CancellationSignal.NONE);
                    if(observed.isPresent())return outcome(current,new PkiOperationOutcome.Completed(observed.orElseThrow()));
                } catch(RuntimeException unavailable) {
                    return activationUnknown(current);
                }
                return activationUnknown(current);
            }
            if(current.terminal()) return current;
            if(current.receipt().isPresent()) {
                if(current.sdkProof().isPresent())sdkAdmission.validateIntegrity(current);
                return reconcile(current);
            }
            if(current.sdkProof().isPresent())sdkAdmission.validateRetained(current,request(current),current.envelope());
            if(current.state()==AdministrativeRequest.State.DISPATCHING || current.state()==AdministrativeRequest.State.RUNNING) {
                return finish(current,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SYNCHRONOUS_OUTCOME_UNKNOWN");
            }
            if(current.approvalId().isPresent()) {
                var approval=realm.approvals().requireCurrent(current.approvalId().orElseThrow());
                if(approval.state()==ApprovalService.State.REJECTED || approval.state()==ApprovalService.State.CANCELLED) return finish(current,AdministrativeRequest.State.REJECTED,Optional.empty(),"APPROVAL_REJECTED");
                if(approval.state()==ApprovalService.State.EXPIRED) return finish(current,AdministrativeRequest.State.EXPIRED,Optional.empty(),"APPROVAL_EXPIRED");
                if(approval.state()!=ApprovalService.State.APPROVED) return current;
            }
            var request=request(current);
            var admission=realm.gateway().assessAdministrativeRequest(request);
            requireSameAdmission(current,admission);validateActor(current);
            Instant deadline=clock.instant().plusMillis(current.executionTimeoutMillis());
            CancellationSignal cancellation=()->closed.get() || !clock.instant().isBefore(deadline);
            if(request.operation() instanceof AdministrativeOperation.Signing signing) {
                AccessContext access=new AccessContext(new Principal("ADMIN_PRINCIPAL",request.principalId()),new Purpose(signing.operation().name()),Optional.empty(),Optional.empty());
                PreparedSemanticSigningRequest prepared;
                if (signing.operation() instanceof PkiSigningOperation.IssueOcspResponderCertificate provision) {
                    ocspProvisioning.requireClaim(current);
                    var correlated = signingService.get().prepareManagedOcspResponder(access,provision.request(),
                            realm.gateway().administrativeSigningEvidence(admission),cancellation);
                    if (correlated instanceof zeroecho.pki.api.issuance.CorrelatedIssuancePreparation.Existing) {
                        var receipt = signingService.get().findManagedOcspResponderReceipt(provision.request())
                                .orElseThrow(() -> new IllegalStateException("OCSP retained receipt unavailable"));
                        synchronized (control) {
                            var exact = find(id).orElseThrow();
                            if (exact.revision() != current.revision()) return exact;
                            current = claim(exact,Optional.of(receipt));
                        }
                        return reconcile(current);
                    }
                    prepared = ((zeroecho.pki.api.issuance.CorrelatedIssuancePreparation.Prepared)correlated).prepared();
                } else if(current.sdkProof().isPresent()) {
                    var input=sdkAdmission.preparation(current,request,current.envelope());
                    var operation=HybridSdkIssuerResolver.issue(request);
                    var commands=realm.session().signingCommands().orElseThrow();
                    var preview=commands.previewSdk(operation,access,input.subject(),Optional.of(HybridSdkIssuerResolver.frozenValidity(input.target())),cancellation);
                    var proof=new zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval(preview,input.primaryFrame(),input.target(),
                            input.primaryProof(),input.alternativeProof(),input.proofCommitment(),input.acceptedAt());
                    prepared=commands.prepareSdk(operation,access,input.subject(),proof,realm.gateway().administrativeSigningEvidence(admission),cancellation);
                } else {
                    prepared=realm.session().signingCommands().orElseThrow().prepare(signing.operation(),access,
                            realm.gateway().administrativeSigningEvidence(admission),cancellation);
                }
                var service=signingService.get();
                try {
                    synchronized(control) {
                        var exact=find(id).orElseThrow();
                        if(exact.revision()!=current.revision()) throw new IllegalStateException("Request changed during preparation");
                        var live=realm.gateway().assessAdministrativeRequest(request(exact));requireSameAdmission(exact,live);validateActor(exact);
                        if(exact.sdkProof().isPresent())sdkAdmission.validateRetained(exact,request(exact),exact.envelope());
                        cancellation.throwIfCancelled();
                        current=claim(exact,Optional.of(prepared.receipt()));
                    }
                } catch(Exception failure) { service.discard(prepared);throw failure; }
                try {
                    var accepted=service.accept(prepared);
                    if (signing.operation() instanceof PkiSigningOperation.IssueOcspResponderCertificate provision
                            && accepted.disposition()==zeroecho.pki.api.signing.SigningAcceptanceDisposition.ATTACHED_EXISTING
                            && !current.receipt().equals(Optional.of(accepted.receipt()))) {
                        synchronized (control) {
                            var exact=find(id).orElseThrow();
                            if (exact.revision()!=current.revision()) return exact;
                            var proof=ocspProvisioning.attachment(exact,provision.request(),accepted.receipt());
                            var attached=update(exact,exact.state(),Optional.of(accepted.receipt()),Optional.empty(),Optional.empty());
                            control.attachOcspProvisioningReceipt(AdministrativeRequestCodec.encode(attached),
                                    AdministrativeRequestCodec.encode(exact).commitment(),ocspProvisioning.transition(exact,attached),proof);
                            audit(attached); current=attached;
                        }
                    }
                } catch(RuntimeException uncertain) { return reconcile(current); }
                return reconcile(current);
            }
            var dispatched=update(current,AdministrativeRequest.State.DISPATCHING,Optional.empty(),Optional.empty(),Optional.empty());
            write(current,dispatched,Optional.empty(),Optional.empty());
            var outcome=activation.isPresent()?realm.gateway().executeRootActivation(request,activationEvidence(current,activation.orElseThrow()),cancellation)
                    :realm.gateway().execute(request,cancellation);
            if(outcome instanceof ServerOperationGateway.Outcome.Executed executed) return outcome(dispatched,executed.outcome());
            if(outcome instanceof ServerOperationGateway.Outcome.ControlExecuted executed
                    && executed.outcome() instanceof ServerControlOperationOutcome.Ordinary ordinary) return outcome(dispatched,ordinary.outcome());
            return finish(dispatched,AdministrativeRequest.State.FAILED,Optional.empty(),outcome instanceof ServerOperationGateway.Outcome.Denied ? "AUTHORIZATION_DENIED" : "POLICY_CHANGED");
        } catch(SecurityException denied) {
            var latest=find(id).orElseThrow();
            if(latest.receipt().isPresent()) return observationUnavailable(latest);
            if(latest.state()==AdministrativeRequest.State.DISPATCHING) return finish(latest,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SYNCHRONOUS_OUTCOME_UNKNOWN");
            return failCurrent(id,"PROFILE_CHANGED".equals(denied.getMessage()) ? "PROFILE_CHANGED" : "AUTHORIZATION_REVOKED");
        }
        catch(PkiException domain) {
            var latest=find(id).orElseThrow();
            if(latest.receipt().isPresent()) return observationUnavailable(latest);
            if(latest.state()==AdministrativeRequest.State.DISPATCHING) return finish(latest,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SYNCHRONOUS_OUTCOME_UNKNOWN");
            return failCurrent(id,safeDomainCode(domain));
        }
        catch(java.io.InterruptedIOException cancelled) {
            var latest=find(id).orElseThrow();
            if(latest.receipt().isPresent()) return observationUnavailable(latest);
            if(latest.state()==AdministrativeRequest.State.DISPATCHING) return finish(latest,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SYNCHRONOUS_OUTCOME_UNKNOWN");
            return failCurrent(id,"EXECUTION_DEADLINE");
        }
        catch(RuntimeException failure) {
            var latest=find(id).orElseThrow();
            if(latest.receipt().isPresent()) return observationUnavailable(latest);
            if(latest.state()==AdministrativeRequest.State.DISPATCHING) return finish(latest,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SYNCHRONOUS_OUTCOME_UNKNOWN");
            return failCurrent(id,"OPERATION_INPUT_INVALID");
        } finally { synchronized(control) { inFlight.remove(id); } }
    }

    private AdministrativeRequest observationUnavailable(AdministrativeRequest current) {
        if(current.failureCode().filter("SIGNING_OBSERVATION_UNAVAILABLE"::equals).isPresent()) return current;
        var next=update(current,current.state(),current.receipt(),Optional.empty(),Optional.of("SIGNING_OBSERVATION_UNAVAILABLE"));
        write(current,next,Optional.empty(),Optional.empty());return next;
    }

    private Optional<PkiOperation.SelectIssuancePath> activationSelection(AdministrativeRequest retained) {
        if(!retained.operation().equals(PkiOperation.SelectIssuancePath.NAME))return Optional.empty();
        var operation=request(retained).operation();
        if(operation instanceof AdministrativeOperation.Pki pki&&pki.operation() instanceof PkiOperation.SelectIssuancePath selected
                &&selected.transitionCommitment().isPresent()&&selected.distributionAcknowledged())return Optional.of(selected);
        return Optional.empty();
    }

    private zeroecho.pki.api.ca.RootTrustAnchorActivation activationEvidence(AdministrativeRequest retained,PkiOperation.SelectIssuancePath selected) {
        var approval=realm.approvals().requireCurrent(retained.approvalId().orElseThrow());
        if(!approval.operationCommitment().equals(retained.operationCommitment())||!retained.policyCommitment().filter(approval.policyCommitment()::equals).isPresent())throw new SecurityException("Activation approval target differs");
        var inspected=realm.session().operations().execute(new PkiOperation.InspectIssuerGeneration(selected.issuerId()),CancellationSignal.NONE);
        if(!(inspected instanceof PkiOperationOutcome.Completed complete))throw new IllegalStateException("Activation transition unavailable");
        var fields=complete.result().fields();
        if(!LifecycleProjection.text(fields,"transitionCommitment").equals(selected.transitionCommitment().orElseThrow()))throw new SecurityException("Activation transition differs");
        var head=selected.expectedHead().orElseThrow();
        return new zeroecho.pki.api.ca.RootTrustAnchorActivation(1,new zeroecho.pki.api.PkiId(LifecycleProjection.text(fields,"transitionId")),
                selected.transitionCommitment().orElseThrow(),head,selected.issuerId(),selected.pathId(),Math.addExact(head.epoch(),1),
                new zeroecho.pki.api.PkiId(retained.requestId()),retained.actor().principalId(),retained.policyCommitment().orElseThrow(),
                retained.operationCommitment(),retained.createdAt(),true);
    }

    private AdministrativeRequest activationUnknown(AdministrativeRequest retained) {
        if(retained.state()==AdministrativeRequest.State.RECONCILIATION_REQUIRED)return retained;
        return finish(retained,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"ROOT_ACTIVATION_OUTCOME_UNKNOWN");
    }

    private AdministrativeRequest reconcile(AdministrativeRequest current) {
        var service=signingService.get();
        SigningAcceptanceReceipt receipt=current.receipt().orElseThrow();
        SigningAcceptanceResolution resolution=service.resolve(receipt);
        if(resolution==SigningAcceptanceResolution.CONFLICT) return finish(current,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SIGNING_RECEIPT_CONFLICT");
        if(resolution==SigningAcceptanceResolution.NOT_ACCEPTED) {
            if (current.operation().equals(OcspProvisioningSlot.OPERATION)) return finish(current,
                    AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"OCSP_PROVISIONING_ACCEPTANCE_NOT_RETAINED");
            if(current.state()!=AdministrativeRequest.State.DISPATCHING) return finish(current,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SIGNING_ACCEPTANCE_LOST");
            synchronized(control) {
                var exact=find(current.requestId()).orElseThrow();
                if(exact.revision()!=current.revision()) return exact;
                var next=update(exact,AdministrativeRequest.State.READY,Optional.empty(),Optional.empty(),Optional.empty());
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
                var approval=prior.map(v->approvalState(v,ApprovalService.State.APPROVED,Optional.empty()));
                write(exact,next,prior,approval);return next;
            }
        }
        var snapshot=service.find(receipt.operationId()).orElseThrow();
        return switch(snapshot.state()) {
            case SIGNING,PUBLISHING -> {
                if(current.state()==AdministrativeRequest.State.RUNNING) yield current;
                var next=update(current,AdministrativeRequest.State.RUNNING,current.receipt(),Optional.empty(),Optional.empty());write(current,next,Optional.empty(),Optional.empty());yield next;
            }
            case FAILED -> finish(current,AdministrativeRequest.State.FAILED,Optional.empty(),snapshot.detailCode().filter(AdministrativeRequestCoordinator::safeSigningCode).orElse("SIGNING_FAILED"));
            case EXPIRED -> finish(current,AdministrativeRequest.State.EXPIRED,Optional.empty(),"SIGNING_EXPIRED");
            case COMPLETED -> finish(current,AdministrativeRequest.State.SUCCEEDED,Optional.of(new PkiOperationValue.ObjectValue(
                    realm.session().signingCommands().orElseThrow().completedResult(snapshot).fields())),null);
        };
    }

    private AdministrativeRequest claim(AdministrativeRequest current,Optional<SigningAcceptanceReceipt> receipt) {
        Optional<ApprovalService.Request> prior=current.approvalId().map(realm.approvals()::requireCurrent);
        prior.ifPresent(v->{if(v.state()!=ApprovalService.State.APPROVED || !v.requesterPrincipalId().equals(current.actor().principalId())
                || !v.operationCommitment().equals(current.operationCommitment()) || !v.scope().equals(current.scope())
                || !v.policyCommitment().equals(current.policyCommitment().orElseThrow())) throw new SecurityException("Approval does not bind request");});
        var next=update(current,AdministrativeRequest.State.DISPATCHING,receipt,Optional.empty(),Optional.empty());
        write(current,next,prior,prior.map(v->approvalState(v,ApprovalService.State.EXECUTING,Optional.empty())));return next;
    }

    private AdministrativeRequest outcome(AdministrativeRequest current,PkiOperationOutcome outcome) {
        if(outcome instanceof PkiOperationOutcome.Completed completed) return finish(current,AdministrativeRequest.State.SUCCEEDED,Optional.of(new PkiOperationValue.ObjectValue(completed.result().fields())),null);
        if(outcome instanceof PkiOperationOutcome.Failed failed) {
            boolean uncertain = switch(failed.classification()) {
                case RECOVERY_REQUIRED,EXTERNAL_OUTCOME_UNKNOWN,RESOURCE_FAILURE,CANCELLED,INTERNAL_FAILURE -> true;
                default -> false;
            };
            return finish(current,uncertain?AdministrativeRequest.State.RECONCILIATION_REQUIRED:AdministrativeRequest.State.FAILED,Optional.empty(),failed.code());
        }
        return finish(current,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"UNRETAINED_PENDING_OUTCOME");
    }
    private AdministrativeRequest finish(AdministrativeRequest current,AdministrativeRequest.State state,Optional<PkiOperationValue.ObjectValue> result,String code) {
        synchronized(control) {
            var exact=find(current.requestId()).orElseThrow(); if(exact.revision()!=current.revision()) return exact;
            var next=update(exact,state,exact.receipt(),result,Optional.ofNullable(code));
            Optional<ApprovalService.Request> prior=exact.approvalId().map(realm.approvals()::requireCurrent).filter(v->v.state()==ApprovalService.State.EXECUTING);
            write(exact,next,prior,prior.map(v->approvalState(v,ApprovalService.State.EXECUTED,Optional.of(state.name()))));return next;
        }
    }
    private AdministrativeRequest failCurrent(String id,String code) { var v=find(id).orElseThrow();return finish(v,AdministrativeRequest.State.FAILED,Optional.empty(),code); }
    private static PkiOperationValue.ObjectValue freezeCreationEnvelope(PkiOperationValue.ObjectValue envelope, AdministrativeOperation operation) {
        Optional<String> algorithm=operation instanceof AdministrativeOperation.Signing signing?switch(signing.operation()) {
            case PkiSigningOperation.CreateAuthority value -> value.signatureAlgorithmId();
            case PkiSigningOperation.CreateIntermediate value -> value.signatureAlgorithmId();
            default -> Optional.empty();
        }:Optional.empty();

        var fields=new LinkedHashMap<>(envelope.fields());
        var arguments=new LinkedHashMap<>(((PkiOperationValue.ObjectValue)fields.get("arguments")).fields());
        if(algorithm.isPresent())arguments.put("signatureAlgorithmId",text(algorithm.orElseThrow()));
        arguments=new LinkedHashMap<>(LifecycleProjection.arguments(new PkiOperationValue.ObjectValue(arguments),operation).fields());
        if (operation instanceof AdministrativeOperation.Signing signing
                && signing.operation() instanceof PkiSigningOperation.IssueOcspResponderCertificate selected) {
            arguments = new LinkedHashMap<>(OcspProvisioningProjection.encode(selected.request()).fields());
        }
        fields.put("arguments",new PkiOperationValue.ObjectValue(arguments));
        return new PkiOperationValue.ObjectValue(fields);
    }

    private static Optional<String> sdkProfileCommitment(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame target) {
        String policy=new String(target.field(12),java.nio.charset.StandardCharsets.UTF_8);
        if(!policy.matches("sha256:[0-9a-f]{64}"))throw new ValidationFailure("SDK_PROFILE_COMMITMENT_UNSUPPORTED");
        String id=new String(target.field(10),java.nio.charset.StandardCharsets.UTF_8);
        long version=java.nio.ByteBuffer.wrap(target.field(11)).getLong();
        return Optional.of(ApprovalService.digest(id+"|"+version+"|"+policy.substring(7)));
    }
    private Optional<String> profileCommitment(ServerOperationGateway.Request request) {
        if (!(request.operation() instanceof AdministrativeOperation.Signing signing)) return Optional.empty();
        Optional<String> profile = switch(signing.operation()) {
            case PkiSigningOperation.CreateAuthority value -> Optional.of(value.profileId());
            case PkiSigningOperation.RenewCredential value -> credentialProfile(value.credentialId());
            case PkiSigningOperation.ReissueCredential value -> credentialProfile(value.credentialId());
            case PkiSigningOperation.RolloverCaCertificate value -> authorityProfile(value.caId());
            case PkiSigningOperation.RotateCaKey value -> authorityProfile(value.caId());
            default -> request.resource().scope().profileId();
        };
        if (profile.isEmpty()) return Optional.empty();
        var reference=realm.session().profiles().requireActiveProfile(profile.orElseThrow()).reference();
        return Optional.of(ApprovalService.digest(reference.profileId()+"|"+reference.profileVersion()+"|"+java.util.HexFormat.of().formatHex(reference.canonicalSha256())));
    }
    private Optional<String> authorityProfile(zeroecho.pki.api.PkiId authorityId) {
        var authority=realm.session().repository().authority(authorityId).orElseThrow();
        var generation=realm.session().repository().issuer(authority.currentIssuanceIssuerId()).orElseThrow();
        return credentialProfile(generation.credentialId());
    }
    private Optional<String> credentialProfile(zeroecho.pki.api.PkiId credentialId) {
        var credential=realm.session().repository().credential(credentialId).orElseThrow();
        return switch(credential.profileBinding()) {
            case zeroecho.pki.api.credential.CaProfileBinding binding -> Optional.of(binding.reference().profileId());
            case zeroecho.pki.api.credential.EndEntityProfileBinding binding -> Optional.of(binding.reference().profileId());
        };
    }
    private void requireSameAdmission(AdministrativeRequest value,ServerOperationGateway.Admission admission) {
        if(!value.profileCommitment().equals(profileCommitment(admission.request()))) throw new SecurityException("PROFILE_CHANGED");
        if(!value.operationCommitment().equals(admission.commitment()) || !value.scope().equals(admission.request().resource().scope())
                || !value.policyCommitment().equals(admission.policy().map(ApprovalService.Policy::commitment))) throw new SecurityException("Target or policy changed");
    }
    private void validateBeforeApproval(ServerOperationGateway.Admission admission) {
        if(admission.request().operation() instanceof AdministrativeOperation.Signing signing) {
            var op=signing.operation();
            if(!(op instanceof PkiSigningOperation.GenerateStatus)) {
                AccessContext access=new AccessContext(new Principal("ADMIN_PRINCIPAL",admission.request().principalId()),new Purpose(op.name()),Optional.empty(),Optional.empty());
                realm.session().signingCommands().orElseThrow().validate(op,access,realm.gateway().administrativeSigningEvidence(admission),CancellationSignal.NONE);
            } else if(admission.policy().isPresent()) throw new ValidationFailure("PURE_VALIDATION_UNAVAILABLE");
        } else if(admission.request().operation() instanceof AdministrativeOperation.Control
                && admission.policy().isPresent()) {
            realm.gateway().validateAdministrativeControl(admission);
        } else if(admission.request().operation() instanceof AdministrativeOperation.Pki pki && admission.policy().isPresent()) {
            realm.session().operations().validate(pki.operation(),CancellationSignal.NONE);
        } else if(admission.policy().isPresent()) throw new ValidationFailure("PURE_VALIDATION_UNAVAILABLE");
    }
    private ServerOperationGateway.Request request(AdministrativeRequest value) {
        var decoded=HttpOperationCodec.decode(value.operation(),StrictJson.encode(value.envelope()),262144,realm.configuration().realmId(),realm.gateway()::descriptor);
        return new ServerOperationGateway.Request(realm.configuration().realmId(),value.actor().principalId(),value.actor().mode(),value.actor().transportPrincipalId(),value.actor().evidence(),
                decoded.operation(),decoded.resource(),Permission.Relationship.ANY,decoded.context(),value.approvalId(),value.requestId());
    }
    private void validateActor(AdministrativeRequest value) { validateActor(value.actor()); }
    void requireSdkActor(ServerOperationGateway.Request request) {
        validateActor(new AdministrativeRequest.Actor(request.principalId(),request.authenticationMode(),request.transportPrincipalId(),request.credentialEvidence()));
    }
    private void validateActor(AdministrativeRequest.Actor actor) {
        if(!realm.principal(actor.principalId()).enabled()) throw new SecurityException("Requester disabled");
        var active=authentication; if(active==null) return;
        if(active.mode()!=actor.mode()) throw new SecurityException("Authentication policy changed");
        if(active.mode()==AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY) {
            String proxy=actor.transportPrincipalId().orElseThrow(()->new SecurityException("Proxy unavailable"));
            if(!active.trustedProxyPrincipalIds().contains(proxy)) throw new SecurityException("Proxy unavailable");realm.gateway().validateForwardingPrincipal(proxy);
        }
        var evidence=actor.evidence().orElseThrow(()->new SecurityException("Credential evidence unavailable"));
        var mappings=active.mode()==AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY?active.forwardedClientMappings():active.directClientMappings();
        if(mappings.stream().noneMatch(m->m.principalId().equals(actor.principalId()) && (m.certificateSha256().filter(evidence.certificateSha256()::equals).isPresent()
                || m.subjectPublicKeyInfoSha256().filter(evidence.legacySpkiSha256()::contains).isPresent() || m.issuerSerialSha256().filter(evidence.issuerSerialSha256()::equals).isPresent()))) throw new SecurityException("Credential mapping removed");
    }
    private boolean canRead(AdministrativeRequest value,String viewer) {
        try {
            if(!realm.principal(viewer).enabled()) return false;
            if(viewer.equals(value.actor().principalId())) return true;
            return realm.gateway().authorizeControl(viewer,Permission.Action.REQUEST_READ_ANY,new Permission.Resource(Permission.ResourceType.APPROVAL,value.scope(),Optional.empty(),Optional.of(value.actor().principalId())),Permission.Context.empty(),value.requestId()).allowed();
        } catch(RuntimeException unavailable) { return false; }
    }
    private boolean canReviewTarget(AdministrativeRequest value,String viewer) {
        try {
            var original=request(value);
            var inspect=new ServerOperationGateway.Request(original.realmId(),viewer,original.authenticationMode(),original.transportPrincipalId(),Optional.empty(),original.operation(),original.resource(),original.relationship(),original.context(),original.approvalId(),original.correlationId());
            realm.gateway().assessAdministrativeRequest(inspect);return true;
        } catch(RuntimeException denied) { return false; }
    }
    private Optional<AdministrativeRequest> find(String id) { return control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,id).map(AdministrativeRequestCodec::decode); }
    private void write(AdministrativeRequest old,AdministrativeRequest next,Optional<ApprovalService.Request> prior,Optional<ApprovalService.Request> approval) {
        if (old.operation().equals(OcspProvisioningSlot.OPERATION)) {
            control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(next),Optional.of(AdministrativeRequestCodec.encode(old).commitment()),
                    prior,approval,Optional.empty(),Optional.of(ocspProvisioning.transition(old,next)));
        } else {
            control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(next),Optional.of(AdministrativeRequestCodec.encode(old).commitment()),prior,approval);
        }
        audit(next);
    }
    private void audit(AdministrativeRequest value) {
        try {
            realm.auditTransport("ADMINISTRATIVE_REQUEST_STATE",value.actor().principalId(),Map.of(
                    "requestId",value.requestId(),"operation",value.operation(),"state",value.state().name(),
                    "revision",Long.toString(value.revision()),"targetCommitment",value.targetCommitment()));
        } catch (IllegalStateException closing) {
            // The durable private control record is authoritative; a closing audit projection cannot undo it.
        }
    }
    private AdministrativeRequest update(AdministrativeRequest old,AdministrativeRequest.State state,Optional<SigningAcceptanceReceipt> receipt,
            Optional<PkiOperationValue.ObjectValue> result,Optional<String> code) {
        return new AdministrativeRequest(old.requestId(),old.revision()+1,old.operation(),old.envelope(),old.actor(),old.scope(),old.operationCommitment(),old.profileCommitment(),old.targetCommitment(),state,old.createdAt(),now(),old.executionTimeoutMillis(),old.approvalId(),old.policyCommitment(),receipt,result,code,old.sdkProof());
    }
    private static ApprovalService.Request approvalState(ApprovalService.Request old,ApprovalService.State state,Optional<String> result) {
        return new ApprovalService.Request(old.approvalId(),old.operationId(),old.operationCommitment(),old.scope(),old.requesterPrincipalId(),old.createdAt(),old.expiresAt(),old.policy(),old.policyCommitment(),state,old.decisions(),result);
    }
    private Instant now() { return clock.instant().truncatedTo(ChronoUnit.MILLIS); }
    private static boolean safeSigningCode(String code) {
        if(java.util.Arrays.stream(zeroecho.pki.spi.crypto.SigningProvider.DetailCode.values()).anyMatch(value -> value.name().equals(code))) return true;
        if(java.util.Arrays.stream(zeroecho.pki.api.PkiFailureReason.values()).anyMatch(value -> value.externalSafe() && value.name().equals(code))) return true;
        return Set.of("CONTENT_INTEGRITY_FAILURE","PROVIDER_ID_MISMATCH","CANCELLED","EXPIRED").contains(code);
    }
    private static String safeDomainCode(PkiException failure) { return failure.failureReason().filter(zeroecho.pki.api.PkiFailureReason::externalSafe).map(Enum::name).orElse("PKI_POLICY_REJECTED"); }
    private static PkiOperationValue.Text text(String value) { return new PkiOperationValue.Text(value); }

    /**
     * States which catalog operations have a durable ordinary-result workflow boundary.
     * @param descriptor current operation descriptor
     * @return whether submission is supported; reads, approval decisions and secret/channel operations are excluded
     */
    public static boolean supports(OperationSecurityDescriptors.Descriptor descriptor) {
        String id=descriptor.operationId();
        boolean validatedCa = descriptor.family()==OperationSecurityDescriptors.Family.SIGNING_OPERATION
                || Set.of(PkiOperation.ActivateProfile.NAME,PkiOperation.TransitionAuthority.NAME,PkiOperation.SelectIssuancePath.NAME).contains(id);
        return descriptor.mutating() && (validatedCa || ServerControlOperationExecutor.administrativeValidationAvailable(id)
                || descriptor.approvalCategory()==OperationSecurityDescriptors.ApprovalCategory.NONE)
                && !id.startsWith("security.approval.") && !id.startsWith("enrollment.request.")
                && !Set.of(PkiOperation.IssueCredentialConfirmationChallenge.NAME,PkiOperation.CompleteCredentialConfirmationProof.NAME).contains(id)
                && !id.startsWith("backup.") && !id.contains("capability.issue")
                && !id.contains(".stream.") && !id.contains("restore");
    }
    private void run() {
        while(!closed.get()) {
            try {
                var page=control.protocolRecords(ServerControlStore.ADMINISTRATIVE_REQUEST,scanOffset,PAGE);
                for(var record:page.values()) { if(closed.get()) break;var value=AdministrativeRequestCodec.decode(record);if(!value.terminal()||value.state()==AdministrativeRequest.State.RECONCILIATION_REQUIRED&&activationSelection(value).isPresent()) process(value.requestId()); }
                scanOffset=page.hasMore()?page.nextOffset():0;
                wake.tryAcquire(1000,java.util.concurrent.TimeUnit.MILLISECONDS);
            } catch(InterruptedException stopped) { if(closed.get()) break; }
            catch(RuntimeException failure) { try { Thread.sleep(1000); } catch(InterruptedException stopped) { if(closed.get()) break; } }
        }
    }
    /** Stops and joins the realm-owned worker before control/session resources are closed. */
    @Override public void close() {
        closed.set(true);wake.release();Thread thread=worker;
        if(thread!=null && thread!=Thread.currentThread()) { thread.interrupt();try{thread.join(10000);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException("Workflow shutdown interrupted");}if(thread.isAlive())throw new IllegalStateException("Workflow worker did not stop"); }
    }
    /** Stable input failure suitable for field-level transport responses. */
    public static final class ValidationFailure extends IllegalArgumentException {
        private static final long serialVersionUID=1L;
        private final String code;
        /** @param code closed safe machine failure code */
        public ValidationFailure(String code) { super(code); if(!code.matches("[A-Z0-9_]{3,128}"))throw new IllegalArgumentException("Invalid validation code");this.code=code; }
        /** @return safe field validation code */
        public String code() { return code; }
    }
    /** Authorized conflict with an already occupied canonical responder provisioning target. */
    public static final class ProvisioningConflict extends IllegalArgumentException {
        private static final long serialVersionUID=1L;
        private final String canonicalRequestId;
        private ProvisioningConflict(String requestId){super("OCSP_PROVISIONING_TARGET_CONFLICT");this.canonicalRequestId=requestId;}
        /** @return authorized canonical pending or completed request identity */
        public String canonicalRequestId(){return canonicalRequestId;}
    }
    /** Conflicting reuse of an ordinary client-selected request identity. */
    public static final class Conflict extends IllegalArgumentException { private static final long serialVersionUID=1L; }
    /** Finite retained/pending capacity has been reached. */
    public static final class Capacity extends IllegalStateException { private static final long serialVersionUID=1L; }
}
