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
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiSigningOperation;

/**
 * Realm-owned durable administrative workflow and bounded recovery worker.
 *
 * <p>Submission retains an exact target and creates its required approval atomically. Human
 * decisions only change approval state; this worker resumes as the original requester. Signing
 * receipts precede acceptance and recovery never submits an uncertain replacement. Generic
 * synchronous mutations interrupted after their durable dispatch marker require reconciliation.</p>
 *
 * <p>The realm, control store, clock and signing-service supplier are borrowed
 * composition dependencies. The coordinator owns its daemon worker, wake signal
 * and in-flight guard, not the lifetime of those session resources. Construction
 * does not start recovery. Durable records remain authoritative if an advisory
 * wakeup or audit projection is unavailable.</p>
 */
public final class AdministrativeRequestCoordinator implements AutoCloseable {
    private static final String REQUEST_UNAVAILABLE = "Request unavailable";

    private static final int MAXIMUM_RETAINED = 10_000;
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
    private final RequestExecution execution = new RequestExecution();
    private final RequestAdmission requestAdmission = new RequestAdmission();
    private final AdministrativeRequestRecovery recovery;
    private final AdministrativeRequestState requestState;
    private final AdministrativeSigningPreparation signingPreparation;
    private final AdministrativeRequestPolicy requestPolicy;
    // The standalone server retains this exact cross-thread publication contract.
    @SuppressWarnings({"PMD.DoNotUseThreads", "PMD.AvoidUsingVolatile"})
    private volatile Thread worker;
    // The standalone server retains this exact cross-thread publication contract.
    @SuppressWarnings({"PMD.AvoidUsingVolatile"})
    private volatile PkiServerConfiguration.Authentication authentication;
    private int scanOffset;

    /**
     * Composes realm-session signing with SDK resolution left unsupported. Construction does not start the worker.
     *
     * @param realm owning realm and session, borrowed
     * @param control authoritative control store, borrowed
     * @param clock trusted workflow clock, borrowed
     */
    /* default */ AdministrativeRequestCoordinator(ServerRealmContext realm, ServerControlStore control, Clock clock) {
        this(realm, control, clock, () -> realm.session().semanticSigning().orElseThrow());
    }

    /**
     * Composes a supplied signing observer with SDK resolution left unsupported. Construction does not start
     * the worker.
     *
     * @param realm owning realm and session, borrowed
     * @param control authoritative control store, borrowed
     * @param clock trusted workflow clock, borrowed
     * @param signingService required service supplier; resolved at preparation/observation time
     */

    /* default */ AdministrativeRequestCoordinator(ServerRealmContext realm, ServerControlStore control, Clock clock,
            java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService) {
        this(realm,control,clock,signingService,"https://unconfigured.invalid:443",HybridSdkAdmissionService.unsupported());
    }

    /**
     * Composes an explicit SDK origin with the realm issuer resolver. Construction does not start the worker.
     *
     * @param realm owning realm and session, borrowed
     * @param control authoritative control store, borrowed
     * @param clock trusted workflow clock, borrowed
     * @param sdkOrigin configured SDK origin; does not activate an HTTP carrier
     */

    /* default */ AdministrativeRequestCoordinator(ServerRealmContext realm, ServerControlStore control, Clock clock, String sdkOrigin) {
        this(realm,control,clock,()->realm.session().semanticSigning().orElseThrow(),sdkOrigin,new HybridSdkIssuerResolver(realm));
    }

    /**
     * Composes explicit server-owned SDK resolution and signing observation dependencies. Construction does not
     * start the worker.
     *
     * @param realm owning realm and session, borrowed
     * @param control authoritative control store, borrowed
     * @param clock trusted workflow clock, borrowed
     * @param signingService required service supplier; resolved at preparation/observation time
     * @param sdkOrigin configured SDK origin; does not activate an HTTP carrier
     * @param sdkResolver server-owned SDK target resolver
     * @throws NullPointerException if {@code signingService} is null
     */

    /* default */ AdministrativeRequestCoordinator(ServerRealmContext realm, ServerControlStore control, Clock clock,
            java.util.function.Supplier<zeroecho.pki.api.SemanticSigningService> signingService,
            String sdkOrigin, HybridSdkAdmissionService.Resolver sdkResolver) {
        this.realm=realm; this.control=control; this.clock=clock;
        this.signingService=java.util.Objects.requireNonNull(signingService,"signingService");
        this.requestPolicy=new AdministrativeRequestPolicy(realm, () -> authentication);
        this.sdkAdmission=new HybridSdkAdmissionService(control,clock,this,sdkOrigin,sdkResolver);
        this.ocspProvisioning=new OcspResponderProvisioningService(realm.configuration().realmId(),control,signingService);
        this.signingPreparation=new AdministrativeSigningPreparation(realm,signingService,sdkAdmission,ocspProvisioning);
        this.requestState=new AdministrativeRequestState(realm,control,clock,ocspProvisioning);
        this.recovery=new AdministrativeRequestRecovery(realm,control,signingService,requestPolicy,requestState);
    }

    /**
     * Returns the internally composed SDK admission service without enabling a public carrier.
     *
     * @return realm-owned SDK service instance
     */
    /* default */ HybridSdkAdmissionService sdkAdmission() { return sdkAdmission; }

    /**
     * Starts bounded startup recovery and decision-driven dispatch for the permanent server.
     * <p>A repeated call replaces the current policy reference but creates no
     * second worker. The worker scans bounded pages and responds to advisory
     * wakeups; this call does not wait for recovery or drain retained work.</p>
     *
     * @param authentication current trusted authentication/mapping policy
     * @throws NullPointerException if the authentication policy is null
     * @throws IllegalStateException if the coordinator was closed
     */
    // The standalone server owns this bounded worker and retains its original shutdown semantics.
    @SuppressWarnings({"PMD.AvoidSynchronizedAtMethodLevel", "PMD.DoNotUseThreads"})
    public synchronized void start(PkiServerConfiguration.Authentication authentication) {
        if (closed.get()) { throw new IllegalStateException("Administrative workflow is closed"); }
        this.authentication=java.util.Objects.requireNonNull(authentication,"authentication");
        if (worker != null) { return; }
        worker = new Thread(this::run, "zeroecho-administrative-requests"); worker.setDaemon(true); worker.start();
    }

    /**
     * Coalesces advisory wakeups; durable state and periodic scans remain authoritative.
     */
    public void wake() { if (!closed.get() && wake.availablePermits()==0) { wake.release(); } }

    /**
     * Admits one exact authenticated target without executing it on the submitting connection.
     * <p>Exact ordinary replay checks requester ownership and retained target/SDK
     * proof linkage. Dedicated OCSP provisioning derives its canonical request ID
     * from the selected slot and can return an authorized existing request instead
     * of using the caller's ID. New admission validates before approval and checks
     * replay races again inside the committing control transaction. No signing
     * dispatch is performed by this submitting connection.</p>
     *
     * @param requestId stable client identity reused after uncertain acknowledgements
     * @param request original trusted actor and decoded operation
     * @param envelope strict operation envelope containing only version, arguments and optional authority/deadline
     * @param executionTimeout bounded post-approval execution budget
     *
     * @return original or newly retained authoritative request
     * @throws IllegalArgumentException if identity/budget/operation validation fails
     * @throws Conflict if an ordinary ID is retained for different immutable input
     * @throws ProvisioningConflict if an authorized caller targets an occupied canonical slot
     * @throws Capacity if retained or nonterminal request capacity is full
     * @throws SecurityException if requester ownership or target-read authorization fails
     */
    // Retain the established bounded no-cause diagnostic and original interruption behavior.
    @SuppressWarnings({"PMD.PreserveStackTrace"})
    public AdministrativeRequest submit(String requestId, ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, Duration executionTimeout) {
        if (request.operation() instanceof AdministrativeOperation.Signing signing
                && signing.operation() instanceof PkiSigningOperation.IssueOcspResponderCertificate selected) {
            OcspResponderProvisioningService.Selection provisioning = ocspProvisioning.select(selected.request());
            ServerOperationGateway.Request canonical = new ServerOperationGateway.Request(request.realmId(),request.principalId(),request.authenticationMode(),
                    request.transportPrincipalId(),request.credentialEvidence(),request.operation(),request.resource(),request.relationship(),
                    request.context(),request.approvalId(),provisioning.requestId());
            try {
                return requestAdmission.submitInternal(provisioning.requestId(),canonical,envelope,executionTimeout,Optional.empty(),Optional.of(provisioning));
            } catch (OcspResponderProvisioningService.TargetConflict conflict) {
                AdministrativeRequest retained=requestState.find(conflict.canonicalRequestId()).orElseThrow(()->new SecurityException(REQUEST_UNAVAILABLE));
                if(!requestPolicy.canReviewTarget(retained,request.principalId())){ throw new SecurityException(REQUEST_UNAVAILABLE); }
                throw new ProvisioningConflict(retained.requestId());
            }
        }
        return requestAdmission.submitInternal(requestId,request,envelope,executionTimeout,Optional.empty(),Optional.empty());
    }

    /**
     * Submits the exact target using the SDK service's retained acceptance context and consumption mutation.
     *
     * @param requestId stable request identity
     * @param request original trusted gateway request
     * @param envelope retained strict operation envelope
     * @param executionTimeout post-approval execution budget
     * @param proof trusted retained SDK acceptance; not caller-authenticated by this wrapper
     * @return original or newly retained administrative request
     * @throws NullPointerException if proof is null
     * @throws IllegalArgumentException if delegated identity, budget or validation fails
     */
    /* default */ AdministrativeRequest submitSdk(String requestId, ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, Duration executionTimeout, HybridSdkAdmissionService.Acceptance proof) {
        return requestAdmission.submitInternal(requestId,request,envelope,executionTimeout,Optional.of(proof),Optional.empty());
    }

    /**
     * Reads a retained request after caller-specific ownership or approval-read authorization.
     * @param requestId durable request identity
     * @param viewer authenticated current viewer
     * @return retained private request; use projection for disclosure to an HTTP client
     * @throws SecurityException if the request is absent or the viewer cannot read it
     */
    public AdministrativeRequest inspect(String requestId,String viewer) {
        AdministrativeRequest value=requestState.find(requestId).orElseThrow(()->new SecurityException(REQUEST_UNAVAILABLE));
        if(!requestPolicy.canRead(value,viewer)) { throw new SecurityException(REQUEST_UNAVAILABLE); }return value;
    }

    /**
     * Reads a bounded private-record page and filters its retained requests for the viewer.
     *
     * <p>The returned values still contain private envelope/result references. HTTP
     * callers must apply {@link #projection} before disclosure. Visibility and
     * field filters are applied after selecting the underlying bounded page, so
     * a short or empty result can still have a continuation.</p>
     * @param viewer authenticated current viewer
     * @param offset zero-based private-record offset
     * @param limit page size, from one through one hundred
     * @param state optional exact state filter
     * @param requester optional exact requesting identity filter
     * @param operation optional exact catalog operation filter
     * @return visible retained values with the underlying page continuation
     * @throws NullPointerException if a filter container is null
     * @throws IllegalArgumentException if offset/limit or operation-filter syntax is invalid
     */
    public ServerControlStore.Page<AdministrativeRequest> list(String viewer,int offset,int limit,
            Optional<AdministrativeRequest.State> state,Optional<String> requester,Optional<String> operation) {
        return requestState.list(viewer, offset, limit, state, requester, operation, requestPolicy);
    }

    /**
     * Projects approved metadata; detailed target/result disclosure requires current operation authority.
     * <p>The caller must establish metadata visibility first; this method does not
     * repeat canRead. Original requester summaries and detailed target/results
     * additionally require current target-review authority. Fields are projected
     * from retained values rather than globally sanitized or re-authenticated.</p>
     *
     * @param value already visible request
     * @param viewer current viewer
     * @param detail whether to consider original target and final result disclosure
     * @return bounded safe HTTP projection
     */
    public PkiOperationValue.ObjectValue projection(AdministrativeRequest value,String viewer,boolean detail) {
        return requestState.projection(value, viewer, detail, requestPolicy);
    }

    /**
     * Processes one retained request; useful for deterministic fixtures and bounded worker scans.
     * <p>The in-flight guard excludes concurrent work on the same ID in this
     * coordinator. Closed or already in-flight requests are returned without new
     * work. Retained signing receipts are resolved before considering a new
     * dispatch; only definitive nonacceptance of the exact ordinary receipt can
     * restore READY. Uncertain synchronous/root-activation outcomes use their
     * reconciliation paths rather than creating replacement mutations.</p>
     *
     * @param id retained request identity
     *
     * @return latest authoritative state; it can remain pending or require reconciliation
     * @throws java.util.NoSuchElementException if no retained request exists for the ID
     */
    public AdministrativeRequest process(String id) {
        return execution.process(id);
    }

    /**
     * Rechecks the SDK requester's enabled identity and currently configured credential mapping.
     *
     * <p>When start has not installed an authentication policy, only the enabled
     * principal check applies. This helper does not authenticate a new transport.</p>
     *
     * @param request original trusted gateway actor snapshot
     * @throws SecurityException if the enabled/mode/proxy/evidence mapping checks reject the actor
     */
    /* default */ void requireSdkActor(ServerOperationGateway.Request request) {
        requestPolicy.validateActor(new AdministrativeRequest.Actor(request.principalId(),request.authenticationMode(),request.transportPrincipalId(),request.credentialEvidence()));
    }

    /**
     * States which catalog operations have a durable ordinary-result workflow boundary.
     * @param descriptor current operation descriptor
     * @return whether the descriptor passes this durable ordinary-result eligibility filter
     * @throws NullPointerException if the descriptor is null
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
    // Keep the original fail-closed or uncertain-outcome boundary for every runtime provider failure.
    @SuppressWarnings({"PMD.DoNotUseThreads", "PMD.AvoidCatchingGenericException"})
    private void run() {
        while(!closed.get()) {
            try {
                ServerControlStore.Page<ServerControlStore.ProtocolRecord> page=control.protocolRecords(ServerControlStore.ADMINISTRATIVE_REQUEST,scanOffset,PAGE);
                for(ServerControlStore.ProtocolRecord record:page.values()) { if(closed.get()) { break; }AdministrativeRequest value=AdministrativeRequestCodec.decode(record);if(!value.terminal()||value.state()==AdministrativeRequest.State.RECONCILIATION_REQUIRED&&recovery.activationSelection(value).isPresent()) { process(value.requestId()); } }
                scanOffset=page.hasMore()?page.nextOffset():0;
                wake.tryAcquire(1000,java.util.concurrent.TimeUnit.MILLISECONDS);
            } catch(InterruptedException stopped) { if(closed.get()) { break; } }
            catch(RuntimeException failure) { try { Thread.sleep(1000); } catch(InterruptedException stopped) { if(closed.get()) { break; } } }
        }
    }
    /**
     * Marks the coordinator closed, wakes and interrupts its worker, and waits up to ten seconds.
     *
     * <p>This is shutdown of the coordinator-owned worker, not a drain of retained
     * requests or closure of borrowed control/session resources. The worker can
     * remain alive if a provider/callback does not stop; that condition is reported
     * rather than claiming completion. A call from the worker does not join itself.</p>
     *
     * @throws IllegalStateException if the joining caller is interrupted or the worker remains alive
     */
    // Retain worker self-identity, bounded join and original interrupted-shutdown diagnostics.
    @SuppressWarnings({"PMD.DoNotUseThreads", "PMD.CompareObjectsWithEquals", "PMD.PreserveStackTrace"})
    @Override public void close() {
        closed.set(true);wake.release();Thread thread=worker;
        if(thread!=null && thread!=Thread.currentThread()) { thread.interrupt();try{thread.join(10_000);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IllegalStateException("Workflow shutdown interrupted");}if(thread.isAlive()){ throw new IllegalStateException("Workflow worker did not stop"); } }
    }
    /**
     * Stable input failure suitable for field-level transport responses.
     */
    public static final class ValidationFailure extends IllegalArgumentException {
        private static final long serialVersionUID=1L;
        /**
         * Checked machine-code text retained in this exception's serialized state.
         *
         * @serial uppercase letters/digits/underscores, from 3 through 128 characters
         */
        private final String code;
        /**
         * Creates a field-validation failure with a checked finite machine-code spelling.
         *
         * @param code uppercase letters/digits/underscores, from 3 through 128 characters
         * @throws NullPointerException if the code is null
         * @throws IllegalArgumentException if the code does not match the permitted spelling
         */
        public ValidationFailure(String code) { super(code); if(!code.matches("[A-Z0-9_]{3,128}")){ throw new IllegalArgumentException("Invalid validation code"); }this.code=code; }
        /**
         * Returns safe field validation code.
         *
         * @return safe field validation code
         */
        public String code() { return code; }
    }
    /**
     * Authorized conflict with an already occupied canonical responder provisioning target.
     */
    public static final class ProvisioningConflict extends IllegalArgumentException {
        private static final long serialVersionUID=1L;
        /**
         * Authorized canonical request reference retained in this exception's serialized state.
         *
         * @serial supplied request identity; the private constructor does not revalidate it
         */
        private final String canonicalRequestId;
        /**
         * Retains a canonical request identity after the caller has passed target-review authorization.
         *
         * @param requestId authorized retained request identity; stored without further validation
         */
        private ProvisioningConflict(String requestId){super("OCSP_PROVISIONING_TARGET_CONFLICT");this.canonicalRequestId=requestId;}
        /**
         * Returns the canonical request identity retained at the authorized conflict boundary.
         *
         * @return supplied request identity; this accessor does not grant read authority
         */
        public String canonicalRequestId(){return canonicalRequestId;}
    }
    /**
     * Conflicting reuse of an ordinary client-selected request identity.
     */
    public static final class Conflict extends IllegalArgumentException { private static final long serialVersionUID=1L;
        /**
         * Creates the existing ordinary-request conflict signal without a detail message or cause.
         */
        public Conflict() { super(); }
    }
    /**
     * Finite retained/pending capacity has been reached.
     */
    public static final class Capacity extends IllegalStateException { private static final long serialVersionUID=1L;
        /**
         * Creates the existing finite-capacity signal without a detail message or cause.
         */
        public Capacity() { super(); }
    }

    /** Admits a new exact target with its approval and proof consumption atomically. */
    private final class RequestAdmission {
        // Retain the original control-store monitor and exact admitted-request ordering.
        @SuppressWarnings({"PMD.AvoidSynchronizedStatement"})
        private AdministrativeRequest submitInternal(String requestId, ServerOperationGateway.Request request,
                PkiOperationValue.ObjectValue envelope, Duration executionTimeout, Optional<HybridSdkAdmissionService.Acceptance> proof,
                Optional<OcspResponderProvisioningService.Selection> provisioning) {
            if (requestId == null || !requestId.matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}")) { throw new IllegalArgumentException("Invalid request ID"); }
            ServerOperationGateway.Admission admission = proof.map(value->value.context().admission()).orElseGet(()->realm.gateway().assessAdministrativeRequest(request));
            if (!supports(realm.gateway().descriptor(admission.request().operation()))) { throw new IllegalArgumentException("DURABLE_REQUEST_UNSUPPORTED"); }
            PkiOperationValue.ObjectValue retainedEnvelope=AdministrativeRequestPolicy.freezeCreationEnvelope(envelope,admission.request().operation());
            long timeout = executionTimeout.toMillis();
            if (timeout < 1 || timeout > 120_000) { throw new IllegalArgumentException("Invalid execution budget"); }
            String target = provisioning.map(OcspResponderProvisioningService.Selection::targetCommitment)
                    .orElseGet(() -> ApprovalService.digest(admission.commitment() + '|' + timeout));
            synchronized (control) {
                Optional<AdministrativeRequest> prior = existingSubmission(requestId, request, target, proof, provisioning);
                if (prior.isPresent()) { return prior.orElseThrow(); }
            }
            Optional<String> validatedProfile = validateTarget(admission, proof);
            Instant now = requestState.now();
            AdministrativeRequest.Actor actor = new AdministrativeRequest.Actor(request.principalId(),request.authenticationMode(),request.transportPrincipalId(),request.credentialEvidence());
            Optional<String> approvalId=admission.policy().map(v->APPROVAL_PREFIX+requestId);
            AdministrativeRequest retained = new AdministrativeRequest(requestId,0,request.operation().name(),retainedEnvelope,actor,admission.request().resource().scope(),
                    admission.commitment(),validatedProfile,target,approvalId.isPresent()?AdministrativeRequest.State.WAITING_APPROVAL:AdministrativeRequest.State.READY,
                    now,now,timeout,approvalId,admission.policy().map(ApprovalService.Policy::commitment),Optional.empty(),Optional.empty(),Optional.empty(),proof.map(HybridSdkAdmissionService.Acceptance::proof));
            if(proof.isPresent()){ requestPolicy.validateActor(retained); }
            Optional<ApprovalService.Request> approval=admission.policy().map(policy->new ApprovalService.Request(approvalId.orElseThrow(),request.operation().name(),
                    admission.commitment(),admission.request().resource().scope(),request.principalId(),now,now.plus(policy.lifetime()),policy,policy.commitment(),
                    ApprovalService.State.PENDING,List.of(),Optional.empty()));
            synchronized (control) {
                Optional<AdministrativeRequest> raced = existingSubmission(requestId, request, target, proof, provisioning);
                if (raced.isPresent()) { return raced.orElseThrow(); }
                requireCapacity();
                control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(retained),Optional.empty(),Optional.empty(),approval,
                        proof.map(HybridSdkAdmissionService.Acceptance::consumption),
                        provisioning.map(value -> ocspProvisioning.claim(value,retained)));
            }
            requestState.audit(retained);
            wake(); return retained;
        }

        private Optional<AdministrativeRequest> existingSubmission(String requestId, ServerOperationGateway.Request request,
                String target, Optional<HybridSdkAdmissionService.Acceptance> proof,
                Optional<OcspResponderProvisioningService.Selection> provisioning) {
            if (provisioning.isPresent()) {
                Optional<AdministrativeRequest> provisioned=existingProvisioning(provisioning.orElseThrow(), requestId, request);
                if (provisioned.isPresent()) { return provisioned; }
            }
            Optional<AdministrativeRequest> old = requestState.find(requestId);
            if (old.isPresent()) {
                AdministrativeRequest retained=old.orElseThrow();
                if (!retained.actor().principalId().equals(request.principalId())) { throw new SecurityException(REQUEST_UNAVAILABLE); }
                if (!retained.targetCommitment().equals(target) || !retained.sdkProof().equals(proof.map(HybridSdkAdmissionService.Acceptance::proof))) { throw new Conflict(); }
                return Optional.of(retained);
            }
            return Optional.empty();
        }

        private void requireCapacity() {
            int count=0; int pending=0;
            try(ServerControlStore.ProtocolCursor cursor=control.protocolSnapshot(ServerControlStore.ADMINISTRATIVE_REQUEST)) {
                Optional<ServerControlStore.ProtocolRecord> next;
                while((next=cursor.next()).isPresent()) {
                    count++; if(!AdministrativeRequestCodec.decode(next.orElseThrow()).terminal()) { pending++; }
                    if(count>=MAXIMUM_RETAINED || pending>=MAXIMUM_PENDING) { throw new Capacity(); }
                }
            }
        }

        // Retain the established bounded no-cause diagnostic and original interruption behavior.
        @SuppressWarnings({"PMD.PreserveStackTrace"})
        private Optional<String> validateTarget(ServerOperationGateway.Admission admission,
                Optional<HybridSdkAdmissionService.Acceptance> proof) {
            Optional<String> validatedProfile = proof.map(value->AdministrativeRequestPolicy.sdkProfileCommitment(value.context().target())).orElseGet(()->requestPolicy.profileCommitment(admission.request()));
            try { if(proof.isEmpty()){ requestPolicy.validateBeforeApproval(admission); } }
            catch(UnsupportedOperationException unsupported) { throw new ValidationFailure("PURE_VALIDATION_UNAVAILABLE"); }
            catch(IllegalStateException precondition) { throw new ValidationFailure("OPERATION_PRECONDITION_FAILED"); }
            if (proof.isEmpty() && !validatedProfile.equals(requestPolicy.profileCommitment(admission.request()))) {
                throw new ValidationFailure("PROFILE_CHANGED");
            }
            return validatedProfile;
        }

        private Optional<AdministrativeRequest> existingProvisioning(OcspResponderProvisioningService.Selection selection,
                String requestId, ServerOperationGateway.Request request) {

                Optional<AdministrativeRequest> existing = ocspProvisioning.existing(selection);
                if (existing.isPresent()) {
                    AdministrativeRequest retained = existing.orElseThrow();
                    if (!requestPolicy.canReviewTarget(retained,request.principalId())) { throw new SecurityException(REQUEST_UNAVAILABLE); }
                    return Optional.of(retained);
                }
                if (requestState.find(requestId).isPresent()) { throw new IllegalStateException("OCSP provisioning request has no matching slot"); }
                        return Optional.empty();
        }
    }

    /** Drives one admitted request without changing its original lock or custody boundaries. */
    private final class RequestExecution {
        // Keep the original fail-closed or uncertain-outcome boundary for every runtime provider failure.
        @SuppressWarnings({"PMD.AvoidSynchronizedStatement", "PMD.AvoidCatchingGenericException"})
        private AdministrativeRequest process(String id) {
            synchronized(control) { if(closed.get() || !inFlight.add(id)) { return requestState.find(id).orElseThrow(); } }
            try {
                AdministrativeRequest current=requestState.find(id).orElseThrow();
                if (OcspProvisioningSlot.OPERATION.equals(current.operation())) { ocspProvisioning.requireClaim(current); }
                Optional<PkiOperation.SelectIssuancePath> activation=recovery.activationSelection(current);
                if(needsActivationObservation(current, activation)) {
                    return recovery.observeActivation(current, activation.orElseThrow());
                }
                Optional<AdministrativeRequest> resumed = retainedOutcome(current);
                if (resumed.isPresent()) { return resumed.orElseThrow(); }
                Optional<AdministrativeRequest> approval = recovery.approvalOutcome(current);
                if (approval.isPresent()) { return approval.orElseThrow(); }
                ServerOperationGateway.Request request=requestPolicy.request(current);
                ServerOperationGateway.Admission admission=realm.gateway().assessAdministrativeRequest(request);
                requestPolicy.requireSameAdmission(current,admission);requestPolicy.validateActor(current);
                Instant deadline=clock.instant().plusMillis(current.executionTimeoutMillis());
                CancellationSignal cancellation=()->closed.get() || !clock.instant().isBefore(deadline);
                if(request.operation() instanceof AdministrativeOperation.Signing signing) {
                    return processSigning(current, id, request, admission, cancellation, signing);
                }
                AdministrativeRequest dispatched=requestState.update(current,AdministrativeRequest.State.DISPATCHING,Optional.empty(),Optional.empty(),Optional.empty());
                requestState.write(current,dispatched,Optional.empty(),Optional.empty());
                ServerOperationGateway.Outcome outcome=activation.isPresent()?realm.gateway().executeRootActivation(request,recovery.activationEvidence(current,activation.orElseThrow()),cancellation)
                        :realm.gateway().execute(request,cancellation);
                if(outcome instanceof ServerOperationGateway.Outcome.Executed executed) { return recovery.outcome(dispatched,executed.outcome()); }
                if(outcome instanceof ServerOperationGateway.Outcome.ControlExecuted executed
                        && executed.outcome() instanceof ServerControlOperationOutcome.Ordinary ordinary) { return recovery.outcome(dispatched,ordinary.outcome()); }
                return recovery.finish(dispatched,AdministrativeRequest.State.FAILED,Optional.empty(),outcome instanceof ServerOperationGateway.Outcome.Denied ? "AUTHORIZATION_DENIED" : "POLICY_CHANGED");
            } catch(SecurityException denied) {
                return failedAttempt(id, () -> "PROFILE_CHANGED".equals(denied.getMessage()) ? "PROFILE_CHANGED" : "AUTHORIZATION_REVOKED");
            }
            catch(PkiException domain) {
                return failedAttempt(id, () -> AdministrativeRequestState.safeDomainCode(domain));
            }
            catch(java.io.InterruptedIOException cancelled) {
                return failedAttempt(id, () -> "EXECUTION_DEADLINE");
            }
            catch(RuntimeException failure) {
                return failedAttempt(id, () -> "OPERATION_INPUT_INVALID");
            } finally { synchronized(control) { inFlight.remove(id); } }
        }

        // Keep the original fail-closed or uncertain-outcome boundary for every runtime provider failure.
        @SuppressWarnings({"PMD.AvoidSynchronizedStatement", "PMD.AvoidCatchingGenericException"})
        private AdministrativeRequest processSigning(AdministrativeRequest observed, String id,
                ServerOperationGateway.Request request, ServerOperationGateway.Admission admission,
                CancellationSignal cancellation, AdministrativeOperation.Signing signing) throws java.io.InterruptedIOException {
            AdministrativeRequest current = observed;

            AdministrativeSigningPreparation.Result preparation = signingPreparation.prepare(current, request, admission, cancellation, signing);
            if (preparation instanceof AdministrativeSigningPreparation.Existing existing) {
                return existingManagedReceipt(current, id, existing.receipt());
            }
            PreparedSemanticSigningRequest prepared = ((AdministrativeSigningPreparation.Candidate)preparation).candidate();
            zeroecho.pki.api.SemanticSigningService service=signingService.get();
            current=claimPrepared(current,id,prepared,service,cancellation);
            try {
                zeroecho.pki.api.signing.SigningAcceptanceResult accepted=service.accept(prepared);
                if (signing.operation() instanceof PkiSigningOperation.IssueOcspResponderCertificate provision
                        && accepted.disposition()==zeroecho.pki.api.signing.SigningAcceptanceDisposition.ATTACHED_EXISTING
                        && !current.receipt().equals(Optional.of(accepted.receipt()))) {
                    synchronized (control) {
                        AdministrativeRequest exact=requestState.find(id).orElseThrow();
                        if (exact.revision()!=current.revision()) { return exact; }
                        OcspResponderProvisioningService.Attachment proof=ocspProvisioning.attachment(exact,provision.request(),accepted.receipt());
                        AdministrativeRequest attached=requestState.update(exact,exact.state(),Optional.of(accepted.receipt()),Optional.empty(),Optional.empty());
                        control.attachOcspProvisioningReceipt(AdministrativeRequestCodec.encode(attached),
                                AdministrativeRequestCodec.encode(exact).commitment(),ocspProvisioning.transition(exact,attached),proof);
                        requestState.audit(attached); current=attached;
                    }
                }
            } catch(RuntimeException uncertain) { return recovery.reconcile(current); }
            return recovery.reconcile(current);
        }

        private AdministrativeRequest failedAttempt(String id, java.util.function.Supplier<String> code) {
            AdministrativeRequest latest=requestState.find(id).orElseThrow();
            if(latest.receipt().isPresent()) { return recovery.observationUnavailable(latest); }
            if(latest.state()==AdministrativeRequest.State.DISPATCHING) { return recovery.finish(latest,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SYNCHRONOUS_OUTCOME_UNKNOWN"); }
            return recovery.failCurrent(id,code.get());
        }

        private Optional<AdministrativeRequest> retainedOutcome(AdministrativeRequest current) {
            if(current.terminal()) { return Optional.of(current); }
            if(current.receipt().isPresent()) {
                if(current.sdkProof().isPresent()){ sdkAdmission.validateIntegrity(current); }
                return Optional.of(recovery.reconcile(current));
            }
            if(current.sdkProof().isPresent()){ sdkAdmission.validateRetained(current,requestPolicy.request(current),current.envelope()); }
            if(current.state()==AdministrativeRequest.State.DISPATCHING || current.state()==AdministrativeRequest.State.RUNNING) {
                return Optional.of(recovery.finish(current,AdministrativeRequest.State.RECONCILIATION_REQUIRED,Optional.empty(),"SYNCHRONOUS_OUTCOME_UNKNOWN"));
            }
            return Optional.empty();
        }

        private static boolean needsActivationObservation(AdministrativeRequest current,
                Optional<PkiOperation.SelectIssuancePath> activation) {
            return activation.isPresent()&&(current.state()==AdministrativeRequest.State.DISPATCHING
                    ||current.state()==AdministrativeRequest.State.RECONCILIATION_REQUIRED);
        }

        // The original control-store monitor guards retained-receipt revision and claim atomically.
        @SuppressWarnings("PMD.AvoidSynchronizedStatement")
        private AdministrativeRequest existingManagedReceipt(AdministrativeRequest current, String id,
                SigningAcceptanceReceipt receipt) {
            AdministrativeRequest claimed;
            synchronized (control) {

                AdministrativeRequest exact = requestState.find(id).orElseThrow();
                if (exact.revision() != current.revision()) { return exact; }
                claimed = recovery.claim(exact,Optional.of(receipt));

            }
            return recovery.reconcile(claimed);
        }

        // Retain the exact monitor, failure identity and single-use candidate discard boundary.
        @SuppressWarnings({"PMD.AvoidSynchronizedStatement"})
        private AdministrativeRequest claimPrepared(AdministrativeRequest current, String id,
                PreparedSemanticSigningRequest prepared,
                zeroecho.pki.api.SemanticSigningService service, CancellationSignal cancellation)
                throws java.io.InterruptedIOException {
            try {
                synchronized(control) {
                    AdministrativeRequest exact=requestState.find(id).orElseThrow();
                    requirePreparationRevision(current,exact);
                    ServerOperationGateway.Admission live=realm.gateway().assessAdministrativeRequest(requestPolicy.request(exact));requestPolicy.requireSameAdmission(exact,live);requestPolicy.validateActor(exact);
                    if(exact.sdkProof().isPresent()){ sdkAdmission.validateRetained(exact,requestPolicy.request(exact),exact.envelope()); }
                    cancellation.throwIfCancelled();
                    return recovery.claim(exact,Optional.of(prepared.receipt()));
                }
            } catch(Exception failure) { service.discard(prepared);throw failure; }
        }

        private static void requirePreparationRevision(AdministrativeRequest current, AdministrativeRequest exact) {
            if(exact.revision()!=current.revision()) { throw new IllegalStateException("Request changed during preparation"); }
        }
    }
}
