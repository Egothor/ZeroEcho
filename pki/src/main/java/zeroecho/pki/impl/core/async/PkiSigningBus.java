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
package zeroecho.pki.impl.core.async;

import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.application.SigningReconciliationContinuation;
import zeroecho.pki.application.SigningReconciliationRequest;
import zeroecho.pki.application.SigningReconciliationResult;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.impl.framework.x509.UnknownAlgorithmIdentityException;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.TemporaryUniqueIndex;
import zeroecho.pki.util.async.AsyncEndpoint;
import zeroecho.pki.util.async.AsyncState;
import zeroecho.pki.util.async.AsyncStatus;

/**
 * PKI signing bus that orchestrates asynchronous signature operations.
 *
 * <p>
 * The bus derives signing submission, status, result, recovery, and retirement
 * state exclusively from {@link SignWorkflowStore}. Generic asynchronous-bus and
 * workflow-state persistence remain available to unrelated consumers, but are
 * not projections of signing operations.
 * </p>
 *
 * <h2>Execution</h2>
 * <p>
 * This bus is server-side. It does not auto-dispatch execution on SUBMITTED.
 * Instead, completion is driven by {@link #sweep(Instant)} which polls the
 * endpoint. The endpoint performs a one-time {@code execute(opId)} on the first
 * poll by storing signer operation id into continuation state.
 * </p>
 */
// The collaborators counted here form one durable signing lifecycle; splitting
// them would obscure the coordinator/reservation boundary that protects it.
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity", "PMD.PreserveStackTrace",
        "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidLiteralsInIfCondition", "PMD.CloseResource", "PMD.CollapsibleIfStatements",
        "PMD.NcssCount", "PMD.TooManyMethods" })
public final class PkiSigningBus implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(PkiSigningBus.class.getName());

    @SuppressWarnings("PMD.LongVariable")
    private static final String SIGNING_CONTENT_CLEANUP_FAILED =
            "Signing content cleanup failed: code=SIGNING_CONTENT_CLEANUP_FAILED";
    @SuppressWarnings("PMD.LongVariable")
    private static final String PROVIDER_SUBMISSION_UNCERTAIN =
            "Provider submission uncertain: code=PROVIDER_SUBMISSION_UNCERTAIN";
    private static final Duration CLAIM_LEASE = Duration.ofSeconds(30);
    private static final long INITIAL_FENCE = 0L;
    private static final int MAXIMUM_SIGNATURE_BYTES = 1_048_576;
    private static final String OPERATION_ID_PARAMETER = "opId";
    private static final String CANCELLATION_PARAMETER = "cancellation";
    private static final String KEY_REF_PARAMETER = "keyRef";
    private static final String CONTENT_PARAMETER = "content";
    private static final String EXPIRED_DETAIL_CODE = "EXPIRED";

    /**
     * System property controlling the maximum number of characters appended after
     * {@code '#'} in the display operation identifier.
     */
    public static final String PROP_DISPLAY_SUFFIX_MAX_LEN = "zeroecho.pki.opid.displaySuffixMaxLen";

    /**
     * Default maximum length of the display suffix.
     */
    @SuppressWarnings("PMD.LongVariable")
    public static final int DEFAULT_DISPLAY_SUFFIX_MAX_LEN = 64;

    private final PkiStore store;
    private final X509AuthoritySnapshot authority;
    private final SecureRandom random;
    private final String namespace;
    private final SigningServiceCatalog services;
    private final OperationCoordinator coordinator;
    private final ExternalActionCoordinator externalActions;
    private final SignatureWorkflowEndpoint endpoint;
    private final List<SignatureWorkflow.Registration> signerRegistrations;
    private final zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant.HeadroomRegistration
            headroomRegistration;
    private final SigningExecutionRuntime.TerminalOwner terminalOwner;
    private final SigningExecutionRuntime executionRuntime;
    private final ProviderGateway providerGateway;
    private final ForegroundSigningCalls foregroundCalls;
    private final DomainContinuationPublisher domainPublisher;
    private final boolean closeExecutionRuntime;
    private final Duration gracefulDrain;
    private final Duration forcedCancellation;
    private final ReentrantLock lifecycleCloseLock = new ReentrantLock();
    private boolean callbacksClosed;
    private boolean busClosed;

    /**
     * Creates a signing bus in an explicitly composed runtime authority graph.
     *
     * <p>
     * The authority must already bind every signing identity declared by
     * {@code signer} to that exact workflow instance for the {@code SIGN}
     * direction. This constructor validates ownership before registering the
     * workflow or activating durable state. It never constructs an internal
     * authority, accepts an authority from another runtime, or handles private
     * key material.
     * </p>
     *
     * @param store                persistent store
     * @param signer               exact signing workflow owned by
     *                             {@code authority}
     * @param authority            shared immutable runtime authority
     * @throws NullPointerException     if any argument is {@code null}
     * @throws IllegalArgumentException if the authority does not own the exact
     *                                  workflow for every declared signing
     *                                  identity and the {@code SIGN} direction
     */
    public PkiSigningBus(PkiStore store, SignatureWorkflow signer, X509AuthoritySnapshot authority) {
        this(store, List.of(Objects.requireNonNull(signer, "signer")),
                SigningRoutingPolicy.single(signer.id()), resolveDisplaySuffixMaxLen(Optional.empty()), authority,
                defaultExecutionRuntime(), true,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_GRACEFUL_DRAIN,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_FORCED_CANCELLATION);
    }

    /**
     * Creates a self-owned bus routing among several signing services (one per
     * workflow, identified by {@code workflow.id()}), using the process default
     * signing runtime. See {@link #attach(PkiStore, java.util.List, SigningRoutingPolicy,
     * X509AuthoritySnapshot, SigningExecutionRuntime, Duration, Duration)}.
     *
     * @param store persistent store
     * @param workflows one or more signing workflows, one per service
     * @param routing per-key routing policy with a default service
     * @param authority shared immutable runtime authority binding every workflow
     */
    public PkiSigningBus(PkiStore store, List<SignatureWorkflow> workflows, SigningRoutingPolicy routing,
            X509AuthoritySnapshot authority) {
        this(store, workflows, routing, resolveDisplaySuffixMaxLen(Optional.empty()), authority,
                defaultExecutionRuntime(), true,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_GRACEFUL_DRAIN,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_FORCED_CANCELLATION);
    }

    /**
     * Creates a bus attached to one session-owned bounded signing runtime.
     *
     * @param store persistent store that owns the durable signing records
     * @param signer exact signing workflow bound by {@code authority}
     * @param authority immutable authority that authorizes the workflow
     * @param executionRuntime session-owned bounded execution runtime
     * @return an attached bus that does not own {@code executionRuntime}
     */
    public static PkiSigningBus attach(PkiStore store, SignatureWorkflow signer, X509AuthoritySnapshot authority,
            SigningExecutionRuntime executionRuntime) {
        return new PkiSigningBus(store, List.of(Objects.requireNonNull(signer, "signer")),
                SigningRoutingPolicy.single(signer.id()), resolveDisplaySuffixMaxLen(Optional.empty()), authority,
                executionRuntime, false, PkiSessionConfiguration.SigningConfiguration.DEFAULT_GRACEFUL_DRAIN,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_FORCED_CANCELLATION);
    }

    /**
     * Creates a session attachment with its exact foreground drain bounds.
     *
     * @param store persistent store that owns the durable signing records
     * @param signer exact signing workflow bound by {@code authority}
     * @param authority immutable authority that authorizes the workflow
     * @param executionRuntime session-owned bounded execution runtime
     * @param gracefulDrain maximum time allowed for foreground calls to finish naturally
     * @param forcedCancellation maximum time allowed after forcing cancellation
     * @return an attached bus that does not own {@code executionRuntime}
     */
    public static PkiSigningBus attach(PkiStore store, SignatureWorkflow signer, X509AuthoritySnapshot authority,
            SigningExecutionRuntime executionRuntime, Duration gracefulDrain, Duration forcedCancellation) {
        return new PkiSigningBus(store, List.of(Objects.requireNonNull(signer, "signer")),
                SigningRoutingPolicy.single(signer.id()), resolveDisplaySuffixMaxLen(Optional.empty()), authority,
                executionRuntime, false, gracefulDrain, forcedCancellation);
    }

    /**
     * Creates a bus routing among several signing services selected per certification
     * authority. Each workflow is one service (identified by {@code workflow.id()});
     * {@code routing} selects the service for a signing key reference, defaulting
     * unmapped keys to a configured default service. The authority must bind every
     * workflow under its {@code "workflow."+id} implementation for the {@code SIGN}
     * direction. At most one service may use the local-atomic ledger fast path.
     *
     * @param store persistent store
     * @param workflows one or more signing workflows, one per service
     * @param routing per-key routing policy with a default service
     * @param authority shared immutable runtime authority binding every workflow
     * @param executionRuntime session-owned bounded signing runtime
     * @param gracefulDrain graceful drain bound
     * @param forcedCancellation forced cancellation bound
     * @return an attached multi-service signing bus
     */
    public static PkiSigningBus attach(PkiStore store, List<SignatureWorkflow> workflows,
            SigningRoutingPolicy routing, X509AuthoritySnapshot authority, SigningExecutionRuntime executionRuntime,
            Duration gracefulDrain, Duration forcedCancellation) {
        return new PkiSigningBus(store, workflows, routing, resolveDisplaySuffixMaxLen(Optional.empty()), authority,
                executionRuntime, false, gracefulDrain, forcedCancellation);
    }

    /**
     * Creates a signing bus while accepting the obsolete projection path for source
     * compatibility. The path is validated but no file is created, read, replayed,
     * or written.
     *
     * @param store persistent store
     * @param signer exact signing workflow owned by {@code authority}
     * @param obsoleteProjectionPath obsolete non-null path
     * @param authority shared immutable runtime authority
     * @throws NullPointerException if any argument is {@code null}
     * @throws IllegalArgumentException if the authority does not own the workflow
     */
    public PkiSigningBus(PkiStore store, SignatureWorkflow signer, Path obsoleteProjectionPath,
            X509AuthoritySnapshot authority) {
        this(store, List.of(Objects.requireNonNull(signer, "signer")),
                SigningRoutingPolicy.single(signer.id()), requireObsoleteProjectionPath(obsoleteProjectionPath),
                authority, defaultExecutionRuntime(), true,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_GRACEFUL_DRAIN,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_FORCED_CANCELLATION);
    }

    // The construction guard intentionally catches its own validation failures to close partially registered hooks.
    @SuppressWarnings("PMD.ExceptionAsFlowControl")
    private PkiSigningBus(PkiStore store, List<SignatureWorkflow> workflows, SigningRoutingPolicy routing,
            int displaySuffixMaxLen, X509AuthoritySnapshot authority, SigningExecutionRuntime executionRuntime,
            boolean closeExecutionRuntime, Duration gracefulDrain, Duration forcedCancellation) {
        zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant.HeadroomRegistration
                headroomRegistration = null;
        SigningExecutionRuntime.TerminalOwner constructedTerminalOwner = null;
        List<SignatureWorkflow.Registration> constructedRegistrations = new ArrayList<>();
        try {
            Objects.requireNonNull(store, "store");
            Objects.requireNonNull(workflows, "workflows");
            if (workflows.isEmpty()) {
                throw new IllegalArgumentException("At least one signing service is required");
            }
            Objects.requireNonNull(routing, "routing");
            X509AuthoritySnapshot exactAuthority = Objects.requireNonNull(authority, "authority");
            Objects.requireNonNull(executionRuntime, "executionRuntime");

            List<SigningService> configuredServices = new ArrayList<>();
            for (SignatureWorkflow workflow : workflows) {
                Objects.requireNonNull(workflow, "workflow");
                boolean localAtomic =
                        store instanceof zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant
                        && workflow instanceof ZeroEchoLibSignatureWorkflow;
                String serviceNamespace = store.signingNamespace() + "." + workflow.id();
                SignatureWorkflow.ConfigurationCommitment commitment = Objects.requireNonNull(
                        workflow.configurationCommitment(), "workflow configuration commitment");
                validateSigningAuthority(workflow, exactAuthority);
                workflow.validateSigningDomain(serviceNamespace, store.signingHorizon(),
                        store.signingPermittedSkew());
                configuredServices.add(new SigningService(workflow.id(), workflow, serviceNamespace,
                        SigningExecutionSupport.workflowImplementationId(workflow), commitment, localAtomic));
            }
            SigningServiceCatalog catalog = new SigningServiceCatalog(configuredServices, routing);

            this.store = store;
            this.services = catalog;
            this.authority = exactAuthority;
            this.executionRuntime = executionRuntime;
            this.foregroundCalls = new ForegroundSigningCalls();
            this.domainPublisher = new DomainContinuationPublisher(store);
            this.closeExecutionRuntime = closeExecutionRuntime;
            this.gracefulDrain = gracefulDrain;
            this.forcedCancellation = forcedCancellation;
            this.random = new SecureRandom();
            this.namespace = catalog.busNamespace;
            this.coordinator = new OperationCoordinator();
            this.externalActions = new ExternalActionCoordinator();
            resolveDisplaySuffixMaxLen(Optional.of(displaySuffixMaxLen));
            if (catalog.localService != null) {
                SigningService local = catalog.localService;
                constructedTerminalOwner = executionRuntime.attachTerminalOwner();
                SigningExecutionRuntime.TerminalOwner callbackOwner = constructedTerminalOwner;
                ((zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant) store)
                        .recoverMatchedLocalSigning(local.namespace(), local.commitment());
                headroomRegistration =
                        ((zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant) store)
                                .registerSigningHeadroomRestored(
                                        new zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant
                                                .HeadroomListener() {
                                            @Override public void restored(long epoch) {
                                                executionRuntime.headroomRestored(callbackOwner, epoch);
                                            }

                                            @Override public void recoveryRequired() {
                                                executionRuntime.headroomRecoveryRequired(callbackOwner);
                                            }
                                        });
                executionRuntime.headroomRestored(callbackOwner,
                        ((zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant) store)
                                .signingHeadroomEpoch());
            } else {
                headroomRegistration = () -> { };
            }
            this.headroomRegistration = headroomRegistration;
            this.terminalOwner = constructedTerminalOwner;
            this.providerGateway = new ProviderGateway(store, executionRuntime, terminalOwner);
            this.endpoint = new SignatureWorkflowEndpoint(store, catalog, coordinator, externalActions,
                    authority, executionRuntime, providerGateway);
            for (SigningService service : configuredServices) {
                constructedRegistrations.add(Objects.requireNonNull(
                        service.workflow().register(endpoint::onProviderStatusChanged), "signer registration"));
            }
            this.signerRegistrations = List.copyOf(constructedRegistrations);
        } catch (RuntimeException | Error constructionFailure) {
            for (SignatureWorkflow.Registration registration : constructedRegistrations) {
                try {
                    registration.close();
                } catch (RuntimeException cleanupFailure) {
                    constructionFailure.addSuppressed(cleanupFailure);
                }
            }
            if (headroomRegistration != null) {
                try {
                    headroomRegistration.close();
                } catch (RuntimeException cleanupFailure) {
                    constructionFailure.addSuppressed(cleanupFailure);
                }
            }
            if (constructedTerminalOwner != null) {
                try {
                    executionRuntime.detachTerminalOwner(constructedTerminalOwner);
                } catch (RuntimeException cleanupFailure) {
                    constructionFailure.addSuppressed(cleanupFailure);
                }
            }
            closeOwnedRuntimeAfterConstructionFailure(executionRuntime, closeExecutionRuntime, constructionFailure);
            throw constructionFailure;
        }
    }

    private static void closeOwnedRuntimeAfterConstructionFailure(SigningExecutionRuntime runtime,
            boolean owned, Throwable constructionFailure) {
        if (!owned || runtime == null) {
            return;
        }
        try {
            runtime.close();
        } catch (Throwable cleanupFailure) {
            constructionFailure.addSuppressed(cleanupFailure);
        }
    }

    private static SigningExecutionRuntime defaultExecutionRuntime() {
        return new SigningExecutionRuntime(
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_LANE_COUNT,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_QUEUE_CAPACITY,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_GRACEFUL_DRAIN,
                PkiSessionConfiguration.SigningConfiguration.DEFAULT_FORCED_CANCELLATION);
    }

    private static boolean isActiveSignRecord(SignWorkflowStore.Record record) {
        return record.state() == SignWorkflowStore.State.INTENT
                || record.state() == SignWorkflowStore.State.DISPATCHED
                || record.state() == SignWorkflowStore.State.CANCELLING;
    }

    private boolean hasCurrentSigningConfiguration(SignWorkflowStore.Record record) {
        return services.forNamespace(record.namespace())
                .map(service -> record.configurationCommitment().matches(service.commitment()))
                .orElse(false);
    }

    private boolean isLocalRecord(SignWorkflowStore.Record record) {
        return services.forNamespace(record.namespace()).map(SigningService::localAtomic).orElse(false);
    }

    private SignWorkflowStore.Record expireConfigurationMismatch(PkiId operationId,
            SignWorkflowStore.Record fallback, Instant now) {
        try (OperationCoordinator.Lease ignored = coordinator.acquire(operationId)) {
            SignWorkflowStore.Record current = store.getSignRecord(operationId).orElse(fallback);
            if (!isActiveSignRecord(current) || hasCurrentSigningConfiguration(current)
                    || current.deadline().isAfter(now)) {
                return current;
            }
            store.transitionSign(operationId, current.revision(), current.fence(),
                    SignWorkflowStore.State.EXPIRED, Optional.of(EXPIRED_DETAIL_CODE),
                    Optional.empty(), Optional.empty());
            return store.getSignRecord(operationId).orElse(current);
        }
    }

    private static int requireObsoleteProjectionPath(Path obsoleteProjectionPath) {
        Objects.requireNonNull(obsoleteProjectionPath, "obsoleteProjectionPath");
        return resolveDisplaySuffixMaxLen(Optional.empty());
    }

    /**
     * Returns the immutable authority used by this workflow graph.
     *
     * @return authority snapshot
     */
    public X509AuthoritySnapshot authority() {
        return authority;
    }

    /**
     * Returns the bounded execution runtime shared with this bus.
     *
     * @return shared bounded signing execution runtime
     */
    public SigningExecutionRuntime executionRuntime() {
        return executionRuntime;
    }

    /**
     * Registers one synchronous signing call before admission and staging.
     *
     * @param callerCancellation cancellation supplied by the synchronous caller
     * @return a one-shot registration whose close operation ends foreground-call ownership
     */
    public ForegroundCall registerForegroundCall(CancellationSignal callerCancellation) {
        return new ForegroundCall(this, foregroundCalls, foregroundCalls.register(callerCancellation));
    }

    /** One foreground call's lifecycle and combined cancellation view. */
    public static final class ForegroundCall implements AutoCloseable {
        private final PkiSigningBus owner;
        private final ForegroundSigningCalls registry;
        private final ForegroundSigningCalls.ForegroundCall delegate;

        private ForegroundCall(PkiSigningBus owner, ForegroundSigningCalls registry,
                ForegroundSigningCalls.ForegroundCall delegate) {
            this.owner = owner;
            this.registry = registry;
            this.delegate = delegate;
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Bus capability ownership requires exact identity.
        private void requireOwner(PkiSigningBus expectedOwner) {
            if (owner != expectedOwner || registry != expectedOwner.foregroundCalls) {
                throw new IllegalArgumentException("Signing foreground call belongs to another bus");
            }
        }

        /**
         * Returns the combined cancellation view for this foreground call.
         *
         * @return caller, session-forced, and current-thread cancellation
         */
        public CancellationSignal cancellation() {
            return delegate.cancellation();
        }

        /** Fails with the stable shutdown classification after cancellation. */
        public void requireActive() {
            delegate.requireActive();
        }

        private void requireCommitAllowed() {
            delegate.requireCommitAllowed();
        }

        @Override public void close() {
            delegate.close();
        }
    }

    /**
     * Reserves both the promised initial scheduler step and one durable workflow
     * slot before staging or identifier creation.
     *
     * @return opaque one-shot composite admission
     */
    public NewSignAdmission reserveNewSignAdmission() {
        SigningExecutionRuntime.InitialStepReservation initial = executionRuntime.reserveInitialStep();
        try {
            return new NewSignAdmission(initial, store.reserveSignAdmission());
        } catch (SignWorkflowStore.SignAdmissionException exhausted) {
            initial.close();
            throw workflowCapacityExceeded();
        } catch (RuntimeException | Error failure) {
            initial.close();
            throw failure;
        }
    }

    private static SigningExecutionException workflowCapacityExceeded() {
        return new SigningExecutionException(SigningExecutionException.Classification.OVERLOADED,
                "Signing workflow capacity is full: code=SIGNING_OVERLOADED");
    }

    /** Opaque composite admission for exactly one newly arriving sign operation. */
    public final class NewSignAdmission implements AutoCloseable {
        private final PkiSigningBus owner = PkiSigningBus.this;
        private final SigningExecutionRuntime.InitialStepReservation initial;
        private final SignWorkflowStore.SignAdmission durable;
        private final AtomicBoolean bound = new AtomicBoolean();
        private final AtomicBoolean closed = new AtomicBoolean();

        private NewSignAdmission(SigningExecutionRuntime.InitialStepReservation initial,
                SignWorkflowStore.SignAdmission durable) {
            this.initial = initial;
            this.durable = durable;
        }

        private void bind(PkiId operationId) {
            requireOpen();
            if (!bound.compareAndSet(false, true)) {
                throw new IllegalStateException("New signing admission is already bound");
            }
            durable.bind(operationId);
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Admission ownership requires exact bus identity.
        private void requireOwner(PkiSigningBus expectedOwner) {
            if (owner != expectedOwner) {
                throw new IllegalArgumentException("Signing admission belongs to another bus");
            }
        }

        private void requireOpen() {
            if (closed.get()) {
                throw new IllegalStateException("New signing admission is closed");
            }
        }

        @Override public void close() {
            if (closed.compareAndSet(false, true)) {
                closeAdmissionResources(durable, initial);
            }
        }
    }

    @SuppressWarnings("PMD.UseTryWithResources") // Both one-shot resources are fields owned by the admission.
    private static void closeAdmissionResources(SignWorkflowStore.SignAdmission durable,
            SigningExecutionRuntime.InitialStepReservation initial) {
        try {
            durable.close();
        } finally {
            initial.close();
        }
    }

    /**
     * Begins runtime-owned durable staging for one signing input.
     *
     * @param encoding content encoding
     * @return atomic staged-content sink
     */
    public ContentSink beginSigningContent(Encoding encoding) {
        return beginContent(encoding, DurableContentReference.Lifecycle.OPERATION);
    }

    /**
     * Begins atomic runtime-owned content staging.
     *
     * <p>
     * The sink writes to the injected staged-content store and never retains an
     * aggregate payload in the bus. ZeroEcho core imposes no arbitrary
     * product-wide aggregate size limit.
     * </p>
     *
     * @param encoding content encoding
     * @param lifecycle ownership and retirement class
     * @return atomic streamed sink
     * @throws PkiException if staging cannot begin
     */
    public ContentSink beginContent(Encoding encoding, DurableContentReference.Lifecycle lifecycle) {
        try {
            return store.stagedContent().beginContent(Objects.requireNonNull(encoding, "encoding"),
                    Objects.requireNonNull(lifecycle, "lifecycle"));
        } catch (IOException ex) {
            throw new PkiException("Content staging failed: code=SPOOL_STORAGE_FAILED");
        }
    }

    /**
     * Opens immutable repeatable content owned by this runtime.
     *
     * @param reference opaque durable content reference
     * @return repeatable content
     * @throws PkiException if the content is missing, incomplete, corrupt, or
     *                      belongs to another runtime store
     */
    public RepeatableContent openContent(DurableContentReference reference) {
        try {
            return store.stagedContent().openContent(Objects.requireNonNull(reference, "reference"));
        } catch (IOException ex) {
            throw new PkiException("Content open failed: code=CONTENT_INTEGRITY_FAILED");
        }
    }

    /**
     * Releases staged content from this runtime.
     *
     * @param reference content reference
     * @throws PkiException if cleanup fails
     */
    public void releaseContent(DurableContentReference reference) {
        try {
            store.stagedContent().retireUnownedContent(Objects.requireNonNull(reference, "reference"));
        } catch (IOException ex) {
            throw new PkiException("Content cleanup failed: code=SPOOL_STORAGE_FAILED");
        }
    }

    /**
     * Begins a runtime-owned file-backed uniqueness index.
     *
     * @return temporary uniqueness index
     * @throws PkiException if temporary storage cannot be created
     */
    public TemporaryUniqueIndex beginUniqueIndex() {
        try {
            return store.stagedContent().beginUniqueIndex();
        } catch (IOException ex) {
            throw new PkiException("Temporary index failed: code=SPOOL_STORAGE_FAILED");
        }
    }

    private static void validateSigningAuthority(SignatureWorkflow workflow, X509AuthoritySnapshot authority) {
        Set<String> supportedAlgorithms = Set.copyOf(
                Objects.requireNonNull(workflow.supportedAlgorithms(), "workflow.supportedAlgorithms"));
        if (supportedAlgorithms.isEmpty()) {
            throw new IllegalArgumentException("Signature workflow must declare a signing identity");
        }
        int x509Capable = 0;
        for (String algorithm : supportedAlgorithms.stream().sorted().toList()) {
            try {
                X509ExecutionPlan<SignatureWorkflow> plan = authority.planSigning(algorithm,
                        SigningExecutionSupport.workflowImplementationId(workflow), SignatureWorkflow.class);
                authority.authorize(plan, workflow, AlgorithmExecutionCapability.Direction.SIGN);
                x509Capable++;
            } catch (X509AlgorithmResolver.ResolutionException unavailable) {
                if (unavailable.failure() != X509AlgorithmResolver.Failure.NO_BINDING) {
                    throw unavailable;
                }
            } catch (UnknownAlgorithmIdentityException ignored) {
                // The workflow's algorithm identity is unresolvable, so it is not an
                // X.509-capable signing identity; continue probing the others.
            }
        }
        if (x509Capable == 0) {
            throw new IllegalArgumentException("Signature workflow has no X.509-capable signing identity");
        }
    }

    /**
     * Builds a canonical, globally unique operation identifier derived from tuple
     * (owner, clientOpId).
     *
     * <p>
     * The returned value contains a display suffix after {@code '#'} for
     * convenience. Backend lookups always ignore the suffix and operate on the
     * portion before {@code '#'}.
     * </p>
     *
     * @param clientOpId client-chosen identifier
     * @param owner      operation owner
     * @return canonical operation identifier (including optional display suffix)
     */
    public PkiId canonicalizeOperationId(PkiId clientOpId, Principal owner) {
        Objects.requireNonNull(clientOpId, "clientOpId");
        Objects.requireNonNull(owner, "owner");
        return newSubmissionId();
    }

    /**
     * Builds a canonical operation identifier in the namespace of the signing
     * service that handles {@code keyRef}. Multi-service deployments must create the
     * identifier with the same key reference used to submit, so the durable record's
     * namespace matches its submission identifier.
     *
     * @param clientOpId client-chosen identifier
     * @param owner operation owner
     * @param keyRef signing key reference selecting the service namespace
     * @return canonical operation identifier in the routed service's namespace
     */
    public PkiId canonicalizeOperationId(PkiId clientOpId, Principal owner, KeyRef keyRef) {
        Objects.requireNonNull(clientOpId, "clientOpId");
        Objects.requireNonNull(owner, "owner");
        return newSubmissionId(keyRef);
    }

    /**
     * Creates a stable provider-namespaced signing submission identifier.
     *
     * @return new stable identifier
     */
    public PkiId newSubmissionId() {
        return SigningSubmissionId.create(namespace, store.signingNow(), random).id();
    }

    /**
     * Creates a stable submission identifier in the namespace of the signing service
     * that handles {@code keyRef}.
     *
     * @param keyRef signing key reference selecting the service namespace
     * @return new stable identifier in the routed service's namespace
     */
    public PkiId newSubmissionId(KeyRef keyRef) {
        return SigningSubmissionId.create(services.select(Objects.requireNonNull(keyRef, KEY_REF_PARAMETER)).namespace(),
                store.signingNow(), random).id();
    }

    /**
     * Returns the authority executor implementation id of the signing service that
     * handles the given signing key reference under the configured per-CA routing.
     * Callers resolving a signing plan must select this implementation so that the
     * plan binds the exact service that will perform the signature.
     *
     * @param keyRef signing key reference (never {@code null})
     * @return the routed service's {@code SIGN} implementation id
     */
    public String signingImplementationId(KeyRef keyRef) {
        return services.select(Objects.requireNonNull(keyRef, KEY_REF_PARAMETER)).implementationId();
    }

    /**
     * Returns the {@code SIGN} implementation id of the default signing service,
     * used where no specific key reference routes the plan (for example a
     * configuration-time capability check).
     *
     * @return the default service's {@code SIGN} implementation id
     */
    public String defaultSigningImplementationId() {
        return services.defaultService().implementationId();
    }

    /**
     * Submits a sign operation.
     *
     * @param opId            operation id (may include display suffix after '#')
     * @param owner           owner principal
     * @param keyRef          signing key reference
     * @param algorithmId     signature algorithm id
     * @param content         durable repeatable content to sign
     * @param ttl             time-to-live
     * @param workflowPayload minimal continuation payload
     *
     * @apiNote Once this method is invoked with a non-null {@code content}
     *          reference, the bus owns its disposition. A failure before durable
     *          intent creation retires content only after the store proves that no
     *          record exists. Committed or durability-uncertain content remains
     *          owned by the bus for reconciliation and recovery. Callers must not
     *          release the reference after invoking this method.
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public void submitSign(PkiId opId, Principal owner, KeyRef keyRef, String algorithmId,
            DurableContentReference content,
            Duration ttl, Optional<EncodedObject> workflowPayload) {
        Objects.requireNonNull(content, CONTENT_PARAMETER);
        Objects.requireNonNull(keyRef, KEY_REF_PARAMETER);
        PkiId normalized = null;
        SigningExecutionRuntime.InitialStepReservation initial = services.select(keyRef).localAtomic()
                ? executionRuntime.reserveInitialStep() : null;
        SignWorkflowStore.SignAdmission admission;
        try {
            normalized = normalizeBaseOperationId(Objects.requireNonNull(opId, OPERATION_ID_PARAMETER));
            admission = store.reserveSignAdmission(normalized);
        } catch (SignWorkflowStore.SignAdmissionException exhausted) {
            if (initial != null) {
                initial.close();
            }
            releaseSubmissionContentIfUnowned(normalized, content);
            throw workflowCapacityExceeded();
        } catch (RuntimeException | Error failure) {
            if (initial != null) {
                initial.close();
            }
            releaseSubmissionContentIfUnowned(normalized, content);
            throw failure;
        }
        try (initial; admission) {
            submitAdmittedSign(admission, initial, new SignSubmission(normalized, owner, keyRef, algorithmId,
                    content, ttl, workflowPayload, CancellationSignal.NONE, null), null);
        }
    }

    /**
     * Submits a newly staged sign using its pre-staging composite admission.
     *
     * @param admission one-shot composite admission reserved before staging
     * @param opId operation identifier, optionally carrying a display suffix
     * @param owner principal that owns the signing operation
     * @param keyRef managed signing-key reference
     * @param algorithmId canonical signature algorithm identifier
     * @param content durable content reference whose disposition transfers to the bus
     * @param ttl positive lifetime of the durable operation
     * @param workflowPayload optional bounded workflow continuation payload
     */
    public void submitInitialSign(NewSignAdmission admission, PkiId opId, Principal owner,
            KeyRef keyRef, String algorithmId, DurableContentReference content,
            Duration ttl, Optional<EncodedObject> workflowPayload) {
        submitInitialSign(admission, opId, owner, keyRef, algorithmId, content, ttl, workflowPayload,
                CancellationSignal.NONE);
    }

    /**
     * Submits one admitted foreground sign with its lifecycle cancellation.
     *
     * @param admission one-shot composite admission reserved before staging
     * @param opId operation identifier, optionally carrying a display suffix
     * @param owner principal that owns the signing operation
     * @param keyRef managed signing-key reference
     * @param algorithmId canonical signature algorithm identifier
     * @param content durable content reference whose disposition transfers to the bus
     * @param ttl positive lifetime of the durable operation
     * @param workflowPayload optional bounded workflow continuation payload
     * @param cancellation cancellation observed before the durable intent commits
     */
    public void submitInitialSign(NewSignAdmission admission, PkiId opId, Principal owner,
            KeyRef keyRef, String algorithmId, DurableContentReference content,
            Duration ttl, Optional<EncodedObject> workflowPayload,
            CancellationSignal cancellation) {
        submitInitialSign(admission, new SignSubmission(opId, owner, keyRef, algorithmId, content, ttl,
                workflowPayload, cancellation, null));
    }

    /**
     * Submits one admitted sign through its pre-intent lifecycle commit gate.
     *
     * @param admission one-shot composite admission reserved before staging
     * @param opId operation identifier, optionally carrying a display suffix
     * @param owner principal that owns the signing operation
     * @param keyRef managed signing-key reference
     * @param algorithmId canonical signature algorithm identifier
     * @param content durable content reference whose disposition transfers to the bus
     * @param ttl positive lifetime of the durable operation
     * @param workflowPayload optional bounded workflow continuation payload
     * @param foregroundCall active foreground-call registration owned by this bus
     */
    public void submitInitialSign(NewSignAdmission admission, PkiId opId, Principal owner,
            KeyRef keyRef, String algorithmId, DurableContentReference content,
            Duration ttl, Optional<EncodedObject> workflowPayload, ForegroundCall foregroundCall) {
        ForegroundCall exactCall = Objects.requireNonNull(foregroundCall, "foregroundCall");
        submitInitialSign(admission, new SignSubmission(opId, owner, keyRef, algorithmId, content, ttl,
                workflowPayload, CancellationSignal.NONE, exactCall));
    }

    /**
     * Submits one admitted sign atomically linked to its domain continuation.
     *
     * @param admission one-shot composite admission reserved before staging
     * @param request immutable domain signing request and continuation template
     * @param foregroundCall active foreground-call registration owned by this bus
     */
    public void submitInitialSign(NewSignAdmission admission, DomainSigningRequest request,
            ForegroundCall foregroundCall) {
        DomainSigningRequest exact = Objects.requireNonNull(request, "request");
        ForegroundCall exactCall = Objects.requireNonNull(foregroundCall, "foregroundCall");
        submitInitialSign(admission, new SignSubmission(exact.operationId(), exact.owner(), exact.keyRef(),
                exact.algorithmId(), exact.content(), exact.ttl(), exact.workflowPayload(),
                CancellationSignal.NONE, exactCall, Optional.of(exact.domainTemplate())));
    }

    @SuppressWarnings("PMD.CloseResource") // Foreground ownership remains with the initiating content signer.
    private void submitInitialSign(NewSignAdmission admission, SignSubmission submission) {
        NewSignAdmission exactAdmission = Objects.requireNonNull(admission, "admission");
        SignSubmission exactSubmission = Objects.requireNonNull(submission, "submission");
        exactAdmission.requireOwner(this);
        ForegroundCall foregroundCall = exactSubmission.foregroundCall();
        if (foregroundCall != null) {
            foregroundCall.requireOwner(this);
        }
        CancellationSignal exactCancellation = foregroundCall == null
                ? Objects.requireNonNull(exactSubmission.cancellation(), CANCELLATION_PARAMETER)
                : foregroundCall.cancellation();
        DurableContentReference content = Objects.requireNonNull(exactSubmission.content(), CONTENT_PARAMETER);
        PkiId normalized = null;
        try {
            normalized = normalizeBaseOperationId(Objects.requireNonNull(
                    exactSubmission.operationId(), OPERATION_ID_PARAMETER));
            SignSubmission admitted = new SignSubmission(normalized, exactSubmission.owner(),
                    exactSubmission.keyRef(), exactSubmission.algorithmId(), content, exactSubmission.ttl(),
                    exactSubmission.workflowPayload(), exactCancellation, foregroundCall,
                    exactSubmission.domainTemplate());
            submitAdmittedSign(exactAdmission.durable, exactAdmission.initial, admitted, exactAdmission);
        } catch (RuntimeException | Error failure) {
            releaseSubmissionContentIfUnowned(normalized, content);
            throw failure;
        }
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ExceptionAsFlowControl",
            "PMD.CloseResource" }) // Foreground ownership spans caller cleanup after this transition.
    private void submitAdmittedSign(SignWorkflowStore.SignAdmission admission,
            SigningExecutionRuntime.InitialStepReservation initialStep, SignSubmission submission,
            NewSignAdmission compositeAdmission) {

        PkiId opId = submission.operationId();
        Principal owner = submission.owner();
        KeyRef keyRef = submission.keyRef();
        String algorithmId = submission.algorithmId();
        DurableContentReference content = Objects.requireNonNull(submission.content(), CONTENT_PARAMETER);
        Duration ttl = submission.ttl();
        Optional<EncodedObject> workflowPayload = submission.workflowPayload();
        CancellationSignal cancellation = submission.cancellation();
        ForegroundCall foregroundCall = submission.foregroundCall();

        PkiId baseOpId = null;
        boolean remoteCreated = false;
        try {
            SigningService service = services.select(keyRef);
            AlgorithmIdentity submittedIdentity = validateSubmissionInputs(service, opId, owner, keyRef, algorithmId,
                    ttl, workflowPayload);
            PkiId normalizedBaseOpId = normalizeBaseOperationId(opId);
            SigningSubmissionId parsed = SigningSubmissionId.parse(normalizedBaseOpId);
            baseOpId = normalizedBaseOpId;
            Instant deadline = parsed.createdAt().plus(ttl);
            SignContinuation continuation = SignContinuation.decode(workflowPayload.get(), store.stagedContent());
            X509ExecutionPlan<SignatureWorkflow> continuationPlan = authority.planSigning(
                    continuation.algorithmId, service.implementationId(), SignatureWorkflow.class);
            authority.authorize(continuationPlan, service.workflow(), AlgorithmExecutionCapability.Direction.SIGN);
            AlgorithmIdentity continuationIdentity = continuationPlan.selection().requested();
            if (!owner.equals(continuation.accessContext.principal()) || !keyRef.equals(continuation.keyRef)
                    || !submittedIdentity.equals(continuationIdentity)
                    || !content.equals(continuation.content())) {
                throw new IllegalArgumentException("Sign continuation does not match the submitted request");
            }
            continuation = continuation.withAlgorithmId(submittedIdentity.canonicalForm());
            SignatureWorkflow.ConfigurationCommitment configurationCommitment = service.commitment();
            String fingerprint = continuation.semanticFingerprint(configurationCommitment, service.namespace(),
                    deadline);
            EncodedObject persistedRequest = continuation.withSignerOpId(baseOpId).encode();
            SignWorkflowStore.Record intent = new SignWorkflowStore.Record(baseOpId, service.namespace(), fingerprint,
                    configurationCommitment, owner, parsed.createdAt(), deadline, persistedRequest,
                    SignWorkflowStore.State.INTENT, 0L, 0L, Optional.empty(), Optional.of("INTENT"),
                    Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
            LocalAtomicSubmission localSubmission = service.localAtomic()
                    ? new LocalAtomicSubmission(intent, continuation, content) : null;
            if (localSubmission != null) {
                submitLocalAtomic(service, admission, localSubmission.intent(), localSubmission.continuation(),
                        localSubmission.content(), initialStep, cancellation, compositeAdmission, foregroundCall);
            } else {
                Optional<DomainContinuationStore.Record> domainContinuation = Optional.empty();
                if (submission.domainTemplate().isPresent()) {
                    DomainContinuationTemplate template = submission.domainTemplate().orElseThrow();
                    domainContinuation = Optional.of(new DomainContinuationStore.Record(normalizedBaseOpId,
                            2, template.kind(), template.correlationId(), DomainContinuationStore.State.SIGNING, 0L,
                            parsed.createdAt(), deadline, template.command(), template.commandCommitment(),
                            Optional.of(content), Optional.empty(), Optional.empty()));
                }
                SignWorkflowStore.CreateResult created = commitRemoteIntent(admission, intent,
                        domainContinuation, compositeAdmission, foregroundCall);
                if (created == SignWorkflowStore.CreateResult.CONFLICT) {
                    releaseAttachedOrConflictingContent(content);
                    throw new PkiException("Signing submission identifier conflicts with a different request");
                }
                if (created == SignWorkflowStore.CreateResult.ATTACHED) {
                    releaseAttachedOrConflictingContent(content);
                }
                remoteCreated = created == SignWorkflowStore.CreateResult.CREATED;
            }
            if (remoteCreated && initialStep != null) {
                endpoint.executeInitial(baseOpId, initialStep, cancellation);
            }
        } catch (RuntimeException | Error failure) {
            releaseSubmissionContentIfUnowned(baseOpId, content);
            throw failure;
        }
    }

    private AlgorithmIdentity validateSubmissionInputs(SigningService service, PkiId opId, Principal owner,
            KeyRef keyRef, String algorithmId, Duration ttl, Optional<EncodedObject> workflowPayload) {
        Objects.requireNonNull(service, "service");
        Objects.requireNonNull(opId, OPERATION_ID_PARAMETER);
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(keyRef, KEY_REF_PARAMETER);
        Objects.requireNonNull(algorithmId, "algorithmId");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(workflowPayload, "workflowPayload");
        if (algorithmId.isBlank()) {
            throw new IllegalArgumentException("algorithmId must not be blank");
        }
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        if (workflowPayload.isEmpty()) {
            throw new IllegalArgumentException("workflowPayload must be present for new sign operation");
        }
        X509ExecutionPlan<SignatureWorkflow> submittedPlan = authority.planSigning(algorithmId,
                service.implementationId(), SignatureWorkflow.class);
        authority.authorize(submittedPlan, service.workflow(), AlgorithmExecutionCapability.Direction.SIGN);
        return submittedPlan.selection().requested();
    }

    @SuppressWarnings("PMD.CloseResource") // Borrowed workflow is session-owned.
    private void submitLocalAtomic(SigningService service, SignWorkflowStore.SignAdmission admission,
            SignWorkflowStore.Record intent, SignContinuation continuation,
            DurableContentReference reference,
            SigningExecutionRuntime.InitialStepReservation initialStep,
            CancellationSignal cancellation, NewSignAdmission compositeAdmission,
            ForegroundCall foregroundCall) {
        zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant participant =
                (zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant) store;
        ZeroEchoLibSignatureWorkflow local = (ZeroEchoLibSignatureWorkflow) service.workflow();
        RepeatableContent payload;
        try {
            payload = store.stagedContent().openContent(reference);
        } catch (IOException failure) {
            throw new PkiException("Signing content unavailable: code=STAGED_CONTENT_MISSING");
        }
        try (payload) {
            SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(
                    intent.submissionId(), intent.namespace(), intent.configurationCommitment(), 1L,
                    continuation.accessContext,
                    continuation.keyRef, continuation.algorithmId, continuation.signatureCommitment(), payload,
                    Optional.of(continuation.preferredSignatureEncoding), Optional.of(intent.deadline()));
            zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptance;
            if (foregroundCall == null) {
                if (compositeAdmission != null) {
                    compositeAdmission.bind(intent.submissionId());
                }
                acceptance = acceptInitialLocalSign(participant, admission, request,
                        local.configurationCommitment(), intent, reference);
            } else {
                foregroundCall.requireCommitAllowed();
                compositeAdmission.bind(intent.submissionId());
                acceptance = acceptInitialLocalSign(participant, admission, request,
                        local.configurationCommitment(), intent, reference);
                requireForegroundActiveAfterDurableCommit(intent.submissionId(), foregroundCall);
            }
            SignWorkflowStore.Record acceptedRecord = store.getSignRecord(intent.submissionId()).orElseThrow();
            if (acceptedRecord.state() == SignWorkflowStore.State.EXPIRED) {
                if (acceptance.outcome()
                        == zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant.AtomicAcceptance.Outcome.ATTACHED) {
                    releaseAttachedOrConflictingContent(reference);
                }
                return;
            }
            if (acceptance.outcome()
                    == zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant.AtomicAcceptance.Outcome.ATTACHED) {
                releaseAttachedOrConflictingContent(reference);
                return;
            }
            zeroecho.pki.impl.fs.LocalExecutionPermit permit = acceptance.executionPermit().orElseThrow();
            SignatureWorkflow.CallControl control = new SignatureWorkflow.CallControl(
                    intent.deadline(), cancellation);
            providerGateway.submitAcceptedLocal(local, request, permit, control, initialStep);
        } catch (IOException failure) {
            throw new PkiException("Signing content unavailable: code=STAGED_CONTENT_MISSING");
        }
    }

    private static zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant.AtomicAcceptance
            acceptInitialLocalSign(zeroecho.pki.impl.fs.AtomicLocalSigningLedgerParticipant participant,
                    SignWorkflowStore.SignAdmission admission,
                    SignatureWorkflow.SignRequest request,
                    SignatureWorkflow.ConfigurationCommitment configurationCommitment,
                    SignWorkflowStore.Record intent, DurableContentReference reference) {
        try {
            return participant.acceptLocalSign(admission, request, configurationCommitment,
                    intent, reference);
        } catch (RuntimeException failure) {
            throw translateInitialMetadataFailure(failure);
        }
    }

    private SignWorkflowStore.CreateResult commitRemoteIntent(SignWorkflowStore.SignAdmission admission,
            SignWorkflowStore.Record intent, Optional<DomainContinuationStore.Record> domainContinuation,
            NewSignAdmission compositeAdmission,
            ForegroundCall foregroundCall) {
        if (foregroundCall == null) {
            if (compositeAdmission != null) {
                compositeAdmission.bind(intent.submissionId());
            }
            return createRemoteIntent(admission, intent, domainContinuation);
        }
        SignWorkflowStore.CreateResult created;
        foregroundCall.requireCommitAllowed();
        compositeAdmission.bind(intent.submissionId());
        created = createRemoteIntent(admission, intent, domainContinuation);
        if (created == SignWorkflowStore.CreateResult.CREATED) {
            requireForegroundActiveAfterDurableCommit(intent.submissionId(), foregroundCall);
        }
        return created;
    }

    private void requireForegroundActiveAfterDurableCommit(PkiId operationId,
            ForegroundCall foregroundCall) {
        if (foregroundCall.cancellation().isCancelled()) {
            try (OperationCoordinator.Lease ignored = coordinator.acquire(operationId)) {
                store.getSignRecord(operationId).filter(record -> !isTerminalSignState(record.state()))
                        .ifPresent(record -> persistCancelling(operationId, record));
            }
        }
        foregroundCall.requireActive();
    }

    private SignWorkflowStore.CreateResult createRemoteIntent(SignWorkflowStore.SignAdmission admission,
            SignWorkflowStore.Record intent, Optional<DomainContinuationStore.Record> domainContinuation) {
        try (OperationCoordinator.Lease ignored = coordinator.acquire(intent.submissionId())) {
            SignWorkflowStore.CreateResult created;
            try {
                created = domainContinuation.isPresent()
                        ? store.createSignIntent(admission, intent, domainContinuation.orElseThrow())
                        : store.createSignIntent(admission, intent);
            } catch (RuntimeException failure) {
                throw translateInitialMetadataFailure(failure);
            }
            store.getSignRecord(intent.submissionId()).orElseThrow();
            return created;
        }
    }

    /* default */ static RuntimeException translateInitialMetadataFailure(RuntimeException failure) {
        Throwable current = Objects.requireNonNull(failure, "failure");
        while (current != null) {
            if (current instanceof MetadataStoreException metadataFailure
                    && metadataFailure.category()
                            == MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED) {
                return new SigningExecutionException(
                        SigningExecutionException.Classification.OVERLOADED,
                        "Signing metadata admission is full: code=SIGNING_OVERLOADED", failure);
            }
            current = current.getCause();
        }
        return failure;
    }

    private void releaseSubmissionContentIfUnowned(PkiId operationId, DurableContentReference content) {
        try {
            if (operationId == null || store.getSignRecord(operationId).isEmpty()) {
                releaseContent(content);
            }
        } catch (RuntimeException | Error cleanupOrDurabilityFailure) { // NOPMD - preserve primary boundary failure
            // An unreadable durability state is not proof of abandonment. Restart
            // recovery reconciles committed references and reclaims true orphans.
        }
    }

    private void releaseAttachedOrConflictingContent(DurableContentReference content) {
        try {
            releaseContent(content);
        } catch (RuntimeException | Error retainedOrCleanupFailure) { // NOPMD - authoritative record wins
            // An identical attachment may already own this exact reference. A
            // cleanup failure leaves an orphan for restart recovery.
        }
    }

    /**
     * Returns the current durable status if the operation is known.
     *
     * @param opId signing operation identifier
     * @return current status, or empty when no local operation is known
     */
    public Optional<AsyncStatus> status(PkiId opId) {
        return status(opId, CancellationSignal.NONE);
    }

    /**
     * Returns current status using one foreground call's cancellation.
     *
     * @param opId signing operation identifier
     * @param cancellation cancellation observed while reconciling provider state
     * @return current status, or empty when no local operation is known
     */
    public Optional<AsyncStatus> status(PkiId opId, CancellationSignal cancellation) {
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        PkiId normalized = normalizeBaseOperationId(opId);
        try (OperationCoordinator.Lease ignored = coordinator.acquire(normalized)) {
            Optional<SignWorkflowStore.Record> retained = store.getSignRecord(normalized);
            if (retained.isEmpty()) {
                try {
                    SigningSubmissionId parsed = SigningSubmissionId.parse(normalized);
                    if (services.forNamespace(parsed.namespace()).isPresent()) {
                        parsed.validate(parsed.namespace(), store.signingNow(), store.signingHorizon(),
                                store.signingPermittedSkew());
                    }
                } catch (IllegalArgumentException expiredOrForeign) {
                    try {
                        SigningSubmissionId parsed = SigningSubmissionId.parse(normalized);
                        if (services.forNamespace(parsed.namespace()).isPresent()
                                && !store.signingNow().isBefore(parsed.createdAt().plus(store.signingHorizon()))) {
                            return Optional.of(new AsyncStatus(AsyncState.EXPIRED, store.signingNow(),
                                    Optional.of(EXPIRED_DETAIL_CODE), Map.of()));
                        }
                    } catch (IllegalArgumentException malformed) {
                        return Optional.empty();
                    }
                }
            }
        }
        return endpoint.status(normalized, exactCancellation);
    }

    /**
     * Performs one bounded authoritative observation of a submitted signature.
     *
     * <p>This method performs no wait and no retry. A successful observation is
     * accepted only when the durable record contains trustworthy on-time result
     * evidence. Pending state retains no runtime reservation or caller-owned
     * resource.</p>
     *
     * @param opId durable signing identifier
     * @param cancellation observation cancellation
     * @return completed, pending, or terminal-failure observation
     */
    public SigningObservation observeSigningResult(PkiId opId, CancellationSignal cancellation) {
        PkiId normalized = normalizeBaseOperationId(Objects.requireNonNull(opId, OPERATION_ID_PARAMETER));
        Optional<AsyncStatus> observed = status(normalized,
                Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER));
        if (observed.isEmpty() || !isTerminalAsyncState(observed.orElseThrow().state())) {
            return new SigningObservation.Pending(normalized);
        }
        AsyncState state = observed.orElseThrow().state();
        if (state != AsyncState.SUCCEEDED) {
            return new SigningObservation.Failed(normalized, state);
        }
        try (OperationCoordinator.Lease ignored = coordinator.acquire(normalized)) {
            Optional<EncodedObject> result = store.getSignRecord(normalized)
                    .filter(record -> record.state() == SignWorkflowStore.State.SUCCEEDED
                            || record.state() == SignWorkflowStore.State.RETIRED && record.result().isPresent())
                    .filter(PkiSigningBus::hasTrustworthyOnTimeCompletion)
                    .flatMap(SignWorkflowStore.Record::result)
                    .map(value -> new EncodedObject(value.encoding(), value.bytes()));
            return result.<SigningObservation>map(value ->
                    new SigningObservation.Completed(normalized, value))
                    .orElseGet(() -> new SigningObservation.Failed(normalized, AsyncState.FAILED));
        }
    }

    private static boolean isTerminalAsyncState(AsyncState state) {
        return state == AsyncState.SUCCEEDED || state == AsyncState.FAILED
                || state == AsyncState.CANCELLED || state == AsyncState.EXPIRED;
    }

    /** Closed result of one non-waiting signing observation. */
    public sealed interface SigningObservation permits SigningObservation.Completed,
            SigningObservation.Pending, SigningObservation.Failed {

        /**
         * Trustworthy terminal signature result.
         *
         * @param operationId exact durable signing identifier
         * @param signature defensively copied encoded signature
         */
        record Completed(PkiId operationId, EncodedObject signature) implements SigningObservation {
            /** Validates and defensively snapshots the result. */
            public Completed {
                Objects.requireNonNull(operationId, "operationId");
                EncodedObject exact = Objects.requireNonNull(signature, "signature");
                signature = new EncodedObject(exact.encoding(), exact.bytes());
            }
        }

        /**
         * Durable non-terminal operation.
         *
         * @param operationId exact durable signing identifier
         */
        record Pending(PkiId operationId) implements SigningObservation {
            /** Validates the durable identifier. */
            public Pending { Objects.requireNonNull(operationId, "operationId"); }
        }

        /**
         * Durable terminal failure.
         *
         * @param operationId exact durable signing identifier
         * @param state terminal state other than {@link AsyncState#SUCCEEDED}
         */
        record Failed(PkiId operationId, AsyncState state) implements SigningObservation {
            /** Validates the terminal failure. */
            public Failed {
                Objects.requireNonNull(operationId, "operationId");
                Objects.requireNonNull(state, "state");
                if (state == AsyncState.SUCCEEDED || !isTerminalAsyncState(state)) {
                    throw new IllegalArgumentException("Signing failure state must be terminal");
                }
            }
        }
    }

    /**
     * Reads a trustworthy on-time result if present.
     *
     * @param opId signing operation identifier
     * @return defensively copied encoded result, or empty when unavailable
     */
    public Optional<EncodedObject> consumeResult(PkiId opId) {
        return consumeResult(opId, CancellationSignal.NONE);
    }

    /**
     * Reads a trustworthy on-time result using the supplied cancellation view.
     *
     * @param opId signing operation identifier
     * @param cancellation cancellation observed while reconciling provider state
     * @return defensively copied encoded result, or empty when unavailable
     */
    public Optional<EncodedObject> consumeResult(PkiId opId,
            CancellationSignal cancellation) {
        CancellationSignal exactCancellation = Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        PkiId normalized = normalizeBaseOperationId(opId);
        endpoint.reconcileProviderStatus(normalized,
                new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE), exactCancellation),
                null, true);
        try (OperationCoordinator.Lease ignored = coordinator.acquire(normalized)) {
            return store.getSignRecord(normalized)
                    .filter(record -> record.state() == SignWorkflowStore.State.SUCCEEDED
                            || record.state() == SignWorkflowStore.State.RETIRED && record.result().isPresent())
                    .filter(PkiSigningBus::hasTrustworthyOnTimeCompletion)
                    .flatMap(SignWorkflowStore.Record::result)
                    .map(result -> new EncodedObject(result.encoding(), result.bytes()));
        }
    }

    /**
     * Polls active authoritative signing records and performs expiry maintenance.
     * Candidate failures are isolated so one provider cannot prevent other signing
     * operations from progressing.
     *
     * @param now current maintenance time; must not be {@code null}
     */
    public void sweep(Instant now) {
        Objects.requireNonNull(now, "now");
        List<SignWorkflowStore.Record> records = store.selectDueSignRecords(now, 4096);
        for (SignWorkflowStore.Record record : records) {
            if (record.state() != SignWorkflowStore.State.INTENT
                    && record.state() != SignWorkflowStore.State.DISPATCHED
                    && record.state() != SignWorkflowStore.State.CANCELLING) {
                continue;
            }
            try {
                endpoint.status(record.submissionId(), CancellationSignal.NONE);
            } catch (RuntimeException failure) {
                if (LOG.isLoggable(Level.WARNING)) {
                    LOG.log(Level.WARNING, "Signing sweep candidate failed: code={0}, exception={1}",
                            new Object[] { "SIGNING_SWEEP_CANDIDATE_FAILED", failure.getClass().getName() });
                }
            }
        }
        reconcileExpiredOperations(records);
        store.purgeExpiredSignRecords();
    }

    /**
     * Performs one bounded synchronous recovery pass. The pass scans at most the
     * requested record bound, retains only that page, and invokes the provider no
     * more than the requested call budget. Its returned cursor advances only after
     * each scanned candidate is dispositioned, including a malformed candidate;
     * prefetched candidates remain eligible for the next pass when any execution
     * budget stops processing. Every admitted pass first performs one store-bounded
     * retention purge; that maintenance is not repeated within the pass and does
     * not consume the record or provider-call budgets.
     *
     * @param request immutable pass bounds
     * @return aggregate safe pass outcome
     */
    public SigningReconciliationResult reconcile(SigningReconciliationRequest request) {
        return reconcileAdmitted(Objects.requireNonNull(request, "request"));
    }

    private SigningReconciliationResult reconcileAdmitted(SigningReconciliationRequest request) {
        if (request.cancellation().isCancelled() || !store.signingNow().isBefore(request.deadline())) {
            return new SigningReconciliationResult(request.continuation(), 0, 0, 0, 0, false);
        }
        // The server reconciliation worker is the idle-runtime maintenance
        // heartbeat. Keep retention to the store's single bounded batch so one
        // scheduled pass can never turn into an unbounded purge loop.
        store.purgeExpiredSignRecords();
        if (request.cancellation().isCancelled() || !store.signingNow().isBefore(request.deadline())) {
            return new SigningReconciliationResult(request.continuation(), 0, 0, 0, 0, false);
        }
        List<PkiId> advisorySnapshot = executionRuntime.snapshotAdvisories(request.maximumRecords());
        ReconciliationPage page;
        try {
            page = reconciliationPage(request);
        } catch (RuntimeException | Error failure) {
            executionRuntime.completeAdvisoryPass(advisorySnapshot, Set.copyOf(advisorySnapshot));
            throw failure;
        }
        return reconcilePage(request, page, reconcileAdvisories(request, advisorySnapshot));
    }

    private SigningReconciliationResult reconcilePage(SigningReconciliationRequest request,
            ReconciliationPage page, AdvisoryReconciliation advisory) {
        ReconciliationAccumulator result = new ReconciliationAccumulator(page, advisory);
        Set<PkiId> advisoryAttempted = advisory.attempted();
        for (SignWorkflowStore.PageCandidate candidate : page.candidates()) {
            if (result.exhausted(request, store.signingNow())) {
                break;
            }
            result.nextPageCandidate();
            if (candidate.record().isPresent()
                    && advisoryAttempted.contains(candidate.record().orElseThrow().submissionId())) {
                result.dispositioned(candidate.cursor(), page);
                continue;
            }
            result.examined++;
            Optional<String> previousCursor = result.nextCursor;
            result.nextCursor = Optional.of(candidate.cursor());
            if (candidate.record().isEmpty()) {
                result.unresolved++;
                result.retryable++;
                result.dispositioned(candidate.cursor(), page);
                continue;
            }
            ReconciliationStep step = reconcilePageCandidate(candidate.record().orElseThrow(), request,
                    request.maximumProviderCalls() - result.providerCalls);
            result.providerCalls += step.providerCalls();
            if (!step.dispositioned()) {
                result.nextCursor = previousCursor;
                result.unresolved++;
                result.retryable++;
                break;
            }
            result.record(step);
            result.dispositioned(candidate.cursor(), page);
        }
        return result.toResult();
    }

    private ReconciliationStep reconcilePageCandidate(SignWorkflowStore.Record candidate,
            SigningReconciliationRequest request, int remainingProviderCalls) {
        try {
            ReconciliationStep signing = reconcileRecord(candidate, request, remainingProviderCalls);
            return reconcileDomainAfterSigning(candidate, signing);
        } catch (RuntimeException localFailure) {
            return isolateCandidateFailure(candidate, new ProviderCallCounter(), localFailure);
        }
    }

    private AdvisoryReconciliation reconcileAdvisories(SigningReconciliationRequest request,
            List<PkiId> snapshot) {
        Set<PkiId> attempted = new HashSet<>();
        Set<PkiId> retained = new HashSet<>();
        int examined = 0;
        int providerCalls = 0;
        int progressed = 0;
        int unresolved = 0;
        int retryable = 0;
        int index = 0;
        PkiId active = null;
        try {
            while (index < snapshot.size() && examined < request.maximumRecords()
                    && providerCalls < request.maximumProviderCalls()
                    && !request.cancellation().isCancelled()
                    && store.signingNow().isBefore(request.deadline())) {
                active = snapshot.get(index++);
                attempted.add(active);
                examined++;
                Optional<SignWorkflowStore.Record> current = store.getSignRecord(active);
                if (current.isEmpty()) {
                    active = null;
                    continue;
                }
                ReconciliationStep step = reconcileRecord(current.orElseThrow(), request,
                        request.maximumProviderCalls() - providerCalls);
                step = reconcileDomainAfterSigning(current.orElseThrow(), step);
                providerCalls += step.providerCalls();
                progressed += step.progressed() ? 1 : 0;
                unresolved += step.unresolved() ? 1 : 0;
                retryable += step.retryable() ? 1 : 0;
                if (step.unresolved()) {
                    retained.add(active);
                }
                active = null;
            }
        } finally {
            if (active != null) {
                retained.add(active);
            }
            while (index < snapshot.size()) {
                retained.add(snapshot.get(index++));
            }
            executionRuntime.completeAdvisoryPass(snapshot, retained);
        }
        return new AdvisoryReconciliation(attempted, examined, providerCalls, progressed, unresolved, retryable);
    }

    private ReconciliationStep reconcileDomainAfterSigning(SignWorkflowStore.Record candidate,
            ReconciliationStep signing) {
        try {
            Optional<SignWorkflowStore.Record> current = store.getSignRecord(candidate.submissionId());
            if (current.flatMap(SignWorkflowStore.Record::nextEligibleAt)
                    .filter(eligible -> eligible.isAfter(store.signingNow())).isPresent()) {
                return signing;
            }
            boolean domainProgressed = reconcileDomainContinuation(candidate.submissionId());
            return domainProgressed && !signing.progressed()
                    ? new ReconciliationStep(signing.providerCalls(), true, signing.unresolved(),
                            signing.retryable(), signing.dispositioned())
                    : signing;
        } catch (RuntimeException publicationFailure) {
            ReconciliationStep deferred = isolateCandidateFailure(candidate,
                    new ProviderCallCounter(), publicationFailure);
            return new ReconciliationStep(signing.providerCalls(), signing.progressed() || deferred.progressed(),
                    true, true, deferred.dispositioned());
        }
    }

    private record AdvisoryReconciliation(Set<PkiId> attempted, int examined, int providerCalls,
            int progressed, int unresolved, int retryable) {
        private AdvisoryReconciliation {
            attempted = Set.copyOf(attempted);
        }
    }

    @SuppressWarnings("PMD.NPathComplexity")
    private ReconciliationPage reconciliationPage(SigningReconciliationRequest request) {
        CancellationSignal scanControl = () -> request.cancellation().isCancelled()
                || !store.signingNow().isBefore(request.deadline());
        SigningReconciliationContinuation continuation = request.continuation();
        Optional<String> initialCursor = continuation.cursor();
        Optional<String> highWatermark = continuation.cycleHighWatermark();
        Optional<String> wrapUpperBound = continuation.cycleWrapUpperBound();
        boolean initialWrapped = continuation.cycleWrapped();
        Instant cutoff = store.signingNow();
        SignWorkflowStore.Page first;
        try {
            Optional<String> pageUpperBound = initialWrapped ? wrapUpperBound : highWatermark;
            Optional<String> pageCursor = initialWrapped && initialCursor.isPresent()
                    && wrapUpperBound.isPresent()
                    && initialCursor.orElseThrow().compareTo(wrapUpperBound.orElseThrow()) >= 0
                            ? Optional.empty() : initialCursor;
            first = store.pageDueSignRecords(cutoff, pageCursor, pageUpperBound,
                    request.maximumRecords(), scanControl);
        } catch (IllegalArgumentException invalidAdvisoryCursor) {
            first = store.pageDueSignRecords(cutoff, Optional.empty(), Optional.empty(),
                    request.maximumRecords(), scanControl);
            initialCursor = Optional.empty();
            highWatermark = Optional.empty();
            wrapUpperBound = Optional.empty();
            initialWrapped = false;
        }
        if (highWatermark.isEmpty()) {
            highWatermark = first.highWatermark();
            wrapUpperBound = initialCursor;
            if (initialCursor.isPresent() && highWatermark.isPresent()
                    && initialCursor.orElseThrow().compareTo(highWatermark.orElseThrow()) > 0) {
                initialCursor = highWatermark;
                wrapUpperBound = highWatermark;
            }
        }
        if (highWatermark.isEmpty()) {
            return completedPage(List.of(), initialCursor);
        }
        List<SignWorkflowStore.PageCandidate> candidates = new ArrayList<>(first.candidates());
        if (!first.endReached()) {
            return new ReconciliationPage(candidates, initialCursor, highWatermark, wrapUpperBound, initialWrapped,
                    -1, -1);
        }
        if (initialWrapped || wrapUpperBound.isEmpty()) {
            return completingPage(candidates, initialCursor, highWatermark, wrapUpperBound, initialWrapped);
        }
        int wrapBoundary = candidates.size();
        int remaining = request.maximumRecords() - candidates.size();
        if (remaining == 0) {
            return new ReconciliationPage(candidates, initialCursor, highWatermark, wrapUpperBound, false,
                    wrapBoundary, -1);
        }
        SignWorkflowStore.Page wrapped = store.pageDueSignRecords(cutoff, Optional.empty(),
                wrapUpperBound, remaining, scanControl);
        Set<String> seen = new HashSet<>();
        for (SignWorkflowStore.PageCandidate candidate : candidates) {
            seen.add(candidate.cursor());
        }
        for (SignWorkflowStore.PageCandidate candidate : wrapped.candidates()) {
            if (seen.add(candidate.cursor())) {
                candidates.add(candidate);
            }
        }
        int completionBoundary = wrapped.endReached() ? candidates.size() : -1;
        boolean wrappedInitially = initialWrapped;
        if (wrapBoundary == 0) {
            wrappedInitially = true;
            wrapBoundary = -1;
        }
        if (completionBoundary == 0) {
            return completedPage(candidates, initialCursor);
        }
        return new ReconciliationPage(candidates, initialCursor, highWatermark, wrapUpperBound, wrappedInitially,
                wrapBoundary, completionBoundary);
    }

    private static ReconciliationPage completingPage(List<SignWorkflowStore.PageCandidate> candidates,
            Optional<String> initialCursor, Optional<String> highWatermark, Optional<String> wrapUpperBound,
            boolean wrapped) {
        if (candidates.isEmpty()) {
            return completedPage(candidates, initialCursor);
        }
        return new ReconciliationPage(candidates, initialCursor, highWatermark, wrapUpperBound, wrapped, -1,
                candidates.size());
    }

    private static ReconciliationPage completedPage(List<SignWorkflowStore.PageCandidate> candidates,
            Optional<String> initialCursor) {
        return new ReconciliationPage(candidates, initialCursor, Optional.empty(), Optional.empty(), false, -1, 0);
    }

    private record ReconciliationPage(List<SignWorkflowStore.PageCandidate> candidates,
            Optional<String> initialCursor, Optional<String> initialHighWatermark,
            Optional<String> initialWrapUpperBound, boolean initialWrapped, int wrapBoundary,
            int completionBoundary) {
        private ReconciliationPage {
            candidates = List.copyOf(candidates);
        }
    }

    /** Mutable counters and cursor state confined to one reconciliation pass. */
    private static final class ReconciliationAccumulator {
        private Optional<String> nextCursor;
        private Optional<String> cycleHighWatermark;
        private Optional<String> cycleWrapUpperBound;
        private boolean cycleWrapped;
        private boolean endReached;
        private int examined;
        private int progressed;
        private int unresolved;
        private int retryable;
        private int providerCalls;
        private int pagePosition;

        private ReconciliationAccumulator(ReconciliationPage page, AdvisoryReconciliation advisory) {
            nextCursor = page.initialCursor();
            cycleHighWatermark = page.initialHighWatermark();
            cycleWrapUpperBound = page.initialWrapUpperBound();
            cycleWrapped = page.initialWrapped();
            endReached = page.completionBoundary() == 0;
            examined = advisory.examined();
            progressed = advisory.progressed();
            unresolved = advisory.unresolved();
            retryable = advisory.retryable();
            providerCalls = advisory.providerCalls();
        }

        private boolean exhausted(SigningReconciliationRequest request, Instant now) {
            return examined >= request.maximumRecords() || request.cancellation().isCancelled()
                    || !now.isBefore(request.deadline()) || providerCalls >= request.maximumProviderCalls();
        }

        private void nextPageCandidate() {
            pagePosition++;
        }

        private void dispositioned(String cursor, ReconciliationPage page) {
            nextCursor = Optional.of(cursor);
            if (pagePosition == page.wrapBoundary()) {
                cycleWrapped = true;
                endReached = true;
            }
            if (pagePosition == page.completionBoundary()) {
                cycleHighWatermark = Optional.empty();
                cycleWrapUpperBound = Optional.empty();
                cycleWrapped = false;
                endReached = true;
            }
        }

        private void record(ReconciliationStep step) {
            progressed += step.progressed() ? 1 : 0;
            unresolved += step.unresolved() ? 1 : 0;
            retryable += step.retryable() ? 1 : 0;
        }

        private SigningReconciliationResult toResult() {
            SigningReconciliationContinuation continuation = new SigningReconciliationContinuation(nextCursor,
                    cycleHighWatermark, cycleWrapUpperBound, cycleWrapped);
            return new SigningReconciliationResult(continuation, examined, progressed, unresolved, retryable,
                    endReached);
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private ReconciliationStep reconcileRecord(SignWorkflowStore.Record candidate,
            SigningReconciliationRequest request, int remainingCalls) {
        ProviderCallCounter calls = new ProviderCallCounter();
        SignWorkflowStore.Record before = candidate;
        try {
            Optional<SignWorkflowStore.Record> currentOptional = store.getSignRecord(candidate.submissionId());
            if (currentOptional.isEmpty()) {
                return ReconciliationStep.RESOLVED;
            }
            before = currentOptional.orElseThrow();
            Instant now = store.signingNow();
            Optional<ReconciliationStep> configurationIsolation = isolateConfigurationMismatch(before, now);
            if (configurationIsolation.isPresent()) {
                return configurationIsolation.orElseThrow();
            }
            if (before.nextEligibleAt().filter(eligible -> eligible.isAfter(now)).isPresent()) {
                return ReconciliationStep.UNRESOLVED;
            }
            if (isTerminalSignState(before.state())) {
                return retireReconciledUnlessDomain(before);
            }
            if (remainingCalls <= 0) {
                return ReconciliationStep.UNRESOLVED;
            }
            SignatureWorkflow.CallControl control = callControl(before, request, now);
            if (before.state() == SignWorkflowStore.State.INTENT) {
                if (before.fence() == 0L) {
                    endpoint.execute(before.submissionId(), control, false, calls, null);
                } else {
                    endpoint.reconcileProviderStatus(before.submissionId(), control, calls, true);
                }
            } else {
                endpoint.reconcileProviderStatus(before.submissionId(), control, calls, false);
            }
            SignWorkflowStore.Record afterStatus = store.getSignRecord(before.submissionId()).orElse(before);
            if (afterStatus.state() == SignWorkflowStore.State.CANCELLING) {
                if (afterStatus.detailCode().filter("CANCEL_REQUESTED"::equals).isPresent()
                        && remainingCalls - calls.attempts() > 0 && callActive(request)) {
                    submitReconciliationCancellation(afterStatus,
                            callControl(afterStatus, request, store.signingNow()), calls);
                }
            }
            SignWorkflowStore.Record after = store.getSignRecord(before.submissionId()).orElse(before);
            if (isTerminalSignState(after.state())) {
                ReconciliationStep retired = retireReconciledUnlessDomain(after);
                return new ReconciliationStep(calls.attempts(), true, retired.unresolved(), retired.retryable(),
                        retired.dispositioned());
            }
            clearRetry(after);
            SignWorkflowStore.Record finalState = store.getSignRecord(before.submissionId()).orElse(after);
            return new ReconciliationStep(calls.attempts(), finalState.revision() != before.revision(), true, false,
                    true);
        } catch (RuntimeException failure) {
            if (isSchedulerUnavailable(failure)) {
                return ReconciliationStep.SCHEDULER_UNAVAILABLE;
            }
            return isolateCandidateFailure(before, calls, failure);
        }
    }

    private Optional<ReconciliationStep> isolateConfigurationMismatch(
            SignWorkflowStore.Record before, Instant now) {
        if (hasCurrentSigningConfiguration(before)) {
            return Optional.empty();
        }
        if (before.state() == SignWorkflowStore.State.EXPIRED) {
            return Optional.of(ReconciliationStep.RESOLVED);
        }
        if (!isActiveSignRecord(before)) {
            return Optional.empty();
        }
        SignWorkflowStore.Record isolated = expireConfigurationMismatch(before.submissionId(), before, now);
        boolean progressed = isolated.revision() != before.revision();
        boolean unresolved = isActiveSignRecord(isolated);
        return Optional.of(new ReconciliationStep(0, progressed, unresolved, false, true));
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private ReconciliationStep isolateCandidateFailure(SignWorkflowStore.Record fallback,
            ProviderCallCounter calls, RuntimeException failure) {
        SigningExecutionSupport.rethrowStoreWideFailure(failure);
        SignWorkflowStore.Record failed = fallback;
        try {
            failed = store.getSignRecord(fallback.submissionId()).orElse(fallback);
        } catch (RuntimeException readFailure) {
            SigningExecutionSupport.rethrowStoreWideFailure(readFailure);
        }
        boolean publishingDomain = failed.state() == SignWorkflowStore.State.SUCCEEDED
                && store.getDomainContinuation(failed.submissionId())
                        .filter(value -> value.state() == DomainContinuationStore.State.PUBLISHING)
                        .isPresent();
        if (isTerminalSignState(failed.state()) && !publishingDomain) {
            return new ReconciliationStep(calls.attempts(), false, true, true, true);
        }
        SignWorkflowStore.ReconciliationFailureClass classification = switch (failed.state()) {
            case INTENT -> SignWorkflowStore.ReconciliationFailureClass.SUBMISSION_UNCERTAIN;
            case CANCELLING -> failed.detailCode().filter("CANCEL_REQUESTED"::equals).isPresent()
                    ? SignWorkflowStore.ReconciliationFailureClass.CANCELLATION_UNCERTAIN
                    : SignWorkflowStore.ReconciliationFailureClass.STATUS_UNAVAILABLE;
            case DISPATCHED -> SignWorkflowStore.ReconciliationFailureClass.STATUS_UNAVAILABLE;
            default -> SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE;
        };
        Optional<SignWorkflowStore.Record> deferred = Optional.empty();
        try {
            deferred = store.deferSignReconciliation(failed.submissionId(), failed.revision(), failed.fence(),
                    classification);
        } catch (RuntimeException writeFailure) {
            SigningExecutionSupport.rethrowStoreWideFailure(writeFailure);
        }
        return new ReconciliationStep(calls.attempts(), deferred.isPresent(), true, true, true);
    }

    /* default */ boolean reconcileDomainContinuation(PkiId operationId) {
        Optional<DomainContinuationStore.Record> optional = store.getDomainContinuation(operationId);
        if (optional.isEmpty()) {
            return false;
        }
        DomainContinuationStore.Record domain = optional.orElseThrow();
        Optional<SignWorkflowStore.Record> signing = store.getSignRecord(operationId);
        if (signing.isEmpty()) {
            return false;
        }
        SignWorkflowStore.Record sign = signing.orElseThrow();
        if (domain.state() == DomainContinuationStore.State.COMPLETED
                || domain.state() == DomainContinuationStore.State.FAILED
                || domain.state() == DomainContinuationStore.State.EXPIRED) {
            retireCompletedDomainSigning(sign);
            return false;
        }
        if (sign.state() == SignWorkflowStore.State.EXPIRED) {
            boolean transitioned = store.transitionDomainContinuation(operationId, domain.revision(),
                    DomainContinuationStore.State.EXPIRED, Optional.empty(), Optional.of("EXPIRED")).isPresent();
            retireCompletedDomainSigning(sign);
            return transitioned;
        }
        if (sign.state() == SignWorkflowStore.State.FAILED
                || sign.state() == SignWorkflowStore.State.CANCELLED) {
            boolean transitioned = store.transitionDomainContinuation(operationId, domain.revision(),
                    DomainContinuationStore.State.FAILED, Optional.empty(),
                    Optional.of(sign.detailCode().orElse("SIGNING_FAILED"))).isPresent();
            retireCompletedDomainSigning(sign);
            return transitioned;
        }
        if (sign.state() != SignWorkflowStore.State.SUCCEEDED || !hasTrustworthyOnTimeCompletion(sign)) {
            return false;
        }
        DomainContinuationStore.Record publishing = domain;
        if (domain.state() == DomainContinuationStore.State.SIGNING) {
            Optional<DomainContinuationStore.Record> transitioned = store.transitionDomainContinuation(operationId,
                    domain.revision(), DomainContinuationStore.State.PUBLISHING,
                    Optional.empty(), Optional.empty());
            if (transitioned.isEmpty()) {
                return false;
            }
            publishing = transitioned.orElseThrow();
        }
        EncodedObject result;
        try {
            result = domainPublisher.reconstruct(publishing, sign.result().orElseThrow());
            domainPublisher.publish(publishing, result);
        } catch (DomainContinuationPublisher.PostconditionFailure publicationFailure) {
            store.transitionDomainContinuation(operationId, publishing.revision(),
                    DomainContinuationStore.State.FAILED, Optional.empty(),
                    Optional.of("POSTCONDITION_FAILED"));
            retireCompletedDomainSigning(sign);
            return true;
        }
        DomainContinuationPublisher.afterDurablePublication(
                DomainContinuationPublisher.PublicationFaultPoint.BEFORE_CONTINUATION_DONE);
        Optional<DomainContinuationStore.Record> completed = store.transitionDomainContinuation(operationId,
                publishing.revision(), DomainContinuationStore.State.COMPLETED,
                Optional.of(result), Optional.of("COMPLETED"));
        if (completed.isPresent()) {
            retireCompletedDomainSigning(sign);
        }
        return completed.isPresent();
    }

    private void retireCompletedDomainSigning(SignWorkflowStore.Record observed) {
        SignWorkflowStore.Record current = store.getSignRecord(observed.submissionId()).orElse(observed);
        if (current.state() == SignWorkflowStore.State.SUCCEEDED
                || current.state() == SignWorkflowStore.State.FAILED
                || current.state() == SignWorkflowStore.State.CANCELLED) {
            store.retireSign(current.submissionId(), current.revision(), current.fence());
            executionRuntime.completeOperation(current.submissionId());
        }
    }

    private ReconciliationStep retireReconciled(SignWorkflowStore.Record record) {
        try {
            SignWorkflowStore.Record retired = confirmRetirement(record.submissionId(), record);
            boolean contentFree = retired.state() == SignWorkflowStore.State.RETIRED
                    || retired.state() == SignWorkflowStore.State.EXPIRED;
            return new ReconciliationStep(0, contentFree, false, false, true);
        } catch (RuntimeException failure) {
            SigningExecutionSupport.rethrowStoreWideFailure(failure);
            return new ReconciliationStep(0, false, true, true, true);
        }
    }

    private ReconciliationStep retireReconciledUnlessDomain(SignWorkflowStore.Record record) {
        return store.getDomainContinuation(record.submissionId()).isPresent()
                ? ReconciliationStep.RESOLVED : retireReconciled(record);
    }

    private void clearRetry(SignWorkflowStore.Record record) {
        if (record.failureCount() > 0) {
            store.clearSignReconciliation(record.submissionId(), record.revision(), record.fence());
        }
    }

    private void submitReconciliationCancellation(SignWorkflowStore.Record record,
            SignatureWorkflow.CallControl control, ProviderCallCounter calls) {
        if (!hasCurrentSigningConfiguration(record)) {
            return;
        }
        Optional<ExternalActionCoordinator.Reservation> reservation = externalActions.tryReserve(record.submissionId(),
                ExternalAction.CANCEL);
        if (reservation.isEmpty()) {
            return;
        }
        SignatureWorkflow workflow = services.forNamespace(record.namespace()).orElseThrow().workflow();
        try (ExternalActionCoordinator.Reservation ignored = reservation.orElseThrow()) {
            providerGateway.cancel(workflow, record.submissionId(), record.fence(), "reconciliation", control,
                    calls::beforeProviderCall);
        }
        markCancellationSubmitted(record.submissionId(), record);
    }

    private SignatureWorkflow.CallControl callControl(SignWorkflowStore.Record record,
            SigningReconciliationRequest request, Instant now) {
        Instant callDeadline = now.plus(request.providerCallTimeout());
        if (callDeadline.isAfter(request.deadline())) {
            callDeadline = request.deadline();
        }
        // The original operation deadline fences every provider action. Store lookup
        // converts due active records to content-free EXPIRED before this control can
        // be used, while this bound also rejects a step queued across the deadline.
        if (callDeadline.isAfter(record.deadline())) {
            callDeadline = record.deadline();
        }
        return new SignatureWorkflow.CallControl(callDeadline, request.cancellation());
    }

    private boolean callActive(SigningReconciliationRequest request) {
        return !request.cancellation().isCancelled() && store.signingNow().isBefore(request.deadline());
    }

    private static boolean isSchedulerUnavailable(RuntimeException failure) {
        return failure instanceof SigningExecutionException executionFailure
                && executionFailure.classification() == SigningExecutionException.Classification.OVERLOADED;
    }

    private record ReconciliationStep(int providerCalls, boolean progressed, boolean unresolved,
            boolean retryable, boolean dispositioned) {
        private static final ReconciliationStep RESOLVED = new ReconciliationStep(0, false, false, false, true);
        private static final ReconciliationStep UNRESOLVED = new ReconciliationStep(0, false, true, false, true);
        private static final ReconciliationStep SCHEDULER_UNAVAILABLE =
                new ReconciliationStep(0, false, true, true, false);
    }

    /** Exact attempts made during one candidate reconciliation. */
    private static final class ProviderCallCounter {
        private int attempts;

        private void beforeProviderCall() {
            attempts++;
        }

        private int attempts() {
            return attempts;
        }
    }

    /**
     * Best-effort retirement of a sign operation and all locally owned state.
     *
     * <p>
     * Before the deadline, the operation is first reconciled with the provider. If
     * it remains active,
     * the store durably enters non-terminal
     * {@link SignWorkflowStore.State#CANCELLING} before the provider is called.
     * Regardless of whether cancellation is accepted, the provider is read again. A
     * still-running operation remains durably {@code CANCELLING} for a later retry.
     * Only an observed immutable provider terminal state is changed to
     * {@code RETIRED}, and an on-time successful result is preserved. At the
     * original deadline, an active operation instead becomes content-free
     * {@code EXPIRED} without another provider call and remains {@code EXPIRED}.
     * If physical staged-content deletion fails after {@code RETIRED} commits,
     * authoritative terminal evidence remains committed before a stable cleanup
     * failure is reported; restart recovery reclaims the resulting orphan.
     * </p>
     *
     * @param opId   operation identifier; must not be {@code null}
     * @param reason non-sensitive cancellation reason; must not be blank
     * @throws NullPointerException     if {@code opId} is {@code null}
     * @throws IllegalArgumentException if {@code reason} is {@code null} or blank
     * @throws PkiException             if locally owned cleanup fails
     */
    public void retireSignOperation(PkiId opId, String reason) {
        retireSignOperation(opId, reason, CancellationSignal.NONE);
    }

    /**
     * Retires one foreground operation using its lifecycle cancellation.
     *
     * @param opId exact signing operation identifier
     * @param reason nonblank, non-sensitive cancellation reason
     * @param cancellation cancellation observed while contacting the provider
     */
    public void retireSignOperation(PkiId opId, String reason,
            CancellationSignal cancellation) {
        retireAdmitted(opId, reason, Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER));
    }

    /**
     * Retires one operation while its synchronous caller is still registered.
     * Shutdown cancellation may leave an unresolved durable operation for later
     * recovery; no runtime registration owns that persisted workflow.
     *
     * @param opId exact signing operation identifier
     * @param reason nonblank, non-sensitive cancellation reason
     * @param foregroundCall active foreground-call registration owned by this bus
     */
    public void retireSignOperation(PkiId opId, String reason, ForegroundCall foregroundCall) {
        ForegroundCall exactCall = Objects.requireNonNull(foregroundCall, "foregroundCall");
        exactCall.requireOwner(this);
        retireAdmitted(opId, reason, CancellationSignal.NONE);
    }

    @SuppressWarnings("PMD.EmptyCatchBlock") // Provider failure deliberately yields to durable cancellation.
    private void retireAdmitted(PkiId opId, String reason, CancellationSignal exactCancellation) {
        PkiId baseOpId = normalizeBaseOperationId(opId);
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be null/blank");
        }
        try {
            endpoint.reconcileProviderStatus(baseOpId,
                    new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE), exactCancellation),
                    null, true);
        } catch (PkiException providerStatusUnavailable) {
            // Retirement still owns the durable transition to CANCELLING. The
            // provider/status failure remains retryable through reconciliation.
        }
        SignWorkflowStore.Record state;
        try (OperationCoordinator.Lease ignored = coordinator.acquire(baseOpId)) {
            Optional<SignWorkflowStore.Record> optional = store.getSignRecord(baseOpId);
            if (optional.isEmpty()) {
                executionRuntime.completeOperation(baseOpId);
                return;
            }
            state = optional.get();
        }
        if (!hasCurrentSigningConfiguration(state)
                && (isActiveSignRecord(state) || state.state() == SignWorkflowStore.State.EXPIRED)) {
            if (isActiveSignRecord(state)) {
                expireConfigurationMismatch(baseOpId, state, store.signingNow());
            }
            return;
        }
        if (!isTerminalSignState(state.state())) {
            state = cancelForRetirement(baseOpId, state, reason, exactCancellation);
            if (!isTerminalSignState(state.state())) {
                return;
            }
        }
        Throwable postCommitCleanupFailure = null;
        try (OperationCoordinator.Lease ignored = coordinator.acquire(baseOpId)) {
            state = store.getSignRecord(baseOpId).orElse(state);
            if (!isTerminalSignState(state.state())) {
                return;
            }
            try {
                confirmRetirement(baseOpId, state);
            } catch (RuntimeException | Error failure) {
                SignWorkflowStore.Record observed = store.getSignRecord(baseOpId)
                        .orElseThrow(() -> rethrowRetirementFailure(failure));
                if (observed.state() != SignWorkflowStore.State.RETIRED) {
                    throw failure;
                }
                postCommitCleanupFailure = failure;
            }
        }
        if (postCommitCleanupFailure instanceof Error error) {
            throw error;
        }
        if (postCommitCleanupFailure != null) {
            throw new PkiException(SIGNING_CONTENT_CLEANUP_FAILED);
        }
    }

    private static RuntimeException rethrowRetirementFailure(Throwable failure) {
        if (failure instanceof Error error) {
            throw error;
        }
        return (RuntimeException) failure;
    }


    private void reconcileExpiredOperations(List<SignWorkflowStore.Record> records) {
        Instant current = store.signingNow();
        for (SignWorkflowStore.Record candidate : records) {
            Optional<String> reason = SigningExecutionSupport.retirementReason(store, candidate, current);
            if (reason.isEmpty()) {
                continue;
            }
            PkiId operationId = candidate.submissionId();
            if (isActiveSignRecord(candidate) && !hasCurrentSigningConfiguration(candidate)) {
                expireConfigurationMismatch(operationId, candidate, current);
                continue;
            }
            retireAdmitted(operationId, reason.orElseThrow(),
                    CancellationSignal.NONE);
        }
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.EmptyCatchBlock" })
    private SignWorkflowStore.Record cancelForRetirement(PkiId operationId, SignWorkflowStore.Record state,
            String reason, CancellationSignal cancellation) {
        if (isLocalRecord(state) && state.state() == SignWorkflowStore.State.DISPATCHED
                && hasCurrentSigningConfiguration(state)) {
            SignatureWorkflow.CallControl control = callControl(state, store.signingNow().plus(CLAIM_LEASE),
                    cancellation);
            SignatureWorkflow workflow = services.forNamespace(state.namespace()).orElseThrow().workflow();
            try {
                providerGateway.cancel(workflow, operationId, state.fence(), reason, control, null);
            } catch (SigningExecutionException unavailable) {
                if (!isSchedulerUnavailable(unavailable)) {
                    throw unavailable;
                }
            }
            return store.getSignRecord(operationId).orElse(state);
        }
        SignWorkflowStore.Record cancelling;
        Optional<ExternalActionCoordinator.Reservation> reserved = Optional.empty();
        try (OperationCoordinator.Lease ignored = coordinator.acquire(operationId)) {
            SignWorkflowStore.Record current = store.getSignRecord(operationId).orElse(state);
            cancelling = persistCancelling(operationId, current);
            if (cancelling.state() != SignWorkflowStore.State.CANCELLING) {
                return cancelling;
            }
            if (cancelling.fence() == 0) {
                return cancelUnsubmitted(operationId, cancelling);
            }
            if (cancelling.detailCode().filter("CANCEL_SUBMITTED"::equals).isEmpty()
                    && hasCurrentSigningConfiguration(cancelling)) {
                reserved = externalActions.tryReserve(operationId, ExternalAction.CANCEL);
            }
        }
        if (!hasCurrentSigningConfiguration(cancelling)) {
            return expireConfigurationMismatch(operationId, cancelling, store.signingNow());
        }
        if (cancelling.detailCode().filter("CANCEL_SUBMITTED"::equals).isPresent()) {
            endpoint.reconcileProviderStatus(operationId,
                    new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE), cancellation),
                    null, true);
            return store.getSignRecord(operationId).orElse(cancelling);
        }
        if (reserved.isEmpty()) {
            return cancelling;
        }
        try (ExternalActionCoordinator.Reservation ignored = reserved.get()) {
            SignatureWorkflow.CallControl control = callControl(cancelling, store.signingNow().plus(CLAIM_LEASE),
                    cancellation);
            SignatureWorkflow workflow = services.forNamespace(cancelling.namespace()).orElseThrow().workflow();
            providerGateway.cancel(workflow, operationId, cancelling.fence(), reason, control, null);
        } catch (RuntimeException ex) {
            if (isSchedulerUnavailable(ex)) {
                return store.getSignRecord(operationId).orElse(cancelling);
            }
            try {
                endpoint.reconcileProviderStatus(operationId,
                        new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE), cancellation),
                        null, true);
            } catch (PkiException statusUnavailable) {
                // Authoritative CANCELLING remains retryable.
            }
            SignWorkflowStore.Record current = store.getSignRecord(operationId).orElse(cancelling);
            if (current.state() != SignWorkflowStore.State.CANCELLING) {
                return current;
            }
            throw new PkiException("Provider cancellation failed: code=PROVIDER_CANCEL_FAILED");
        }
        markCancellationSubmitted(operationId, cancelling);
        return reconcileCancellationOutcome(operationId, cancellation);
    }

    private void markCancellationSubmitted(PkiId operationId, SignWorkflowStore.Record expected) {
        try (OperationCoordinator.Lease ignored = coordinator.acquire(operationId)) {
            Optional<SignWorkflowStore.Record> currentOptional = store.getSignRecord(operationId);
            if (currentOptional.isEmpty()) {
                return;
            }
            SignWorkflowStore.Record current = currentOptional.get();
            if (current.state() == SignWorkflowStore.State.CANCELLING && current.revision() == expected.revision()
                    && current.fence() == expected.fence()) {
                store.transitionSign(operationId, current.revision(), current.fence(),
                        SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_SUBMITTED"), Optional.empty(),
                        Optional.empty());
            }
        }
    }

    private SignWorkflowStore.Record persistCancelling(PkiId operationId, SignWorkflowStore.Record initial) {
        SignWorkflowStore.Record state = initial;
        for (int attempt = 0; attempt < 4; attempt++) {
            if (state.state() == SignWorkflowStore.State.CANCELLING || isTerminalSignState(state.state())) {
                return state;
            }
            if (state.state() != SignWorkflowStore.State.INTENT
                    && state.state() != SignWorkflowStore.State.DISPATCHED) {
                throw new PkiException("Signing operation cannot enter CANCELLING from " + state.state());
            }
            Optional<SignWorkflowStore.Record> transitioned = store.transitionSign(operationId, state.revision(),
                    state.fence(), SignWorkflowStore.State.CANCELLING, Optional.of("CANCEL_REQUESTED"),
                    Optional.empty(), Optional.empty());
            if (transitioned.isPresent()) {
                return transitioned.get();
            }
            state = requireSignRecordDuringCancellation(operationId);
        }
        throw new PkiException("Unable to persist authoritative CANCELLING state");
    }

    private SignWorkflowStore.Record cancelUnsubmitted(PkiId operationId,
            SignWorkflowStore.Record cancellationRequest) {
        SignWorkflowStore.Record state = cancellationRequest;
        for (int attempt = 0; attempt < 4; attempt++) {
            if (state.state() != SignWorkflowStore.State.CANCELLING) {
                return state;
            }
            if (state.fence() != cancellationRequest.fence()) {
                return state;
            }
            Optional<SignWorkflowStore.Record> cancelled = store.transitionSign(operationId, state.revision(),
                    state.fence(), SignWorkflowStore.State.CANCELLED, Optional.of("CANCELLED"), Optional.empty(),
                    Optional.of(store.signingNow()));
            if (cancelled.isPresent()) {
                return cancelled.get();
            }
            state = requireSignRecordDuringCancellation(operationId);
        }
        throw new PkiException("Unable to confirm authoritative signing cancellation");
    }

    private SignWorkflowStore.Record reconcileCancellationOutcome(PkiId operationId,
            CancellationSignal cancellation) {
        SignWorkflowStore.Record state = requireSignRecordDuringCancellation(operationId);
        for (int attempt = 0; attempt < 4; attempt++) {
            endpoint.reconcileProviderStatus(operationId,
                    new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE), cancellation),
                    null, true);
            state = requireSignRecordDuringCancellation(operationId);
            if (state.state() != SignWorkflowStore.State.CANCELLING) {
                return state;
            }
        }
        return state;
    }

    private SignWorkflowStore.Record requireSignRecordDuringCancellation(PkiId operationId) {
        return store.getSignRecord(operationId)
                .orElseThrow(() -> new PkiException("Authoritative signing record disappeared during cancellation"));
    }

    private static boolean isTerminalSignState(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.RETIRED || state == SignWorkflowStore.State.SUCCEEDED
                || state == SignWorkflowStore.State.FAILED || state == SignWorkflowStore.State.CANCELLED
                || state == SignWorkflowStore.State.EXPIRED;
    }

    private static boolean hasTrustworthyOnTimeCompletion(SignWorkflowStore.Record record) {
        return record.providerUpdatedAt().isPresent() && record.providerUpdatedAt().get().isBefore(record.deadline());
    }

    private static SignatureWorkflow.CallControl callControl(SignWorkflowStore.Record record,
            Instant callSpecificDeadline, CancellationSignal cancellation) {
        Instant deadline = callSpecificDeadline.isAfter(record.deadline())
                ? record.deadline() : callSpecificDeadline;
        return new SignatureWorkflow.CallControl(deadline, cancellation);
    }

    private static SignatureWorkflow.CallControl submissionCallControl(SignWorkflowStore.Record record,
            Instant callSpecificDeadline, CancellationSignal cancellation) {
        Instant deadline = callSpecificDeadline.isAfter(record.deadline())
                ? record.deadline() : callSpecificDeadline;
        return new SignatureWorkflow.CallControl(deadline, cancellation);
    }

    private SignWorkflowStore.Record confirmRetirement(PkiId operationId, SignWorkflowStore.Record initial) {
        SignWorkflowStore.Record state = initial;
        for (int attempt = 0; attempt < 4 && state.state() != SignWorkflowStore.State.RETIRED
                && state.state() != SignWorkflowStore.State.EXPIRED; attempt++) {
            Optional<SignWorkflowStore.Record> retired = store.retireSign(operationId, state.revision(), state.fence());
            if (retired.isPresent()) {
                state = retired.get();
                break;
            }
            Optional<SignWorkflowStore.Record> refreshed = store.getSignRecord(operationId);
            if (refreshed.isEmpty()) {
                throw new PkiException("Authoritative signing record disappeared during retirement");
            }
            state = refreshed.get();
        }
        if (state.state() != SignWorkflowStore.State.RETIRED
                && state.state() != SignWorkflowStore.State.EXPIRED) {
            throw new PkiException("Unable to confirm authoritative signing retirement");
        }
        executionRuntime.completeOperation(operationId);
        return state;
    }

    private static PkiId normalizeBaseOperationId(PkiId opId) {
        Objects.requireNonNull(opId, OPERATION_ID_PARAMETER);
        String raw = opId.value();
        int idx = raw.indexOf('#');
        if (idx < 0) {
            return opId;
        }
        String base = raw.substring(0, idx);
        if (base.isBlank()) {
            throw new IllegalArgumentException("Invalid operationId: empty base");
        }
        return new PkiId(base);
    }

    private static int resolveDisplaySuffixMaxLen(Optional<Integer> explicit) {
        if (explicit != null && explicit.isPresent()) {
            Integer v = explicit.get();
            if (v <= 0) {
                throw new IllegalArgumentException("displaySuffixMaxLen must be positive");
            }
            return v;
        }

        String prop = System.getProperty(PROP_DISPLAY_SUFFIX_MAX_LEN);
        if (prop == null || prop.isBlank()) {
            return DEFAULT_DISPLAY_SUFFIX_MAX_LEN;
        }
        try {
            int parsed = Integer.parseInt(prop.trim());
            if (parsed <= 0) {
                throw new IllegalArgumentException(
                        "System property " + PROP_DISPLAY_SUFFIX_MAX_LEN + " must be a positive integer");
            }
            return parsed;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(
                    "System property " + PROP_DISPLAY_SUFFIX_MAX_LEN + " must be a positive integer", ex);
        }
    }

    @Override
    public void close() {
        lifecycleCloseLock.lock();
        try {
            if (busClosed) {
                return;
            }
            foregroundCalls.quiesce();
            RuntimeException attachmentFailure = null;
            try {
                if (terminalOwner != null) {
                    executionRuntime.detachTerminalOwner(terminalOwner);
                }
            } catch (RuntimeException failure) {
                attachmentFailure = failure;
            }
            try {
                headroomRegistration.close();
            } catch (RuntimeException failure) {
                attachmentFailure = appendFailure(attachmentFailure, failure);
            }
            if (!callbacksClosed) {
                try {
                    for (SignatureWorkflow.Registration registration : signerRegistrations) {
                        registration.close();
                    }
                    endpoint.closeAdvisories();
                    callbacksClosed = true;
                } catch (RuntimeException failure) {
                    attachmentFailure = appendFailure(attachmentFailure, failure);
                }
            }
            boolean drained = foregroundCalls.awaitDrained(deadlineAfter(gracefulDrain));
            if (!drained) {
                foregroundCalls.forceCancellationPhase();
                drained = foregroundCalls.awaitDrained(deadlineAfter(forcedCancellation));
            }
            if (!drained) {
                throw new SigningExecutionException(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                        "Signing bus drain timed out: code=SIGNING_SHUTDOWN_TIMEOUT");
            }
            if (terminalOwner != null) {
                try {
                    executionRuntime.awaitTerminalOwnerDrain(
                            terminalOwner, gracefulDrain, forcedCancellation);
                } catch (RuntimeException failure) {
                    if (attachmentFailure != null) {
                        failure.addSuppressed(attachmentFailure);
                    }
                    throw failure;
                }
            }
            if (closeExecutionRuntime) {
                executionRuntime.close();
            }
            if (attachmentFailure != null) {
                throw attachmentFailure;
            }
            foregroundCalls.finishClosed();
            busClosed = true;
        } finally {
            lifecycleCloseLock.unlock();
        }
    }

    private static RuntimeException appendFailure(RuntimeException current, RuntimeException addition) {
        if (current == null) {
            return addition;
        }
        current.addSuppressed(addition);
        return current;
    }

    private static long deadlineAfter(Duration duration) {
        return System.nanoTime() + duration.toNanos();
    }

    /**
     * Lifecycle-bounded per-operation critical-section coordinator.
     *
     * <p>
     * The lock protects only short local and durable-state decisions. Provider,
     * callback, listener, and provider call code must run after the lease is
     * closed. Different operation identifiers never share an entry.
     * </p>
     */
    private static final class OperationCoordinator {
        private final ConcurrentMap<PkiId, Entry> entries = new ConcurrentHashMap<>();

        private Lease acquire(PkiId operationId) {
            Entry entry = entries.compute(operationId, (ignored, current) -> {
                Entry selected = current == null ? new Entry() : current;
                selected.references.incrementAndGet();
                return selected;
            });
            entry.enter();
            return new Lease(operationId, entry);
        }

        /**
         * Thread-confined ownership handle.
         */
        private final class Lease implements AutoCloseable {
            private final PkiId operationId;
            private final Entry entry;
            private boolean closed;

            private Lease(PkiId operationId, Entry entry) {
                this.operationId = operationId;
                this.entry = entry;
            }

            @Override
            public void close() {
                if (closed) {
                    return;
                }
                closed = true;
                entry.exit();
                entries.computeIfPresent(operationId, (ignored, current) -> {
                    if (!current.equals(entry)) {
                        return current;
                    }
                    return current.references.decrementAndGet() == 0 ? null : current;
                });
            }
        }

        /**
         * Reentrant owner state for one operation identifier.
         */
        private static final class Entry {
            private final ReentrantLock lock = new ReentrantLock();
            private final AtomicInteger references = new AtomicInteger();

            private void enter() {
                lock.lock();
            }

            private void exit() {
                lock.unlock();
            }
        }
    }

    /**
     * External provider actions subject to per-operation single-flight control.
     */
    private enum ExternalAction {
        /** Provider submission. */
        SUBMIT,
        /** Provider status retrieval. */
        STATUS,
        /** Provider cancellation. */
        CANCEL
    }

    /**
     * One configured signing service: a downstream {@link SignatureWorkflow} plus
     * its derived, stable signing identity. Several services may be attached to one
     * bus so that different certification authorities route their signing to
     * different backends (local {@code zeroecho-lib} or one of several remote
     * services); a service is selected at submit time by the signing {@link KeyRef}
     * and recovered afterwards from the record's durable {@link #namespace}.
     *
     * @param serviceId       stable service identity (equals {@code workflow.id()})
     * @param workflow        downstream signature workflow
     * @param namespace       durable signing namespace ({@code store."."serviceId})
     * @param implementationId authority executor implementation id
     * @param commitment      effective configuration commitment of {@code workflow}
     * @param localAtomic     whether this service uses the local-atomic ledger fast path
     */
    private record SigningService(String serviceId, SignatureWorkflow workflow, String namespace,
            String implementationId, SignatureWorkflow.ConfigurationCommitment commitment, boolean localAtomic) {
    }

    /**
     * Maps a signing {@link KeyRef} to the identity of the service that must handle
     * it, falling back to a configured default service for unmapped keys. This is
     * the per-CA routing policy: a deployment maps each authority's issuer key to a
     * specific signing service and leaves the rest on the default service.
     */
    public static final class SigningRoutingPolicy {
        private final Map<String, String> serviceIdByKeyRef;
        private final String defaultServiceId;

        /**
         * Creates a routing policy.
         *
         * @param serviceIdByKeyRef map of signing key-reference value to service id
         * @param defaultServiceId  service id used for any unmapped key reference
         */
        public SigningRoutingPolicy(Map<String, String> serviceIdByKeyRef, String defaultServiceId) {
            this.serviceIdByKeyRef = Map.copyOf(Objects.requireNonNull(serviceIdByKeyRef, "serviceIdByKeyRef"));
            this.defaultServiceId = Objects.requireNonNull(defaultServiceId, "defaultServiceId");
        }

        /** Routes every key reference to a single service. */
        private static SigningRoutingPolicy single(String serviceId) {
            return new SigningRoutingPolicy(Map.of(), serviceId);
        }

        private String serviceIdFor(KeyRef keyRef) {
            return serviceIdByKeyRef.getOrDefault(keyRef.value(), defaultServiceId);
        }
    }

    /**
     * Immutable set of configured signing services with the routing that selects
     * one per submit and the namespace index that recovers one per persisted
     * record. A record's namespace embeds the owning service identity, so it is the
     * restart-safe routing key for status, cancellation, and reconciliation.
     */
    private static final class SigningServiceCatalog {
        private final Map<String, SigningService> byNamespace;
        private final Map<String, SigningService> byServiceId;
        private final SigningRoutingPolicy routing;
        private final String busNamespace;
        private final SigningService localService;

        private SigningServiceCatalog(List<SigningService> services, SigningRoutingPolicy routing) {
            this.routing = Objects.requireNonNull(routing, "routing");
            Map<String, SigningService> namespaces = new java.util.HashMap<>();
            Map<String, SigningService> ids = new java.util.HashMap<>();
            SigningService local = null;
            for (SigningService service : services) {
                if (ids.put(service.serviceId(), service) != null
                        || namespaces.put(service.namespace(), service) != null) {
                    throw new IllegalArgumentException("Duplicate signing service identity: " + service.serviceId());
                }
                if (service.localAtomic()) {
                    if (local != null) {
                        throw new IllegalArgumentException("At most one local-atomic signing service is supported");
                    }
                    local = service;
                }
            }
            this.byNamespace = Map.copyOf(namespaces);
            this.byServiceId = Map.copyOf(ids);
            this.localService = local;
            SigningService defaultService = ids.get(routing.defaultServiceId);
            if (defaultService == null) {
                throw new IllegalArgumentException("Default signing service is not configured: "
                        + routing.defaultServiceId);
            }
            this.busNamespace = defaultService.namespace();
        }

        private Optional<SigningService> forNamespace(String recordNamespace) {
            return Optional.ofNullable(byNamespace.get(recordNamespace));
        }

        private SigningService select(KeyRef keyRef) {
            SigningService service = byServiceId.get(routing.serviceIdFor(keyRef));
            if (service == null) {
                throw new PkiException("No signing service is configured for the routed key: code="
                        + "SIGNING_ROUTE_UNRESOLVED");
            }
            return service;
        }

        private SigningService defaultService() {
            return byServiceId.get(routing.defaultServiceId);
        }

    }

    /** The sole lane-owning boundary for calls into a signing workflow. */
    private static final class ProviderGateway {
        private final PkiStore store;
        private final SigningExecutionRuntime runtime;
        private final SigningExecutionRuntime.TerminalOwner terminalOwner;

        private ProviderGateway(PkiStore store,
                SigningExecutionRuntime runtime,
                SigningExecutionRuntime.TerminalOwner terminalOwner) {
            this.store = store;
            this.runtime = runtime;
            this.terminalOwner = terminalOwner;
        }

        private PkiId submit(X509ExecutionPlan<SignatureWorkflow> plan,
                SignatureWorkflow.SignRequest request, SignatureWorkflow.CallControl control,
                SigningExecutionRuntime.InitialStepReservation initialStep, Runnable beforeCall) {
            return invoke(request.submissionId(), control, initialStep, beforeCall,
                    laneControl -> plan.executor().submitSign(request, laneControl));
        }

        private PkiId submitAcceptedLocal(ZeroEchoLibSignatureWorkflow local,
                SignatureWorkflow.SignRequest request, zeroecho.pki.impl.fs.LocalExecutionPermit permit,
                SignatureWorkflow.CallControl control,
                SigningExecutionRuntime.InitialStepReservation initialStep) {
            CancellationSignal cancellation = control.cancellation();
            SigningExecutionRuntime.TerminalPreparation<PkiId> preparation = () -> {
                SignatureWorkflow.CallControl laneControl = new SignatureWorkflow.CallControl(
                        control.deadline(), runtime.currentCancellation(cancellation));
                laneControl.requireActive(store.signingNow());
                ZeroEchoLibSignatureWorkflow.LocalTerminalCompletion completion =
                        local.prepareAcceptedLocalSign(request, permit, laneControl);
                return new SigningExecutionRuntime.TerminalCompletion<>() {
                    @Override public PkiId commit() { return completion.commit(); }
                    @Override public PkiId acceptedResult() { return completion.acceptedResult(); }
                    @Override public void close() { completion.close(); }
                };
            };
            return runtime.executeInitialTerminalStep(
                    Objects.requireNonNull(terminalOwner, "terminalOwner"),
                    Objects.requireNonNull(initialStep, "initialStep"),
                    request.submissionId(), preparation, runtimeDeadline(control), cancellation);
        }

        private SignatureWorkflow.OperationStatus status(SignatureWorkflow workflow, PkiId operationId,
                SignatureWorkflow.CallControl control, Runnable beforeCall) {
            return invoke(operationId, control, null, beforeCall,
                    laneControl -> workflow.status(operationId, laneControl));
        }

        private void cancel(SignatureWorkflow workflow, PkiId operationId, long fence, String reason,
                SignatureWorkflow.CallControl control, Runnable beforeCall) {
            invoke(operationId, control, null, beforeCall, laneControl -> {
                workflow.cancel(operationId, fence, reason, laneControl);
                return null;
            });
        }

        private <T> T invoke(PkiId operationId, SignatureWorkflow.CallControl control,
                SigningExecutionRuntime.InitialStepReservation initialStep, Runnable beforeCall,
            ProviderInvocation<T> invocation) {
            CancellationSignal cancellation = control.cancellation();
            java.util.concurrent.Callable<T> step = () -> {
                SignatureWorkflow.CallControl laneControl = new SignatureWorkflow.CallControl(
                        control.deadline(), runtime.currentCancellation(cancellation));
                laneControl.requireActive(store.signingNow());
                if (beforeCall != null) {
                    beforeCall.run();
                }
                T result = invocation.invoke(laneControl);
                laneControl.requireActive(store.signingNow());
                return result;
            };
            Instant deadline = runtimeDeadline(control);
            return initialStep == null
                    ? runtime.executeOperationStep(operationId, step, deadline, cancellation)
                    : runtime.executeInitialStep(initialStep, operationId, step, deadline, cancellation);
        }

        private Instant runtimeDeadline(SignatureWorkflow.CallControl control) {
            Duration remaining = Duration.between(store.signingNow(), control.deadline());
            return remaining.isNegative() ? Instant.now() : Instant.now().plus(remaining);
        }

        /** Executes exactly one provider invocation using lane-combined call control. */
        @FunctionalInterface
        private interface ProviderInvocation<T> {
            /** Invokes the provider with the authoritative lane control. */
            T invoke(SignatureWorkflow.CallControl laneControl);
        }
    }

    /**
     * Lifecycle-bounded, non-blocking single-flight reservations for provider
     * calls.
     */
    private static final class ExternalActionCoordinator {
        private final ConcurrentMap<PkiId, ExternalAction> actions = new ConcurrentHashMap<>();

        private Optional<Reservation> tryReserve(PkiId operationId, ExternalAction action) {
            return actions.putIfAbsent(operationId, action) == null ? Optional.of(new Reservation(operationId, action))
                    : Optional.empty();
        }

        /**
         * Reservation that releases one external action on close.
         */
        private final class Reservation implements AutoCloseable {
            private final PkiId operationId;
            private final ExternalAction action;
            private boolean closed;

            private Reservation(PkiId operationId, ExternalAction action) {
                this.operationId = operationId;
                this.action = action;
            }

            @Override
            public void close() {
                if (!closed) {
                    closed = true;
                    actions.remove(operationId, action);
                }
            }
        }
    }

    /**
     * Async endpoint that bridges durable PKI sign orchestration to the underlying
     * {@link SignatureWorkflow}.
     *
     * <p>
     * This endpoint implements the execution boundary between the authoritative
     * signing store and the actual signer workflow. It does not eagerly start the downstream
     * signing operation at submission time. Instead, the first status poll for an
     * operation whose persisted {@link SignContinuation} does not yet contain a
     * downstream signer operation identifier triggers the signer submission and
     * advances the authoritative signing record.
     * </p>
     *
     * <p>
     * The endpoint therefore serves two purposes:
     * </p>
     * <ul>
     * <li>it materializes the downstream {@link SignatureWorkflow.SignRequest} from
     * the authoritative signing record,</li>
     * <li>it maps downstream signer status and result semantics back to generic
     * {@link AsyncStatus} and {@link EncodedObject} responses expected by the
     * signing-bus API.</li>
     * </ul>
     *
     * <h2>Persistence semantics</h2>
     * <ul>
     * <li>The canonical PKI workflow state is stored as a
     * {@link SignWorkflowStore.Record}.</li>
     * <li>The record's persisted {@link SignContinuation} initially carries the input
     * required to submit the sign operation.</li>
     * <li>The continuation binds the provider operation identifier to the
     * authoritative submission identifier before dispatch.</li>
     * </ul>
     *
     * <h2>Failure semantics</h2>
     * <ul>
     * <li>If no authoritative signing record exists for the requested operation, the endpoint
     * behaves as absent and returns an empty result from {@link #status(PkiId)} and
     * {@link #result(PkiId)}.</li>
     * <li>Malformed authoritative records fail closed at the store boundary.</li>
     * <li>Downstream signer failure is reported through the mapped async status
     * returned by {@link #status(PkiId)}.</li>
     * <li>Ambiguous downstream submission remains fenced and recovery-required in
     * the authoritative record.</li>
     * </ul>
     *
     * <h2>Thread-safety</h2>
     * <p>
     * Per-operation coordinator leases protect only short durable-state decisions.
     * An action-tagged reservation prevents concurrent provider calls for the same
     * identifier while every provider invocation runs without a coordinator lease.
     * Unrelated identifiers therefore overlap, and synchronous provider callbacks
     * can re-enter status reconciliation without deadlock. Callbacks coalesce
     * identifiers into a bounded advisory set; polling remains authoritative.
     * </p>
     */
    private static final class SignatureWorkflowEndpoint implements AsyncEndpoint<PkiId, EncodedObject> {

        private final PkiStore store;
        private final SigningServiceCatalog services;
        private final OperationCoordinator coordinator;
        private final ExternalActionCoordinator externalActions;
        private final X509AuthoritySnapshot authority;
        private final AtomicBoolean closed;
        private final SigningExecutionRuntime executionRuntime;
        private final ProviderGateway providerGateway;

        /**
         * Creates the endpoint instance.
         *
         * @param store    PKI store used to read and update authoritative signing
         *                 state; must not be {@code null}
         * @param services resolves the downstream signing service that owns each
         *                 persisted record (by namespace); must not be {@code null}
         */
        private SignatureWorkflowEndpoint(PkiStore store, SigningServiceCatalog services,
                OperationCoordinator coordinator,
                ExternalActionCoordinator externalActions, X509AuthoritySnapshot authority,
                SigningExecutionRuntime executionRuntime,
                ProviderGateway providerGateway) {
            this.store = store;
            this.services = services;
            this.coordinator = coordinator;
            this.externalActions = externalActions;
            this.authority = authority;
            this.closed = new AtomicBoolean();
            this.executionRuntime = Objects.requireNonNull(executionRuntime, "executionRuntime");
            this.providerGateway = Objects.requireNonNull(providerGateway, "providerGateway");
        }

        private boolean hasCurrentSigningConfiguration(SignWorkflowStore.Record record) {
            return services.forNamespace(record.namespace())
                    .map(service -> record.configurationCommitment().matches(service.commitment()))
                    .orElse(false);
        }

        private boolean isLocalService(SignWorkflowStore.Record record) {
            return services.forNamespace(record.namespace()).map(SigningService::localAtomic).orElse(false);
        }

        /**
         * Materializes and submits the downstream signer operation for a persisted PKI
         * sign workflow.
         *
         * <p>
         * This method reads the persisted {@link SignWorkflowStore.Record}, decodes its
         * {@link SignContinuation}, constructs a {@link SignatureWorkflow.SignRequest},
         * submits it to the configured {@link SignatureWorkflow}, and then advances
         * the authoritative fenced state.
         * </p>
         *
         * <p>
         * If no authoritative signing record exists for the supplied operation identifier, the method
         * returns without effect. This allows callers such as {@link #status(PkiId)} to
         * treat missing state as a non-existent operation rather than as an internal
         * error.
         * </p>
         *
         * <p>
         * This method submits only an initial-fence intent. A positive fence proves a
         * provider call may already have been accepted and can only be resolved by
         * authoritative provider status reconciliation.
         * </p>
         *
         * @param opId canonical PKI operation identifier; must not be {@code null}
         * @throws NullPointerException if {@code opId} is {@code null}
         * @throws PkiException         if the persisted signing state is inconsistent
         */
        public void execute(PkiId opId) {
            execute(opId, new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE),
                    CancellationSignal.NONE), true, null, null);
        }

        private void executeInitial(PkiId opId,
                SigningExecutionRuntime.InitialStepReservation initialStep,
                CancellationSignal cancellation) {
            execute(opId, new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE),
                    cancellation), false, null,
                    Objects.requireNonNull(initialStep, "initialStep"));
        }

        private boolean execute(PkiId opId, SignatureWorkflow.CallControl control, boolean pollAfterAcceptance,
                ProviderCallCounter calls,
                SigningExecutionRuntime.InitialStepReservation initialStep) {
            Objects.requireNonNull(opId, OPERATION_ID_PARAMETER);
            Objects.requireNonNull(control, "control");
            SigningExecutionRuntime.InitialStepReservation stepReservation = initialStep == null
                    ? executionRuntime.reserveInitialStep() : initialStep;
            try (stepReservation) {
                Optional<SubmissionCall> prepared = prepareSubmission(opId);
                if (prepared.isEmpty()) {
                    return false;
                }
                SubmissionCall call = prepared.get();
                SignatureWorkflow.CallControl boundedControl = submissionCallControl(call.record(),
                        control.deadline(), control.cancellation());
                PkiId returned;
                try (ExternalActionCoordinator.Reservation ignored = call.reservation()) {
                    authority.authorize(call.plan(), call.plan().executor(),
                            AlgorithmExecutionCapability.Direction.SIGN);
                    boundedControl.requireActive(store.signingNow());
                    try {
                        returned = providerGateway.submit(call.plan(), call.request(), boundedControl,
                                stepReservation, calls == null ? null : calls::beforeProviderCall);
                    } catch (SigningExecutionException unavailable) {
                        throw unavailable;
                    } catch (RuntimeException ambiguousFailure) {
                        throw new PkiException(PROVIDER_SUBMISSION_UNCERTAIN);
                    }
                }
                recordSubmissionAcceptance(call, returned);
                if (pollAfterAcceptance) {
                    reconcileProviderStatus(opId);
                }
                return true;
            }
        }

        // On success the reservation ownership moves into SubmissionCall and spans
        // the provider call; try-with-resources here would release single-flight early.
        @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
        private Optional<SubmissionCall> prepareSubmission(PkiId opId) {
            try (OperationCoordinator.Lease ignored = coordinator.acquire(opId)) {
                Optional<SignWorkflowStore.Record> currentOptional = store.getSignRecord(opId);
                if (currentOptional.isEmpty() || currentOptional.get().state() != SignWorkflowStore.State.INTENT) {
                    return Optional.empty();
                }
                SignWorkflowStore.Record current = currentOptional.get();
                if (current.fence() != INITIAL_FENCE) {
                    return Optional.empty();
                }
                if (!current.deadline().isAfter(store.signingNow())) {
                    store.transitionSign(opId, current.revision(), current.fence(), SignWorkflowStore.State.EXPIRED,
                            Optional.of(EXPIRED_DETAIL_CODE), Optional.empty(), Optional.empty());
                    return Optional.empty();
                }
                Optional<ExternalActionCoordinator.Reservation> reserved = externalActions.tryReserve(opId,
                        ExternalAction.SUBMIT);
                if (reserved.isEmpty()) {
                    return Optional.empty();
                }
                Optional<SignWorkflowStore.Record> claimedOptional = store.tryClaimSign(opId, current.revision(),
                        CLAIM_LEASE);
                if (claimedOptional.isEmpty()) {
                    reserved.get().close();
                    return Optional.empty();
                }
                SignWorkflowStore.Record claimed = claimedOptional.get();
                ExternalActionCoordinator.Reservation reservation = reserved.get();
                boolean reservationTransferred = false;
                try {
                    SignContinuation continuation = SignContinuation.decode(claimed.request(), store.stagedContent());
                    SignatureWorkflow workflow = services.forNamespace(claimed.namespace()).orElseThrow(
                            () -> new PkiException("Signing service unresolved: code=SIGNING_SERVICE_UNRESOLVED"))
                            .workflow();
                    X509ExecutionPlan<SignatureWorkflow> plan = authority.planSigning(continuation.algorithmId,
                            SigningExecutionSupport.workflowImplementationId(workflow), SignatureWorkflow.class);
                    authority.authorize(plan, workflow, AlgorithmExecutionCapability.Direction.SIGN);
                    AlgorithmIdentity persistedIdentity = plan.selection().requested();
                    if (!persistedIdentity.canonicalForm().equals(continuation.algorithmId)) {
                        throw new IllegalArgumentException("Persisted sign continuation is not canonical");
                    }
                    RepeatableContent content = openContent(continuation.content());
                    SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(opId,
                            claimed.namespace(), claimed.configurationCommitment(), claimed.fence(),
                            continuation.accessContext, continuation.keyRef, continuation.algorithmId,
                            continuation.signatureCommitment(), content,
                            Optional.of(continuation.preferredSignatureEncoding), Optional.of(claimed.deadline()));
                    if (!constantTimeAsciiEquals(claimed.fingerprint(), request.semanticFingerprint())) {
                        store.transitionSign(opId, claimed.revision(), claimed.fence(), SignWorkflowStore.State.FAILED,
                                Optional.of("REQUEST_INTEGRITY_FAILURE"), Optional.empty(), Optional.empty());
                        return Optional.empty();
                    }
                    SubmissionCall call = new SubmissionCall(claimed, request, reservation, plan);
                    reservationTransferred = true;
                    return Optional.of(call);
                } finally {
                    if (!reservationTransferred) {
                        reservation.close();
                    }
                }
            }
        }

        private RepeatableContent openContent(DurableContentReference reference) {
            try {
                return store.stagedContent().openContent(reference);
            } catch (IOException ex) {
                throw new PkiException("Signing content unavailable: code=STAGED_CONTENT_MISSING");
            }
        }

        private static boolean constantTimeAsciiEquals(String left, String right) {
            byte[] leftBytes = left.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] rightBytes = right.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            try {
                return MessageDigest.isEqual(leftBytes, rightBytes);
            } finally {
                java.util.Arrays.fill(leftBytes, (byte) 0);
                java.util.Arrays.fill(rightBytes, (byte) 0);
            }
        }

        private void recordSubmissionAcceptance(SubmissionCall call, PkiId returned) {
            if (isLocalService(call.record())) {
                return;
            }
            try (OperationCoordinator.Lease ignored = coordinator.acquire(call.record().submissionId())) {
                Optional<SignWorkflowStore.Record> afterCall = store.getSignRecord(call.record().submissionId());
                if (afterCall.isEmpty() || afterCall.get().revision() != call.record().revision()
                        || afterCall.get().fence() != call.record().fence()
                        || afterCall.get().state() != SignWorkflowStore.State.INTENT) {
                    return;
                }
                if (!call.record().submissionId().equals(returned)) {
                    store.transitionSign(call.record().submissionId(), call.record().revision(), call.record().fence(),
                            SignWorkflowStore.State.FAILED, Optional.of("PROVIDER_ID_MISMATCH"), Optional.empty(),
                            Optional.empty());
                    return;
                }
                store.transitionSign(call.record().submissionId(), call.record().revision(), call.record().fence(),
                        SignWorkflowStore.State.DISPATCHED, Optional.of("DISPATCHED"), Optional.empty(),
                        Optional.empty());
            }
        }

        private record SubmissionCall(SignWorkflowStore.Record record, SignatureWorkflow.SignRequest request,
                ExternalActionCoordinator.Reservation reservation, X509ExecutionPlan<SignatureWorkflow> plan) {
        }

        /**
         * Returns the current mapped async status of the supplied PKI sign workflow.
         *
         * <p>
         * This method is also the lazy execution trigger of the endpoint. When the
         * authoritative record remains in {@link SignWorkflowStore.State#INTENT}, the
         * first status poll calls {@link #execute(PkiId)}.
         * </p>
         *
         * <p>
         * Once a downstream signer operation exists, the returned status is derived
     * from {@link SignatureWorkflow#status(PkiId, SignatureWorkflow.CallControl)}
     * using this mapping:
         * </p>
         * <ul>
         * <li>missing or non-terminal downstream status -
         * {@link AsyncState#RUNNING},</li>
         * <li>successful downstream status carrying a valid signature result -
         * {@link AsyncState#SUCCEEDED},</li>
         * <li>all other terminal outcomes - their corresponding terminal async
         * state.</li>
         * </ul>
         *
         * <p>
         * If no authoritative signing record exists, this method returns
         * {@link Optional#empty()}.
         * </p>
         *
         * @param opId canonical PKI operation identifier; must not be {@code null}
         * @return optional containing the current mapped async status, or an empty
         *         optional when no persisted signing record exists for the supplied
         *         operation
         * @throws NullPointerException if {@code opId} is {@code null}
         * @throws PkiException         if lazy execution encounters inconsistent
         *                              persisted signing state
         */
        @Override
        public Optional<AsyncStatus> status(PkiId opId) {
            return status(opId, CancellationSignal.NONE);
        }

        private Optional<AsyncStatus> status(PkiId opId,
                CancellationSignal cancellation) {
            Objects.requireNonNull(opId, OPERATION_ID_PARAMETER);
            CancellationSignal exactCancellation =
                    Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
            Instant now = store.signingNow();
            Optional<SignWorkflowStore.Record> initial = readAndExpireInitialIntent(opId, now);
            if (initial.isEmpty()) {
                return Optional.empty();
            }
            SignWorkflowStore.Record record = initial.orElseThrow();
            if (isActiveSignRecord(record) && !hasCurrentSigningConfiguration(record)) {
                return Optional.of(mapStoreStatus(record));
            }
            try {
                boolean providerStatusReconciled = initiateOrReconcileIntent(opId, record, now, exactCancellation);
                record = reconcileActiveStatus(opId, record, providerStatusReconciled, exactCancellation);
            } catch (SigningExecutionException unavailable) {
                if (!isSchedulerUnavailable(unavailable)) {
                    throw unavailable;
                }
                record = store.getSignRecord(opId).orElse(record);
            }
            return Optional.of(mapObservedStatus(record, now));
        }

        private Optional<SignWorkflowStore.Record> readAndExpireInitialIntent(PkiId operationId, Instant now) {
            try (OperationCoordinator.Lease ignored = coordinator.acquire(operationId)) {
                Optional<SignWorkflowStore.Record> recordOptional = store.getSignRecord(operationId);
                if (recordOptional.isEmpty()) {
                    return Optional.empty();
                }
                SignWorkflowStore.Record record = recordOptional.orElseThrow();
                boolean initialUnsubmitted = record.state() == SignWorkflowStore.State.INTENT
                        && record.fence() == INITIAL_FENCE;
                boolean configurationMismatch = isActiveSignRecord(record)
                        && !hasCurrentSigningConfiguration(record);
                if (!record.deadline().isAfter(now) && (initialUnsubmitted || configurationMismatch)) {
                    store.transitionSign(operationId, record.revision(), record.fence(),
                            SignWorkflowStore.State.EXPIRED,
                            Optional.of(EXPIRED_DETAIL_CODE), Optional.empty(), Optional.empty());
                    record = store.getSignRecord(operationId).orElse(record);
                }
                return Optional.of(record);
            }
        }

        private boolean initiateOrReconcileIntent(PkiId operationId, SignWorkflowStore.Record record, Instant now,
                CancellationSignal cancellation) {
            if (record.state() != SignWorkflowStore.State.INTENT) {
                return false;
            }
            SignatureWorkflow.CallControl control = callControl(record, now.plus(CLAIM_LEASE),
                    cancellation);
            if (record.fence() == INITIAL_FENCE) {
                return record.deadline().isAfter(now) && execute(operationId, control, true, null, null);
            }
            return reconcileProviderStatus(operationId, control, null, true);
        }

        private SignWorkflowStore.Record reconcileActiveStatus(PkiId operationId,
                SignWorkflowStore.Record previous, boolean alreadyReconciled,
                CancellationSignal cancellation) {
            SignWorkflowStore.Record current = store.getSignRecord(operationId).orElse(previous);
            if (alreadyReconciled || !isProviderActive(current)) {
                return current;
            }
            reconcileProviderStatus(operationId,
                    new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE), cancellation),
                    null, true);
            return store.getSignRecord(operationId).orElse(current);
        }

        private static boolean isProviderActive(SignWorkflowStore.Record record) {
            return record.state() == SignWorkflowStore.State.DISPATCHED
                    || record.state() == SignWorkflowStore.State.CANCELLING;
        }

        private static AsyncStatus mapObservedStatus(SignWorkflowStore.Record record, Instant now) {
            if (!record.deadline().isAfter(now) && isProviderActive(record)) {
                return new AsyncStatus(AsyncState.EXPIRED, now, Optional.of(EXPIRED_DETAIL_CODE), Map.of());
            }
            return mapStoreStatus(record);
        }

        private void onProviderStatusChanged(PkiId operationId, SignatureWorkflow.OperationStatus advisory) {
            try {
                if (operationId == null || advisory == null) {
                    logInvalidAdvisory();
                    return;
                }
                if (!closed.get()) {
                    executionRuntime.advisory(operationId);
                }
            } catch (RuntimeException malformedAdvisory) {
                logInvalidAdvisory();
            }
        }

        private static void logInvalidAdvisory() {
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Provider signing advisory ignored: code=PROVIDER_ADVISORY_INVALID");
            }
        }

        // Provider implementations are an untrusted boundary and may throw any runtime
        // failure.
        private void reconcileProviderStatus(PkiId operationId) {
            reconcileProviderStatus(operationId,
                    new SignatureWorkflow.CallControl(store.signingNow().plus(CLAIM_LEASE),
                            CancellationSignal.NONE),
                    null, true);
        }

        private boolean reconcileProviderStatus(PkiId operationId, SignatureWorkflow.CallControl control,
                ProviderCallCounter calls, boolean permitUncertainIntent) {
            Optional<StatusCall> prepared = prepareStatusCall(operationId, permitUncertainIntent);
            if (prepared.isEmpty()) {
                return false;
            }
            StatusCall call = prepared.get();
            SignatureWorkflow.CallControl boundedControl = callControl(call.record(), control.deadline(),
                    control.cancellation());
            try (ExternalActionCoordinator.Reservation ignored = call.reservation()) {
                try {
                    SignatureWorkflow workflow = services.forNamespace(call.record().namespace()).orElseThrow(
                            () -> new PkiException("Signing service unresolved: code=SIGNING_SERVICE_UNRESOLVED"))
                            .workflow();
                    SignatureWorkflow.OperationStatus providerStatus = providerGateway.status(workflow, operationId,
                            boundedControl, calls == null ? null : calls::beforeProviderCall);
                    applyProviderStatus(call, providerStatus);
                } catch (SigningExecutionException unavailable) {
                    throw unavailable;
                } catch (RuntimeException providerFailure) {
                    throw new PkiException("Provider status failed: code=PROVIDER_STATUS_FAILED");
                }
            }
            return true;
        }

        private Optional<StatusCall> prepareStatusCall(PkiId operationId, boolean permitUncertainIntent) {
            try (OperationCoordinator.Lease ignored = coordinator.acquire(operationId)) {
                Optional<SignWorkflowStore.Record> beforeCall = store.getSignRecord(operationId);
                if (beforeCall.isEmpty() || beforeCall.get().state() != SignWorkflowStore.State.DISPATCHED
                        && beforeCall.get().state() != SignWorkflowStore.State.CANCELLING
                        && (!permitUncertainIntent || beforeCall.get().state() != SignWorkflowStore.State.INTENT
                                || beforeCall.get().fence() <= 0L)) {
                    return Optional.empty();
                }
                if (!hasCurrentSigningConfiguration(beforeCall.orElseThrow())) {
                    return Optional.empty();
                }
                Optional<ExternalActionCoordinator.Reservation> reserved = externalActions.tryReserve(operationId,
                        ExternalAction.STATUS);
                return reserved.map(reservation -> new StatusCall(beforeCall.get(), reservation));
            }
        }

        @SuppressWarnings("PMD.NPathComplexity")
        private void applyProviderStatus(StatusCall call, SignatureWorkflow.OperationStatus providerStatus) {
            try (OperationCoordinator.Lease ignored = coordinator.acquire(call.record().submissionId())) {
                Optional<SignWorkflowStore.Record> currentOptional = store.getSignRecord(call.record().submissionId());
                if (currentOptional.isEmpty()
                        || currentOptional.get().state() != SignWorkflowStore.State.DISPATCHED
                                && currentOptional.get().state() != SignWorkflowStore.State.CANCELLING
                                && currentOptional.get().state() != SignWorkflowStore.State.INTENT
                        || currentOptional.get().fence() != call.record().fence()) {
                    return;
                }
                SignWorkflowStore.Record current = currentOptional.get();
                if (current.state() == SignWorkflowStore.State.INTENT) {
                    Optional<SignWorkflowStore.Record> attached = store.transitionSign(current.submissionId(),
                            current.revision(), current.fence(), SignWorkflowStore.State.DISPATCHED,
                            Optional.of("DISPATCHED"), Optional.empty(), Optional.empty());
                    if (attached.isEmpty()) {
                        return;
                    }
                    current = attached.orElseThrow();
                }
                if (!providerStatus.isTerminal()) {
                    return;
                }
                if (isLocalService(current) && isTerminalSignState(current.state())) {
                    return;
                }
                Optional<EncodedObject> result = providerStatus.result()
                        .flatMap(SignatureWorkflow.OperationResult::signature);
                SignWorkflowStore.State target = mapProviderState(providerStatus.state());
                Optional<String> detail = safeProviderOutcomeCode(providerStatus.state());
                boolean validSignature = providerStatus.result().isPresent()
                        && providerStatus.result().orElseThrow().verified().isEmpty()
                        && result.filter(SignatureWorkflowEndpoint::isValidSignatureResult).isPresent();
                if (target == SignWorkflowStore.State.SUCCEEDED && !validSignature) {
                    target = SignWorkflowStore.State.FAILED;
                    detail = Optional.of("PROVIDER_RESULT_INVALID");
                    result = Optional.empty();
                }
                if (target == SignWorkflowStore.State.SUCCEEDED
                        && !providerStatus.updatedAt().isBefore(current.deadline())) {
                    target = SignWorkflowStore.State.EXPIRED;
                    detail = Optional.of("LATE_PROVIDER_SUCCESS");
                    result = Optional.empty();
                }
                store.transitionSign(call.record().submissionId(), current.revision(), current.fence(), target, detail,
                        result, Optional.of(providerStatus.updatedAt()));
            }
        }

        private record StatusCall(SignWorkflowStore.Record record, ExternalActionCoordinator.Reservation reservation) {
        }

        private void closeAdvisories() {
            closed.set(true);
        }

        /**
         * Returns the produced signature result for a successfully completed PKI sign
         * workflow.
         *
         * <p>
         * This method does not trigger lazy execution. It only attempts to resolve a
         * result for an already materialized downstream signer operation.
         * </p>
         *
         * <p>
         * The method returns an empty result in all of the following cases:
         * </p>
         * <ul>
         * <li>no persisted signing record exists for the supplied operation,</li>
         * <li>the downstream signer reports no status,</li>
         * <li>the downstream signer has not yet reached
         * {@link SignatureWorkflow.State#SUCCEEDED},</li>
         * <li>the downstream signer completed successfully but exposes no signature
         * result.</li>
         * </ul>
         *
         * @param opId canonical PKI operation identifier; must not be {@code null}
         * @return optional containing the signature as an {@link EncodedObject}, or an
         *         empty optional when no successful signature result is currently
         *         available
         * @throws NullPointerException if {@code opId} is {@code null}
         */
        @Override
        public Optional<EncodedObject> result(PkiId opId) {
            Objects.requireNonNull(opId, OPERATION_ID_PARAMETER);
            reconcileProviderStatus(opId);
            try (OperationCoordinator.Lease ignored = coordinator.acquire(opId)) {
                return store.getSignRecord(opId)
                        .filter(record -> record.state() == SignWorkflowStore.State.SUCCEEDED
                                || record.state() == SignWorkflowStore.State.RETIRED && record.result().isPresent())
                        .flatMap(SignWorkflowStore.Record::result);
            }
        }

        private static SignWorkflowStore.State mapProviderState(SignatureWorkflow.State state) {
            return switch (state) {
                case SUCCEEDED -> SignWorkflowStore.State.SUCCEEDED;
                case CANCELLED -> SignWorkflowStore.State.CANCELLED;
                case EXPIRED -> SignWorkflowStore.State.EXPIRED;
                default -> SignWorkflowStore.State.FAILED;
            };
        }

        private static boolean isValidSignatureResult(EncodedObject result) {
            if (result.encoding() != Encoding.BINARY) {
                return false;
            }
            byte[] bytes = result.bytes();
            try {
                return bytes.length > 0 && bytes.length <= MAXIMUM_SIGNATURE_BYTES;
            } finally {
                java.util.Arrays.fill(bytes, (byte) 0);
            }
        }

        private static Optional<String> safeProviderOutcomeCode(SignatureWorkflow.State state) {
            return Optional.of(switch (state) {
                case SUCCEEDED -> "SIGNED";
                case CANCELLED -> "CANCELLED";
                case EXPIRED -> EXPIRED_DETAIL_CODE;
                case FAILED -> "PROVIDER_FAILED";
                case PENDING, RUNNING, WAITING_APPROVAL -> "RUNNING";
            });
        }

        private static AsyncStatus mapStoreStatus(SignWorkflowStore.Record record) {
            AsyncState state = switch (record.state()) {
                case INTENT, DISPATCHED, CANCELLING -> AsyncState.RUNNING;
                case SUCCEEDED -> AsyncState.SUCCEEDED;
                case CANCELLED -> AsyncState.CANCELLED;
                case EXPIRED -> AsyncState.EXPIRED;
                case RETIRED -> record.result().isPresent() ? AsyncState.SUCCEEDED : AsyncState.CANCELLED;
                case FAILED -> AsyncState.FAILED;
            };
            return new AsyncStatus(state, record.createdAt(), record.detailCode(), Map.of());
        }
    }

    /**
     * Persisted continuation payload for a PKI sign operation.
     *
     * <p>
     * This value object carries the minimum workflow state required to continue or
     * re-attach a sign operation across durable orchestration boundaries. It is
     * stored inside {@link SignWorkflowStore.Record#request()} and is used by
     * {@link SignatureWorkflowEndpoint} to materialize the downstream
     * {@link SignatureWorkflow.SignRequest} lazily on first polling and to remember
     * the assigned downstream signer operation identifier afterwards.
     * </p>
     *
     * <p>
     * The continuation contains:
     * </p>
     * <ul>
     * <li>the logical access context associated with the sign request,</li>
     * <li>the requested signature algorithm identifier,</li>
     * <li>the to-be-signed payload,</li>
     * <li>the signing key reference,</li>
     * <li>the preferred output encoding of the resulting signature,</li>
     * <li>optionally the downstream signer workflow operation identifier once the
     * signer has accepted the request.</li>
     * </ul>
     *
     * <h2>Encoding model</h2>
     * <p>
     * Instances are encoded into a compact binary representation through
     * {@link #encode()} and reconstructed through
     * {@link #decode(EncodedObject, StagedContentStore)}.
     * The binary format is versioned by {@link #VERSION}. The current version
     * persists the algorithm identifier, payload encoding and bytes, key reference,
     * preferred signature encoding, and the optional downstream signer operation
     * identifier.
     * </p>
     *
     * <h2>Important limitation</h2>
     * <p>
     * The current binary encoding does not persist the original
     * {@link zeroecho.pki.api.audit.AccessContext} losslessly. During
     * {@link #decode(EncodedObject, StagedContentStore)}, a synthetic system access context is created
     * instead. This is sufficient for the current continuation flow, but callers
     * must not assume that {@code decode(encode(x))} preserves the original access
     * context exactly.
     * </p>
     *
     * <h2>Thread-safety</h2>
     * <p>
     * Instances of this class are immutable and therefore thread-safe.
     * </p>
     */
    public static final class SignContinuation {

        private static final byte VERSION = 4;
        private static final long MINIMUM_CONTENT_LENGTH = 0L;

        private final zeroecho.pki.api.audit.AccessContext accessContext;
        private final String algorithmId;
        private final Optional<DurableContentReference> content;
        private final ContentCommitment commitment;
        private final KeyRef keyRef;
        private final Encoding preferredSignatureEncoding;
        private final Optional<PkiId> signerOpId;

        /**
         * Creates a continuation payload for a sign operation.
         *
         * @param accessContext              logical access context associated with the
         *                                   sign request; must not be {@code null}
         * @param algorithmId                non-blank signature algorithm identifier;
         *                                   must not be {@code null} or blank
         * @param content                    durable to-be-signed content reference
         *                                   {@code null}
         * @param keyRef                     signing key reference; must not be
         *                                   {@code null}
         * @param preferredSignatureEncoding preferred encoding of the resulting
         *                                   signature; must not be {@code null}
         * @param signerOpId                 optional downstream signer workflow
         *                                   operation identifier; must not be
         *                                   {@code null}
         * @throws NullPointerException     if any argument is {@code null}
         * @throws IllegalArgumentException if {@code algorithmId} is blank
         */
        public SignContinuation(zeroecho.pki.api.audit.AccessContext accessContext, String algorithmId,
                DurableContentReference content, KeyRef keyRef, Encoding preferredSignatureEncoding,
                Optional<PkiId> signerOpId) {
            this.accessContext = Objects.requireNonNull(accessContext, "accessContext");
            this.algorithmId = Objects.requireNonNull(algorithmId, "algorithmId");
            DurableContentReference exactContent = Objects.requireNonNull(content, CONTENT_PARAMETER);
            this.content = Optional.of(exactContent);
            this.commitment = ContentCommitment.of(exactContent);
            this.keyRef = Objects.requireNonNull(keyRef, KEY_REF_PARAMETER);
            this.preferredSignatureEncoding = Objects.requireNonNull(preferredSignatureEncoding,
                    "preferredSignatureEncoding");
            this.signerOpId = Objects.requireNonNull(signerOpId, "signerOpId");
            if (algorithmId.isBlank()) {
                throw new IllegalArgumentException("algorithmId must not be blank");
            }
        }

        private SignContinuation(zeroecho.pki.api.audit.AccessContext accessContext, String algorithmId,
                Optional<DurableContentReference> content, ContentCommitment commitment, KeyRef keyRef,
                Encoding preferredSignatureEncoding, Optional<PkiId> signerOpId) {
            this.accessContext = Objects.requireNonNull(accessContext, "accessContext");
            this.algorithmId = Objects.requireNonNull(algorithmId, "algorithmId");
            this.content = Objects.requireNonNull(content, CONTENT_PARAMETER);
            this.commitment = Objects.requireNonNull(commitment, "commitment");
            this.keyRef = Objects.requireNonNull(keyRef, KEY_REF_PARAMETER);
            this.preferredSignatureEncoding = Objects.requireNonNull(preferredSignatureEncoding,
                    "preferredSignatureEncoding");
            this.signerOpId = Objects.requireNonNull(signerOpId, "signerOpId");
            if (algorithmId.isBlank() || content.isPresent() && !commitment.matches(content.get())) {
                throw new IllegalArgumentException("Invalid sign continuation content commitment");
            }
        }

        /**
         * Returns a new continuation with the downstream signer workflow operation
         * identifier assigned.
         *
         * <p>
         * This method does not mutate the current instance. It creates a new immutable
         * continuation carrying all existing fields plus the supplied signer operation
         * identifier.
         * </p>
         *
         * @param opId downstream signer workflow operation identifier; must not be
         *             {@code null}
         * @return new continuation instance containing the supplied signer workflow
         *         operation identifier
         * @throws NullPointerException if {@code opId} is {@code null}
         */
        public SignContinuation withSignerOpId(PkiId opId) {
            return new SignContinuation(accessContext, algorithmId, content, commitment, keyRef,
                    preferredSignatureEncoding, Optional.of(opId));
        }

        private SignContinuation withAlgorithmId(String canonicalAlgorithmId) {
            return new SignContinuation(accessContext, canonicalAlgorithmId, content, commitment, keyRef,
                    preferredSignatureEncoding, signerOpId);
        }

        /**
         * Returns a terminal continuation retaining only immutable content commitment metadata.
         *
         * @return an immutable continuation with no live staged-content reference
         */
        public SignContinuation withoutLiveContent() {
            return new SignContinuation(accessContext, algorithmId, Optional.empty(), commitment, keyRef,
                    preferredSignatureEncoding, signerOpId);
        }

        /**
         * Returns the downstream signer workflow operation identifier when it has
         * already been assigned.
         *
         * <p>
         * The value is absent for continuations representing a sign operation that has
         * been accepted by the PKI orchestration layer but has not yet been submitted
         * to the downstream {@link SignatureWorkflow}.
         * </p>
         *
         * @return optional downstream signer workflow operation identifier
         */
        public Optional<PkiId> signerOpId() {
            return signerOpId;
        }

        /**
         * Returns the payload-free durable reference used for recovery.
         *
         * @return staged content reference; never a live handle or payload
         */
        public DurableContentReference content() {
            return content.orElseThrow(() -> new IllegalStateException("Retired continuation has no live content"));
        }

        /**
         * Returns whether this continuation still requires live staged content.
         *
         * @return {@code true} when {@link #content()} remains available
         */
        public boolean hasLiveContent() {
            return content.isPresent();
        }

        /**
         * Restores the committed reference through its owning store for delayed cleanup.
         *
         * @param stagedContent owning staged-content store used when the live reference was retired
         * @return the live or restored durable content reference
         * @throws IOException if the owning store cannot restore the committed reference
         */
        public DurableContentReference restoreContent(zeroecho.pki.spi.store.StagedContentStore stagedContent)
                throws IOException {
            Objects.requireNonNull(stagedContent, "stagedContent");
            if (content.isPresent()) {
                return content.get();
            }
            return stagedContent.restoreReference(commitment.storeId(), commitment.contentId(), commitment.encoding(),
                    commitment.length(), commitment.sha256(), commitment.lifecycle());
        }

        /**
         * Computes the canonical semantic fingerprint for this persisted request.
         *
         * <p>
         * The calculation delegates to the same versioned algorithm used by
         * {@link SignatureWorkflow.SignRequest}. It does not include the mutable
         * fencing token.
         * </p>
         *
         * @param configurationCommitment exact workflow configuration commitment
         * @param namespace authoritative provider/store namespace; must not be
         *                  {@code null}
         * @param deadline  authoritative signing deadline; must not be {@code null}
         * @return canonical versioned semantic fingerprint
         * @throws NullPointerException if either argument is {@code null}
         */
        public String semanticFingerprint(SignatureWorkflow.ConfigurationCommitment configurationCommitment,
                String namespace, Instant deadline) {
            Objects.requireNonNull(deadline, "deadline");
            return SignatureWorkflow.SignRequest.fingerprint(configurationCommitment, namespace, accessContext,
                    keyRef, algorithmId, signatureCommitment(),
                    Optional.of(preferredSignatureEncoding), Optional.of(deadline));
        }

        private SignatureWorkflow.ContentCommitment signatureCommitment() {
            return new SignatureWorkflow.ContentCommitment(SignatureWorkflow.ContentCommitment.SHA256_V1,
                    commitment.length(), commitment.sha256());
        }

        /**
         * Tests whether this continuation is bound to the durable operation identity.
         *
         * @param submissionId authoritative submission identifier; must not be
         *                     {@code null}
         * @param owner        authoritative request owner; must not be {@code null}
         * @return {@code true} only when the stored provider operation identifier and
         *         access principal exactly match the supplied identity
         * @throws NullPointerException if either argument is {@code null}
         */
        public boolean isBoundTo(PkiId submissionId, Principal owner) {
            Objects.requireNonNull(submissionId, "submissionId");
            Objects.requireNonNull(owner, "owner");
            return owner.equals(accessContext.principal()) && signerOpId.filter(submissionId::equals).isPresent();
        }

        /**
         * Encodes this continuation into a versioned binary payload suitable for
         * persistence inside a {@link SignWorkflowStore.Record}.
         *
         * <p>
         * The returned {@link EncodedObject} always uses {@link Encoding#BINARY}. The
         * current binary layout stores:
         * </p>
         * <ul>
         * <li>format version,</li>
         * <li>algorithm identifier,</li>
         * <li>store-issued staged-content reference metadata,</li>
         * <li>key reference,</li>
         * <li>preferred signature encoding,</li>
         * <li>presence marker and optional downstream signer workflow operation
         * identifier.</li>
         * </ul>
         *
         * <p>
         * The original {@link zeroecho.pki.api.audit.AccessContext} is not serialized
         * by the current format.
         * </p>
         *
         * @return binary encoded continuation payload
         */
        public EncodedObject encode() {
            WipeableByteArrayOutputStream bytes = new WipeableByteArrayOutputStream();
            byte[] encoded = null;
            try {
                try (java.io.DataOutputStream output = new java.io.DataOutputStream(bytes)) {
                    output.writeByte(VERSION);
                    output.writeUTF(accessContext.principal().type());
                    output.writeUTF(accessContext.principal().name());
                    output.writeUTF(accessContext.purpose().value());
                    output.writeBoolean(accessContext.objectId().isPresent());
                    if (accessContext.objectId().isPresent()) {
                        output.writeUTF(accessContext.objectId().get().value());
                    }
                    output.writeBoolean(accessContext.formatId().isPresent());
                    if (accessContext.formatId().isPresent()) {
                        output.writeUTF(accessContext.formatId().get().value());
                    }
                    output.writeUTF(algorithmId);
                    output.writeUTF(keyRef.value());
                    output.writeBoolean(content.isPresent());
                    output.writeUTF(commitment.storeId());
                    output.writeUTF(commitment.contentId());
                    output.writeByte(commitment.encoding().ordinal());
                    output.writeLong(commitment.length());
                    output.writeUTF(commitment.sha256());
                    output.writeByte(commitment.lifecycle().ordinal());
                    output.writeByte(preferredSignatureEncoding.ordinal());
                    output.writeBoolean(signerOpId.isPresent());
                    if (signerOpId.isPresent()) {
                        output.writeUTF(signerOpId.get().value());
                    }
                }
                encoded = bytes.toByteArray();
                return new EncodedObject(Encoding.BINARY, encoded);
            } catch (IOException ex) {
                throw new PkiException("Failed to encode sign continuation: code=CONTINUATION_ENCODE_FAILED");
            } finally {
                if (encoded != null) {
                    java.util.Arrays.fill(encoded, (byte) 0);
                }
                bytes.wipe();
            }
        }

        /**
         * Decodes a binary continuation payload previously produced by
         * {@link #encode()}.
         *
         * <p>
         * The supplied object must use {@link Encoding#BINARY} and must carry a
         * supported continuation format version. The current implementation restores
         * the persisted algorithm identifier, payload, key reference, preferred
         * signature encoding, and optional downstream signer workflow operation
         * identifier.
         * </p>
         *
         * <p>
         * Because the current binary format does not serialize the original
         * {@link zeroecho.pki.api.audit.AccessContext}, this method reconstructs a
         * synthetic system access context with principal {@code SYSTEM/pki} and purpose
         * {@code SIGN}. The decoded continuation is therefore operationally usable for
         * the current workflow logic, but it is not a lossless reconstruction of the
         * original object graph.
         * </p>
         *
         * @param obj binary encoded continuation payload; must not be {@code null}
         * @param stagedContent owning store used to restore and validate the persisted
         *        content reference
         * @return decoded continuation instance
         * @throws NullPointerException     if {@code obj} is {@code null}
         * @throws IllegalArgumentException if {@code obj} does not use
         *                                  {@link Encoding#BINARY}, if the embedded
         *                                  format version is not supported, or if the
         *                                  binary payload is malformed
         */
        public static SignContinuation decode(EncodedObject obj,
                zeroecho.pki.spi.store.StagedContentStore stagedContent) {
            Objects.requireNonNull(obj, "obj");
            Objects.requireNonNull(stagedContent, "stagedContent");
            if (obj.encoding() != Encoding.BINARY) {
                throw new IllegalArgumentException("Expected BINARY continuation payload");
            }
            byte[] encoded = obj.bytes();
            try (java.io.DataInputStream input = new java.io.DataInputStream(
                    new java.io.ByteArrayInputStream(encoded))) {
                int version = input.readUnsignedByte();
                if (version != VERSION) {
                    throw new PkiException("Unsupported sign continuation version");
                }
                Principal principal = new Principal(input.readUTF(), input.readUTF());
                zeroecho.pki.api.audit.Purpose purpose = new zeroecho.pki.api.audit.Purpose(input.readUTF());
                Optional<PkiId> objectId = input.readBoolean() ? Optional.of(new PkiId(input.readUTF()))
                        : Optional.empty();
                Optional<FormatId> formatId = input.readBoolean()
                        ? Optional.of(new FormatId(input.readUTF()))
                        : Optional.empty();
                String algId = input.readUTF();
                KeyRef key = new KeyRef(input.readUTF());
                boolean liveContent = input.readBoolean();
                String storeId = input.readUTF();
                String contentId = input.readUTF();
                Encoding contentEncoding = Encoding.values()[input.readUnsignedByte()];
                long contentLength = input.readLong();
                String sha256 = input.readUTF();
                DurableContentReference.Lifecycle lifecycle = DurableContentReference.Lifecycle
                        .values()[input.readUnsignedByte()];
                ContentCommitment commitment = new ContentCommitment(storeId, contentId, contentEncoding,
                        contentLength, sha256, lifecycle);
                Optional<DurableContentReference> content = liveContent
                        ? Optional.of(stagedContent.restoreReference(storeId, contentId, contentEncoding,
                                contentLength, sha256, lifecycle))
                        : Optional.empty();
                Encoding preferred = Encoding.values()[input.readUnsignedByte()];
                Optional<PkiId> signerId = input.readBoolean() ? Optional.of(new PkiId(input.readUTF()))
                        : Optional.empty();
                requireCompleteInput(input);
                zeroecho.pki.api.audit.AccessContext access = new zeroecho.pki.api.audit.AccessContext(principal,
                        purpose, objectId, formatId);
                return new SignContinuation(access, algId, content, commitment, key, preferred, signerId);
            } catch (IOException | IndexOutOfBoundsException ex) {
                throw new PkiException("Malformed sign continuation: code=CONTINUATION_MALFORMED");
            } finally {
                java.util.Arrays.fill(encoded, (byte) 0);
            }
        }

        private record ContentCommitment(String storeId, String contentId, Encoding encoding, long length,
                String sha256, DurableContentReference.Lifecycle lifecycle) {
            private ContentCommitment {
                Objects.requireNonNull(storeId, "storeId");
                Objects.requireNonNull(contentId, "contentId");
                Objects.requireNonNull(encoding, "encoding");
                Objects.requireNonNull(sha256, "sha256");
                Objects.requireNonNull(lifecycle, "lifecycle");
                if (length < MINIMUM_CONTENT_LENGTH) {
                    throw new IllegalArgumentException("Content length must not be negative");
                }
            }

            private static ContentCommitment of(DurableContentReference reference) {
                return new ContentCommitment(reference.storeId(), reference.contentId(), reference.encoding(),
                        reference.length(), reference.sha256(), reference.lifecycle());
            }

            private boolean matches(DurableContentReference reference) {
                return storeId.equals(reference.storeId()) && contentId.equals(reference.contentId())
                        && encoding == reference.encoding() && length == reference.length()
                        && sha256.equals(reference.sha256()) && lifecycle == reference.lifecycle();
            }
        }

        private static void requireCompleteInput(java.io.DataInputStream input) throws IOException {
            if (input.read() >= 0) {
                throw new IOException("Trailing sign continuation data");
            }
        }

        /**
         * Output stream whose retained continuation bytes can be overwritten.
         */
        private static final class WipeableByteArrayOutputStream extends java.io.ByteArrayOutputStream {
            private void wipe() {
                java.util.Arrays.fill(buf, (byte) 0);
                reset();
            }
        }
    }
}
