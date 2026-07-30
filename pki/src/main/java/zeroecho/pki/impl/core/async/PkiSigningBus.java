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

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.orch.OrchestrationDurabilityPolicy;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.util.async.AsyncEndpoint;
import zeroecho.pki.util.async.AsyncState;
import zeroecho.pki.util.async.AsyncStatus;
import zeroecho.pki.util.async.impl.AppendOnlyLineStore;
import zeroecho.pki.util.async.impl.DurableAsyncBus;

/**
 * PKI signing bus that orchestrates asynchronous signature operations.
 *
 * <p>
 * The bus persists operation metadata and status transitions to a line-based
 * store and persists workflow continuation state to {@link PkiStore}.
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
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity", "PMD.PreserveStackTrace" })
public final class PkiSigningBus implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(PkiSigningBus.class.getName());

    /**
     * Operation type for signing.
     */
    public static final String TYPE_SIGN = "PKI.SIGN";

    private static final String ENDPOINT_SIGNER = "signer";
    private static final Duration CLAIM_LEASE = Duration.ofSeconds(30);
    private static final long INITIAL_FENCE = 0L;

    /**
     * System property controlling the maximum number of characters appended after
     * {@code '#'} in the display operation identifier.
     */
    public static final String PROP_DISPLAY_SUFFIX_MAX_LEN = "zeroecho.pki.opid.displaySuffixMaxLen";

    /**
     * Default maximum length of the display suffix.
     */
    public static final int DEFAULT_DISPLAY_SUFFIX_MAX_LEN = 64;

    private final PkiStore store;
    private final DurableAsyncBus<PkiId, Principal, String, EncodedObject> bus;
    private final SignatureWorkflow signer;
    private final SecureRandom random;
    private final String namespace;
    private final OperationCoordinator coordinator;
    private final ExternalActionCoordinator externalActions;
    private final SignatureWorkflowEndpoint endpoint;
    private final SignatureWorkflow.Registration signerRegistration;

    private final OrchestrationDurabilityPolicy durabilityPolicy;

    /**
     * Creates a signing bus.
     *
     * @param store                persistent store (source of truth for
     *                             continuation state)
     * @param signer               signature workflow
     * @param durableLineStorePath path to append-only line store file
     */
    public PkiSigningBus(PkiStore store, SignatureWorkflow signer, Path durableLineStorePath) {
        this(store, signer, durableLineStorePath, resolveDisplaySuffixMaxLen(Optional.empty()),
                OrchestrationDurabilityPolicy.DURABLE_MIN_STATE);
    }

    /**
     * Creates a signing bus.
     *
     * <p>
     * The {@code displaySuffixMaxLen} parameter controls the maximum number of
     * characters appended after {@code '#'} in operation identifiers returned by
     * {@link #canonicalizeOperationId(PkiId, Principal)}. If
     * {@code displaySuffixMaxLen} is not positive, the constructor fails.
     * </p>
     *
     * @param store                persistent store (source of truth for
     *                             continuation state)
     * @param signer               signature workflow
     * @param durableLineStorePath path to append-only line store file
     * @param displaySuffixMaxLen  maximum number of characters after {@code '#'}
     */
    public PkiSigningBus(PkiStore store, SignatureWorkflow signer, Path durableLineStorePath, int displaySuffixMaxLen) {
        this(store, signer, durableLineStorePath, displaySuffixMaxLen, OrchestrationDurabilityPolicy.DURABLE_MIN_STATE);
    }

    /**
     * Creates a signing bus with explicit workflow continuation durability policy.
     *
     * @param store                persistent store (source of truth for
     *                             continuation state)
     * @param signer               signature workflow
     * @param durableLineStorePath path to append-only line store file
     * @param displaySuffixMaxLen  maximum number of characters after {@code '#'}
     * @param durabilityPolicy     durability policy used when persisting workflow
     *                             state
     */
    public PkiSigningBus(PkiStore store, SignatureWorkflow signer, Path durableLineStorePath, int displaySuffixMaxLen,
            OrchestrationDurabilityPolicy durabilityPolicy) {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(signer, "signer");
        Objects.requireNonNull(durableLineStorePath, "durableLineStorePath");
        Objects.requireNonNull(durabilityPolicy, "durabilityPolicy");

        this.store = store;
        this.signer = signer;
        this.random = new SecureRandom();
        this.namespace = store.signingNamespace() + "." + signer.id();
        signer.validateSigningDomain(this.namespace, store.signingHorizon(), store.signingPermittedSkew());
        this.coordinator = new OperationCoordinator();
        this.externalActions = new ExternalActionCoordinator();
        resolveDisplaySuffixMaxLen(Optional.of(displaySuffixMaxLen));
        this.durabilityPolicy = durabilityPolicy;

        AppendOnlyLineStore ls = new AppendOnlyLineStore(durableLineStorePath);
        this.bus = new DurableAsyncBus<>(new PkiAsyncCodecs.PkiIdCodec(), new PkiAsyncCodecs.PrincipalCodec(),
                new PkiAsyncCodecs.StringIdCodec(), new PkiAsyncCodecs.EncodedObjectResultCodec(true), ls);

        for (WorkflowStateRecord state : store.listWorkflowStates()) {
            if (TYPE_SIGN.equals(state.type()) && state.payload().isPresent()) {
                try {
                    SignContinuation.decode(state.payload().orElseThrow());
                } catch (RuntimeException ex) { // NOPMD - malformed persisted state must fail closed
                    throw new PkiException("Invalid persisted sign continuation: code=CONTINUATION_INVALID");
                }
            }
        }
        this.endpoint = new SignatureWorkflowEndpoint(store, signer, coordinator, externalActions);
        this.bus.registerEndpoint(ENDPOINT_SIGNER, endpoint);
        this.signerRegistration = signer.register(endpoint::onProviderStatusChanged);
        for (SignWorkflowStore.Record record : store.listSignRecords()) {
            if (record.state() == SignWorkflowStore.State.INTENT || record.state() == SignWorkflowStore.State.DISPATCHED
                    || record.state() == SignWorkflowStore.State.CANCELLING) {
                project(record);
            }
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
     * Creates a stable provider-namespaced signing submission identifier.
     *
     * @return new stable identifier
     */
    public PkiId newSubmissionId() {
        return SigningSubmissionId.create(namespace, store.signingNow(), random).id();
    }

    /**
     * Submits a sign operation.
     *
     * @param opId            operation id (may include display suffix after '#')
     * @param owner           owner principal
     * @param keyRef          signing key reference
     * @param algorithmId     signature algorithm id
     * @param payload         bytes to sign
     * @param ttl             time-to-live
     * @param workflowPayload minimal continuation payload
     */
    public void submitSign(PkiId opId, Principal owner, KeyRef keyRef, String algorithmId, EncodedObject payload,
            Duration ttl, Optional<EncodedObject> workflowPayload) {

        Objects.requireNonNull(opId, "opId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(keyRef, "keyRef");
        Objects.requireNonNull(algorithmId, "algorithmId");
        Objects.requireNonNull(payload, "payload");
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
        PkiId baseOpId = normalizeBaseOperationId(opId);
        SignWorkflowStore.Record authoritative;
        try (OperationCoordinator.Lease ignored = coordinator.acquire(baseOpId)) {
            SigningSubmissionId parsed = SigningSubmissionId.parse(baseOpId);
            Instant deadline = parsed.createdAt().plus(ttl);
            SignContinuation continuation = SignContinuation.decode(workflowPayload.get());
            if (!owner.equals(continuation.accessContext.principal()) || !keyRef.equals(continuation.keyRef)
                    || !algorithmId.equals(continuation.algorithmId)
                    || payload.encoding() != continuation.payload.encoding()
                    || !java.util.Arrays.equals(payload.bytes(), continuation.payload.bytes())) {
                throw new IllegalArgumentException("Sign continuation does not match the submitted request");
            }
            String fingerprint = continuation.semanticFingerprint(namespace, deadline);
            EncodedObject persistedRequest = continuation.withSignerOpId(baseOpId).encode();
            SignWorkflowStore.Record intent = new SignWorkflowStore.Record(baseOpId, namespace, fingerprint, owner,
                    parsed.createdAt(), deadline, persistedRequest, SignWorkflowStore.State.INTENT, 0L, 0L,
                    Optional.empty(), Optional.of("INTENT"), Optional.empty(), Optional.empty());
            SignWorkflowStore.CreateResult created = store.createSignIntent(intent);
            if (created == SignWorkflowStore.CreateResult.CONFLICT) {
                throw new PkiException("Signing submission identifier conflicts with a different request");
            }
            authoritative = store.getSignRecord(baseOpId).orElseThrow();
        }
        project(authoritative);
    }

    /**
     * Returns current status if known.
     */
    public Optional<AsyncStatus> status(PkiId opId) {
        PkiId normalized = normalizeBaseOperationId(opId);
        try (OperationCoordinator.Lease ignored = coordinator.acquire(normalized)) {
            Optional<SignWorkflowStore.Record> retained = store.getSignRecord(normalized);
            if (retained.isEmpty()) {
                try {
                    SigningSubmissionId parsed = SigningSubmissionId.parse(normalized);
                    parsed.validate(namespace, store.signingNow(), store.signingHorizon(),
                            store.signingPermittedSkew());
                } catch (IllegalArgumentException expiredOrForeign) {
                    try {
                        SigningSubmissionId parsed = SigningSubmissionId.parse(normalized);
                        if (namespace.equals(parsed.namespace())
                                && !store.signingNow().isBefore(parsed.createdAt().plus(store.signingHorizon()))) {
                            return Optional.of(new AsyncStatus(AsyncState.EXPIRED, store.signingNow(),
                                    Optional.of("EXPIRED"), Map.of()));
                        }
                    } catch (IllegalArgumentException malformed) {
                        return Optional.empty();
                    }
                }
            }
        }
        return endpoint.status(normalized);
    }

    /**
     * Consumes result if present.
     */
    public Optional<EncodedObject> consumeResult(PkiId opId) {
        PkiId normalized = normalizeBaseOperationId(opId);
        endpoint.reconcileProviderStatus(normalized);
        try (OperationCoordinator.Lease ignored = coordinator.acquire(normalized)) {
            return store.getSignRecord(normalized)
                    .filter(record -> record.state() == SignWorkflowStore.State.SUCCEEDED
                            || record.state() == SignWorkflowStore.State.RETIRED && record.result().isPresent())
                    .filter(PkiSigningBus::hasTrustworthyOnTimeCompletion).flatMap(SignWorkflowStore.Record::result)
                    .map(result -> new EncodedObject(result.encoding(), result.bytes()));
        }
    }

    /**
     * Sweeps the durable bus.
     */
    public void sweep(Instant now) {
        bus.sweep(now);
        reconcileExpiredOperations();
        store.purgeExpiredSignRecords();
    }

    /**
     * Deletes workflow continuation state once finished.
     */
    public void deleteWorkflowState(PkiId opId) {
        PkiId normalized = normalizeBaseOperationId(opId);
        try (OperationCoordinator.Lease ignored = coordinator.acquire(normalized)) {
            store.deleteWorkflowState(normalized);
        }
    }

    /**
     * Best-effort retirement of a sign operation and all locally owned state.
     *
     * <p>
     * The operation is first reconciled with the provider. If it remains active,
     * the store durably enters non-terminal
     * {@link SignWorkflowStore.State#CANCELLING} before the provider is called.
     * Regardless of whether cancellation is accepted, the provider is read again. A
     * still-running operation remains durably {@code CANCELLING} for a later retry.
     * Only an observed immutable provider terminal state is changed to
     * {@code RETIRED}, and an on-time successful result is preserved.
     * </p>
     *
     * @param opId   operation identifier; must not be {@code null}
     * @param reason non-sensitive cancellation reason; must not be blank
     * @throws NullPointerException     if {@code opId} is {@code null}
     * @throws IllegalArgumentException if {@code reason} is {@code null} or blank
     * @throws PkiException             if locally owned cleanup fails
     */
    public void retireSignOperation(PkiId opId, String reason) {
        PkiId baseOpId = normalizeBaseOperationId(opId);
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be null/blank");
        }
        endpoint.reconcileProviderStatus(baseOpId);
        SignWorkflowStore.Record state;
        try (OperationCoordinator.Lease ignored = coordinator.acquire(baseOpId)) {
            Optional<SignWorkflowStore.Record> optional = store.getSignRecord(baseOpId);
            if (optional.isEmpty()) {
                return;
            }
            state = optional.get();
        }
        if (!isTerminalSignState(state.state())) {
            state = cancelForRetirement(baseOpId, state, reason);
            if (!isTerminalSignState(state.state())) {
                return;
            }
        }
        try (OperationCoordinator.Lease ignored = coordinator.acquire(baseOpId)) {
            state = store.getSignRecord(baseOpId).orElse(state);
            if (!isTerminalSignState(state.state())) {
                return;
            }
            state = confirmRetirement(baseOpId, state);
            store.deleteWorkflowState(baseOpId);
        }
        AsyncState advisoryState = state.result().isPresent() ? AsyncState.SUCCEEDED : AsyncState.CANCELLED;
        bus.update(baseOpId, new AsyncStatus(advisoryState, store.signingNow(), Optional.of("RETIRED"),
                Map.of("reason", "local-retirement")), state.result());
        bus.retire(baseOpId);
    }

    private void reconcileExpiredOperations() {
        Instant current = store.signingNow();
        for (SignWorkflowStore.Record candidate : store.listSignRecords()) {
            boolean deadlineExpired = !candidate.deadline().isAfter(current);
            boolean horizonExpired = !candidate.createdAt().plus(store.signingHorizon()).isAfter(current);
            if (!deadlineExpired && !horizonExpired) {
                continue;
            }
            if (candidate.state() == SignWorkflowStore.State.RETIRED && !horizonExpired) {
                continue;
            }
            PkiId operationId = candidate.submissionId();
            retireSignOperation(operationId, deadlineExpired ? "deadline-expired" : "retention-expired");
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private SignWorkflowStore.Record cancelForRetirement(PkiId operationId, SignWorkflowStore.Record state,
            String reason) {
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
            if (cancelling.detailCode().filter("CANCEL_SUBMITTED"::equals).isEmpty()) {
                reserved = externalActions.tryReserve(operationId, ExternalAction.CANCEL);
            }
        }
        if (cancelling.detailCode().filter("CANCEL_SUBMITTED"::equals).isPresent()) {
            endpoint.reconcileProviderStatus(operationId);
            return store.getSignRecord(operationId).orElse(cancelling);
        }
        if (reserved.isEmpty()) {
            return cancelling;
        }
        try (ExternalActionCoordinator.Reservation ignored = reserved.get()) {
            signer.cancel(operationId, cancelling.fence(), reason);
        } catch (RuntimeException ex) {
            endpoint.reconcileProviderStatus(operationId);
            SignWorkflowStore.Record current = store.getSignRecord(operationId).orElse(cancelling);
            if (current.state() != SignWorkflowStore.State.CANCELLING) {
                return current;
            }
            throw new PkiException("Provider cancellation failed: code=PROVIDER_CANCEL_FAILED");
        }
        markCancellationSubmitted(operationId, cancelling);
        return reconcileCancellationOutcome(operationId);
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
                    Optional.empty());
            if (cancelled.isPresent()) {
                return cancelled.get();
            }
            state = requireSignRecordDuringCancellation(operationId);
        }
        throw new PkiException("Unable to confirm authoritative signing cancellation");
    }

    private SignWorkflowStore.Record reconcileCancellationOutcome(PkiId operationId) {
        SignWorkflowStore.Record state = requireSignRecordDuringCancellation(operationId);
        for (int attempt = 0; attempt < 4; attempt++) {
            endpoint.reconcileProviderStatus(operationId);
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

    private SignWorkflowStore.Record confirmRetirement(PkiId operationId, SignWorkflowStore.Record initial) {
        SignWorkflowStore.Record state = initial;
        for (int attempt = 0; attempt < 4 && state.state() != SignWorkflowStore.State.RETIRED; attempt++) {
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
        if (state.state() != SignWorkflowStore.State.RETIRED) {
            throw new PkiException("Unable to confirm authoritative signing retirement");
        }
        return state;
    }

    private void project(SignWorkflowStore.Record record) {
        try {
            store.putWorkflowState(new WorkflowStateRecord(record.submissionId(), TYPE_SIGN, record.owner(),
                    durabilityPolicy, record.createdAt(), store.signingNow(), record.deadline(),
                    record.request().encoding(), Optional.of(record.request())));
            Duration ttl = Duration.between(record.createdAt(), record.deadline());
            bus.submit(record.submissionId(), TYPE_SIGN, record.owner(), ENDPOINT_SIGNER, record.createdAt(), ttl);
        } catch (RuntimeException ex) { // NOPMD - projection is advisory
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Advisory projection failed: code={0}, exception={1}",
                        new Object[] { "PROJECTION_REFRESH_FAILED", ex.getClass().getName() });
            }
        }
    }

    private static PkiId normalizeBaseOperationId(PkiId opId) {
        Objects.requireNonNull(opId, "opId");
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
        signerRegistration.close();
        endpoint.closeAdvisories();
    }

    /**
     * Lifecycle-bounded per-operation critical-section coordinator.
     *
     * <p>
     * The lock protects only short local and durable-state decisions. Provider,
     * callback, listener, and advisory projection code must run after the lease is
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
     * This endpoint implements the execution boundary between the durable async bus
     * and the actual signer workflow. It does not eagerly start the downstream
     * signing operation at submission time. Instead, the first status poll for an
     * operation whose persisted {@link SignContinuation} does not yet contain a
     * downstream signer operation identifier triggers the signer submission and
     * updates the persisted workflow continuation state.
     * </p>
     *
     * <p>
     * The endpoint therefore serves two purposes:
     * </p>
     * <ul>
     * <li>it materializes the downstream {@link SignatureWorkflow.SignRequest} from
     * the persisted PKI workflow state,</li>
     * <li>it maps downstream signer status and result semantics back to generic
     * {@link AsyncStatus} and {@link EncodedObject} responses expected by the
     * durable async bus.</li>
     * </ul>
     *
     * <h2>Persistence semantics</h2>
     * <ul>
     * <li>The canonical PKI workflow state is stored in {@link PkiStore} as a
     * {@link WorkflowStateRecord}.</li>
     * <li>The persisted {@link SignContinuation} initially carries the input
     * required to submit the sign operation.</li>
     * <li>After the downstream signer accepts the request, the continuation is
     * rewritten to include the assigned signer operation identifier.</li>
     * </ul>
     *
     * <h2>Failure semantics</h2>
     * <ul>
     * <li>If no workflow state exists for the requested operation, the endpoint
     * behaves as absent and returns an empty result from {@link #status(PkiId)} and
     * {@link #result(PkiId)}.</li>
     * <li>If workflow state exists but the payload is missing,
     * {@link #status(PkiId)} reports a synthetic failed state while
     * {@link #execute(PkiId)} raises a {@link PkiException} because the persisted
     * state is internally inconsistent.</li>
     * <li>Downstream signer failure is reported through the mapped async status
     * returned by {@link #status(PkiId)}.</li>
     * <li>If downstream submission succeeds but continuation persistence fails, the
     * downstream handle is cancelled, the stale continuation is deleted, and the
     * endpoint reports a terminal local failure.</li>
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

        private static final int MAX_PENDING_ADVISORIES = 1024;

        private final PkiStore store;
        private final SignatureWorkflow signer;
        private final OperationCoordinator coordinator;
        private final ExternalActionCoordinator externalActions;
        private final ConcurrentMap<PkiId, Boolean> pendingAdvisories;
        private final AtomicInteger pendingAdvisoryCount;
        private final AtomicBoolean closed;

        /**
         * Creates the endpoint instance.
         *
         * @param store  PKI store used to read and update persisted workflow
         *               continuation state; must not be {@code null}
         * @param signer downstream signature workflow used to execute the actual sign
         *               operation and to query its status; must not be {@code null}
         */
        private SignatureWorkflowEndpoint(PkiStore store, SignatureWorkflow signer, OperationCoordinator coordinator,
                ExternalActionCoordinator externalActions) {
            this.store = store;
            this.signer = signer;
            this.coordinator = coordinator;
            this.externalActions = externalActions;
            this.pendingAdvisories = new ConcurrentHashMap<>();
            this.pendingAdvisoryCount = new AtomicInteger();
            this.closed = new AtomicBoolean();
        }

        /**
         * Materializes and submits the downstream signer operation for a persisted PKI
         * sign workflow.
         *
         * <p>
         * This method reads the persisted {@link WorkflowStateRecord}, decodes its
         * {@link SignContinuation}, constructs a {@link SignatureWorkflow.SignRequest},
         * submits it to the configured {@link SignatureWorkflow}, and then persists an
         * updated continuation that includes the assigned downstream signer operation
         * identifier.
         * </p>
         *
         * <p>
         * If no workflow state exists for the supplied operation identifier, the method
         * returns without effect. This allows callers such as {@link #status(PkiId)} to
         * treat missing state as a non-existent operation rather than as an internal
         * error.
         * </p>
         *
         * <p>
         * This method is intended to be called only for operations whose continuation
         * does not yet contain a signer operation identifier. Repeated invocation for
         * an already-submitted operation would cause an unnecessary second submission
         * unless prevented by the caller's control flow.
         * </p>
         *
         * @param opId canonical PKI operation identifier; must not be {@code null}
         * @throws NullPointerException if {@code opId} is {@code null}
         * @throws PkiException         if the persisted workflow state is inconsistent,
         *                              in particular when the workflow payload is
         *                              missing
         */
        public void execute(PkiId opId) {
            Objects.requireNonNull(opId, "opId");
            Optional<SubmissionCall> prepared = prepareSubmission(opId);
            if (prepared.isEmpty()) {
                return;
            }
            SubmissionCall call = prepared.get();
            PkiId returned;
            try (ExternalActionCoordinator.Reservation ignored = call.reservation()) {
                returned = signer.submitSign(call.request());
            } catch (RuntimeException ambiguousFailure) { // NOPMD - provider acceptance is unknown
                return;
            }
            recordSubmissionAcceptance(call, returned);
            reconcileProviderStatus(opId);
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
                if (!current.deadline().isAfter(store.signingNow())) {
                    if (current.fence() == INITIAL_FENCE) {
                        store.transitionSign(opId, current.revision(), current.fence(), SignWorkflowStore.State.EXPIRED,
                                Optional.of("EXPIRED"), Optional.empty(), Optional.empty());
                    }
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
                    SignContinuation continuation = SignContinuation.decode(claimed.request());
                    SignatureWorkflow.SignRequest request = SignatureWorkflow.SignRequest.create(opId,
                            claimed.namespace(), claimed.fence(), continuation.accessContext, continuation.keyRef,
                            continuation.algorithmId, continuation.payload,
                            Optional.of(continuation.preferredSignatureEncoding), Optional.of(claimed.deadline()));
                    if (!constantTimeAsciiEquals(claimed.fingerprint(), request.semanticFingerprint())) {
                        store.transitionSign(opId, claimed.revision(), claimed.fence(), SignWorkflowStore.State.FAILED,
                                Optional.of("REQUEST_INTEGRITY_FAILURE"), Optional.empty(), Optional.empty());
                        return Optional.empty();
                    }
                    SubmissionCall call = new SubmissionCall(claimed, request, reservation);
                    reservationTransferred = true;
                    return Optional.of(call);
                } finally {
                    if (!reservationTransferred) {
                        reservation.close();
                    }
                }
            }
        }

        private static boolean constantTimeAsciiEquals(String left, String right) {
            byte[] leftBytes = left.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] rightBytes = right.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            try {
                return java.security.MessageDigest.isEqual(leftBytes, rightBytes);
            } finally {
                java.util.Arrays.fill(leftBytes, (byte) 0);
                java.util.Arrays.fill(rightBytes, (byte) 0);
            }
        }

        private void recordSubmissionAcceptance(SubmissionCall call, PkiId returned) {
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
                ExternalActionCoordinator.Reservation reservation) {
        }

        /**
         * Returns the current mapped async status of the supplied PKI sign workflow.
         *
         * <p>
         * This method is also the lazy execution trigger of the endpoint. When the
         * persisted {@link SignContinuation} does not yet contain a downstream signer
         * operation identifier, the first status poll calls {@link #execute(PkiId)} and
         * returns a synthetic {@link AsyncState#RUNNING} status with detail code
         * {@value #DC_SUBMITTED}.
         * </p>
         *
         * <p>
         * Once a downstream signer operation exists, the returned status is derived
         * from {@link SignatureWorkflow#status(PkiId)} using this mapping:
         * </p>
         * <ul>
         * <li>missing downstream status - {@link AsyncState#RUNNING} with detail code
         * {@value #DC_RUNNING},</li>
         * <li>non-terminal downstream status - {@link AsyncState#RUNNING} with detail
         * code {@value #DC_RUNNING},</li>
         * <li>successful downstream status carrying a signature result -
         * {@link AsyncState#SUCCEEDED} with detail code {@value #DC_SIGNED},</li>
         * <li>all other terminal outcomes - {@link AsyncState#FAILED} with detail code
         * {@value #DC_FAILED}.</li>
         * </ul>
         *
         * <p>
         * If the workflow state exists but the payload is missing, the method returns a
         * synthetic failed status with reason {@code missing-payload}. If no workflow
         * state exists, it returns {@link Optional#empty()}.
         * </p>
         *
         * @param opId canonical PKI operation identifier; must not be {@code null}
         * @return optional containing the current mapped async status, or an empty
         *         optional when no persisted workflow state exists for the supplied
         *         operation
         * @throws NullPointerException if {@code opId} is {@code null}
         * @throws PkiException         if lazy execution is triggered and
         *                              {@link #execute(PkiId)} encounters inconsistent
         *                              persisted workflow state
         */
        @Override
        public Optional<AsyncStatus> status(PkiId opId) {
            Objects.requireNonNull(opId, "opId");
            removeAdvisory(opId);
            SignWorkflowStore.Record record;
            Instant now;
            try (OperationCoordinator.Lease ignored = coordinator.acquire(opId)) {
                Optional<SignWorkflowStore.Record> recordOptional = store.getSignRecord(opId);
                if (recordOptional.isEmpty()) {
                    return Optional.empty();
                }
                record = recordOptional.get();
                now = store.signingNow();
                if (!record.deadline().isAfter(now) && record.state() == SignWorkflowStore.State.INTENT
                        && record.fence() == INITIAL_FENCE) {
                    store.transitionSign(opId, record.revision(), record.fence(), SignWorkflowStore.State.EXPIRED,
                            Optional.of("EXPIRED"), Optional.empty(), Optional.empty());
                    record = store.getSignRecord(opId).orElse(record);
                }
            }
            if (record.state() == SignWorkflowStore.State.INTENT && record.deadline().isAfter(now)) {
                execute(opId);
            }
            record = store.getSignRecord(opId).orElse(record);
            if (record.state() == SignWorkflowStore.State.DISPATCHED
                    || record.state() == SignWorkflowStore.State.CANCELLING) {
                reconcileProviderStatus(opId);
                record = store.getSignRecord(opId).orElse(record);
            }
            if (!record.deadline().isAfter(now) && (record.state() == SignWorkflowStore.State.DISPATCHED
                    || record.state() == SignWorkflowStore.State.CANCELLING)) {
                return Optional.of(new AsyncStatus(AsyncState.EXPIRED, now, Optional.of("EXPIRED"), Map.of()));
            }
            return Optional.of(mapStoreStatus(record));
        }

        private void onProviderStatusChanged(PkiId operationId, SignatureWorkflow.OperationStatus advisory) {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(advisory, "advisory");
            if (closed.get() || pendingAdvisories.containsKey(operationId)) {
                return;
            }
            int current;
            do {
                current = pendingAdvisoryCount.get();
                if (current >= MAX_PENDING_ADVISORIES) {
                    return;
                }
            } while (!pendingAdvisoryCount.compareAndSet(current, current + 1));
            if (closed.get()) {
                pendingAdvisoryCount.decrementAndGet();
                return;
            }
            if (pendingAdvisories.putIfAbsent(operationId, Boolean.TRUE) != null) {
                pendingAdvisoryCount.decrementAndGet();
                return;
            }
            if (closed.get()) {
                removeAdvisory(operationId);
            }
        }

        // Provider implementations are an untrusted boundary and may throw any runtime
        // failure.
        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private void reconcileProviderStatus(PkiId operationId) {
            removeAdvisory(operationId);
            Optional<StatusCall> prepared = prepareStatusCall(operationId);
            if (prepared.isEmpty()) {
                return;
            }
            StatusCall call = prepared.get();
            try (ExternalActionCoordinator.Reservation ignored = call.reservation()) {
                try {
                    SignatureWorkflow.OperationStatus providerStatus = signer.status(operationId);
                    applyProviderStatus(call, providerStatus);
                } catch (RuntimeException providerFailure) {
                    throw new PkiException("Provider status failed: code=PROVIDER_STATUS_FAILED");
                }
            }
        }

        private Optional<StatusCall> prepareStatusCall(PkiId operationId) {
            try (OperationCoordinator.Lease ignored = coordinator.acquire(operationId)) {
                Optional<SignWorkflowStore.Record> beforeCall = store.getSignRecord(operationId);
                if (beforeCall.isEmpty() || beforeCall.get().state() != SignWorkflowStore.State.DISPATCHED
                        && beforeCall.get().state() != SignWorkflowStore.State.CANCELLING) {
                    return Optional.empty();
                }
                Optional<ExternalActionCoordinator.Reservation> reserved = externalActions.tryReserve(operationId,
                        ExternalAction.STATUS);
                return reserved.map(reservation -> new StatusCall(beforeCall.get(), reservation));
            }
        }

        private void applyProviderStatus(StatusCall call, SignatureWorkflow.OperationStatus providerStatus) {
            if (!providerStatus.isTerminal()) {
                return;
            }
            try (OperationCoordinator.Lease ignored = coordinator.acquire(call.record().submissionId())) {
                Optional<SignWorkflowStore.Record> currentOptional = store.getSignRecord(call.record().submissionId());
                if (currentOptional.isEmpty()
                        || currentOptional.get().state() != SignWorkflowStore.State.DISPATCHED
                                && currentOptional.get().state() != SignWorkflowStore.State.CANCELLING
                        || currentOptional.get().fence() != call.record().fence()) {
                    return;
                }
                SignWorkflowStore.Record current = currentOptional.get();
                Optional<EncodedObject> result = providerStatus.result()
                        .flatMap(SignatureWorkflow.OperationResult::signature);
                SignWorkflowStore.State target = mapProviderState(providerStatus.state());
                Optional<String> detail = sanitizeProviderDetail(providerStatus.detailCode());
                if (target == SignWorkflowStore.State.SUCCEEDED && result.isEmpty()) {
                    target = SignWorkflowStore.State.FAILED;
                    detail = Optional.of("PROVIDER_RESULT_MISSING");
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

        private void removeAdvisory(PkiId operationId) {
            if (pendingAdvisories.remove(operationId) != null) {
                pendingAdvisoryCount.decrementAndGet();
            }
        }

        private void closeAdvisories() {
            closed.set(true);
            for (PkiId operationId : pendingAdvisories.keySet()) {
                removeAdvisory(operationId);
            }
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
         * <li>no persisted workflow state exists for the supplied operation,</li>
         * <li>workflow state exists but carries no payload,</li>
         * <li>the continuation does not yet contain a downstream signer operation
         * identifier,</li>
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
            Objects.requireNonNull(opId, "opId");
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

        private static Optional<String> sanitizeProviderDetail(Optional<String> detail) {
            if (detail.isEmpty()) {
                return Optional.empty();
            }
            String value = detail.orElseThrow();
            if (value.length() > 64 || !value.matches("[A-Z0-9_]+")) {
                return Optional.of("PROVIDER_DETAIL_INVALID");
            }
            return detail;
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
     * stored inside {@link WorkflowStateRecord#payload()} and is used by
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
     * {@link #encode()} and reconstructed through {@link #decode(EncodedObject)}.
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
     * {@link #decode(EncodedObject)}, a synthetic system access context is created
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

        private static final byte VERSION = 2;

        private final zeroecho.pki.api.audit.AccessContext accessContext;
        private final String algorithmId;
        private final EncodedObject payload;
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
         * @param payload                    to-be-signed payload; must not be
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
                EncodedObject payload, KeyRef keyRef, Encoding preferredSignatureEncoding, Optional<PkiId> signerOpId) {
            this.accessContext = Objects.requireNonNull(accessContext, "accessContext");
            this.algorithmId = Objects.requireNonNull(algorithmId, "algorithmId");
            this.payload = Objects.requireNonNull(payload, "payload");
            this.keyRef = Objects.requireNonNull(keyRef, "keyRef");
            this.preferredSignatureEncoding = Objects.requireNonNull(preferredSignatureEncoding,
                    "preferredSignatureEncoding");
            this.signerOpId = Objects.requireNonNull(signerOpId, "signerOpId");
            if (algorithmId.isBlank()) {
                throw new IllegalArgumentException("algorithmId must not be blank");
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
            return new SignContinuation(accessContext, algorithmId, payload, keyRef, preferredSignatureEncoding,
                    Optional.of(opId));
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
         * Computes the canonical semantic fingerprint for this persisted request.
         *
         * <p>
         * The calculation delegates to the same versioned algorithm used by
         * {@link SignatureWorkflow.SignRequest}. It does not include the mutable
         * fencing token.
         * </p>
         *
         * @param namespace authoritative provider/store namespace; must not be
         *                  {@code null}
         * @param deadline  authoritative signing deadline; must not be {@code null}
         * @return canonical versioned semantic fingerprint
         * @throws NullPointerException if either argument is {@code null}
         */
        public String semanticFingerprint(String namespace, Instant deadline) {
            Objects.requireNonNull(deadline, "deadline");
            return SignatureWorkflow.SignRequest.fingerprint(namespace, accessContext, keyRef, algorithmId, payload,
                    Optional.of(preferredSignatureEncoding), Optional.of(deadline));
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
         * persistence inside a {@link WorkflowStateRecord}.
         *
         * <p>
         * The returned {@link EncodedObject} always uses {@link Encoding#BINARY}. The
         * current binary layout stores:
         * </p>
         * <ul>
         * <li>format version,</li>
         * <li>algorithm identifier,</li>
         * <li>payload encoding and bytes,</li>
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
            byte[] payloadBytes = payload.bytes();
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
                    output.writeByte(payload.encoding().ordinal());
                    output.writeInt(payloadBytes.length);
                    output.write(payloadBytes);
                    output.writeByte(preferredSignatureEncoding.ordinal());
                    output.writeBoolean(signerOpId.isPresent());
                    if (signerOpId.isPresent()) {
                        output.writeUTF(signerOpId.get().value());
                    }
                }
                encoded = bytes.toByteArray();
                return new EncodedObject(Encoding.BINARY, encoded);
            } catch (java.io.IOException ex) {
                throw new PkiException("Failed to encode sign continuation: code=CONTINUATION_ENCODE_FAILED");
            } finally {
                java.util.Arrays.fill(payloadBytes, (byte) 0);
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
         * @return decoded continuation instance
         * @throws NullPointerException     if {@code obj} is {@code null}
         * @throws IllegalArgumentException if {@code obj} does not use
         *                                  {@link Encoding#BINARY}, if the embedded
         *                                  format version is not supported, or if the
         *                                  binary payload is malformed
         */
        public static SignContinuation decode(EncodedObject obj) {
            Objects.requireNonNull(obj, "obj");
            if (obj.encoding() != Encoding.BINARY) {
                throw new IllegalArgumentException("Expected BINARY continuation payload");
            }
            byte[] encoded = obj.bytes();
            byte[] payloadBytes = null;
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
                Optional<zeroecho.pki.api.FormatId> formatId = input.readBoolean()
                        ? Optional.of(new zeroecho.pki.api.FormatId(input.readUTF()))
                        : Optional.empty();
                String algId = input.readUTF();
                KeyRef key = new KeyRef(input.readUTF());
                Encoding payloadEncoding = Encoding.values()[input.readUnsignedByte()];
                int payloadLength = input.readInt();
                if (payloadLength <= 0 || payloadLength > 16 * 1024 * 1024) {
                    throw new PkiException("Invalid sign continuation payload length");
                }
                payloadBytes = input.readNBytes(payloadLength);
                if (payloadBytes.length != payloadLength) {
                    throw new PkiException("Truncated sign continuation payload");
                }
                Encoding preferred = Encoding.values()[input.readUnsignedByte()];
                Optional<PkiId> signerId = input.readBoolean() ? Optional.of(new PkiId(input.readUTF()))
                        : Optional.empty();
                zeroecho.pki.api.audit.AccessContext access = new zeroecho.pki.api.audit.AccessContext(principal,
                        purpose, objectId, formatId);
                return new SignContinuation(access, algId, new EncodedObject(payloadEncoding, payloadBytes), key,
                        preferred, signerId);
            } catch (java.io.IOException | IndexOutOfBoundsException ex) {
                throw new PkiException("Malformed sign continuation: code=CONTINUATION_MALFORMED");
            } finally {
                java.util.Arrays.fill(encoded, (byte) 0);
                if (payloadBytes != null) {
                    java.util.Arrays.fill(payloadBytes, (byte) 0);
                }
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
