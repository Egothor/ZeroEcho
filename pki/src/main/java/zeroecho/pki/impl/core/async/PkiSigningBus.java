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
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.orch.OrchestrationDurabilityPolicy;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.util.async.AsyncBus;
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
public final class PkiSigningBus implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(PkiSigningBus.class.getName());

    /**
     * Operation type for signing.
     */
    public static final String TYPE_SIGN = "PKI.SIGN";

    private static final String ENDPOINT_SIGNER = "signer";

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
    private final AsyncBus<PkiId, Principal, String, EncodedObject> bus;

    private final int displaySuffixMaxLen;
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
        this.displaySuffixMaxLen = resolveDisplaySuffixMaxLen(Optional.of(displaySuffixMaxLen));
        this.durabilityPolicy = durabilityPolicy;

        AppendOnlyLineStore ls = new AppendOnlyLineStore(durableLineStorePath);
        this.bus = new DurableAsyncBus<>(new PkiAsyncCodecs.PkiIdCodec(), new PkiAsyncCodecs.PrincipalCodec(),
                new PkiAsyncCodecs.StringIdCodec(), new PkiAsyncCodecs.EncodedObjectResultCodec(true), ls);

        SignatureWorkflowEndpoint endpoint = new SignatureWorkflowEndpoint(store, signer);
        this.bus.registerEndpoint(ENDPOINT_SIGNER, endpoint);

        // IMPORTANT: no auto-dispatch here; execution is driven by sweep() polling
        // endpoint.status().
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
        return OperationIdCodec.toDisplay(OperationIdCodec.toCanonicalBase(clientOpId, owner), owner,
                displaySuffixMaxLen);
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

        PkiId baseOpId = normalizeBaseOperationId(opId);

        Optional<WorkflowStateRecord> existing = store.getWorkflowState(baseOpId);
        if (existing.isPresent()) {
            WorkflowStateRecord wsExisting = existing.get();
            if (!TYPE_SIGN.equals(wsExisting.type())) {
                throw new PkiException("OperationId already exists for different type");
            }
            if (!owner.equals(wsExisting.owner())) {
                throw new PkiException("OperationId already exists for different owner");
            }

            // Idempotent re-submit / re-attach: do not overwrite store.
            try {
                Instant nowExisting = Instant.now();
                this.bus.submit(baseOpId, TYPE_SIGN, owner, ENDPOINT_SIGNER, nowExisting, ttl);
            } catch (RuntimeException ex) { // NOPMD
                if (LOG.isLoggable(Level.FINE)) {
                    LOG.log(Level.FINE, "Re-submit ignored (bus likely already contains the op)", ex);
                }
            }
            return;
        }

        if (workflowPayload.isEmpty()) {
            throw new IllegalArgumentException("workflowPayload must be present for new sign operation");
        }

        Instant now = Instant.now();
        Encoding payloadEncoding = workflowPayload.get().encoding();

        WorkflowStateRecord ws = new WorkflowStateRecord(baseOpId, TYPE_SIGN, owner, durabilityPolicy, now, now,
                now.plus(ttl), payloadEncoding, workflowPayload);

        store.putWorkflowState(ws);

        this.bus.submit(baseOpId, TYPE_SIGN, owner, ENDPOINT_SIGNER, now, ttl);
    }

    /**
     * Returns current status if known.
     */
    public Optional<AsyncStatus> status(PkiId opId) {
        return bus.status(normalizeBaseOperationId(opId));
    }

    /**
     * Consumes result if present.
     */
    public Optional<EncodedObject> consumeResult(PkiId opId) {
        return bus.consumeResult(normalizeBaseOperationId(opId));
    }

    /**
     * Sweeps the durable bus.
     */
    public void sweep(Instant now) {
        bus.sweep(now);
    }

    /**
     * Deletes workflow continuation state once finished.
     */
    public void deleteWorkflowState(PkiId opId) {
        store.deleteWorkflowState(normalizeBaseOperationId(opId));
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
        // No-op: this class does not own store/signer. DurableAsyncBus does not require
        // explicit close.
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
     * </ul>
     *
     * <h2>Thread-safety</h2>
     * <p>
     * This endpoint is effectively stateless apart from its collaborators.
     * Concurrent behavior therefore depends primarily on the thread-safety and
     * consistency guarantees of the configured {@link PkiStore} and
     * {@link SignatureWorkflow}.
     * </p>
     */
    private static final class SignatureWorkflowEndpoint implements AsyncEndpoint<PkiId, EncodedObject> {

        private static final String DC_SUBMITTED = "SUBMITTED";
        private static final String DC_RUNNING = "RUNNING";
        private static final String DC_SIGNED = "SIGNED";
        private static final String DC_FAILED = "FAILED";

        private final PkiStore store;
        private final SignatureWorkflow signer;

        /**
         * Creates the endpoint instance.
         *
         * @param store  PKI store used to read and update persisted workflow
         *               continuation state; must not be {@code null}
         * @param signer downstream signature workflow used to execute the actual sign
         *               operation and to query its status; must not be {@code null}
         */
        private SignatureWorkflowEndpoint(PkiStore store, SignatureWorkflow signer) {
            this.store = store;
            this.signer = signer;
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

            Optional<WorkflowStateRecord> wsOpt = store.getWorkflowState(opId);
            if (wsOpt.isEmpty()) {
                return;
            }

            WorkflowStateRecord ws = wsOpt.get();
            Optional<EncodedObject> payloadOpt = ws.payload();
            if (payloadOpt.isEmpty()) {
                throw new PkiException("Missing workflow payload for sign operation");
            }

            SignContinuation cont = SignContinuation.decode(payloadOpt.get());

            SignatureWorkflow.SignRequest req = new SignatureWorkflow.SignRequest(cont.accessContext, cont.keyRef,
                    cont.algorithmId, cont.payload, Optional.of(cont.preferredSignatureEncoding),
                    Optional.of(ws.expiresAt()));

            PkiId signerOpId = signer.submitSign(req);

            SignContinuation withSigner = cont.withSignerOpId(signerOpId);
            WorkflowStateRecord updated = new WorkflowStateRecord(ws.opId(), ws.type(), ws.owner(),
                    ws.durabilityPolicy(), ws.createdAt(), Instant.now(), ws.expiresAt(), ws.payloadEncoding(),
                    Optional.of(withSigner.encode()));
            store.putWorkflowState(updated);
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
            Optional<WorkflowStateRecord> wsOpt = store.getWorkflowState(opId);
            if (wsOpt.isEmpty()) {
                return Optional.empty();
            }

            WorkflowStateRecord ws = wsOpt.get();
            Optional<EncodedObject> payloadOpt = ws.payload();
            if (payloadOpt.isEmpty()) {
                return Optional.of(new AsyncStatus(AsyncState.FAILED, Instant.now(), Optional.of(DC_FAILED),
                        Map.of("reason", "missing-payload")));
            }

            SignContinuation cont = SignContinuation.decode(payloadOpt.get());
            if (cont.signerOpId.isEmpty()) {
                // First poll drives submit to signer (this is the "async boundary").
                execute(opId);
                return Optional
                        .of(new AsyncStatus(AsyncState.RUNNING, Instant.now(), Optional.of(DC_SUBMITTED), Map.of()));
            }

            SignatureWorkflow.OperationStatus st = signer.status(cont.signerOpId.get());
            if (st == null) {
                return Optional.of(new AsyncStatus(AsyncState.RUNNING, Instant.now(), Optional.of(DC_RUNNING),
                        Map.of("reason", "no-status")));
            }

            if (!st.isTerminal()) {
                return Optional
                        .of(new AsyncStatus(AsyncState.RUNNING, st.updatedAt(), Optional.of(DC_RUNNING), Map.of()));
            }

            if (st.state() == SignatureWorkflow.State.SUCCEEDED && st.result().isPresent()
                    && st.result().get().signature().isPresent()) {
                return Optional
                        .of(new AsyncStatus(AsyncState.SUCCEEDED, st.updatedAt(), Optional.of(DC_SIGNED), Map.of()));
            }

            return Optional.of(new AsyncStatus(AsyncState.FAILED, st.updatedAt(), Optional.of(DC_FAILED),
                    Map.of("detailCode", st.detailCode().orElse(""))));
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

            Optional<WorkflowStateRecord> wsOpt = store.getWorkflowState(opId);
            if (wsOpt.isEmpty()) {
                return Optional.empty();
            }
            Optional<EncodedObject> payloadOpt = wsOpt.get().payload();
            if (payloadOpt.isEmpty()) {
                return Optional.empty();
            }
            SignContinuation cont = SignContinuation.decode(payloadOpt.get());
            if (cont.signerOpId.isEmpty()) {
                return Optional.empty();
            }
            SignatureWorkflow.OperationStatus st = signer.status(cont.signerOpId.get());
            if (st == null || st.state() != SignatureWorkflow.State.SUCCEEDED || st.result().isEmpty()) {
                return Optional.empty();
            }
            return st.result().get().signature();
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

        private static final byte VERSION = 1;

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
            byte[] algBytes = algorithmId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] keyBytes = keyRef.value().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] opBytes = signerOpId.map(x -> x.value().getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    .orElse(new byte[0]);

            java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(1 + 2 + algBytes.length + 1 + 4
                    + payload.bytes().length + 2 + keyBytes.length + 1 + 1 + 2 + opBytes.length);
            bb.put(VERSION);
            bb.putShort((short) algBytes.length);
            bb.put(algBytes);
            bb.put((byte) payload.encoding().ordinal());
            bb.putInt(payload.bytes().length);
            bb.put(payload.bytes());
            bb.putShort((short) keyBytes.length);
            bb.put(keyBytes);
            bb.put((byte) preferredSignatureEncoding.ordinal());
            bb.put((byte) (signerOpId.isPresent() ? 1 : 0));
            bb.putShort((short) opBytes.length);
            bb.put(opBytes);
            return new EncodedObject(Encoding.BINARY, bb.array());
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
            java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(obj.bytes());
            byte v = bb.get();
            if (v != VERSION) {
                throw new IllegalArgumentException("Unsupported continuation version");
            }
            int algLen = Short.toUnsignedInt(bb.getShort());
            byte[] algBytes = new byte[algLen];
            bb.get(algBytes);
            String algId = new String(algBytes, java.nio.charset.StandardCharsets.UTF_8);

            Encoding payloadEnc = Encoding.values()[Byte.toUnsignedInt(bb.get())];
            int payloadLen = bb.getInt();
            byte[] payloadBytes = new byte[payloadLen];
            bb.get(payloadBytes);

            int keyLen = Short.toUnsignedInt(bb.getShort());
            byte[] keyBytes = new byte[keyLen];
            bb.get(keyBytes);
            KeyRef keyRef = new KeyRef(new String(keyBytes, java.nio.charset.StandardCharsets.UTF_8));

            Encoding prefEnc = Encoding.values()[Byte.toUnsignedInt(bb.get())];
            boolean hasOp = bb.get() != 0;
            int opLen = Short.toUnsignedInt(bb.getShort());
            byte[] opBytes = new byte[opLen];
            bb.get(opBytes);

            Optional<PkiId> signerOpId = Optional.empty();
            if (hasOp) {
                signerOpId = Optional.of(new PkiId(new String(opBytes, java.nio.charset.StandardCharsets.UTF_8)));
            }

            Principal sys = new Principal("SYSTEM", "pki");
            zeroecho.pki.api.audit.Purpose purpose = new zeroecho.pki.api.audit.Purpose("SIGN");
            zeroecho.pki.api.audit.AccessContext ac = new zeroecho.pki.api.audit.AccessContext(sys, purpose,
                    Optional.empty(), Optional.empty());
            return new SignContinuation(ac, algId, new EncodedObject(payloadEnc, payloadBytes), keyRef, prefEnc,
                    signerOpId);
        }
    }
}
