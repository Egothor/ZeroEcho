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

package zeroecho.pki.impl.core.signing;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.OneShotContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningService;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.PreparedSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResolution;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.signing.SigningOperation;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.api.signing.SigningRequest;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Stateless thread-safe implementation over the authoritative signing store. */
public final class DefaultSigningService implements SigningService { // NOPMD - CyclomaticComplexity totals independent dispatch/codec branches; method-level checks remain enabled.
    private static final int MAXIMUM_CANCEL_ATTEMPTS = 8;
    private final PkiStore store;
    private final SigningProvider provider;
    private final AlgorithmIdentity defaultSignatureAlgorithm;
    private final Duration signingTtl;
    private final SecureRandom random;
    private final Runnable requireOpen;
    private final AcceptanceOperation acceptance;
    private final Runnable wakeReactor;
    private final ObservationWait observationWait;
    private final String namespace;
    private final Object preparedOwner = new Object();

    /**
     * Creates a service bound to one exact store/provider configuration.
     *
     * @param store authoritative durable store
     * @param provider configured signing provider
     * @param defaultSignatureAlgorithm exact configured default for semantic signing; raw requests select their own identity
     * @param signingTtl configured acceptance lifetime
     * @param random secure submission-identity randomness
     * @param requireOpen owning-session lifecycle guard
     * @param acceptance reactor-owned acceptance operation
     * @param wakeReactor coalesced reactor wake signal
     * @param observationWait existing reactor-owned bounded observation wait
     * @throws NullPointerException if a required dependency or default identity is null
     * @throws IllegalArgumentException if the default identity is not a permitted supported signature or the lifetime is invalid
     */
    public DefaultSigningService(PkiStore store, SigningProvider provider,
            AlgorithmIdentity defaultSignatureAlgorithm, Duration signingTtl, SecureRandom random,
            Runnable requireOpen, AcceptanceOperation acceptance,
            Runnable wakeReactor, ObservationWait observationWait) {
        this.store = Objects.requireNonNull(store, "store");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.defaultSignatureAlgorithm = Objects.requireNonNull(defaultSignatureAlgorithm, "defaultSignatureAlgorithm");
        if (defaultSignatureAlgorithm.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw new IllegalArgumentException("Configured identity must identify a signature");
        }
        X509SecurityFloor.requirePermitted(defaultSignatureAlgorithm);
        this.signingTtl = requirePositive(signingTtl);
        if (signingTtl.compareTo(store.signingHorizon()) > 0) {
            throw new IllegalArgumentException("signingTtl exceeds the store horizon");
        }
        this.random = Objects.requireNonNull(random, "random");
        this.requireOpen = Objects.requireNonNull(requireOpen, "requireOpen");
        this.acceptance = Objects.requireNonNull(acceptance, "acceptance");
        this.wakeReactor = Objects.requireNonNull(wakeReactor, "wakeReactor");
        this.observationWait = Objects.requireNonNull(observationWait, "observationWait");
        this.namespace = store.signingNamespace() + "." + provider.id();
        provider.validateSigningDomain(namespace, store.signingHorizon(),
                store.signingPermittedSkew());
        if (!provider.supportedAlgorithms().contains(defaultSignatureAlgorithm.canonicalForm())) {
            throw new IllegalArgumentException("Configured signing algorithm is unsupported");
        }
    }

    @Override public SigningSubmissionId newSubmissionId() {
        requireOpen.run();
        return SigningSubmissionId.create(namespace, store.signingNow(), random);
    }

    @Override
    public PreparedSigningRequest prepare(SigningRequest request,
            OneShotContent candidate, CancellationSignal cancellation) {
        return prepare(request, candidate, cancellation, SignWorkflowStore.Mode.NORMAL);
    }

    @Override
    public PreparedSigningRequest prepareBoundedObservation(SigningRequest request,
            OneShotContent candidate, CancellationSignal cancellation) {
        return prepare(request, candidate, cancellation, SignWorkflowStore.Mode.BOUNDED_OBSERVATION);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private PreparedSigningRequest prepare(SigningRequest request,
            OneShotContent candidate, CancellationSignal cancellation, SignWorkflowStore.Mode mode) {
        requireOpen.run();
        SigningRequest exact = Objects.requireNonNull(request, "request");
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(cancellation, "cancellation");
        Instant now = store.signingNow();
        exact.submissionId().validate(namespace, now, store.signingHorizon(),
                store.signingPermittedSkew());
        AcceptanceComponents.validate(exact);
        X509SecurityFloor.requirePermitted(exact.signatureAlgorithm());
        if (!provider.supportedAlgorithms().contains(exact.signatureAlgorithm().canonicalForm())) {
            throw new IllegalArgumentException("Requested signing algorithm is unsupported");
        }
        Instant deadline = deadline(exact.submissionId().createdAt());
        DurableContentReference reference;
        try {
            reference = store.stagedContent().stage(candidate, exact.candidateEncoding(),
                    DurableContentReference.Lifecycle.OPERATION, cancellation);
        } catch (IOException failure) {
            throw new PkiException("Signing candidate staging failed", failure);
        }
        try {
            DurableContentReference authoritative = restore(reference);
            SignWorkflowStore.AcceptanceCommand command = command(exact, authoritative, deadline,
                    Optional.empty(), mode, Optional.empty());
            SigningAcceptanceReceipt receipt = receipt(command);
            return new DefaultPreparedSigningRequest(exact, authoritative, receipt,
                    preparedOwner, Optional.empty(), mode, Optional.empty());
        } catch (RuntimeException failure) {
            retireAfterPreparationFailure(reference, failure);
            throw failure;
        }
    }

    /* default */ DefaultPreparedSigningRequest prepareDomain(DomainSigningRequest request,
            PkiId fairnessAuthorityId, SignWorkflowStore.OuterCommand outer) {
        requireOpen.run();
        Objects.requireNonNull(request, "request");
        if (!defaultSignatureAlgorithm.canonicalForm().equals(request.algorithmId()) || !signingTtl.equals(request.ttl())) {
            throw new IllegalArgumentException("Domain signing configuration differs from this session");
        }
        SigningSubmissionId submission = SigningSubmissionId.parse(request.operationId());
        submission.validate(namespace, store.signingNow(), store.signingHorizon(), store.signingPermittedSkew());
        SigningRequest metadata = new SigningRequest(submission, request.accessContext(), request.keyRef(),
                fairnessAuthorityId, defaultSignatureAlgorithm, request.content().encoding(), request.signatureEncoding());
        AcceptanceComponents.validate(metadata);
        DurableContentReference candidate = restore(request.content());
        if (candidate.lifecycle() != DurableContentReference.Lifecycle.OPERATION) {
            throw new IllegalArgumentException("Semantic candidate lifecycle must be OPERATION");
        }
        Optional<SignWorkflowStore.CaSubjectProofStep> proofStep = restoreProof(request.proofStep());
        boolean intermediate = zeroecho.pki.impl.core.continuation.IntermediateSigningCommand.supports(
                zeroecho.pki.impl.core.continuation.DomainCommandEncoding.operation(outer.command()));
        if (intermediate != proofStep.isPresent()) {
            throw new IllegalArgumentException("Intermediate signing requires its internal proof candidate");
        }
        provider.inputCapabilities().select(request.algorithmId(), candidate.length());
        proofStep.ifPresent(step -> provider.inputCapabilities().select(step.algorithmId(), step.challenge().length()));
        Optional<SignWorkflowStore.OuterCommand> paired = Optional.of(outer);
        SignWorkflowStore.AcceptanceCommand command = command(metadata, candidate,
                deadline(submission.createdAt()), paired, SignWorkflowStore.Mode.NORMAL, proofStep);
        if (outer.kind() == zeroecho.pki.spi.store.DomainContinuationStore.Kind.KEY_PROOF) {
            zeroecho.pki.impl.core.continuation.ManagedKeyProofBindings.requireEnvelope(
                    SignWorkflowStore.AcceptanceEnvelope.from(command));
        }
        if (intermediate) {
            SignWorkflowStore.AcceptanceEnvelope envelope = SignWorkflowStore.AcceptanceEnvelope.from(command);
            zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.requireEnvelope(envelope);
            try { zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.requireLiveCandidates(store.stagedContent(), envelope); }
            catch (IOException failure) { throw new PkiException("CA proof candidate validation failed", failure); }
        }
        return new DefaultPreparedSigningRequest(metadata, candidate, receipt(command), preparedOwner, paired,
                SignWorkflowStore.Mode.NORMAL, proofStep);
    }

    /* default */ void requireAvailable() { requireOpen.run(); }

    /* default */ Duration signingTtl() { return signingTtl; }

    /* default */ Optional<SignWorkflowStore.Workflow> workflow(PkiId operationId) {
        requireOpen.run();
        PkiId exact = Objects.requireNonNull(operationId, "operationId");
        SigningSubmissionId parsed = SigningSubmissionId.parse(exact);
        return namespace.equals(parsed.namespace()) ? store.getSignWorkflow(exact) : Optional.empty();
    }

    @Override public SigningAcceptanceResult accept(PreparedSigningRequest prepared) {
        requireOpen.run();
        DefaultPreparedSigningRequest exact = requirePrepared(prepared);
        exact.requireUnused();
        SignWorkflowStore.AcceptanceCommand command = validatePrepared(exact);
        provider.inputCapabilities().select(exact.request().signatureAlgorithm().canonicalForm(), exact.candidate().length());
        exact.proofStep().ifPresent(step -> provider.inputCapabilities().select(step.algorithmId(), step.challenge().length()));
        SignWorkflowStore.AcceptanceResult result = acceptance.accept(
                command, exact::consumeForAccept);
        if (result == SignWorkflowStore.AcceptanceResult.ACCEPTED
                || result == SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING) {
            wakeReactor.run();
        }
        return new SigningAcceptanceResult(map(result), exact.receipt());
    }

    @Override public SigningAcceptanceResolution resolve(SigningAcceptanceReceipt receipt) {
        requireOpen.run();
        SigningAcceptanceReceipt exact = Objects.requireNonNull(receipt, "receipt");
        SigningSubmissionId.parse(exact.operationId()).validate(namespace,
                store.signingNow(), store.signingHorizon(), store.signingPermittedSkew());
        SignWorkflowStore.AcceptanceResolution result = store.resolveAcceptance(
                exact.operationId(), SignWorkflowStore.AcceptanceCommitment.parse(
                        exact.encodedCommitment()));
        return SigningAcceptanceResolution.valueOf(result.name());
    }

    @Override public Optional<SigningOperation> find(PkiId operationId) {
        return workflow(operationId).map(DefaultSigningService::operation);
    }

    @Override
    public Optional<SigningOperation> awaitBoundedObservation(PkiId operationId, CancellationSignal cancellation) {
        requireOpen.run();
        PkiId exact = Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(cancellation, "cancellation");
        if (!namespace.equals(SigningSubmissionId.parse(exact).namespace())) {
            return Optional.empty();
        }
        Optional<SignWorkflowStore.Workflow> current = observationWait.await(exact, cancellation);
        return current.map(workflow -> {
            if (workflow.initialAttemptPhase() == SignWorkflowStore.InitialAttemptPhase.FAILED) {
                throw new PkiException("Bounded signing initial attempt failed");
            }
            return operation(workflow);
        });
    }

    @Override public Optional<SigningOperation> cancel(PkiId operationId) {
        requireOpen.run();
        PkiId exact = Objects.requireNonNull(operationId, "operationId");
        SigningSubmissionId parsed = SigningSubmissionId.parse(exact);
        if (!namespace.equals(parsed.namespace())) {
            return Optional.empty();
        }
        for (int attempt = 0; attempt < MAXIMUM_CANCEL_ATTEMPTS; attempt++) {
            Optional<SignWorkflowStore.Workflow> current = store.getSignWorkflow(exact);
            if (current.isEmpty()) {
                return Optional.empty();
            }
            SignWorkflowStore.Workflow workflow = current.orElseThrow();
            if (workflow.state() != SignWorkflowStore.State.INTENT
                    && workflow.state() != SignWorkflowStore.State.DISPATCHED) {
                return Optional.of(operation(workflow));
            }
            Optional<SignWorkflowStore.Workflow> cancelled = store.requestSignCancellation(
                    exact, workflow.revision(), workflow.fence());
            if (cancelled.isPresent()) {
                if (cancelled.orElseThrow().state() == SignWorkflowStore.State.CANCELLING) {
                    wakeReactor.run();
                }
                return cancelled.map(DefaultSigningService::operation);
            }
        }
        return store.getSignWorkflow(exact).map(DefaultSigningService::operation);
    }

    @Override public void discard(PreparedSigningRequest prepared) {
        requireOpen.run();
        DefaultPreparedSigningRequest exact = requirePrepared(prepared);
        exact.beginDiscard();
        try {
            discardPrepared(exact);
        } catch (IOException failure) {
            throw new PkiException("Signing candidate discard failed", failure);
        }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    // Identity comparison preserves ownership tokens or prevents Throwable self-suppression; value equality is incorrect here.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CompareObjectsWithEquals" })
    private void discardPrepared(DefaultPreparedSigningRequest prepared) throws IOException {
        boolean completed = false;
        try {
            if (prepared.needsDiscardValidation()) { validatePrepared(prepared); }
            Throwable primary = null;
            java.util.List<DurableContentReference> candidates = prepared.candidates();
            for (int index = 0; index < candidates.size(); index++) {
                if (prepared.discarded(index)) { continue; }
                prepared.startDestructiveDiscard();
                try {
                    store.stagedContent().retireUnownedContent(candidates.get(index));
                    prepared.markDiscarded(index);
                } catch (IOException | RuntimeException | Error failure) {
                    if (primary == null) { primary = failure; }
                    else if (primary != failure) { primary.addSuppressed(failure); }
                }
            }
            if (primary instanceof IOException failure) { throw failure; }
            if (primary instanceof RuntimeException failure) { throw failure; }
            if (primary instanceof Error failure) { throw failure; }
            completed = true;
        } finally {
            if (completed) { prepared.completeDiscard(); }
            else { prepared.retryDiscard(); }
        }
    }

    private DefaultPreparedSigningRequest requirePrepared(PreparedSigningRequest prepared) {
        if (!(Objects.requireNonNull(prepared, "prepared")
                instanceof DefaultPreparedSigningRequest exact)
                || !exact.ownedBy(preparedOwner)) {
            throw new IllegalArgumentException("Prepared request belongs to another signing service");
        }
        return exact;
    }

    private SignWorkflowStore.AcceptanceCommand validatePrepared(
            DefaultPreparedSigningRequest prepared) {
        DurableContentReference candidate = restore(prepared.candidate());
        Instant deadline = deadline(prepared.request().submissionId().createdAt());
        SignWorkflowStore.AcceptanceCommand command = command(prepared.request(), candidate,
                deadline, prepared.outer(), prepared.mode(), restoreProof(prepared.proofStep()));
        if (!receipt(command).equals(prepared.receipt())) {
            throw new IllegalArgumentException("Prepared signing receipt mismatch");
        }
        return command;
    }

    private SignWorkflowStore.AcceptanceCommand command(SigningRequest request,
            DurableContentReference candidate, Instant deadline,
            Optional<SignWorkflowStore.OuterCommand> outer, SignWorkflowStore.Mode mode,
            Optional<SignWorkflowStore.CaSubjectProofStep> proofStep) {
        return new SignWorkflowStore.AcceptanceCommand(request.submissionId().id(), namespace,
                provider.configurationCommitment(), request.accessContext(), request.keyRef(),
                request.fairnessAuthorityId(), request.signatureAlgorithm().canonicalForm(), Encoding.BINARY,
                request.submissionId().createdAt(), deadline, candidate, outer, mode, proofStep);
    }

    private Optional<SignWorkflowStore.CaSubjectProofStep> restoreProof(Optional<SignWorkflowStore.CaSubjectProofStep> proofStep) {
        return proofStep.map(step -> new SignWorkflowStore.CaSubjectProofStep(step.operationId(), step.subjectKeyRef(),
                step.algorithmId(), restore(step.challenge())));
    }

    private DurableContentReference restore(DurableContentReference reference) {
        try {
            return store.stagedContent().restoreReference(reference.storeId(),
                    reference.contentId(), reference.encoding(), reference.length(),
                    reference.sha256(), reference.lifecycle());
        } catch (IOException failure) {
            throw new PkiException("Signing candidate validation failed", failure);
        }
    }

    private Instant deadline(Instant createdAt) {
        try {
            return createdAt.plus(signingTtl);
        } catch (DateTimeException overflow) {
            throw new IllegalArgumentException("Signing deadline is not representable", overflow);
        }
    }

    private static SigningAcceptanceReceipt receipt(
            SignWorkflowStore.AcceptanceCommand command) {
        return SigningAcceptanceReceipt.parse(command.operationId(),
                command.commitment().encoded());
    }

    private static SigningAcceptanceDisposition map(
            SignWorkflowStore.AcceptanceResult result) {
        return SigningAcceptanceDisposition.valueOf(result.name());
    }

    private static SigningOperation operation(SignWorkflowStore.Workflow workflow) {
        SigningOperationState state = operationState(workflow);
        Optional<EncodedObject> signature = state == SigningOperationState.SUCCEEDED
                ? workflow.result() : Optional.empty();
        return new SigningOperation(SigningSubmissionId.parse(workflow.operationId()), state,
                workflow.revision(), workflow.createdAt(), workflow.deadline(),
                workflow.providerUpdatedAt(), workflow.detailCode(), signature);
    }

    /* default */ static SigningOperationState operationState(SignWorkflowStore.Workflow workflow) {
        return switch (workflow.state()) {
            case INTENT, DISPATCHED -> SigningOperationState.PENDING;
            case CANCELLING -> SigningOperationState.CANCELLING;
            case SUCCEEDED -> SigningOperationState.SUCCEEDED;
            case FAILED -> SigningOperationState.FAILED;
            case CANCELLED -> SigningOperationState.CANCELLED;
            case EXPIRED -> SigningOperationState.EXPIRED;
            case RETIRED -> retiredState(workflow);
        };
    }

    private static SigningOperationState retiredState(SignWorkflowStore.Workflow workflow) {
        if (workflow.result().isPresent()
                && workflow.detailCode().filter("SIGNED"::equals).isPresent()) {
            return SigningOperationState.SUCCEEDED;
        }
        if (workflow.detailCode().filter("CANCELLED"::equals).isPresent()) {
            return SigningOperationState.CANCELLED;
        }
        return SigningOperationState.FAILED;
    }

    private void retireAfterPreparationFailure(DurableContentReference reference,
            RuntimeException primary) {
        try {
            store.stagedContent().retireUnownedContent(reference);
        } catch (IOException cleanup) {
            primary.addSuppressed(cleanup);
        }
    }

    private static Duration requirePositive(Duration value) {
        Objects.requireNonNull(value, "signingTtl");
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException("signingTtl must be positive");
        }
        return value;
    }

    /** Local finite UTF-8 commitment-component validation. */
    private static final class AcceptanceComponents {
        private static final int MAX_BYTES = 1_048_576;
        private static final int ASCII_MAX = 0x7f;
        private static final int TWO_BYTE_MAX = 0x7ff;

        private static void validate(SigningRequest request) {
            validateUtf8(request.accessContext().principal().type());
            validateUtf8(request.accessContext().principal().name());
            validateUtf8(request.accessContext().purpose().value());
            request.accessContext().objectId().ifPresent(value ->
                    validateUtf8(value.value()));
            request.accessContext().formatId().ifPresent(value ->
                    validateUtf8(value.value()));
            validateUtf8(request.keyRef().value());
            validateUtf8(request.fairnessAuthorityId().value());
        }

        private static void validateUtf8(String value) {
            int encodedBytes = 0;
            int index = 0;
            while (index < value.length()) {
                char current = value.charAt(index);
                if (current <= ASCII_MAX) {
                    encodedBytes++;
                } else if (current <= TWO_BYTE_MAX) {
                    encodedBytes += 2;
                } else if (Character.isHighSurrogate(current)
                        && index + 1 < value.length()
                        && Character.isLowSurrogate(value.charAt(index + 1))) {
                    encodedBytes += 4;
                    index++;
                } else if (Character.isSurrogate(current)) {
                    encodedBytes++;
                } else {
                    encodedBytes += 3;
                }
                index++;
                if (encodedBytes > MAX_BYTES) {
                    throw new IllegalArgumentException(
                            "Acceptance component exceeds the current bound");
                }
            }
        }
    }

    /** Borrowed wait callback implemented by the service's existing reactor. */
    @FunctionalInterface
    public interface ObservationWait {
        /**
         * Waits for the authoritative bounded initial-attempt outcome.
         *
         * @param operationId accepted operation identity
         * @param cancellation cooperative wait cancellation
         * @return current completed/failed-attempt snapshot, or empty when unknown or purged
         */
        Optional<SignWorkflowStore.Workflow> await(PkiId operationId, CancellationSignal cancellation);
    }

    /** Reactor-owned acceptance operation and custody-transfer boundary. */
    @FunctionalInterface
    public interface AcceptanceOperation {
        /**
         * Accepts under the owning reactor's shutdown gate.
         *
         * @param command exact immutable acceptance command
         * @param transferCustody atomic prepared-candidate custody transfer
         * @return durable acceptance disposition
         */
        SignWorkflowStore.AcceptanceResult accept(
                SignWorkflowStore.AcceptanceCommand command, Runnable transferCustody);
    }
}
