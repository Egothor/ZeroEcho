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

package zeroecho.pki.application;

import java.io.InterruptedIOException;
import java.time.Instant;
import java.util.NoSuchElementException;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.impl.core.signing.SigningStepExecutor;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.SignWorkflowStore.Workflow;

/** Sequential borrowed executor retaining only call-scoped operation observations. */
final class DefaultLocalSigningExecutor implements LocalSigningExecutor {
    private static final String RECOVERY_REQUIRED_CODE = "RECOVERY_REQUIRED";

    private static final String COMPLETE = "signing.operation.complete";
    private final PkiStore store;
    private final SigningProvider provider;
    private final SemanticSigningService semantic;
    private final PkiSigningCommands commands;
    private final LocalSigningConfiguration configuration;
    private final SigningStepExecutor steps;
    private final LocalInvocationAudit audit;
    private final Runnable requireOpen;

    /* default */ DefaultLocalSigningExecutor(PkiStore store, SigningProvider provider, SemanticSigningService semantic,
            PkiSigningCommands commands, LocalSigningConfiguration configuration,
            SigningStepExecutor.OuterTerminalDriver driver, LocalInvocationAudit audit, Runnable requireOpen) {
        this.store = Objects.requireNonNull(store, "store");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.semantic = Objects.requireNonNull(semantic, "semantic");
        this.commands = Objects.requireNonNull(commands, "commands");
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.steps = new SigningStepExecutor(store, provider, configuration.providerCallTimeout(), driver);
        this.audit = Objects.requireNonNull(audit, "audit");
        this.requireOpen = Objects.requireNonNull(requireOpen, "requireOpen");
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    @Override public LocalSigningResult execute(PkiSigningOperation operation, CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(cancellation, "cancellation");
        String name = operation.name();
        audit.record(name, "INVOKED", Optional.empty(), "REQUESTED");
        PreparedSemanticSigningRequest prepared = null;
        Optional<SigningAcceptanceReceipt> receipt = Optional.empty();
        boolean acceptanceInvoked = false;
        LocalSigningResult result;
        try {
            requireNotCancelled(cancellation);
            prepared = commands.prepare(operation, audit.access(name), Optional.empty(), cancellation);
            receipt = Optional.of(prepared.receipt());
            requireNotCancelled(cancellation);
            acceptanceInvoked = true;
            SigningAcceptanceResult accepted = semantic.accept(prepared);
            receipt = Optional.of(accepted.receipt());
            result = switch (accepted.disposition()) {
                case ACCEPTED, ATTACHED_EXISTING -> drive(name, accepted.receipt(), cancellation);
                case CONFLICT -> failed(name, PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT", receipt);
                case CAPACITY_REJECTED -> failed(name, PkiOperationFailure.OVERLOADED, "SIGNING_OVERLOADED", receipt);
            };
        } catch (InterruptedIOException cancelled) {
            result = failed(name, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED", receipt);
        } catch (RuntimeException failure) {
            result = acceptanceInvoked
                    ? failed(name, PkiOperationFailure.RECOVERY_REQUIRED, RECOVERY_REQUIRED_CODE, receipt)
                    : classify(name, failure, receipt);
        }
        if (!acceptanceInvoked && prepared != null) {
            try {
                semantic.discard(prepared);
            } catch (RuntimeException cleanupFailure) {
                result = failed(name, PkiOperationFailure.RECOVERY_REQUIRED, RECOVERY_REQUIRED_CODE, receipt);
            }
        }
        return audited(name, Optional.empty(), result);
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    @Override public LocalSigningResult complete(PkiId operationId, CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(cancellation, "cancellation");
        audit.record(COMPLETE, "INVOKED", Optional.of(operationId), "REQUESTED");
        Optional<SigningAcceptanceReceipt> receipt = Optional.empty();
        LocalSigningResult result;
        try {
            // Semantic lookup excludes unknown, foreign and raw sign-only operations.
            Optional<SemanticSigningOperation> observation = semantic.find(operationId);
            Optional<Workflow> loaded = observation.isEmpty() ? Optional.empty() : store.getSignWorkflow(operationId);
            if (loaded.isEmpty()) {
                result = failed(COMPLETE, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND", receipt);
            } else {
                Workflow workflow = loaded.orElseThrow();
                receipt = Optional.of(SigningAcceptanceReceipt.parse(operationId, workflow.fingerprint()));
                result = drive(COMPLETE, receipt.orElseThrow(), cancellation);
            }
        } catch (RuntimeException failure) {
            result = classify(COMPLETE, failure, receipt);
        }
        return audited(COMPLETE, Optional.of(operationId), result);
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    @Override public PkiOperationOutcome inspect(PkiId operationId, CancellationSignal cancellation) {
        requireOpen.run();
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(cancellation, "cancellation");
        String name = "signing.operation.inspect";
        audit.record(name, "INVOKED", Optional.of(operationId), "REQUESTED");
        PkiOperationOutcome result;
        try {
            requireNotCancelled(cancellation);
            SemanticSigningOperation observation = semantic.find(operationId).orElseThrow();
            Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
            if (observation.state() == SemanticSigningState.COMPLETED) {
                fields.putAll(commands.completedResult(observation).fields());
            }
            fields.put("operationId", new PkiOperationValue.Text(operationId.value()));
            fields.put("kind", new PkiOperationValue.Text(observation.scope().kind().name()));
            fields.put("state", new PkiOperationValue.Text(observation.state().name()));
            fields.put("signingState", new PkiOperationValue.Text(observation.signingState().name()));
            fields.put("revision", new PkiOperationValue.IntegerValue(observation.revision()));
            fields.put("signingRevision", new PkiOperationValue.IntegerValue(observation.signingRevision()));
            fields.put("createdAt", new PkiOperationValue.Text(observation.createdAt().toString()));
            fields.put("deadline", new PkiOperationValue.Text(observation.deadline().toString()));
            observation.detailCode().ifPresent(value -> fields.put("detailCode", new PkiOperationValue.Text(value)));
            result = new PkiOperationOutcome.Completed(new PkiOperationResult(name, fields));
        } catch (InterruptedIOException failure) {
            result = new PkiOperationOutcome.Failed(name, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED");
        } catch (RuntimeException failure) {
            result = ((LocalSigningResult.Failed) classify(name, failure, Optional.empty())).failure();
        }
        audit.record(name, "RESULT", Optional.of(operationId), result instanceof PkiOperationOutcome.Failed failure
                ? failure.code() : "COMPLETED");
        return result;
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private LocalSigningResult drive(String name, SigningAcceptanceReceipt receipt, CancellationSignal cancellation) {
        PkiId id = receipt.operationId();
        // The only continuation edges are proof -> verification -> certificate-ready.
        // No revision, eligibility or provider observation can cause an open-ended retry.
        for (int stage = 0; stage < 3; stage++) {
            requireOpen.run();
            SemanticSigningOperation observation = semantic.find(id).orElseThrow();
            Workflow workflow = store.getSignWorkflow(id).orElseThrow();
            LocalSigningResult terminal = terminal(name, receipt, observation, workflow);
            if (terminal != null) { return terminal; }
            if (!workflow.namespace().equals(store.signingNamespace() + "." + provider.id())
                    || !provider.configurationCommitment().matches(workflow.configurationCommitment())) {
                return failed(name, PkiOperationFailure.POLICY_REJECTION, "PROVIDER_ID_MISMATCH", Optional.of(receipt));
            }
            Instant now = store.signingNow();
            if (workflow.leaseUntil().filter(value -> value.isAfter(now)).isPresent()
                    || workflow.nextEligibleAt().filter(value -> value.isAfter(now)).isPresent()) {
                return failed(name, PkiOperationFailure.RECOVERY_REQUIRED, "SIGNING_NOT_READY", Optional.of(receipt));
            }
            if (cancelled(cancellation)) {
                return failed(name, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED", Optional.of(receipt));
            }
            SemanticSigningOperation after;
            Workflow fresh;
            try {
                steps.advance(workflow, source -> {
                    requireOpen.run();
                    return store.claimSignStep(source.operationId(), source.revision(), configuration.claimLease());
                }, cancellation, () -> { });
                // Completion wins over cancellation arriving during signing or publication.
                after = semantic.find(id).orElseThrow();
                fresh = store.getSignWorkflow(id).orElseThrow();
            } catch (RuntimeException uncertainProgress) {
                return failed(name, PkiOperationFailure.RECOVERY_REQUIRED, RECOVERY_REQUIRED_CODE, Optional.of(receipt));
            }
            terminal = terminal(name, receipt, after, fresh);
            if (terminal != null) { return terminal; }
            if (cancelled(cancellation)) {
                return failed(name, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED", Optional.of(receipt));
            }
            if (!forward(workflow.stage(), fresh.stage())) {
                return failed(name, PkiOperationFailure.RECOVERY_REQUIRED, RECOVERY_REQUIRED_CODE, Optional.of(receipt));
            }
        }
        return failed(name, PkiOperationFailure.RECOVERY_REQUIRED, RECOVERY_REQUIRED_CODE, Optional.of(receipt));
    }

    private LocalSigningResult terminal(String name, SigningAcceptanceReceipt receipt,
            SemanticSigningOperation operation, Workflow workflow) {
        return switch (operation.state()) {
            case COMPLETED -> new LocalSigningResult.Completed(commands.completedResult(operation), receipt);
            case EXPIRED -> failed(name, PkiOperationFailure.CANCELLED, "SIGNING_EXPIRED", Optional.of(receipt));
            case FAILED -> operation.signingState() == SigningOperationState.CANCELLED
                    ? failed(name, PkiOperationFailure.CANCELLED, "CANCELLED", Optional.of(receipt))
                    : failed(name, PkiOperationFailure.POLICY_REJECTION,
                            operation.detailCode().orElseGet(() -> workflow.detailCode().orElse("SIGNING_FAILED")), Optional.of(receipt));
            case SIGNING, PUBLISHING -> null;
        };
    }

    private static boolean forward(SignWorkflowStore.Stage before, SignWorkflowStore.Stage after) {
        return before == SignWorkflowStore.Stage.CA_PROOF && after == SignWorkflowStore.Stage.CA_PROOF_VERIFYING
                || before == SignWorkflowStore.Stage.CA_PROOF_VERIFYING && after == SignWorkflowStore.Stage.CA_CERTIFICATE_READY;
    }

    private LocalSigningResult audited(String name, Optional<PkiId> requested, LocalSigningResult result) {
        if (result instanceof LocalSigningResult.Completed completed) {
            audit.record(name, "RESULT", Optional.of(completed.receipt().operationId()), "COMPLETED");
        } else {
            LocalSigningResult.Failed failed = (LocalSigningResult.Failed) result;
            audit.record(name, "RESULT", failed.receipt().map(SigningAcceptanceReceipt::operationId).or(() -> requested), failed.failure().code());
        }
        return result;
    }

    private static LocalSigningResult classify(String name, RuntimeException failure,
            Optional<SigningAcceptanceReceipt> receipt) {
        if (failure instanceof PkiException pki && pki.failureReason().orElse(null) == PkiFailureReason.STORE_DURABILITY_UNCONFIRMED) {
            return failed(name, PkiOperationFailure.RECOVERY_REQUIRED, RECOVERY_REQUIRED_CODE, receipt);
        }
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof InterruptedIOException || cause instanceof java.util.concurrent.CancellationException) {
                return failed(name, PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED", receipt);
            }
        }
        if (failure instanceof UnsupportedOperationException) { return failed(name, PkiOperationFailure.VALIDATION_FAILURE, "CAPABILITY_NOT_CONFIGURED", receipt); }
        if (failure instanceof NoSuchElementException) { return failed(name, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND", receipt); }
        if (failure instanceof IllegalArgumentException) { return failed(name, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID", receipt); }
        if (failure instanceof SigningExecutionException signing) {
            return signing.classification() == SigningExecutionException.Classification.OVERLOADED
                    ? failed(name, PkiOperationFailure.OVERLOADED, "SIGNING_OVERLOADED", receipt)
                    : failed(name, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED", receipt);
        }
        if (failure instanceof PkiException) { return failed(name, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED", receipt); }
        if (failure instanceof IllegalStateException) { return failed(name, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED", receipt); }
        return failed(name, PkiOperationFailure.INTERNAL_FAILURE, "PKI_INTERNAL_FAILURE", receipt);
    }

    // Standalone execution checks or restores interruption; it neither creates threads nor runs in a J2EE container.
    @SuppressWarnings({ "PMD.DoNotUseThreads" })
    private static boolean cancelled(CancellationSignal cancellation) {
        return cancellation.isCancelled() || Thread.currentThread().isInterrupted();
    }

    private static void requireNotCancelled(CancellationSignal cancellation) throws InterruptedIOException {
        if (cancelled(cancellation)) { throw new InterruptedIOException("Local operation cancelled"); }
    }

    private static LocalSigningResult failed(String name, PkiOperationFailure classification, String code,
            Optional<SigningAcceptanceReceipt> receipt) {
        return new LocalSigningResult.Failed(new PkiOperationOutcome.Failed(name, classification, code), receipt);
    }
}
