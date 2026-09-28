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

package zeroecho.pki.spi.crypto;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SigningProvider.CallControl;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.crypto.SigningProvider.OperationObservation;
import zeroecho.pki.spi.crypto.SigningProvider.SignRequest;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Bound call executor that validates authoritative store/provider identity before
 * every provider dispatch, reconciliation, or cancellation invocation.
 *
 * <p>This object owns no workflow lifecycle. It retains only the store/provider
 * binding and one finite call timeout; all operation state is supplied from the
 * authoritative store for each invocation.</p>
 */
@SuppressWarnings("PMD.LongVariable")
public final class SigningProviderExecutor {
    private static final Duration MAXIMUM_PROVIDER_CALL_TIMEOUT = Duration.ofDays(1);
    private final SignWorkflowStore store;
    private final SigningProvider provider;
    private final Duration providerCallTimeout;
    private final String expectedNamespace;

    /**
     * Creates an O(1)-memory executor for one exact store/provider binding.
     *
     * @param store authoritative signing store
     * @param provider bound signing provider
     * @param providerCallTimeout positive finite call timeout no greater than one day
     * @throws IllegalArgumentException if the timeout is not positive or exceeds one day
     */
    public SigningProviderExecutor(SignWorkflowStore store, SigningProvider provider,
            Duration providerCallTimeout) {
        this.store = Objects.requireNonNull(store, "store");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.providerCallTimeout = requirePositive(providerCallTimeout);
        expectedNamespace = store.signingNamespace() + "." + provider.id();
        provider.validateSigningDomain(expectedNamespace, store.signingHorizon(), store.signingPermittedSkew());
    }

    /**
     * Dispatches one durably claimed {@code DISPATCHED} state.
     *
     * @param workflow exact current claimed workflow
     * @param content candidate content owned by the caller
     * @param cancellation cooperative cancellation signal
     * @return bounded provider observation
     */
    public OperationObservation dispatch(SignWorkflowStore.Workflow workflow, RepeatableContent content,
            CancellationSignal cancellation) {
        SignWorkflowStore.Workflow exact = requireBound(workflow, SignWorkflowStore.State.DISPATCHED);
        Objects.requireNonNull(content, "content");
        ProviderStep step = providerStep(exact);
        SigningProvider.ContentCommitment contentCommitment = new ContentCommitment(
                ContentCommitment.SHA256_V1, step.candidate().length(), step.candidate().sha256());
        Optional<zeroecho.pki.api.Encoding> encoding = Optional.of(exact.envelope().signatureEncoding());
        Optional<Instant> deadline = Optional.of(exact.deadline());
        String fingerprint = SignRequest.fingerprint(exact.configurationCommitment(), expectedNamespace,
                exact.envelope().accessContext(), step.keyRef(), step.algorithmId(),
                contentCommitment, encoding, deadline);
        SignRequest request = new SignRequest(step.operationId(), expectedNamespace, fingerprint,
                exact.configurationCommitment(), exact.fence(), exact.envelope().accessContext(),
                step.keyRef(), step.algorithmId(), contentCommitment, content,
                encoding, deadline, Objects.requireNonNull(cancellation, "cancellation"));
        return requireOperationId(step.operationId(), provider.dispatch(request, control(exact, cancellation)));
    }

    /**
     * Reconciles one durably claimed {@code DISPATCHED} or {@code CANCELLING} state.
     *
     * @param workflow exact current claimed workflow
     * @param cancellation cooperative cancellation signal
     * @return bounded provider observation
     */
    public OperationObservation reconcile(SignWorkflowStore.Workflow workflow, CancellationSignal cancellation) {
        SignWorkflowStore.Workflow exact = requireBoundActive(workflow);
        return requireOperationId(exact.providerOperationId(),
                provider.reconcile(exact.providerOperationId(), control(exact, cancellation)));
    }

    /**
     * Cancels one durably claimed {@code CANCELLING} state.
     *
     * @param workflow exact current claimed workflow
     * @param reason finite safe cancellation reason
     * @param cancellation cooperative cancellation signal
     * @return bounded provider observation
     */
    public OperationObservation cancel(SignWorkflowStore.Workflow workflow,
            SigningProvider.CancellationReason reason, CancellationSignal cancellation) {
        SignWorkflowStore.Workflow exact = requireBound(workflow, SignWorkflowStore.State.CANCELLING);
        return requireOperationId(exact.providerOperationId(), provider.cancel(exact.providerOperationId(), exact.fence(),
                Objects.requireNonNull(reason, "reason"), control(exact, cancellation)));
    }

    private SignWorkflowStore.Workflow requireBoundActive(SignWorkflowStore.Workflow workflow) {
        SignWorkflowStore.Workflow exact = Objects.requireNonNull(workflow, "workflow");
        if (exact.state() != SignWorkflowStore.State.DISPATCHED
                && exact.state() != SignWorkflowStore.State.CANCELLING) {
            throw new IllegalArgumentException("Signing workflow is not provider-call eligible");
        }
        return requireBoundIdentity(exact);
    }

    private SignWorkflowStore.Workflow requireBound(SignWorkflowStore.Workflow workflow,
            SignWorkflowStore.State requiredState) {
        SignWorkflowStore.Workflow exact = Objects.requireNonNull(workflow, "workflow");
        if (exact.state() != requiredState) {
            throw new IllegalArgumentException("Signing workflow is not provider-call eligible");
        }
        return requireBoundIdentity(exact);
    }

    private SignWorkflowStore.Workflow requireBoundIdentity(SignWorkflowStore.Workflow workflow) {
        requireProviderStage(workflow.stage());
        SignWorkflowStore.Workflow authoritative = store.getSignWorkflow(workflow.operationId())
                .orElseThrow(() -> new IllegalStateException("Signing provider claim is no longer present"));
        requireProviderStage(authoritative.stage());
        if (authoritative.revision() != workflow.revision()
                || authoritative.fence() != workflow.fence()
                || authoritative.state() != workflow.state()
                || authoritative.stage() != workflow.stage()
                || !authoritative.downstreamOperationId().equals(workflow.downstreamOperationId())
                || !authoritative.envelope().acceptanceCommitment()
                        .matches(workflow.envelope().acceptanceCommitment())
                || !sameEnvelope(authoritative.envelope(), workflow.envelope())) {
            throw new IllegalStateException("Signing provider claim is stale");
        }
        if (!expectedNamespace.equals(authoritative.namespace())
                || !provider.configurationCommitment().matches(authoritative.configurationCommitment())) {
            throw new IllegalStateException("Signing provider binding mismatch");
        }
        Instant now = store.signingNow();
        if (authoritative.fence() <= 0L || authoritative.leaseUntil().isEmpty()
                || !authoritative.leaseUntil().orElseThrow().isAfter(now)
                || !authoritative.downstreamOperationId().equals(Optional.of(authoritative.providerOperationId()))) {
            throw new IllegalStateException("Signing provider claim is incomplete");
        }
        return authoritative;
    }

    private static boolean sameEnvelope(SignWorkflowStore.AcceptanceEnvelope left,
            SignWorkflowStore.AcceptanceEnvelope right) {
        return left.operationId().equals(right.operationId())
                && left.providerNamespace().equals(right.providerNamespace())
                && left.providerConfigurationCommitment().matches(
                        right.providerConfigurationCommitment())
                && left.accessContext().equals(right.accessContext())
                && left.keyRef().equals(right.keyRef())
                && left.fairnessAuthorityId().equals(right.fairnessAuthorityId())
                && left.algorithmId().equals(right.algorithmId())
                && left.signatureEncoding() == right.signatureEncoding()
                && left.createdAt().equals(right.createdAt())
                && left.deadline().equals(right.deadline())
                && sameCandidate(left.candidate(), right.candidate())
                && sameProof(left.proofStep(), right.proofStep())
                && sameOuter(left.outer(), right.outer());
    }

    private static void requireProviderStage(SignWorkflowStore.Stage stage) {
        if (stage != SignWorkflowStore.Stage.SINGLE && stage != SignWorkflowStore.Stage.CA_PROOF
                && stage != SignWorkflowStore.Stage.CA_CERTIFICATE) {
            throw new IllegalArgumentException("Signing stage is not provider-call eligible");
        }
    }

    private static ProviderStep providerStep(SignWorkflowStore.Workflow workflow) {
        if (workflow.stage() == SignWorkflowStore.Stage.CA_PROOF) {
            SignWorkflowStore.CaSubjectProofStep proof = workflow.envelope().proofStep().orElseThrow();
            return new ProviderStep(proof.operationId(), proof.subjectKeyRef(), proof.algorithmId(), proof.challenge());
        }
        return new ProviderStep(workflow.operationId(), workflow.envelope().keyRef(), workflow.envelope().algorithmId(),
                workflow.envelope().candidate());
    }

    private static boolean sameProof(Optional<SignWorkflowStore.CaSubjectProofStep> left,
            Optional<SignWorkflowStore.CaSubjectProofStep> right) {
        if (left.isEmpty() || right.isEmpty()) { return left.isEmpty() && right.isEmpty(); }
        SignWorkflowStore.CaSubjectProofStep first = left.orElseThrow();
        SignWorkflowStore.CaSubjectProofStep second = right.orElseThrow();
        return first.operationId().equals(second.operationId()) && first.subjectKeyRef().equals(second.subjectKeyRef())
                && first.algorithmId().equals(second.algorithmId()) && sameCandidate(first.challenge(), second.challenge());
    }

    private record ProviderStep(PkiId operationId, zeroecho.pki.api.KeyRef keyRef, String algorithmId,
            zeroecho.pki.api.content.DurableContentReference candidate) { }

    private static boolean sameCandidate(zeroecho.pki.api.content.DurableContentReference left,
            zeroecho.pki.api.content.DurableContentReference right) {
        return left.storeId().equals(right.storeId())
                && left.contentId().equals(right.contentId())
                && left.encoding() == right.encoding()
                && left.length() == right.length()
                && left.sha256().equals(right.sha256())
                && left.lifecycle() == right.lifecycle();
    }

    private static boolean sameOuter(Optional<SignWorkflowStore.OuterCommand> left,
            Optional<SignWorkflowStore.OuterCommand> right) {
        if (left.isEmpty() || right.isEmpty()) {
            return left.isEmpty() && right.isEmpty();
        }
        SignWorkflowStore.OuterCommand first = left.orElseThrow();
        SignWorkflowStore.OuterCommand second = right.orElseThrow();
        return first.kind() == second.kind()
                && first.correlationId().equals(second.correlationId())
                && first.command().encoding() == second.command().encoding()
                && Arrays.equals(first.command().bytes(), second.command().bytes())
                && first.commandCommitment().equals(second.commandCommitment());
    }

    private CallControl control(SignWorkflowStore.Workflow workflow, CancellationSignal cancellation) {
        Instant now = store.signingNow();
        Instant callLimit = now.plus(providerCallTimeout);
        Instant deadline = callLimit.isBefore(workflow.deadline()) ? callLimit : workflow.deadline();
        CallControl control = new CallControl(deadline, Objects.requireNonNull(cancellation, "cancellation"));
        control.requireActive(now);
        return control;
    }

    private static OperationObservation requireOperationId(PkiId requested, OperationObservation observation) {
        OperationObservation exact = Objects.requireNonNull(observation, "observation");
        if (!requested.equals(exact.operationId())) {
            throw new IllegalStateException("Signing provider operation id mismatch");
        }
        return exact;
    }

    private static Duration requirePositive(Duration value) {
        Objects.requireNonNull(value, "providerCallTimeout");
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException("providerCallTimeout must be positive");
        }
        if (value.compareTo(MAXIMUM_PROVIDER_CALL_TIMEOUT) > 0) {
            throw new IllegalArgumentException("providerCallTimeout exceeds its finite bound");
        }
        return value;
    }
}
