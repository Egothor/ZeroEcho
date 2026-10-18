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

package zeroecho.pki.impl.core.continuation;

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.impl.core.signing.SigningStepExecutor;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Idempotent local CA-proof verification and terminal-signing publication driver. */
public final class SigningOuterTerminalDriver
        implements SigningStepExecutor.OuterTerminalDriver {
    private static final int MAXIMUM_CAS_ATTEMPTS = 8;
    private final PkiStore store;
    private final DomainContinuationPublisher publisher;
    private final FullCrlContinuationPublisher fullCrl;
    private final Optional<ManagedKeyProofVerifier> proof;

    /**
     * Creates a driver borrowing the authoritative store.
     *
     * @param store authoritative durable store
     */
    public SigningOuterTerminalDriver(PkiStore store) {
        this(store, StandardX509Bindings.catalog(), Integer.MAX_VALUE - 8L);
    }

    /**
     * Creates a driver using the session's exact binding catalog and resolved EdDSA bound.
     * @param store authoritative durable store
     * @param bindings immutable session X.509 bindings
     * @param pureEdDsaMaximumTbsBytes inclusive raw-message bound for pure EdDSA
     */
    public SigningOuterTerminalDriver(PkiStore store, X509BindingCatalog bindings, long pureEdDsaMaximumTbsBytes) {
        this.store = Objects.requireNonNull(store, "store");
        publisher = new DomainContinuationPublisher(store);
        FullCrlSigningCommand.requireAdmission("", 0, pureEdDsaMaximumTbsBytes);
        fullCrl = new FullCrlContinuationPublisher(store, Objects.requireNonNull(bindings, "bindings"), pureEdDsaMaximumTbsBytes);
        proof = Optional.empty();
    }

    /**
     * Creates the session driver with the exact selected verification authority.
     * @param store authoritative store
     * @param authority session-owned immutable verification authority and bindings
     * @param verifier exact verification executor bound to that authority
     * @param pureEdDsaMaximumTbsBytes inclusive raw pure-EdDSA message bound
     */
    public SigningOuterTerminalDriver(PkiStore store, X509AuthoritySnapshot authority,
            BcX509VerificationExecutor verifier, long pureEdDsaMaximumTbsBytes) {
        this.store = Objects.requireNonNull(store, "store");
        publisher = new DomainContinuationPublisher(store);
        FullCrlSigningCommand.requireAdmission("", 0, pureEdDsaMaximumTbsBytes);
        fullCrl = new FullCrlContinuationPublisher(store, authority.bindings(), pureEdDsaMaximumTbsBytes);
        proof = Optional.of(new ManagedKeyProofVerifier(store, authority, verifier, pureEdDsaMaximumTbsBytes));
    }

    @Override public void advance(SignWorkflowStore.Workflow workflow) {
        SignWorkflowStore.Workflow exact = Objects.requireNonNull(workflow, "workflow");
        if (exact.state() == SignWorkflowStore.State.DISPATCHED
                && exact.stage() == SignWorkflowStore.Stage.CA_PROOF_VERIFYING) {
            advanceCaProof(exact);
            return;
        }
        for (int attempt = 0; attempt < MAXIMUM_CAS_ATTEMPTS; attempt++) {
            Optional<DomainContinuationStore.Record> loaded =
                    store.getDomainContinuation(exact.operationId());
            if (loaded.isEmpty()) {
                throw new IllegalStateException("Signing outer continuation is missing");
            }
            DomainContinuationStore.Record domain = loaded.orElseThrow();
            if (domain.kind() == DomainContinuationStore.Kind.KEY_PROOF) {
                ManagedKeyProofBindings.requireWorkflow(exact, domain);
            }
            if (terminal(domain.state())) {
                retire(exact);
                return;
            }
            Optional<DomainContinuationStore.Record> changed = switch (exact.state()) {
                case SUCCEEDED -> advanceSuccess(domain, exact);
                case FAILED, CANCELLED -> store.transitionDomainContinuation(
                        domain.operationId(), domain.revision(),
                        DomainContinuationStore.State.FAILED, Optional.empty(),
                        Optional.of(exact.state() == SignWorkflowStore.State.CANCELLED
                                ? "CANCELLED" : exact.detailCode().orElse("SIGNING_FAILED")));
                case EXPIRED -> store.transitionDomainContinuation(domain.operationId(),
                        domain.revision(), DomainContinuationStore.State.EXPIRED,
                        Optional.empty(), Optional.of("EXPIRED"));
                default -> throw new IllegalArgumentException("Signing workflow is not terminal");
            };
            if (changed.filter(value -> terminal(value.state())).isPresent()) {
                retire(exact);
                return;
            }
        }
        throw new IllegalStateException("Signing outer continuation did not converge");
    }

    private void advanceCaProof(SignWorkflowStore.Workflow workflow) {
        try {
            proof.orElseThrow(() -> new IllegalStateException("Managed key proof verifier unavailable"))
                    .verifyComposite(workflow);
            store.completeCaProofVerification(workflow.operationId(), workflow.revision(), workflow.fence())
                    .filter(changed -> changed.state() == SignWorkflowStore.State.EXPIRED)
                    .ifPresent(this::advance);
        } catch (DomainContinuationPublisher.PostconditionFailure failure) {
            store.transitionSign(workflow.operationId(), workflow.revision(), workflow.fence(),
                    SignWorkflowStore.State.FAILED, Optional.of(failure.getMessage()), Optional.empty(), Optional.empty())
                    .ifPresent(this::advance);
        }
    }

    private Optional<DomainContinuationStore.Record> advanceSuccess(
            DomainContinuationStore.Record domain, SignWorkflowStore.Workflow workflow) {
        EncodedObject signature = workflow.result().orElseThrow();
        DomainContinuationStore.Record publishing = domain;
        if (domain.state() == DomainContinuationStore.State.SIGNING) {
            Optional<DomainContinuationStore.Record> changed = store.transitionDomainContinuation(
                    domain.operationId(), domain.revision(),
                    DomainContinuationStore.State.PUBLISHING, Optional.empty(), Optional.empty());
            if (changed.isEmpty()) {
                return Optional.empty();
            }
            publishing = changed.orElseThrow();
        }
        EncodedObject result;
        try {
            if (publishing.kind() == DomainContinuationStore.Kind.KEY_PROOF) {
                result = proof.orElseThrow(() -> new IllegalStateException("Managed key proof verifier unavailable"))
                        .verify(publishing, workflow);
            } else if (FullCrlSigningCommand.supports(DomainCommandEncoding.decode(publishing.command()).operation())) {
                result = fullCrl.publish(publishing, signature);
            } else {
                result = publisher.reconstruct(publishing, signature);
                publisher.publish(publishing, result);
            }
        } catch (DomainContinuationPublisher.PostconditionFailure failure) {
            return store.transitionDomainContinuation(publishing.operationId(),
                    publishing.revision(), DomainContinuationStore.State.FAILED,
                    Optional.empty(), Optional.of(failure.getMessage()));
        }
        return store.transitionDomainContinuation(publishing.operationId(),
                publishing.revision(), DomainContinuationStore.State.COMPLETED,
                Optional.of(result), Optional.of("COMPLETED"));
    }

    private void retire(SignWorkflowStore.Workflow workflow) {
        store.retireSign(workflow.operationId(), workflow.revision(), workflow.fence());
    }

    private static boolean terminal(DomainContinuationStore.State state) {
        return state == DomainContinuationStore.State.COMPLETED
                || state == DomainContinuationStore.State.FAILED
                || state == DomainContinuationStore.State.EXPIRED;
    }
}
