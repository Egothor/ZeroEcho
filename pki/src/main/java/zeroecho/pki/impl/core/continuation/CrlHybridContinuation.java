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

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.CrlSigningRoleTuple;
import zeroecho.pki.impl.framework.x509.StreamingCrlAlternativeSignature;
import zeroecho.pki.impl.framework.x509.StreamingCrlSignatureVerifier;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.store.CrlHybridExecution;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pkix.Pkix;

/**
 * The sole STATUS parent drives one retained ALT result and one private native child.
 */
final class CrlHybridContinuation {
    private final PkiStore store;
    private final X509BindingCatalog bindings;
    private final long pureMaximum;
    private final FullCrlContinuationPublisher publisher;

    /**
     * Creates a hybrid CRL driver borrowing the store, bindings, and streaming publisher.
     *
     * @param store borrowed PKI store; must not be null
     * @param bindings immutable X.509 binding catalogue
     * @param pureMaximum maximum pure-EdDSA message length in bytes
     * @param publisher borrowed completed-CRL publisher
     */
    CrlHybridContinuation(PkiStore store, X509BindingCatalog bindings, long pureMaximum,
            FullCrlContinuationPublisher publisher) {
        this.store = store; this.bindings = bindings; this.pureMaximum = pureMaximum; this.publisher = publisher;
    }

    /**
     * Advances or retires one durable hybrid CRL parent and its captured native child.
     *
     * <p>Reloads authoritative workflow state, preserves captured commitments, and records
     * terminal publication outcomes without resubmitting the alternative signature.</p>
     *
     * @param supplied parent workflow identity to reload from authoritative storage
     * @throws IllegalStateException if required alternative-signature output is not retained
     * @throws PkiException if advancing the hybrid continuation fails and requires recovery
     */
    void advance(SignWorkflowStore.Workflow supplied) {
        var parent = store.getSignWorkflow(supplied.operationId()).orElseThrow();
        var domain = store.getDomainContinuation(parent.operationId()).orElseThrow();
        if (terminal(domain)) { retire(parent); return; }
        if (parent.state() == SignWorkflowStore.State.FAILED || parent.state() == SignWorkflowStore.State.CANCELLED
                || parent.state() == SignWorkflowStore.State.EXPIRED) {
            finish(domain, parent.state() == SignWorkflowStore.State.EXPIRED ? DomainContinuationStore.State.EXPIRED
                    : DomainContinuationStore.State.FAILED, parent.detailCode().orElse("SIGNING_FAILED"), Optional.empty());
            retire(parent); return;
        }
        if (parent.state() != SignWorkflowStore.State.SUCCEEDED) throw new IllegalStateException("Hybrid CRL alternative result is not retained");
        if (domain.state() == DomainContinuationStore.State.SIGNING) {
            var changed = store.transitionDomainContinuation(domain.operationId(), domain.revision(),
                    DomainContinuationStore.State.PUBLISHING, Optional.empty(), Optional.empty());
            if (changed.isEmpty()) return;
            domain = changed.orElseThrow();
        }
        try {
            var command = DomainCommandEncoding.decode(domain.command());
            FullCrlSigningCommand.validate(command);
            var descriptor = CrlHybridSigningCommand.descriptor(command);
            var execution = store.getCrlHybridExecution(parent.operationId()).orElseThrow();
            var binding = store.getIssuerCryptographicBinding(new PkiId(command.field(6))).orElseThrow();
            if (!binding.commitment().equals(descriptor.issuerBindingCommitment())
                    || !execution.parentCommandCommitment().equals(domain.commandCommitment())
                    || !execution.nativeChildId().equals(descriptor.nativeChildId())) throw invalid("HYBRID_CRL_CAPTURE_DIFFERS");
            if (execution.phase() == SignWorkflowStore.CrlHybridPhase.AWAITING_ALT) {
                if (!store.signingNow().isBefore(parent.deadline())) {
                    finish(domain, DomainContinuationStore.State.EXPIRED, "EXPIRED", Optional.empty()); retire(parent); return;
                }
                execution = adopt(parent, domain, command, binding, execution);
                if (execution == null) return;
            }
            var child = store.getSignWorkflow(execution.nativeChildId()).orElseThrow();
            if ((child.state() == SignWorkflowStore.State.SUCCEEDED || child.state() == SignWorkflowStore.State.RETIRED)
                    && child.result().isPresent() && child.detailCode().filter("SIGNED"::equals).isPresent()) {
                EncodedObject result = publisher.publishHybrid(domain, execution, parent, child);
                finish(domain, DomainContinuationStore.State.COMPLETED, "COMPLETED", Optional.of(result));
                retire(parent);
            } else if (child.state() == SignWorkflowStore.State.FAILED || child.state() == SignWorkflowStore.State.CANCELLED
                    || child.state() == SignWorkflowStore.State.EXPIRED || child.state() == SignWorkflowStore.State.RETIRED) {
                finish(domain, child.state() == SignWorkflowStore.State.EXPIRED ? DomainContinuationStore.State.EXPIRED
                        : DomainContinuationStore.State.FAILED, child.detailCode().orElse("HYBRID_CRL_NATIVE_FAILED"), Optional.empty());
                retire(parent);
            }
        } catch (DomainContinuationPublisher.PostconditionFailure failure) {
            finish(domain, DomainContinuationStore.State.FAILED, failure.getMessage(), Optional.empty()); retire(parent);
        } catch (IOException | GeneralSecurityException failure) {
            throw new PkiException("Hybrid CRL continuation requires recovery", failure);
        }
    }

    private CrlHybridExecution adopt(SignWorkflowStore.Workflow parent, DomainContinuationStore.Record domain,
            DomainCommandEncoding.Decoded command, IssuerCryptographicBinding binding, CrlHybridExecution execution)
            throws IOException, GeneralSecurityException {
        var descriptor = CrlHybridSigningCommand.descriptor(command);
        byte[] alternativeSignature = parent.result().orElseThrow().bytes();
        DurableContentReference nativeTbs = null;
        boolean custodyUncertain = false;
        try (RepeatableContent alternativeTbs = store.stagedContent().openContent(parent.envelope().candidate())) {
            var alternative = binding.alternative().orElseThrow();
            byte[] certificateBytes = new DomainContentAccess(store).materialize(store.getCredential(binding.credentialId())
                    .orElseThrow().content(), "HYBRID_CRL_ISSUER_INVALID");
            var certificate = Pkix.parseCertificate(certificateBytes);
            var layout = new StreamingDerReader().inspectAlternativeCrlTbs(alternativeTbs, CancellationSignal.NONE);
            if (parent.result().orElseThrow().encoding() != Encoding.BINARY || alternativeSignature.length == 0
                    || alternativeSignature.length > descriptor.alternativeMaximumSignatureBytes()
                    || !Arrays.equals(layout.alternativeAlgorithmDer(), alternative.signatureAlgorithmIdentifier().bytes())
                    || !layout.crlNumber().toString().equals(command.field(10))) throw invalid("HYBRID_CRL_ALTERNATIVE_INVALID");
            FullCrlSigningCommand.requireAdmission(alternative.signatureAlgorithm().canonicalForm(), layout.encodedLength(), pureMaximum);
            try {
                if (!StreamingCrlSignatureVerifier.verify(alternativeTbs, alternative.signatureAlgorithm().canonicalForm(),
                        CrlSigningRoleTuple.alternativeSpki(certificate), alternativeSignature, bindings, CancellationSignal.NONE).equals(command.field(28)))
                    throw invalid("HYBRID_CRL_ALTERNATIVE_INVALID");
            } catch (GeneralSecurityException | IllegalArgumentException | IOException failure) {
                throw new DomainContinuationPublisher.PostconditionFailure("HYBRID_CRL_ALTERNATIVE_INVALID", failure);
            }
            try (var sink = store.stagedContent().beginContent(Encoding.DER, DurableContentReference.Lifecycle.OPERATION);
                    OutputStream output = sink.outputStream()) {
                long length = StreamingCrlAlternativeSignature.completeTbs(alternativeTbs,
                        BcX509AlgorithmAdapter.fromLib(Pkix.parseAlgorithmIdentifier(java.util.HexFormat.of().parseHex(command.field(9)))),
                        alternativeSignature, output, CancellationSignal.NONE);
                FullCrlSigningCommand.requireAdmission(command.field(8), length, pureMaximum);
                nativeTbs = sink.complete();
                if (nativeTbs == null || nativeTbs.length() != length || nativeTbs.encoding() != Encoding.DER
                        || nativeTbs.lifecycle() != DurableContentReference.Lifecycle.OPERATION
                        || !store.stagedContent().contentStoreId().equals(nativeTbs.storeId())) throw invalid("HYBRID_CRL_NATIVE_CONTENT_INVALID");
            }
            var envelope = parent.envelope();
            var child = new SignWorkflowStore.AcceptanceCommand(descriptor.nativeChildId(), envelope.providerNamespace(),
                    envelope.providerConfigurationCommitment(), envelope.accessContext(), binding.primary().keyRef(),
                    envelope.fairnessAuthorityId(), binding.primary().signatureAlgorithm().canonicalForm(), Encoding.BINARY,
                    envelope.createdAt(), envelope.deadline(), nativeTbs, Optional.empty(), SignWorkflowStore.Mode.NORMAL, Optional.empty());
            SignWorkflowStore.AcceptanceResult result;
            try {
                custodyUncertain = true;
                result = store.adoptCrlNativeChild(parent.operationId(), parent.revision(), parent.fence(), execution.revision(), child);
                custodyUncertain = false;
            } catch (RuntimeException uncertain) {
                var resolution = store.resolveCrlNativeChild(parent.operationId(), child.commitment());
                if (resolution == SignWorkflowStore.AcceptanceResolution.MATCHED) {
                    nativeTbs = null;
                    return store.getCrlHybridExecution(parent.operationId()).orElseThrow();
                }
                custodyUncertain = false;
                if (resolution == SignWorkflowStore.AcceptanceResolution.CONFLICT) throw invalid("HYBRID_CRL_CHILD_CONFLICT");
                if (uncertain instanceof IllegalArgumentException)
                    throw new DomainContinuationPublisher.PostconditionFailure("HYBRID_CRL_CHILD_REJECTED", uncertain);
                throw uncertain;
            }
            if (result == SignWorkflowStore.AcceptanceResult.ACCEPTED || result == SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING) {
                nativeTbs = null;
                return store.getCrlHybridExecution(parent.operationId()).orElseThrow();
            }
            if (result == SignWorkflowStore.AcceptanceResult.CONFLICT) throw invalid("HYBRID_CRL_CHILD_CONFLICT");
            throw new PkiException("Hybrid CRL native admission requires recovery");
        } finally {
            Arrays.fill(alternativeSignature, (byte) 0);
            if (nativeTbs != null && !custodyUncertain) store.stagedContent().retireUnownedContent(nativeTbs);
        }
    }

    private void finish(DomainContinuationStore.Record domain, DomainContinuationStore.State state, String detail,
            Optional<EncodedObject> result) {
        store.transitionDomainContinuation(domain.operationId(), domain.revision(), state, result, Optional.of(detail));
    }

    private void retire(SignWorkflowStore.Workflow parent) {
        var current = store.getSignWorkflow(parent.operationId()).orElseThrow();
        var domain = store.getDomainContinuation(parent.operationId()).orElseThrow();
        if (!terminal(domain)) return;
        var execution = store.getCrlHybridExecution(parent.operationId()).orElseThrow();
        SignWorkflowStore.Workflow child = null;
        if (execution.phase() == SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED) {
            child = store.getSignWorkflow(execution.nativeChildId()).orElseThrow();
            if (child.state() == SignWorkflowStore.State.INTENT || child.state() == SignWorkflowStore.State.DISPATCHED
                    || child.state() == SignWorkflowStore.State.CANCELLING) return;
        }
        store.retireSign(current.operationId(), current.revision(), current.fence());
        if (child != null && child.state() != SignWorkflowStore.State.RETIRED)
            store.retireSign(child.operationId(), child.revision(), child.fence());
    }

    private static boolean terminal(DomainContinuationStore.Record domain) {
        return domain.state() == DomainContinuationStore.State.COMPLETED || domain.state() == DomainContinuationStore.State.FAILED
                || domain.state() == DomainContinuationStore.State.EXPIRED;
    }
    private static DomainContinuationPublisher.PostconditionFailure invalid(String code) {
        return new DomainContinuationPublisher.PostconditionFailure(code);
    }
}
