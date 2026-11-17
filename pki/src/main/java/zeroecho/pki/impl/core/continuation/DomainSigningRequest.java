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

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.store.SignWorkflowStore;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Exact bounded inputs for one signing operation with durable domain ownership.
 *
 * <p>The request carries references to staged content; constructing it neither opens
 * that content nor transfers its custody to durable acceptance. Proof identities must
 * differ from the parent and share its provider namespace; an alternative proof
 * requires a distinct primary proof.
 * The accepting signing boundary separately validates policy, algorithm, lifetime and
 * content commitments before admitting work.
 *
 * @param operationId internal durable parent operation identifier; must not be null
 * @param accessContext trusted invocation context; must not be null
 * @param keyRef managed signing-key reference, not private key material; must not be null
 * @param algorithmId selected canonical signature algorithm; must not be null
 * @param content durable to-be-signed content reference; must not be null
 * @param ttl requested positive operation lifetime, checked by acceptance; must not be null
 * @param signatureEncoding requested signature encoding; must not be null
 * @param domainTemplate immutable outer-operation template; must not be null
 * @param proofStep parent-owned primary proof step, or an empty optional; must not be null
 * @param alternativeProofStep distinct parent-owned alternative proof step, or an empty
 *        optional; the optional must not be null
 */
public record DomainSigningRequest(PkiId operationId, AccessContext accessContext, KeyRef keyRef,
        String algorithmId, Encoding signatureEncoding,
        DurableContentReference content, Duration ttl,
        DomainContinuationTemplate domainTemplate, Optional<SignWorkflowStore.CaSubjectProofStep> proofStep,
        Optional<SignWorkflowStore.CaSubjectProofStep> alternativeProofStep) {
    /**
     * Requires all components and checks proof-identity namespaces and distinctness.
     *
     * <p>This constructor does not resolve managed keys, open content, validate the requested
     * lifetime or submit an operation. Those checks remain at the consuming signing boundary.
     *
     * @throws NullPointerException if a required component or optional container is null
     * @throws IllegalArgumentException if a proof identity equals the parent or uses another
     *     namespace, an alternative step has no primary step, or both roles reuse the same child
     * @param operationId internal durable parent operation identifier; must not be null
     * @param accessContext trusted invocation context; must not be null
     * @param keyRef managed signing-key reference, not private key material; must not be null
     * @param algorithmId selected canonical signature algorithm; must not be null
     * @param signatureEncoding requested signature encoding; must not be null
     * @param content durable to-be-signed content reference; must not be null
     * @param ttl requested positive operation lifetime, checked by acceptance; must not be null
     * @param domainTemplate immutable outer-operation template; must not be null
     * @param proofStep parent-owned primary proof step, or an empty optional; must not be null
     * @param alternativeProofStep distinct parent-owned alternative proof step, or an empty
     *     optional; the optional must not be null
     */
    public DomainSigningRequest {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(accessContext, "accessContext");
        Objects.requireNonNull(keyRef, "keyRef");
        Objects.requireNonNull(algorithmId, "algorithmId");
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(signatureEncoding, "signatureEncoding");
        Objects.requireNonNull(domainTemplate, "domainTemplate");
        proofStep = Objects.requireNonNull(proofStep, "proofStep");
        alternativeProofStep = Objects.requireNonNull(alternativeProofStep, "alternativeProofStep");
        proofStep.ifPresent(step -> step.requireParent(operationId));
        alternativeProofStep.ifPresent(step -> step.requireParent(operationId));
        if (alternativeProofStep.isPresent() && (proofStep.isEmpty()
                || alternativeProofStep.orElseThrow().operationId().equals(proofStep.orElseThrow().operationId()))) {
            throw new IllegalArgumentException(
                    "Alternative proof requires a distinct primary proof step");
        }
    }
    /**
     * Creates a request with at most one primary subject-key proof.
     *
     * <p>The alternative-proof optional is empty. Content custody remains with the
     * preparation until the consuming service accepts or discards it.
     *
     * @param operationId exact durable parent operation identifier
     * @param accessContext trusted invocation context
     * @param keyRef selected managed issuer key
     * @param algorithmId exact issuer signature algorithm
     * @param signatureEncoding requested signature encoding
     * @param content staged final candidate TBS reference
     * @param ttl requested positive signing lifetime
     * @param domainTemplate immutable outer continuation template
     * @param proofStep parent-owned primary subject proof, or an empty optional
     * @throws NullPointerException if a component or optional container is null
     * @throws IllegalArgumentException if the proof identity equals the parent or uses another namespace
     */
    public DomainSigningRequest(PkiId operationId, AccessContext accessContext, KeyRef keyRef,
            String algorithmId, Encoding signatureEncoding, DurableContentReference content, Duration ttl,
            DomainContinuationTemplate domainTemplate, Optional<SignWorkflowStore.CaSubjectProofStep> proofStep) {
        this(operationId, accessContext, keyRef, algorithmId, signatureEncoding, content, ttl, domainTemplate, proofStep,
                Optional.empty());
    }
    /**
     * Lists the staged candidates whose custody accompanies the preparation.
     *
     * <p>The order is final TBS, primary challenge when present, then alternative
     * challenge when present. The returned list is an unmodifiable snapshot of
     * content references; it neither materializes bytes nor opens or closes content.
     *
     * @return the final candidate and required proof challenges in role order
     */
    public List<DurableContentReference> candidates() {
        List<DurableContentReference> candidates = new ArrayList<>();
        candidates.add(content);
        proofStep.ifPresent(step -> candidates.add(step.challenge()));
        alternativeProofStep.ifPresent(step -> candidates.add(step.challenge()));
        return List.copyOf(candidates);
    }

}
