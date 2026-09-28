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
package zeroecho.pki.impl.core.continuation;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.List;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.content.DurableContentReference;

/**
 * Exact bounded inputs for one signing operation with durable domain ownership.
 * @param operationId private durable operation identifier
 * @param accessContext trusted access context
 * @param keyRef managed signing-key reference
 * @param algorithmId canonical signature algorithm
 * @param content durable to-be-signed content reference
 * @param ttl positive operation lifetime
 * @param signatureEncoding requested signature encoding
 * @param domainTemplate durable outer-operation template
 * @param proofStep optional parent-owned internal CA proof candidate
 */
public record DomainSigningRequest(PkiId operationId, AccessContext accessContext, KeyRef keyRef,
        String algorithmId, Encoding signatureEncoding,
        DurableContentReference content, Duration ttl,
        DomainContinuationTemplate domainTemplate, Optional<SignWorkflowStore.CaSubjectProofStep> proofStep) {
    /** Validates mandatory immutable inputs. */
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
        proofStep.ifPresent(step -> step.requireParent(operationId));
    }
    /** {@return both caller-owned candidates, final TBS first and optional proof second} */
    public List<DurableContentReference> candidates() {
        return proofStep.isEmpty() ? List.of(content) : List.of(content, proofStep.orElseThrow().challenge());
    }

}
