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

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Optional;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

/** Exact immutable binding between an internal proof and its parent CA/TBS intent. */
public final class CaSubjectProofBindings {
    private CaSubjectProofBindings() { }

    /**
     * Checks retained metadata without opening either candidate or resolving codecs.
     * @param envelope accepted composite CA envelope
     * @return exact frozen proof command
     */
    public static DomainCommandEncoding.Decoded requireEnvelope(SignWorkflowStore.AcceptanceEnvelope envelope) {
        SignWorkflowStore.CaSubjectProofStep step = envelope.proofStep().orElseThrow(CaSubjectProofBindings::invalid);
        IntermediateSigningCommand.requireEnvelope(envelope);
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(envelope.outer().orElseThrow().command());
        DomainCommandEncoding.Decoded proof = IntermediateSigningCommand.validate(command);
        if (!command.field(18).equals(step.operationId().value())
                || !command.field(6).equals(step.subjectKeyRef().value())
                || !proof.field(8).equals(step.algorithmId()) || !envelope.algorithmId().equals(step.algorithmId())) { throw invalid(); }
        ManagedKeyProofBindings.requireCandidate(proof, step.challenge());
        return proof;
    }

    /**
     * Reads both bounded live candidates and rejects challenge, intent, algorithm,
     * SPKI or final-TBS substitution. No signature verification/provider call occurs.
     * @param store owning content store
     * @param envelope accepted/prospective composite envelope
     * @throws IOException if content integrity or canonical DER validation fails
     */
    public static void requireLiveCandidates(StagedContentStore store, SignWorkflowStore.AcceptanceEnvelope envelope) throws IOException {
        DomainCommandEncoding.Decoded proof = requireEnvelope(envelope);
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(envelope.outer().orElseThrow().command());
        SignWorkflowStore.CaSubjectProofStep step = envelope.proofStep().orElseThrow();
        String intent = CaSigningIntent.commitmentOfCanonicalAlgorithm(command, envelope.algorithmId());
        byte[] challenge = ManagedKeyProofBindings.readChallenge(store, step.operationId(), envelope.deadline(),
                Optional.of(new ManagedKeyProofChallenge.CaContext(envelope.operationId(), intent)), proof, step.challenge());
        ManagedKeyProofChallenge.Decoded decoded = ManagedKeyProofChallenge.decode(challenge);
        byte[] tbs;
        try (RepeatableContent content = store.openContent(envelope.candidate()); InputStream input = content.openStream()) {
            int length = Math.toIntExact(envelope.candidate().length());
            tbs = input.readNBytes(length);
            if (tbs.length != length || input.read() != -1
                    || !ContentCommitment.sha256(tbs).sha256().equals(command.field(22))) { throw invalid(); }
        }
        StreamingDerReader.CertificateTbsLayout layout = new StreamingDerReader()
                .inspectUnsignedCertificateTbs(tbs, 1_048_576);
        byte[] spki = decoded.spki();
        byte[] algorithm = ManagedKeyProofCommand.hex(proof.field(9), 1,
                ManagedKeyProofCommand.MAX_ALGORITHM_DER_BYTES);
        if (!Arrays.equals(tbs, layout.subjectPublicKeyInfoOffset(),
                    Math.addExact(layout.subjectPublicKeyInfoOffset(), layout.subjectPublicKeyInfoLength()),
                    spki, 0, spki.length)
                || !Arrays.equals(tbs, layout.algorithmOffset(),
                    Math.addExact(layout.algorithmOffset(), layout.algorithmLength()), algorithm, 0, algorithm.length)) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("CA subject proof binding differs"); }
}
