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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;

/**
 * Configuration-independent immutable proof bindings shared by admission,
 * observation and recovery. Metadata checks never reopen retired content. Live
 * challenge checks use bounded O(challenge bytes) time and auxiliary memory.
 */
public final class ManagedKeyProofBindings {
    private ManagedKeyProofBindings() { }

    /**
     * Derives the private correlation bound to an exact submission identity.
     * @param operationId exact submission ID
     * @return deterministic private correlation
     */
    public static String correlation(PkiId operationId) {
        return "key-proof." + ContentCommitment.sha256(operationId.value().getBytes(StandardCharsets.UTF_8)).sha256();
    }

    /**
     * Requires all frozen scalar bindings against an immutable acceptance envelope.
     * @param envelope exact retained or prospective acceptance
     * @return validated complete command
     */
    public static DomainCommandEncoding.Decoded requireEnvelope(SignWorkflowStore.AcceptanceEnvelope envelope) {
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow(ManagedKeyProofBindings::invalid);
        if (outer.kind() != DomainContinuationStore.Kind.KEY_PROOF) { throw invalid(); }
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(new DomainContinuationTemplate(
                outer.kind(), java.util.Optional.of(outer.correlationId()), outer.command(), outer.commandCommitment()));
        SigningSubmissionId id = SigningSubmissionId.parse(envelope.operationId());
        ManagedKeyProofChallenge.requireOperation(envelope.operationId(), command.field(6));
        if (!command.field(6).equals(envelope.providerNamespace()) || !id.namespace().equals(envelope.providerNamespace())
                || !id.createdAt().equals(envelope.createdAt()) || !envelope.deadline().isAfter(envelope.createdAt())
                || !command.field(7).equals(HexFormat.of().formatHex(envelope.providerConfigurationCommitment().bytes()))
                || !command.field(5).equals(envelope.keyRef().value())
                || !command.field(8).equals(envelope.algorithmId())
                || !command.field(1).equals(envelope.fairnessAuthorityId().value())
                || envelope.signatureEncoding() != Encoding.BINARY
                || !correlation(envelope.operationId()).equals(outer.correlationId())) { throw invalid(); }
        requireCandidate(command, envelope.candidate());
        return command;
    }

    /**
     * Checks candidate metadata without opening content or requiring current ownership.
     * @param command complete validated proof command
     * @param candidate exact live or retained candidate reference
     */
    public static void requireCandidate(DomainCommandEncoding.Decoded command, DurableContentReference candidate) {
        if (candidate.encoding() != Encoding.BINARY || candidate.lifecycle() != DurableContentReference.Lifecycle.OPERATION
                || candidate.length() != ManagedKeyProofCommand.positiveLength(command.field(12),
                        ManagedKeyProofCommand.MAX_CHALLENGE_BYTES)
                || !candidate.sha256().equals(command.field(13))) { throw invalid(); }
    }

    /**
     * Reads one live candidate to exact EOF and requires all challenge commitments.
     * Store/content I/O failures propagate without being classified as invalid signatures.
     * @param store owning staged-content store
     * @param operationId exact submission ID
     * @param deadline exact accepted deadline
     * @param context expected parent context, empty for standalone proofs
     * @param command complete validated command
     * @param candidate live candidate reference
     * @return exact bounded challenge bytes for verification
     * @throws IOException if content cannot be read or does not match its commitment
     */
    public static byte[] readChallenge(StagedContentStore store, PkiId operationId, java.time.Instant deadline,
            java.util.Optional<ManagedKeyProofChallenge.CaContext> context,
            DomainCommandEncoding.Decoded command, DurableContentReference candidate) throws IOException {
        requireCandidate(command, candidate);
        int length = Math.toIntExact(candidate.length());
        try (RepeatableContent content = store.openContent(candidate); InputStream input = content.openStream()) {
            byte[] bytes = input.readNBytes(length);
            if (bytes.length != length || input.read() != -1
                    || !ContentCommitment.sha256(bytes).sha256().equals(candidate.sha256())) {
                throw new IOException("Managed key proof challenge integrity differs");
            }
            ManagedKeyProofChallenge.Decoded decoded = ManagedKeyProofChallenge.decode(bytes);
            if (!operationId.equals(decoded.operationId()) || !deadline.equals(decoded.deadline())
                    || !context.equals(decoded.context()) || !command.equals(decoded.command())) { throw invalid(); }
            return bytes;
        }
    }

    /**
     * Validates the exact immutable envelope/continuation and terminal provenance.
     * Completed records validate their marker without opening retired candidate bytes.
     * @param workflow retained signing workflow
     * @param domain associated proof continuation
     * @return complete validated command
     */
    public static DomainCommandEncoding.Decoded requireWorkflow(SignWorkflowStore.Workflow workflow,
            DomainContinuationStore.Record domain) {
        SignWorkflowStore.AcceptanceEnvelope envelope = workflow.envelope();
        DomainCommandEncoding.Decoded command = requireEnvelope(envelope);
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow();
        requireDomainEnvelope(domain, envelope, outer);
        if ((domain.state() == DomainContinuationStore.State.SIGNING || domain.state() == DomainContinuationStore.State.PUBLISHING)
                && domain.signingContent().filter(envelope.candidate()::equals).isEmpty()) { throw invalid(); }
        if (domain.state() == DomainContinuationStore.State.PUBLISHING || domain.state() == DomainContinuationStore.State.COMPLETED) {
            boolean succeeded = workflow.state() == SignWorkflowStore.State.SUCCEEDED
                    || workflow.state() == SignWorkflowStore.State.RETIRED && workflow.detailCode().filter("SIGNED"::equals).isPresent();
            EncodedObject signature = workflow.result().orElseThrow(ManagedKeyProofBindings::invalid);
            if (!succeeded || signature.encoding() != Encoding.BINARY || signature.byteLength() > 1_048_576) { throw invalid(); }
        }
        if (domain.state() == DomainContinuationStore.State.COMPLETED) { requireResult(domain); }
        return command;
    }

    /**
     * Encodes the non-artifact success marker of a proof continuation.
     * @param domain proof continuation
     * @return exact 70-byte binary ASCII success marker
     */
    public static EncodedObject result(DomainContinuationStore.Record domain) {
        if (domain.kind() != DomainContinuationStore.Kind.KEY_PROOF
                || !DomainContinuationTemplate.commitment(domain.command()).equals(domain.commandCommitment())) { throw invalid(); }
        return new EncodedObject(Encoding.BINARY, ("proof:" + domain.commandCommitment().substring("domain:v1:".length()))
                .getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Requires the exact non-artifact proof completion marker.
     * @param domain completed proof continuation with an exact non-artifact marker
     */
    public static void requireResult(DomainContinuationStore.Record domain) {
        EncodedObject actual = domain.result().orElseThrow(ManagedKeyProofBindings::invalid);
        if (actual.encoding() != Encoding.BINARY || actual.byteLength() != 70
                || !MessageDigest.isEqual(actual.bytes(), result(domain).bytes())) { throw invalid(); }
    }

    private static IllegalStateException invalid() {
        return new IllegalStateException("Managed key proof immutable binding is inconsistent");
    }

    private static void requireDomainEnvelope(DomainContinuationStore.Record domain,
            SignWorkflowStore.AcceptanceEnvelope envelope, SignWorkflowStore.OuterCommand outer) {
        if (domain.kind() != DomainContinuationStore.Kind.KEY_PROOF
                || !domain.operationId().equals(envelope.operationId())
                || !domain.createdAt().equals(envelope.createdAt()) || !domain.deadline().equals(envelope.deadline())
                || domain.correlationId().filter(outer.correlationId()::equals).isEmpty()
                || !domain.commandCommitment().equals(outer.commandCommitment())
                || domain.command().encoding() != outer.command().encoding()
                || !MessageDigest.isEqual(domain.command().bytes(), outer.command().bytes())) { throw invalid(); }
    }
}
