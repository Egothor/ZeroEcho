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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofBindings;

/** Read-only full-bijection validation of recovered signing metadata. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.CyclomaticComplexity", "PMD.PreserveStackTrace" })
final class SigningRecoveryIntegrityValidator {
    private static final String SIGN_STATE_NAMESPACE = "io.zeroecho.pki.signing-state";
    private static final String SIGN_ENVELOPE_NAMESPACE = "io.zeroecho.pki.signing-envelope";
    private static final String SIGN_BINDING_NAMESPACE =
            "io.zeroecho.pki.signing-candidate-binding";
    private static final String DOMAIN_CONTINUATION_NAMESPACE = // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.
            "io.zeroecho.pki.domain-continuation";
    private static final String DOMAIN_CORRELATION_NAMESPACE =
            "io.zeroecho.pki.domain-correlation";
    private static final String FAILURE_MESSAGE =
            "Metadata ledger format unsupported: code=METADATA_FORMAT_UNSUPPORTED";

    private final Path root;
    private final StagedContentStore stagedContent;
    private final Map<Long, String> artifacts;
    private final Map<MetadataKey, SigningMvccIndex.RecoveredRecord> records;
    private final Map<String, SignWorkflowStore.SchedulingPlan> schedulingByOperation =
            new HashMap<>();
    private long currentTrackedEnvelopeWorkspaceBytes; // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.
    private long peakTrackedEnvelopeWorkspaceBytes; // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.

    private SigningRecoveryIntegrityValidator(Path root,
            SigningManifestCodec.Manifest manifest,
            SigningLedgerRecoveredState.State recovered,
            StagedContentStore stagedContent) throws IOException {
        this.root = Objects.requireNonNull(root, "root");
        this.stagedContent = stagedContent;
        artifacts = artifactNames(Objects.requireNonNull(manifest, "manifest"));
        records = new HashMap<>();
        for (SigningMvccIndex.RecoveredRecord record :
                Objects.requireNonNull(recovered, "recovered").records()) {
            if (records.put(record.key(), record) != null) {
                throw malformed();
            }
        }
    }

    /* default */ static ValidatedSigningRecovery validate(Path root,
            SigningManifestCodec.Manifest manifest,
            SigningLedgerRecoveredState.State recovered, StagedContentStore stagedContent)
            throws IOException {
        try {
            SigningRecoveryIntegrityValidator validator =
                    new SigningRecoveryIntegrityValidator(root, manifest, recovered,
                            stagedContent);
            validator.validateGraph();
            return new ValidatedSigningRecovery(validator.schedulingByOperation,
                    validator.peakTrackedEnvelopeWorkspaceBytes,
                    validator.currentTrackedEnvelopeWorkspaceBytes);
        } catch (MalformedRecoveryDataException | FsCodec.MalformedPayloadException
                | RuntimeException failure) {
            throw new IntegrityException();
        }
    }

    private void validateGraph() throws IOException {
        Map<MetadataKey, SigningMvccIndex.RecoveredRecord> states = namespace(
                SIGN_STATE_NAMESPACE);
        Map<MetadataKey, SigningMvccIndex.RecoveredRecord> envelopes = namespace(
                SIGN_ENVELOPE_NAMESPACE);
        Map<MetadataKey, SigningMvccIndex.RecoveredRecord> bindings = namespace(
                SIGN_BINDING_NAMESPACE);
        Map<MetadataKey, SigningMvccIndex.RecoveredRecord> continuations = namespace(
                DOMAIN_CONTINUATION_NAMESPACE);
        Map<MetadataKey, SigningMvccIndex.RecoveredRecord> correlations = namespace(
                DOMAIN_CORRELATION_NAMESPACE);
        Set<MetadataKey> consumedEnvelopes = new HashSet<>();
        Set<MetadataKey> consumedBindings = new HashSet<>();
        Set<MetadataKey> consumedContinuations = new HashSet<>();
        Set<MetadataKey> consumedCorrelations = new HashSet<>();

        for (Map.Entry<MetadataKey, SigningMvccIndex.RecoveredRecord> entry :
                states.entrySet()) {
            validateWorkflow(entry.getKey(), entry.getValue(), envelopes, bindings,
                    continuations, correlations, consumedEnvelopes, consumedBindings,
                    consumedContinuations, consumedCorrelations);
        }
        requireComplete(envelopes, consumedEnvelopes);
        requireComplete(bindings, consumedBindings);
        requireComplete(continuations, consumedContinuations);
        requireComplete(correlations, consumedCorrelations);
    }

    // Explicit collaborators or atomic persisted coordinates remain visible at this boundary.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    private void validateWorkflow(MetadataKey stateKey,
            SigningMvccIndex.RecoveredRecord stateRecord,
            Map<MetadataKey, SigningMvccIndex.RecoveredRecord> envelopes,
            Map<MetadataKey, SigningMvccIndex.RecoveredRecord> bindings,
            Map<MetadataKey, SigningMvccIndex.RecoveredRecord> continuations,
            Map<MetadataKey, SigningMvccIndex.RecoveredRecord> correlations,
            Set<MetadataKey> consumedEnvelopes, Set<MetadataKey> consumedBindings,
            Set<MetadataKey> consumedContinuations, Set<MetadataKey> consumedCorrelations)
            throws IOException {
        SignWorkflowStore.MutableState state = FsCodec.decodeRecovery(FsCodec.SIGN_MUTABLE_STATE,
                readValue(stateRecord), stagedContent);
        PkiId operationId = state.operationId();
        requireKey(stateKey, SIGN_STATE_NAMESPACE, operationId.value());
        MetadataKey envelopeKey = new MetadataKey(SIGN_ENVELOPE_NAMESPACE, operationId.value());
        SigningMvccIndex.RecoveredRecord envelopeRecord = requireRecord(envelopes, envelopeKey);
        requireConsumed(consumedEnvelopes, envelopeKey);
        SignWorkflowStore.AcceptanceEnvelope envelope = decodeAndProjectEnvelope(
                envelopeRecord, operationId);
        new SignWorkflowStore.Workflow(envelope, state);

        for (zeroecho.pki.api.content.DurableContentReference candidate : new SignWorkflowStore.Workflow(envelope, state).candidates()) {
            String candidateId = candidate.contentId();
            MetadataKey bindingKey = new MetadataKey(SIGN_BINDING_NAMESPACE, candidateId);
            SigningMvccIndex.RecoveredRecord bindingRecord = requireRecord(bindings, bindingKey);
            requireConsumed(consumedBindings, bindingKey);
            SignWorkflowStore.CandidateBinding binding = FsCodec.decodeRecovery(FsCodec.SIGN_CANDIDATE_BINDING, readValue(bindingRecord));
            if (!candidateId.equals(binding.candidateId()) || !operationId.equals(binding.operationId())
                    || candidate.length() != binding.length() || !candidate.sha256().equals(binding.sha256())) { throw malformed(); }
        }
        if (envelope.proofStep().isPresent()) {
            zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.requireEnvelope(envelope);
            if (state.state() != SignWorkflowStore.State.RETIRED && state.state() != SignWorkflowStore.State.EXPIRED) {
                zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.requireLiveCandidates(stagedContent, envelope);
            }
        }

        validateOuter(new SignWorkflowStore.Workflow(envelope, state), continuations, correlations, consumedContinuations,
                consumedCorrelations);
    }

    private SignWorkflowStore.AcceptanceEnvelope decodeAndProjectEnvelope(
            SigningMvccIndex.RecoveredRecord envelopeRecord, PkiId operationId)
            throws IOException {
        byte[] workspace = readValue(envelopeRecord);
        acquireEnvelopeWorkspace(workspace.length);
        try {
            SignWorkflowStore.AcceptanceEnvelope envelope = FsCodec.decodeRecovery(
                    FsCodec.SIGN_ACCEPTANCE_ENVELOPE, workspace, stagedContent);
            if (!operationId.equals(envelope.operationId())) {
                throw malformed();
            }
            if (schedulingByOperation.put(operationId.value(),
                    SignWorkflowStore.SchedulingPlan.from(envelope)) != null) {
                throw malformed();
            }
            return envelope;
        } finally {
            releaseEnvelopeWorkspace(workspace.length);
        }
    }

    private void acquireEnvelopeWorkspace(long bytes) {
        currentTrackedEnvelopeWorkspaceBytes = Math.addExact(
                currentTrackedEnvelopeWorkspaceBytes, bytes);
        peakTrackedEnvelopeWorkspaceBytes = Math.max(peakTrackedEnvelopeWorkspaceBytes,
                currentTrackedEnvelopeWorkspaceBytes);
    }

    private void releaseEnvelopeWorkspace(long bytes) {
        currentTrackedEnvelopeWorkspaceBytes = Math.subtractExact(
                currentTrackedEnvelopeWorkspaceBytes, bytes);
        if (currentTrackedEnvelopeWorkspaceBytes < 0) {
            throw new IllegalStateException("Signing envelope workspace accounting underflow");
        }
    }

    private void validateOuter(SignWorkflowStore.Workflow workflow,
            Map<MetadataKey, SigningMvccIndex.RecoveredRecord> continuations,
            Map<MetadataKey, SigningMvccIndex.RecoveredRecord> correlations,
            Set<MetadataKey> consumedContinuations, Set<MetadataKey> consumedCorrelations)
            throws IOException {
        SignWorkflowStore.AcceptanceEnvelope envelope = workflow.envelope();
        if (envelope.outer().isEmpty()) {
            return;
        }
        PkiId operationId = envelope.operationId();
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow();
        MetadataKey continuationKey = new MetadataKey(
                DOMAIN_CONTINUATION_NAMESPACE, operationId.value());
        SigningMvccIndex.RecoveredRecord continuationRecord = requireRecord(
                continuations, continuationKey);
        requireConsumed(consumedContinuations, continuationKey);
        byte[] encodedContinuation = readValue(continuationRecord);
        DomainContinuationStore.Record continuation = DomainContinuationValidation.validate(
                operationId, FsCodec.decodeRecovery(FsCodec.DOMAIN_CONTINUATION,
                        encodedContinuation, stagedContent), encodedContinuation.length);
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(continuation.command());
        validateOuterContent(workflow, continuation, command);
        boolean sameCommand = outer.command().encoding() == continuation.command().encoding()
                && MessageDigest.isEqual(outer.command().bytes(), continuation.command().bytes());
        boolean liveContentMatches = switch (continuation.state()) {
            case SIGNING, PUBLISHING -> continuation.signingContent()
                    .filter(envelope.candidate()::equals).isPresent();
            case COMPLETED, FAILED, EXPIRED -> true;
        };
        if (continuation.kind() != outer.kind()
                || continuation.correlationId().filter(outer.correlationId()::equals).isEmpty()
                || !outer.commandCommitment().equals(continuation.commandCommitment())
                || !envelope.createdAt().equals(continuation.createdAt())
                || !envelope.deadline().equals(continuation.deadline())
                || !liveContentMatches
                || !sameCommand) {
            throw malformed();
        }

        MetadataKey correlationKey = correlationKey(outer.kind(), outer.correlationId());
        SigningMvccIndex.RecoveredRecord correlationRecord = requireRecord(
                correlations, correlationKey);
        requireConsumed(consumedCorrelations, correlationKey);
        if (!Arrays.equals(correlationValue(operationId), readValue(correlationRecord))) {
            throw malformed();
        }
    }

    private Map<MetadataKey, SigningMvccIndex.RecoveredRecord> namespace(String namespace) {
        Map<MetadataKey, SigningMvccIndex.RecoveredRecord> result = new HashMap<>();
        for (Map.Entry<MetadataKey, SigningMvccIndex.RecoveredRecord> entry : records.entrySet()) {
            if (namespace.equals(entry.getKey().namespace())) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    private byte[] readValue(SigningMvccIndex.RecoveredRecord record) throws IOException {
        String artifact = artifacts.get(record.pointer().generationId());
        if (artifact == null) {
            throw malformed();
        }
        byte[] encoded = new byte[record.pointer().frameLength()];
        try (FileChannel channel = FileChannel.open(root.resolve(artifact),
                StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            channel.position(record.pointer().frameOffset());
            if (SigningFormatSupport.readAvailable(channel, ByteBuffer.wrap(encoded))
                    != encoded.length) {
                throw malformed();
            }
        }
        final SigningWalFrameCodec.Frame frame;
        try {
            frame = SigningWalFrameCodec.decode(encoded);
        } catch (IOException malformed) {
            throw malformed();
        }
        if (frame.sequence() != record.pointer().sequence()
                || frame.recordType() != record.pointer().recordType()) {
            throw malformed();
        }
        final SigningTransactionPayloadCodec.Payload payload;
        try {
            payload = SigningTransactionPayloadCodec.decode(frame.payload());
        } catch (IOException malformed) {
            throw malformed();
        }
        if (payload.kind() != SigningTransactionPayloadCodec.Kind.COMMIT
                && payload.kind() != SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT) {
            throw malformed();
        }
        for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
            if (mutation.key().equals(record.key()) && mutation.content() != null) {
                return mutation.content();
            }
        }
        throw malformed();
    }

    private static Map<Long, String> artifactNames(SigningManifestCodec.Manifest manifest)
            throws IOException {
        Map<Long, String> result = new HashMap<>();
        if (manifest.checkpoint().isPresent()) {
            SigningManifestCodec.Checkpoint checkpoint = manifest.checkpoint().orElseThrow();
            putArtifact(result, checkpoint.generationIdentity(), checkpoint.name());
        }
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            putArtifact(result, segment.generationIdentity(), segment.name());
        }
        putArtifact(result, manifest.activeWal().identity(), manifest.activeWal().name());
        return Map.copyOf(result);
    }

    private static void putArtifact(Map<Long, String> artifacts, long identity, String name)
            throws IOException {
        if (artifacts.put(identity, name) != null) {
            throw malformed();
        }
    }

    private static SigningMvccIndex.RecoveredRecord requireRecord(
            Map<MetadataKey, SigningMvccIndex.RecoveredRecord> source, MetadataKey key)
            throws IOException {
        SigningMvccIndex.RecoveredRecord result = source.get(key);
        if (result == null) {
            throw malformed();
        }
        return result;
    }

    private static void requireConsumed(Set<MetadataKey> consumed, MetadataKey key)
            throws IOException {
        if (!consumed.add(key)) {
            throw malformed();
        }
    }

    private static void requireComplete(
            Map<MetadataKey, SigningMvccIndex.RecoveredRecord> source,
            Set<MetadataKey> consumed) throws IOException {
        if (source.size() != consumed.size() || !source.keySet().equals(consumed)) {
            throw malformed();
        }
    }

    private static void requireKey(MetadataKey key, String namespace, String identity)
            throws IOException {
        if (!namespace.equals(key.namespace()) || !identity.equals(key.key())) {
            throw malformed();
        }
    }

    private static MalformedRecoveryDataException malformed() {
        return new MalformedRecoveryDataException();
    }

    private static MetadataKey correlationKey(DomainContinuationStore.Kind kind,
            String correlationId) {
        try {
            byte[] encoded = (kind.name() + '\n' + correlationId)
                    .getBytes(StandardCharsets.UTF_8);
            return new MetadataKey(DOMAIN_CORRELATION_NAMESPACE,
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(encoded)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static byte[] correlationValue(PkiId operationId) {
        return ("v1\n" + operationId.value()).getBytes(StandardCharsets.UTF_8);
    }

    /** Immutable projection inputs produced by the one semantic-validation pass. */
    /* default */ record ValidatedSigningRecovery(
            Map<String, SignWorkflowStore.SchedulingPlan> schedulingByOperation,
            long peakTrackedEnvelopeWorkspaceBytes, // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.
            long currentTrackedEnvelopeWorkspaceBytes) { // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.
        ValidatedSigningRecovery {
            schedulingByOperation = Map.copyOf(Objects.requireNonNull(
                    schedulingByOperation, "schedulingByOperation"));
            if (peakTrackedEnvelopeWorkspaceBytes < 0
                    || currentTrackedEnvelopeWorkspaceBytes < 0) {
                throw new IllegalArgumentException(
                        "Tracked envelope workspace bytes must not be negative");
            }
        }
    }

    /** Cause-free marker for malformed recovered signing metadata. */
    /* default */ static final class IntegrityException extends IOException {
        private static final long serialVersionUID = 1L;

        private IntegrityException() {
            super(FAILURE_MESSAGE);
        }
    }

    /** Marks malformed durable data independently of operational I/O failure. */
    private static final class MalformedRecoveryDataException extends IOException {
        private static final long serialVersionUID = 1L;
    }


    private void validateOuterContent(SignWorkflowStore.Workflow workflow, DomainContinuationStore.Record continuation,
            DomainCommandEncoding.Decoded command) throws IOException {
        SignWorkflowStore.AcceptanceEnvelope envelope = workflow.envelope();
        PkiId operationId = envelope.operationId();
        if (continuation.kind() == DomainContinuationStore.Kind.KEY_PROOF) {
            ManagedKeyProofBindings.requireWorkflow(workflow, continuation);
            if (continuation.state() == DomainContinuationStore.State.SIGNING
                    || continuation.state() == DomainContinuationStore.State.PUBLISHING) {
                ManagedKeyProofBindings.readChallenge(stagedContent, operationId, envelope.deadline(), java.util.Optional.empty(), command, envelope.candidate());
            }
        }
        if (FullCrlSigningCommand.supports(command.operation())) {
            FullCrlSigningCommand.requireTbs(command, envelope.candidate());
            if (!envelope.algorithmId().equals(command.field(8))) { throw malformed(); }
        }
        if (zeroecho.pki.impl.core.continuation.IntermediateSigningCommand.supports(command.operation())) {
            zeroecho.pki.impl.core.continuation.IntermediateSigningCommand.requireEnvelope(envelope);
        }
    }
}
