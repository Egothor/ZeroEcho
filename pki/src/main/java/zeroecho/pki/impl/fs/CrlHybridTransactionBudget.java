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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.spi.store.CrlHybridExecution;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Real serializer/framing budgets; prototypes are never authority, persisted records or signing inputs. */
final class CrlHybridTransactionBudget {
    private CrlHybridTransactionBudget() { }
    static long maximum(SignWorkflowStore.AcceptanceEnvelope parent, CrlHybridExecution execution,
            SigningHybridCrlDependencies.RowReader rows) throws IOException {
        long[] maximum = {0};
        visitPhases(parent, execution, rows, phase -> maximum[0] = Math.max(maximum[0], SigningTransactionPayloadCodec.encodedCommitSize(phase)));
        return maximum[0];
    }

    static void visitPhases(SignWorkflowStore.AcceptanceEnvelope parent, CrlHybridExecution execution,
            SigningHybridCrlDependencies.RowReader rows, Consumer<List<SigningTransactionPayloadCodec.Mutation>> sink) throws IOException {
        var child = CrlHybridMetadata.futureChildEnvelope(parent, execution, rows);
        var command = zeroecho.pki.impl.core.continuation.DomainCommandEncoding.decode(parent.outer().orElseThrow().command());
        var descriptor = CrlHybridSigningCommand.descriptor(command);
        var initial = new CrlHybridExecution(1, execution.parentId(), execution.parentCommandCommitment(), execution.issuerBindingCommitment(),
                execution.roleTupleCommitment(), execution.nativeChildId(), SignWorkflowStore.CrlHybridPhase.AWAITING_ALT, 0,
                Optional.empty(), Optional.empty(), Optional.empty());
        var linked = new CrlHybridExecution(1, execution.parentId(), execution.parentCommandCommitment(), execution.issuerBindingCommitment(),
                execution.roleTupleCommitment(), execution.nativeChildId(), SignWorkflowStore.CrlHybridPhase.NATIVE_LINKED, 1,
                Optional.of(child.acceptanceCommitment()), Optional.of(child.candidate()), Optional.of("f".repeat(64)));
        byte[] parentSuccess = success(parent, descriptor.alternativeMaximumSignatureBytes());
        byte[] childSuccess = success(child, descriptor.primaryMaximumSignatureBytes());
        var publishing = domain(parent, DomainContinuationStore.State.PUBLISHING, Optional.empty(), Optional.empty());
        var completed = domain(parent, DomainContinuationStore.State.COMPLETED,
                Optional.of(new EncodedObject(Encoding.BINARY, ("crl:" + "f".repeat(64)).getBytes(java.nio.charset.StandardCharsets.US_ASCII))), Optional.of("COMPLETED"));
        var acceptance = new ArrayList<SigningTransactionPayloadCodec.Mutation>();
        acceptance.add(put(FilesystemPkiStore.signingEnvelopeKey(parent.operationId()), FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, parent)));
        acceptance.add(state(parent, FsCodec.encodeSigningState(parent, SignWorkflowStore.MutableState.intent(parent.operationId(), parent.mode(), SignWorkflowStore.Stage.SINGLE))));
        acceptance.add(binding(parent)); acceptance.add(put(FilesystemPkiStore.domainContinuationKey(parent.operationId()), FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, domain(parent, DomainContinuationStore.State.SIGNING, Optional.empty(), Optional.empty()))));
        acceptance.add(put(FilesystemPkiStore.domainCorrelationKey(parent.outer().orElseThrow().kind(), parent.outer().orElseThrow().correlationId()), FilesystemPkiStore.encodeDomainCorrelation(parent.operationId())));
        acceptance.add(put(CrlHybridMetadata.executionKey(parent.operationId()), CrlHybridMetadata.encode(initial)));
        byte[] receiptBytes = rows.read(FsStatusSchedules.receiptKey(parent.operationId()));
        if (receiptBytes != null) {
            var receipt = FsStatusSchedules.decodeExecution(receiptBytes);
            acceptance.add(put(FsStatusSchedules.receiptKey(parent.operationId()), receiptBytes));
            byte[] head = rows.read(FsStatusSchedules.key(receipt.configuration().caId(), receipt.configuration().statusType()));
            if (head == null) throw new IOException("Scheduled hybrid CRL head is missing");
            acceptance.add(put(FsStatusSchedules.key(receipt.configuration().caId(), receipt.configuration().statusType()), head));
        }
        sink.accept(acceptance);
        sink.accept(List.of(state(parent, claimed(parent))));
        sink.accept(List.of(state(parent, parentSuccess)));
        sink.accept(List.of(put(FilesystemPkiStore.domainContinuationKey(parent.operationId()), FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, publishing))));
        sink.accept(List.of(state(parent, parentSuccess), put(FilesystemPkiStore.domainContinuationKey(parent.operationId()), FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, publishing)),
                put(FilesystemPkiStore.signingEnvelopeKey(child.operationId()), FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, child)),
                state(child, FsCodec.encodeSigningState(child, SignWorkflowStore.MutableState.intent(child.operationId(), child.mode(), SignWorkflowStore.Stage.SINGLE))),
                binding(child), put(CrlHybridMetadata.executionKey(parent.operationId()), CrlHybridMetadata.encode(linked)),
                put(CrlHybridMetadata.reverseKey(child.operationId()), CrlHybridMetadata.encode(linked))));
        sink.accept(List.of(state(child, claimed(child))));
        sink.accept(List.of(state(child, childSuccess), state(parent, parentSuccess)));
        sink.accept(List.of(state(child, failed(child)), state(parent, parentSuccess)));
        sink.accept(List.of(state(parent, failed(parent))));
        var statusId = new PkiId("crl:" + "f".repeat(64));
        var statusContent = new BudgetReference(parent.candidate().storeId(), "ffffffff-ffff-ffff-ffff-ffffffffffff", Encoding.DER,
                Long.MAX_VALUE, "f".repeat(64), DurableContentReference.Lifecycle.PERSISTED);
        var status = FullCrlSigningCommand.publicationStatus(statusId, statusContent, publishing, new PkiId("issuer:" + "f".repeat(32)));
        var publication = new ArrayList<SigningTransactionPayloadCodec.Mutation>();
        publication.add(put(FilesystemPkiStore.statusRecordKey(statusId), FsCodec.encode(FsCodec.STATUS_OBJECT, status)));
        publication.add(put(FilesystemPkiStore.statusOwnerKey(statusId), FilesystemPkiStore.encodeStatusOwner(statusId, statusContent)));
        if (receiptBytes != null) {
            var accepted = FsStatusSchedules.decodeExecution(receiptBytes);
            var committed = new StatusScheduleState.Execution(accepted.executionId(), accepted.configuration(), accepted.due(), accepted.fence(),
                    StatusScheduleState.Phase.EFFECT_COMMITTED, accepted.signingOperationId(), accepted.acceptanceCommitment(), Optional.of(statusId), "");
            var key = FsStatusSchedules.key(accepted.configuration().caId(), accepted.configuration().statusType());
            var head = FsStatusSchedules.decodeState(key, rows.read(key));
            publication.add(put(FsStatusSchedules.receiptKey(parent.operationId()), FsStatusSchedules.encodeExecution(committed)));
            publication.add(put(key, FsStatusSchedules.encode(new StatusScheduleState(head.configuration(), head.nextDue(), head.workerRevision(), Optional.of(committed)))));
        }
        publication.add(state(parent, parentSuccess));
        publication.add(put(FilesystemPkiStore.domainContinuationKey(parent.operationId()), FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, publishing)));
        publication.add(put(CrlHybridMetadata.executionKey(parent.operationId()), CrlHybridMetadata.encode(linked)));
        sink.accept(publication);
        sink.accept(List.of(put(FilesystemPkiStore.domainContinuationKey(parent.operationId()), FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, completed)),
                put(CrlHybridMetadata.executionKey(parent.operationId()), CrlHybridMetadata.encode(linked))));
        // Domain failure codes have the actual typed 128-character uppercase bound.
        sink.accept(List.of(put(FilesystemPkiStore.domainContinuationKey(parent.operationId()), FsCodec.encode(FsCodec.DOMAIN_CONTINUATION,
                domain(parent, DomainContinuationStore.State.FAILED, Optional.empty(), Optional.of("F".repeat(128)))))));
        sink.accept(List.of(state(parent, parentSuccess), state(child, childSuccess)));
        var purge = new ArrayList<SigningTransactionPayloadCodec.Mutation>();
        for (var envelope : List.of(parent, child)) {
            purge.add(delete(FilesystemPkiStore.signingEnvelopeKey(envelope.operationId()))); purge.add(delete(FilesystemPkiStore.signingStateKey(envelope.operationId())));
            purge.add(delete(FilesystemPkiStore.signingCandidateBindingKey(envelope.candidate().contentId())));
        }
        purge.add(delete(FilesystemPkiStore.domainContinuationKey(parent.operationId())));
        purge.add(delete(FilesystemPkiStore.domainCorrelationKey(parent.outer().orElseThrow().kind(), parent.outer().orElseThrow().correlationId())));
        purge.add(delete(CrlHybridMetadata.executionKey(parent.operationId()))); purge.add(delete(CrlHybridMetadata.reverseKey(child.operationId())));
        if (receiptBytes != null) purge.add(delete(FsStatusSchedules.receiptKey(parent.operationId())));
        sink.accept(purge);
    }
    private static byte[] success(SignWorkflowStore.AcceptanceEnvelope envelope, int bytes) {
        return FsCodec.encodeSigningState(envelope, mutable(envelope, SignWorkflowStore.State.SUCCEEDED,
                Optional.of(new EncodedObject(Encoding.BINARY, new byte[bytes])), "SIGNED", false));
    }
    private static byte[] claimed(SignWorkflowStore.AcceptanceEnvelope envelope) {
        return FsCodec.encodeSigningState(envelope, mutable(envelope, SignWorkflowStore.State.DISPATCHED, Optional.empty(), "DISPATCHED", true));
    }
    private static byte[] failed(SignWorkflowStore.AcceptanceEnvelope envelope) {
        return FsCodec.encodeSigningState(envelope, mutable(envelope, SignWorkflowStore.State.FAILED, Optional.empty(), "f".repeat(FsCodec.MAX_COMPONENT_BYTES), false));
    }
    private static SignWorkflowStore.MutableState mutable(SignWorkflowStore.AcceptanceEnvelope envelope, SignWorkflowStore.State state,
            Optional<EncodedObject> result, String detail, boolean claim) {
        boolean retry = state == SignWorkflowStore.State.SUCCEEDED || state == SignWorkflowStore.State.DISPATCHED;
        return new SignWorkflowStore.MutableState(envelope.operationId(), state, Long.MAX_VALUE, Long.MAX_VALUE - 1,
                claim ? Optional.of(envelope.deadline()) : Optional.empty(), claim ? Optional.of(envelope.operationId()) : Optional.empty(),
                Optional.of(detail), result, claim ? Optional.empty() : Optional.of(envelope.createdAt()), retry ? Integer.MAX_VALUE : 0,
                retry ? Optional.of(envelope.deadline()) : Optional.empty(),
                retry ? Optional.of(SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE) : Optional.empty(),
                SignWorkflowStore.InitialAttemptPhase.NOT_APPLICABLE, SignWorkflowStore.Stage.SINGLE, Optional.empty());
    }
    private static DomainContinuationStore.Record domain(SignWorkflowStore.AcceptanceEnvelope envelope, DomainContinuationStore.State state,
            Optional<EncodedObject> result, Optional<String> detail) {
        var outer = envelope.outer().orElseThrow();
        boolean live = state == DomainContinuationStore.State.SIGNING || state == DomainContinuationStore.State.PUBLISHING;
        return new DomainContinuationStore.Record(envelope.operationId(), 2, outer.kind(), Optional.of(outer.correlationId()), state,
                Long.MAX_VALUE, envelope.createdAt(), envelope.deadline(), outer.command(), outer.commandCommitment(),
                live ? Optional.of(envelope.candidate()) : Optional.empty(), result, detail);
    }
    private static SigningTransactionPayloadCodec.Mutation state(SignWorkflowStore.AcceptanceEnvelope envelope, byte[] bytes) {
        return put(FilesystemPkiStore.signingStateKey(envelope.operationId()), bytes);
    }
    private static SigningTransactionPayloadCodec.Mutation binding(SignWorkflowStore.AcceptanceEnvelope envelope) {
        var candidate = envelope.candidate();
        return put(FilesystemPkiStore.signingCandidateBindingKey(candidate.contentId()), FsCodec.encode(FsCodec.SIGN_CANDIDATE_BINDING,
                new SignWorkflowStore.CandidateBinding(candidate.contentId(), envelope.operationId(), candidate.length(), candidate.sha256())));
    }
    private static SigningTransactionPayloadCodec.Mutation put(MetadataKey key, byte[] bytes) {
        return new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1, bytes);
    }
    private static SigningTransactionPayloadCodec.Mutation delete(MetadataKey key) {
        return new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.DELETE, key, 1, null);
    }
    private record BudgetReference(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference { }
}
