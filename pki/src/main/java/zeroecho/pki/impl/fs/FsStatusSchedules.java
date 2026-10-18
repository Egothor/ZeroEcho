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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.function.Consumer;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.api.schedule.StatusScheduleState.Execution;
import zeroecho.pki.api.schedule.StatusScheduleState.Phase;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.TransactionalMetadataStore;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;

/** Borrowed transactional schedule authority; bounded pages retain O(P) rows and scan O(S log P). */
final class FsStatusSchedules { // NOPMD CyclomaticComplexity - Aggregate lifecycle/coordinator complexity; individual methods remain checked.
    /* default */ static final String HEAD = "io.zeroecho.pki.status-schedule";
    /* default */ static final String RECEIPT = "io.zeroecho.pki.status-schedule-receipt";
    private static final int VERSION = 1;
    private static final int MAX_BYTES = 65_536;
    private static final int MAX_CONFLICT_ATTEMPTS = 16;
    private static final Comparator<StatusScheduleState> ORDER = Comparator
            .comparing((StatusScheduleState value) -> value.configuration().caId().value())
            .thenComparing(value -> value.configuration().statusType().name());
    private final TransactionalMetadataStore metadata;
    private final Consumer<MetadataCommitResult> outcome;
    private final Consumer<Execution> failureProof;

    /* default */ FsStatusSchedules(TransactionalMetadataStore metadata, Consumer<MetadataCommitResult> outcome) {
        this(metadata, outcome, ignored -> { throw invalid("SCHEDULE_FAILURE_PROOF_UNAVAILABLE"); });
    }

    /* default */ FsStatusSchedules(TransactionalMetadataStore metadata, Consumer<MetadataCommitResult> outcome,
            Consumer<Execution> failureProof) {
        this.metadata = metadata; this.outcome = outcome; this.failureProof = failureProof;
    }

    /* default */ static String cursor(StatusSchedule configuration) {
        return zeroecho.pki.spi.store.PkiStore.statusScheduleCursor(configuration);
    }

    /* default */ static MetadataKey key(PkiId caId, StatusObjectType type) {
        return new MetadataKey(HEAD, digest("status-schedule-key:v1:" + caId.value()) + "." + type.name());
    }

    /* default */ static MetadataKey receiptKey(PkiId operationId) { return new MetadataKey(RECEIPT, operationId.value()); }

    /* default */ Optional<StatusScheduleState> get(PkiId caId, StatusObjectType type) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            Optional<StatusScheduleState> found = read(snapshot, key(caId, type)).map(Stored::value);
            if (found.isPresent() && (!found.orElseThrow().configuration().caId().equals(caId)
                    || found.orElseThrow().configuration().statusType() != type)) { throw invalid("SCHEDULE_IDENTITY"); }
            return found;
        }
    }

    /* default */ List<StatusScheduleState> page(Optional<String> after, int limit, boolean includeUnfinished,
            CancellationSignal cancellation) throws IOException {
        if (limit < 1 || limit > 1001) { throw new IllegalArgumentException("Invalid schedule page size"); }
        Queue<StatusScheduleState> best = new PriorityQueue<>(limit, ORDER.reversed());
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor records = snapshot.scan(MetadataSnapshot.KeyRange.all(HEAD), cancellation)) {
            StatusSchedule boundary = after.isEmpty() ? null : read(snapshot, parseCursor(after.orElseThrow()))
                    .orElseThrow(() -> new IllegalArgumentException("Schedule cursor is unavailable")).value().configuration();
            Optional<MetadataSnapshot.Record> next;
            while ((next = records.next(cancellation)).isPresent()) {
                cancellation.throwIfCancelled();
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    StatusScheduleState value = decode(record);
                    boolean unfinished = value.execution().filter(execution -> execution.phase() != Phase.SCHEDULE_ADVANCED).isPresent();
                    if (!value.configuration().enabled() && !(includeUnfinished && unfinished)) { continue; }
                    if (boundary != null) {
                        int compared = value.configuration().caId().value().compareTo(boundary.caId().value());
                        if (compared < 0 || compared == 0 && value.configuration().statusType().name().compareTo(boundary.statusType().name()) <= 0) { continue; }
                    }
                    if (best.size() < limit) { best.add(value); }
                    else if (ORDER.compare(value, best.peek()) < 0) { best.poll(); best.add(value); }
                }
            }
        }
        List<StatusScheduleState> result = new ArrayList<>(best); result.sort(ORDER); return List.copyOf(result);
    }

    /* default */ StatusSchedule put(StatusSchedule requested, Optional<StatusSchedule> expected, Instant now) throws IOException {
        MetadataKey key = key(requested.caId(), requested.statusType());
        for (int attempt = 0; attempt < MAX_CONFLICT_ATTEMPTS; attempt++) {
            try (MetadataSnapshot snapshot = metadata.snapshot()) {
                Optional<Stored> prior = read(snapshot, key);
                if (prior.isPresent() && (!prior.orElseThrow().value().configuration().caId().equals(requested.caId())
                        || prior.orElseThrow().value().configuration().statusType() != requested.statusType())) { throw invalid("SCHEDULE_IDENTITY"); }
                if (expected.isPresent() && (prior.isEmpty() || !prior.orElseThrow().value().configuration().equals(expected.orElseThrow()))) { return null; }
                StatusScheduleState replacement = replacement(prior, requested, now);
                if (commit(key, prior, replacement)) { return replacement.configuration(); }
                if (expected.isPresent()) { return null; }
            }
        }
        throw new IOException("Schedule update conflict retry limit reached");
    }

    private StatusScheduleState replacement(Optional<Stored> prior, StatusSchedule requested, Instant now) {
        StatusSchedule current = prior.map(value -> value.value().configuration()).orElse(null);
        StatusSchedule configuration = new StatusSchedule(requested.caId(), requested.statusType(), requested.formatId(),
                requested.interval(), requested.graceSeconds(), requested.enabled(), requested.publicationTarget(),
                current == null ? requested.createdAt() : current.createdAt(), requested.updatedAt(),
                current == null ? 1 : Math.addExact(current.revision(), 1));
        StatusScheduleState replacement = prior.map(value -> new StatusScheduleState(configuration,
                value.value().nextDue(), value.value().workerRevision(), value.value().execution()))
                .orElseGet(() -> new StatusScheduleState(configuration, now, 0, Optional.empty()));
        if (replacement.execution().isPresent()) {
            Execution execution = replacement.execution().orElseThrow();
            if (execution.phase() == Phase.FAILED) { failureProof.accept(execution); }
            if (execution.signingOperationId().isEmpty() || execution.phase() == Phase.FAILED) {
                replacement = new StatusScheduleState(configuration, now,
                        Math.addExact(replacement.workerRevision(), 1), Optional.empty());
            }
        }
        return replacement;
    }

    /* default */ Optional<Execution> claim(StatusScheduleState expected, Instant now) throws IOException {
        MetadataKey key = key(expected.configuration().caId(), expected.configuration().statusType());
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            Optional<Stored> stored = read(snapshot, key);
            if (stored.isEmpty() || !stored.orElseThrow().value().equals(expected)) { return Optional.empty(); }
            if (!expected.configuration().enabled() || now.isBefore(expected.nextDue())
                    || expected.execution().filter(value -> value.phase() != Phase.SCHEDULE_ADVANCED).isPresent()) { return Optional.empty(); }
            long fence = Math.addExact(expected.workerRevision(), 1);
            Execution execution = new Execution(executionId(expected.configuration(), expected.nextDue()), expected.configuration(),
                    expected.nextDue(), fence, Phase.CLAIMED, Optional.empty(), "", Optional.empty(), "");
            StatusScheduleState replacement = new StatusScheduleState(expected.configuration(), expected.nextDue(), fence, Optional.of(execution));
            return commit(key, stored, replacement) ? Optional.of(execution) : Optional.empty();
        }
    }

    /* default */ void stageAcceptance(MetadataTransaction transaction, Execution claim, SignWorkflowStore.AcceptanceCommand command) throws IOException {
        validateBinding(claim, SignWorkflowStore.AcceptanceEnvelope.from(command));
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            MetadataKey key = key(claim.configuration().caId(), claim.configuration().statusType());
            Stored head = read(snapshot, key).orElseThrow(() -> invalid("SCHEDULE_CLAIM_MISSING"));
            if (!head.value().execution().equals(Optional.of(claim)) || claim.phase() != Phase.CLAIMED
                    || claim.signingOperationId().isPresent()) { throw invalid("SCHEDULE_CLAIM_CONFLICT"); }
            Execution accepted = new Execution(claim.executionId(), claim.configuration(), claim.due(), claim.fence(),
                    Phase.CLAIMED, Optional.of(command.operationId()), command.commitment().encoded(), Optional.empty(), "");
            replace(transaction, key, head.revision(), encode(new StatusScheduleState(head.value().configuration(),
                    head.value().nextDue(), Math.addExact(head.value().workerRevision(), 1), Optional.of(accepted))));
            create(transaction, receiptKey(command.operationId()), encodeExecution(accepted));
        }
    }

    /* default */ boolean attached(Execution claim, SignWorkflowStore.AcceptanceCommand command) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            Optional<Execution> receipt = receipt(snapshot, command.operationId());
            return receipt.filter(value -> sameClaim(value, claim) && value.acceptanceCommitment().equals(command.commitment().encoded())
                    && value.signingOperationId().equals(Optional.of(command.operationId()))).isPresent();
        }
    }

    /* default */ Optional<Execution> receipt(MetadataSnapshot snapshot, PkiId operationId) throws IOException {
        try (MetadataSnapshot.Record record = snapshot.get(receiptKey(operationId)).orElse(null)) {
            if (record == null) { return Optional.empty(); }
            Execution result = decodeExecution(readBytes(record));
            if (!result.signingOperationId().equals(Optional.of(operationId))) { throw invalid("SCHEDULE_RECEIPT_IDENTITY"); }
            return Optional.of(result);
        }
    }

    /* default */ void stageEffect(MetadataTransaction transaction, PkiId operationId, StatusObject status) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataSnapshot.Record sidecar = snapshot.get(receiptKey(operationId)).orElse(null)) {
            if (sidecar == null) { return; }
            Execution accepted = decodeExecution(readBytes(sidecar));
            if (accepted.phase() == Phase.FAILED) { throw invalid("SCHEDULE_EXECUTION_FAILED"); }
            if (!accepted.signingOperationId().equals(Optional.of(operationId))
                    || !accepted.configuration().caId().equals(status.issuerCaId())
                    || accepted.configuration().statusType() != status.type()
                    || !accepted.configuration().formatId().equals(status.formatId())) { throw invalid("SCHEDULE_EFFECT_MISMATCH"); }
            if (accepted.statusObjectId().isPresent()) {
                if (!accepted.statusObjectId().equals(Optional.of(status.statusObjectId()))) { throw invalid("SCHEDULE_EFFECT_CONFLICT"); }
                return;
            }
            MetadataKey key = key(accepted.configuration().caId(), accepted.configuration().statusType());
            Stored head = read(snapshot, key).orElseThrow(() -> invalid("SCHEDULE_CLAIM_MISSING"));
            if (!head.value().execution().equals(Optional.of(accepted))) { throw invalid("SCHEDULE_CLAIM_CONFLICT"); }
            Execution committed = new Execution(accepted.executionId(), accepted.configuration(), accepted.due(), accepted.fence(),
                    Phase.EFFECT_COMMITTED, accepted.signingOperationId(), accepted.acceptanceCommitment(),
                    Optional.of(status.statusObjectId()), "");
            replace(transaction, receiptKey(operationId), sidecar.recordRevision(), encodeExecution(committed));
            replace(transaction, key, head.revision(), encode(new StatusScheduleState(head.value().configuration(),
                    head.value().nextDue(), Math.addExact(head.value().workerRevision(), 1), Optional.of(committed))));
        }
    }

    /* default */ boolean advance(Execution expected, Instant committedNextUpdate) throws IOException {
        if (expected.phase() != Phase.EFFECT_COMMITTED) { throw invalid("SCHEDULE_EFFECT_REQUIRED"); }
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataTransaction transaction = metadata.beginTransaction()) {
            MetadataKey key = key(expected.configuration().caId(), expected.configuration().statusType());
            Stored head = read(snapshot, key).orElseThrow(() -> invalid("SCHEDULE_CLAIM_MISSING"));
            if (!head.value().execution().equals(Optional.of(expected))) { return false; }
            try (MetadataSnapshot.Record sidecar = snapshot.get(receiptKey(expected.signingOperationId().orElseThrow())).orElseThrow()) {
                if (!decodeExecution(readBytes(sidecar)).equals(expected)) { throw invalid("SCHEDULE_RECEIPT_MISMATCH"); }
                Execution advanced = new Execution(expected.executionId(), expected.configuration(), expected.due(), expected.fence(),
                        Phase.SCHEDULE_ADVANCED, expected.signingOperationId(), expected.acceptanceCommitment(), expected.statusObjectId(), "");
                Instant nextDue = committedNextUpdate.minusSeconds(head.value().configuration().graceSeconds());
                replace(transaction, key, head.revision(), encode(new StatusScheduleState(head.value().configuration(),
                        nextDue, Math.addExact(head.value().workerRevision(), 1), Optional.of(advanced))));
                replace(transaction, receiptKey(expected.signingOperationId().orElseThrow()), sidecar.recordRevision(), encodeExecution(advanced));
                return committed(transaction.commit());
            }
        }
    }

    /* default */ boolean fail(Execution expected, String code) throws IOException {
        if (expected.phase() != Phase.CLAIMED || expected.signingOperationId().isEmpty()) { throw invalid("SCHEDULE_ACCEPTANCE_REQUIRED"); }
        failureProof.accept(expected);
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataTransaction transaction = metadata.beginTransaction()) {
            MetadataKey key = key(expected.configuration().caId(), expected.configuration().statusType());
            Stored head = read(snapshot, key).orElseThrow(() -> invalid("SCHEDULE_CLAIM_MISSING"));
            if (!head.value().execution().equals(Optional.of(expected))) { return false; }
            Execution failed = new Execution(expected.executionId(), expected.configuration(), expected.due(), expected.fence(),
                    Phase.FAILED, expected.signingOperationId(), expected.acceptanceCommitment(), Optional.empty(), code);
            try (MetadataSnapshot.Record sidecar = snapshot.get(receiptKey(expected.signingOperationId().orElseThrow())).orElseThrow()) {
                if (!decodeExecution(readBytes(sidecar)).equals(expected)) { throw invalid("SCHEDULE_RECEIPT_MISMATCH"); }
                replace(transaction, key, head.revision(), encode(new StatusScheduleState(head.value().configuration(),
                        head.value().nextDue(), Math.addExact(head.value().workerRevision(), 1), Optional.of(failed))));
                replace(transaction, sidecar.key(), sidecar.recordRevision(), encodeExecution(failed));
                return committed(transaction.commit());
            }
        }
    }

    /* default */ void validate(Consumer<Execution> validateReceipt) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(HEAD), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    StatusScheduleState head = decode(record);
                    if (head.execution().flatMap(Execution::signingOperationId).isPresent()) {
                        Execution execution = head.execution().orElseThrow();
                        Optional<Execution> accepted = receipt(snapshot, execution.signingOperationId().orElseThrow());
                        if (accepted.isEmpty() && execution.phase() != Phase.SCHEDULE_ADVANCED
                                || accepted.isPresent() && !accepted.orElseThrow().equals(execution)) { throw invalid("SCHEDULE_RECEIPT_MISMATCH"); }
                    }
                }
            }
        }
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(RECEIPT), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    Execution execution = decodeExecution(readBytes(record));
                    if (!receiptKey(execution.signingOperationId().orElseThrow()).equals(record.key())) { throw invalid("SCHEDULE_RECEIPT_IDENTITY"); }
                    StatusScheduleState head = read(snapshot, key(execution.configuration().caId(), execution.configuration().statusType()))
                            .orElseThrow(() -> invalid("SCHEDULE_HEAD_MISSING")).value();
                    if (execution.phase() != Phase.SCHEDULE_ADVANCED && !head.execution().equals(Optional.of(execution))
                            && !(execution.phase() == Phase.FAILED && head.configuration().revision() > execution.configuration().revision())) { throw invalid("SCHEDULE_HEAD_MISMATCH"); }
                    validateReceipt.accept(execution);
                }
            }
        }
    }

    private static void requireCommandMatches(Execution claim, SignWorkflowStore.AcceptanceEnvelope envelope,
            DomainCommandEncoding.Decoded command) {
        Instant evaluation = Instant.parse(command.field(29)).truncatedTo(ChronoUnit.SECONDS);
        if (Instant.parse(command.field(29)).isBefore(claim.due())
                || !command.field(0).equals(claim.configuration().caId().value())
                || !command.field(1).equals(claim.configuration().statusType().name())
                || !command.field(2).equals(claim.configuration().formatId().value())
                || !command.field(5).equals(envelope.keyRef().value())
                || !command.field(8).equals(envelope.algorithmId())
                || !envelope.fairnessAuthorityId().equals(claim.configuration().caId())
                || !Instant.parse(command.field(3)).equals(evaluation)
                || !Instant.parse(command.field(4)).equals(evaluation.plus(claim.configuration().interval()).truncatedTo(ChronoUnit.SECONDS))) {
            throw invalid("SCHEDULE_COMMAND_MISMATCH");
        }
    }

    /* default */ static void validateBinding(Execution claim, SignWorkflowStore.AcceptanceEnvelope envelope) {
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow(() -> invalid("SCHEDULE_STATUS_REQUIRED"));
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(new DomainContinuationTemplate(
                outer.kind(), Optional.of(outer.correlationId()), outer.command(), outer.commandCommitment()));
        String operation = claim.configuration().statusType() == StatusObjectType.CRL ? FullCrlSigningCommand.OPERATION
                : claim.configuration().statusType() == StatusObjectType.DELTA_CRL ? FullCrlSigningCommand.DELTA_OPERATION : "";
        if (outer.kind() != DomainContinuationStore.Kind.STATUS || !operation.equals(command.operation())) { throw invalid("SCHEDULE_STATUS_REQUIRED"); }
        FullCrlSigningCommand.validate(command);
        FullCrlSigningCommand.requireTbs(command, envelope.candidate());
        requireCommandMatches(claim, envelope, command);
        if (claim.signingOperationId().isPresent() && (!claim.signingOperationId().orElseThrow().equals(envelope.operationId())
                || !claim.acceptanceCommitment().equals(envelope.acceptanceCommitment().encoded()))) { throw invalid("SCHEDULE_RECEIPT_MISMATCH"); }
    }

    /* default */ boolean pinned(MetadataSnapshot snapshot, Execution execution) throws IOException {
        if (execution.phase() == Phase.CLAIMED || execution.phase() == Phase.EFFECT_COMMITTED) { return true; }
        return execution.phase() == Phase.FAILED && read(snapshot, key(execution.configuration().caId(), execution.configuration().statusType()))
                .orElseThrow(() -> invalid("SCHEDULE_HEAD_MISSING")).value().execution().equals(Optional.of(execution));
    }

    private boolean commit(MetadataKey key, Optional<Stored> prior, StatusScheduleState replacement) throws IOException {
        try (MetadataTransaction transaction = metadata.beginTransaction()) {
            if (prior.isEmpty()) { create(transaction, key, encode(replacement)); }
            else { replace(transaction, key, prior.orElseThrow().revision(), encode(replacement)); }
            return committed(transaction.commit());
        }
    }
    private boolean committed(MetadataCommitResult result) throws IOException {
        outcome.accept(result);
        if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) { return true; }
        if (result.outcome() == MetadataCommitResult.Outcome.NOT_COMMITTED
                && result.failureCategory().equals(Optional.of(MetadataCommitResult.FailureCategory.CONFLICT))) { return false; }
        throw new IOException("Schedule transaction failed: " + result.failureCategory().map(Enum::name).orElse("UNKNOWN"));
    }
    private static void create(MetadataTransaction transaction, MetadataKey key, byte[] bytes) throws IOException {
        try (RepeatableContent content = new ImmutableByteContent(bytes)) { transaction.create(key, content, CancellationSignal.NONE); }
    }
    private static void replace(MetadataTransaction transaction, MetadataKey key, long revision, byte[] bytes) throws IOException {
        try (RepeatableContent content = new ImmutableByteContent(bytes)) { transaction.replace(key, revision, content, CancellationSignal.NONE); }
    }
    private record Stored(StatusScheduleState value, long revision) { }
    private static Optional<Stored> read(MetadataSnapshot snapshot, MetadataKey key) throws IOException {
        try (MetadataSnapshot.Record record = snapshot.get(key).orElse(null)) {
            return record == null ? Optional.empty() : Optional.of(new Stored(decode(record), record.recordRevision()));
        }
    }
    private static StatusScheduleState decodeState(DataInputStream input, MetadataSnapshot.Record record, byte[] bytes) throws IOException {
        if (input.readInt() != VERSION) { throw invalid("SCHEDULE_VERSION"); }
        StatusSchedule configuration = readSchedule(input);
        Instant due = Instant.parse(input.readUTF()); long revision = input.readLong();
        Optional<Execution> execution = input.readBoolean() ? Optional.of(readExecution(input)) : Optional.empty();
        if (input.read() != -1 || !record.key().equals(key(configuration.caId(), configuration.statusType()))) { throw invalid("SCHEDULE_IDENTITY"); }
        if (execution.isPresent()) {
            Execution claim = execution.orElseThrow();
            if (!claim.configuration().caId().equals(configuration.caId()) || claim.configuration().statusType() != configuration.statusType()
                    || claim.configuration().revision() > configuration.revision() || claim.fence() > revision) { throw invalid("SCHEDULE_FENCE"); }
        }
        StatusScheduleState result = new StatusScheduleState(configuration, due, revision, execution);
        if (!java.util.Arrays.equals(bytes, encode(result))) { throw invalid("SCHEDULE_ENCODING"); }
        return result;
    }

    private static StatusScheduleState decode(MetadataSnapshot.Record record) throws IOException {
        byte[] bytes = readBytes(record);
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            return decodeState(input, record, bytes);
        } catch (RuntimeException malformed) { throw new IOException("Invalid status schedule metadata", malformed); } // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
    }
    private static byte[] encode(StatusScheduleState state) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(VERSION); writeSchedule(output, state.configuration()); output.writeUTF(state.nextDue().toString());
            output.writeLong(state.workerRevision()); output.writeBoolean(state.execution().isPresent());
            if (state.execution().isPresent()) { writeExecution(output, state.execution().orElseThrow()); }
        }
        return bounded(bytes.toByteArray());
    }
    private static byte[] encodeExecution(Execution execution) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) { output.writeInt(VERSION); writeExecution(output, execution); }
        return bounded(bytes.toByteArray());
    }
    private static Execution decodeReceipt(DataInputStream input, byte[] bytes) throws IOException {
        if (input.readInt() != VERSION) { throw invalid("SCHEDULE_VERSION"); }
        Execution result = readExecution(input);
        if (input.read() != -1 || !java.util.Arrays.equals(bytes, encodeExecution(result))) { throw invalid("SCHEDULE_TRAILING_DATA"); }
        return result;
    }

    private static Execution decodeExecution(byte[] bytes) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            return decodeReceipt(input, bytes);
        } catch (RuntimeException malformed) { throw new IOException("Invalid schedule receipt metadata", malformed); } // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
    }
    private static void writeSchedule(DataOutputStream out, StatusSchedule value) throws IOException {
        out.writeUTF(value.caId().value()); out.writeUTF(value.statusType().name()); out.writeUTF(value.formatId().value());
        out.writeUTF(value.interval().toString()); out.writeLong(value.graceSeconds()); out.writeBoolean(value.enabled());
        out.writeBoolean(value.publicationTarget().isPresent());
        if (value.publicationTarget().isPresent()) { out.writeUTF(value.publicationTarget().orElseThrow().type().name()); out.writeUTF(value.publicationTarget().orElseThrow().targetId()); }
        out.writeUTF(value.createdAt().toString()); out.writeUTF(value.updatedAt().toString()); out.writeLong(value.revision());
    }
    private static StatusSchedule readSchedule(DataInputStream in) throws IOException {
        PkiId ca = new PkiId(in.readUTF()); StatusObjectType type = StatusObjectType.valueOf(in.readUTF());
        FormatId format = new FormatId(in.readUTF()); Duration interval = Duration.parse(in.readUTF());
        long grace = in.readLong(); boolean enabled = in.readBoolean();
        Optional<PublicationTarget> target = in.readBoolean() ? Optional.of(new PublicationTarget(PublicationTargetType.valueOf(in.readUTF()), in.readUTF())) : Optional.empty();
        return new StatusSchedule(ca, type, format, interval, grace, enabled, target, Instant.parse(in.readUTF()), Instant.parse(in.readUTF()), in.readLong());
    }
    private static void writeExecution(DataOutputStream out, Execution value) throws IOException {
        out.writeUTF(value.executionId()); writeSchedule(out, value.configuration()); out.writeUTF(value.due().toString());
        out.writeLong(value.fence()); out.writeUTF(value.phase().name()); out.writeBoolean(value.signingOperationId().isPresent());
        if (value.signingOperationId().isPresent()) { out.writeUTF(value.signingOperationId().orElseThrow().value()); }
        out.writeUTF(value.acceptanceCommitment()); out.writeBoolean(value.statusObjectId().isPresent());
        if (value.statusObjectId().isPresent()) { out.writeUTF(value.statusObjectId().orElseThrow().value()); }
        out.writeUTF(value.detailCode());
    }
    private static Execution readExecution(DataInputStream in) throws IOException {
        String id = in.readUTF(); StatusSchedule configuration = readSchedule(in); Instant due = Instant.parse(in.readUTF());
        long fence = in.readLong(); Phase phase = Phase.valueOf(in.readUTF());
        Optional<PkiId> operation = in.readBoolean() ? Optional.of(new PkiId(in.readUTF())) : Optional.empty();
        String commitment = in.readUTF(); Optional<PkiId> status = in.readBoolean() ? Optional.of(new PkiId(in.readUTF())) : Optional.empty();
        Execution result = new Execution(id, configuration, due, fence, phase, operation, commitment, status, in.readUTF());
        if (!id.equals(executionId(configuration, due))) { throw invalid("SCHEDULE_EXECUTION_IDENTITY"); }
        return result;
    }
    private static byte[] readBytes(MetadataSnapshot.Record record) throws IOException {
        try (java.io.InputStream input = record.openStream()) {
            byte[] bytes = input.readNBytes(MAX_BYTES + 1);
            if (bytes.length > MAX_BYTES || record.length().isEmpty() || record.length().orElseThrow() != bytes.length) { throw invalid("SCHEDULE_LENGTH"); }
            return bytes;
        }
    }
    private static byte[] bounded(byte[] bytes) throws IOException {
        if (bytes.length > MAX_BYTES) { throw new IOException("Schedule metadata exceeds its limit"); }
        return bytes;
    }
    private static boolean sameClaim(Execution a, Execution b) {
        return a.executionId().equals(b.executionId()) && a.configuration().equals(b.configuration()) && a.due().equals(b.due()) && a.fence() == b.fence();
    }
    private static String executionId(StatusSchedule configuration, Instant due) {
        String ca = configuration.caId().value();
        return digest("status-schedule-execution:v1:" + ca.length() + ":" + ca + ":" + configuration.revision()
                + ":" + configuration.statusType().name() + ":" + due);
    }
    private static String digest(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(utf8(value))); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private static MetadataKey parseCursor(String cursor) {
        if (!cursor.matches("[0-9a-f]{64}\\.(CRL|DELTA_CRL|OCSP)")) { throw new IllegalArgumentException("Invalid schedule cursor"); }
        return new MetadataKey(HEAD, cursor);
    }
    private static byte[] utf8(String value) {
        try {
            java.nio.ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(value));
            byte[] bytes = new byte[encoded.remaining()]; encoded.get(bytes); return bytes;
        } catch (java.nio.charset.CharacterCodingException malformed) {
            throw new IllegalArgumentException("Schedule identity is not valid Unicode", malformed);
        }
    }
    private static IllegalStateException invalid(String code) { return new IllegalStateException("Invalid schedule state: code=" + code); }
}
