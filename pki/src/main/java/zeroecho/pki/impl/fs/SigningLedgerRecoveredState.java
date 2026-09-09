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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransactionId;

/** Cohesive production fold and artifact catalog construction for recovered ledger state. */
@SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.AvoidLiteralsInIfCondition",
        "PMD.CyclomaticComplexity" })
final class SigningLedgerRecoveredState {
    /* default */ static final String OUTCOME_NAMESPACE = "io.zeroecho.pki.transaction-outcome";
    /* default */ static final String LEDGER_STATE_NAMESPACE = "io.zeroecho.pki.ledger-state";
    /* default */ static final MetadataKey WATERMARK_KEY =
            new MetadataKey(LEDGER_STATE_NAMESPACE, "signing-time-watermark");

    private SigningLedgerRecoveredState() {
    }

    /* default */ static SigningArtifactCatalog catalog(
            SigningManifestCodec.Manifest manifest) {
        SigningArtifactCatalog result = new SigningArtifactCatalog();
        manifest.checkpoint().ifPresent(value -> result.register(
                new SigningArtifactCatalog.Artifact(value.generationIdentity(), value.name(),
                        SigningArtifactCatalog.Kind.CHECKPOINT)));
        for (SigningManifestCodec.Segment value : manifest.sealedSegments()) {
            result.register(new SigningArtifactCatalog.Artifact(value.generationIdentity(),
                    value.name(), SigningArtifactCatalog.Kind.SEALED_WAL));
        }
        SigningManifestCodec.ActiveWal active = manifest.activeWal();
        result.register(new SigningArtifactCatalog.Artifact(active.identity(), active.name(),
                SigningArtifactCatalog.Kind.ACTIVE_WAL));
        return result;
    }

    /* default */ static MetadataKey outcomeKey(UUID token) {
        return new MetadataKey(OUTCOME_NAMESPACE, hex(token));
    }

    /* default */ static MetadataTransactionId transactionId(MetadataStoreId storeId, UUID token) {
        return new MetadataTransactionId(storeId, hex(token));
    }

    /* default */ static MetadataCommitResult unknown(MetadataTransactionId id) {
        return new MetadataCommitResult(id, MetadataCommitResult.Outcome.UNKNOWN,
                OptionalLong.empty(),
                Optional.of(MetadataCommitResult.FailureCategory.STORAGE_FAILURE));
    }

    /* default */ static MetadataCommitResult notCommitted(MetadataTransactionId id,
            MetadataCommitResult.FailureCategory category) {
        return new MetadataCommitResult(id, MetadataCommitResult.Outcome.NOT_COMMITTED,
                OptionalLong.empty(), Optional.of(category));
    }

    private static String hex(UUID token) {
        return String.format(java.util.Locale.ROOT, "%016x%016x",
                token.getMostSignificantBits(), token.getLeastSignificantBits());
    }

    /** Transactional recovery sink that publishes one immutable folded candidate. */
    /* default */ static final class RecoveryFold implements SigningLedgerRecovery.RecoverySink {
        private final MetadataStoreId storeId;
        private State state;

        /* default */ RecoveryFold(Path root, MetadataStoreId storeId) {
            Objects.requireNonNull(root, "root");
            this.storeId = Objects.requireNonNull(storeId, "storeId");
        }

        @Override public Session begin(SigningManifestCodec.Manifest manifest) {
            return new FoldSession(manifest, storeId, this);
        }

        /* default */ State state() {
            if (state == null) {
                throw new IllegalStateException("metadata recovery was not published");
            }
            return state;
        }
    }

    /** Isolated mutable replay state published only after complete validation. */
    private static final class FoldSession implements SigningLedgerRecovery.RecoverySink.Session {
        private final SigningManifestCodec.Manifest manifest;
        private final MetadataStoreId storeId;
        private final RecoveryFold owner;
        private final Map<MetadataKey, SigningMvccIndex.RecoveredRecord> records = new HashMap<>();
        private final Map<UUID, MetadataCommitResult> outcomes = new HashMap<>();
        private long revision;
        private long sequence = -1L;
        private long watermark;
        private int generationSegmentIndex;
        private int checkpointEntries;
        private SigningCheckpointCodec.Header checkpointEntryHeader;
        private boolean checkpointBoundaryAccepted;
        private boolean prepared;

        private FoldSession(SigningManifestCodec.Manifest manifest, MetadataStoreId storeId,
                RecoveryFold owner) {
            this.manifest = manifest;
            this.storeId = storeId;
            this.owner = owner;
        }

        @Override public void acceptCheckpoint(SigningCheckpointCodec.Header header,
                SigningCheckpointCodec.EntryDescriptor entry, SigningWalFrameCodec.Frame frame)
                throws IOException {
            if (manifest.checkpoint().isEmpty() || checkpointBoundaryAccepted) {
                throw new IOException("Metadata checkpoint entry is outside its boundary");
            }
            if (checkpointEntryHeader == null) {
                checkpointEntryHeader = header;
            } else if (!checkpointEntryHeader.equals(header)) {
                throw new IOException("Metadata checkpoint entry headers conflict");
            }
            checkpointEntries = Math.incrementExact(checkpointEntries);
            MetadataKey key = MetadataKey.parse(entry.key());
            SigningTransactionPayloadCodec.Payload payload = decodeBound(frame);
            if (entry.recordType() != frame.recordType()) {
                throw new IOException("Metadata checkpoint descriptor type is inconsistent");
            }
            validateCheckpointBinding(key, frame.transactionId(), payload);
            SigningMvccIndex.RecordPointer pointer = new SigningMvccIndex.RecordPointer(
                    header.generationIdentity(), entry.frameOffset(), entry.frameLength(),
                    entry.sequence(), entry.revision(), entry.recordType());
            SigningMvccIndex.RecoveredRecord recovered =
                    new SigningMvccIndex.RecoveredRecord(key, pointer, entry.revision());
            if (records.put(key, recovered) != null) {
                throw new IOException("Metadata checkpoint key is duplicated");
            }
            if (OUTCOME_NAMESPACE.equals(key.namespace())) {
                installCheckpointOutcome(frame.transactionId(), payload, entry.revision());
            } else if (key.equals(WATERMARK_KEY)) {
                watermark = Math.max(watermark, payload.watermark());
            }
        }

        @Override public void acceptCheckpointBoundary(SigningCheckpointCodec.Header header)
                throws IOException {
            SigningManifestCodec.Checkpoint descriptor = manifest.checkpoint().orElseThrow(
                    () -> new IOException("Metadata checkpoint boundary is unexpected"));
            if (checkpointBoundaryAccepted) {
                throw new IOException("Metadata checkpoint boundary is duplicated");
            }
            if (header.generationIdentity() != descriptor.generationIdentity()
                    || header.revision() != descriptor.revision()
                    || header.committedSequence() != descriptor.coveredSequence()
                    || header.entryCount() != checkpointEntries
                    || checkpointEntryHeader != null && !checkpointEntryHeader.equals(header)) {
                throw new IOException("Metadata checkpoint boundary is inconsistent");
            }
            revision = header.revision();
            sequence = header.committedSequence();
            checkpointBoundaryAccepted = true;
        }

        @Override public void acceptWalGroup(List<SigningWalFrameCodec.ScannedFrame> values,
                long committedRevision) throws IOException {
            if (manifest.checkpoint().isPresent() && !checkpointBoundaryAccepted) {
                throw new IOException("Metadata WAL precedes the checkpoint boundary");
            }
            for (SigningWalFrameCodec.ScannedFrame value : values) {
                long generation = generationFor(value.frame().sequence());
                applyWalFrame(generation, value);
            }
            revision = committedRevision;
            sequence = values.getLast().frame().sequence();
        }

        private void applyWalFrame(long generation,
                SigningWalFrameCodec.ScannedFrame scanned) throws IOException {
            SigningWalFrameCodec.Frame frame = scanned.frame();
            SigningTransactionPayloadCodec.Payload payload = decodeBound(frame);
            SigningMvccIndex.RecordPointer pointer = new SigningMvccIndex.RecordPointer(
                    generation, scanned.offset(), scanned.encodedLength(),
                    frame.sequence(), scanned.revision(), frame.recordType());
            if (payload.kind() == SigningTransactionPayloadCodec.Kind.COMMIT
                    || payload.kind() == SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT) {
                validateAndApplyCallerMutations(payload.mutations(), pointer, scanned.revision());
                if (payload.watermark() >= 0L) {
                    watermark = Math.max(watermark, payload.watermark());
                    records.put(WATERMARK_KEY, new SigningMvccIndex.RecoveredRecord(
                            WATERMARK_KEY, pointer, scanned.revision()));
                }
            }
            applyOutcomeLifecycle(frame.transactionId(), payload, pointer, scanned.revision());
        }

        private SigningTransactionPayloadCodec.Payload decodeBound(
                SigningWalFrameCodec.Frame frame) throws IOException {
            SigningTransactionPayloadCodec.Payload payload =
                    SigningTransactionPayloadCodec.decode(frame.payload());
            SigningWalFrameCodec.RecordType expected = switch (payload.kind()) {
                case ISSUE -> SigningWalFrameCodec.RecordType.ISSUE;
                case COMMIT, DIRECT_COMMIT -> SigningWalFrameCodec.RecordType.COMMIT;
                case REJECT -> SigningWalFrameCodec.RecordType.REJECT;
                case ACK -> SigningWalFrameCodec.RecordType.ACK;
                case WATERMARK -> SigningWalFrameCodec.RecordType.WATERMARK;
            };
            if (frame.recordType() != expected) {
                throw new IOException("Metadata frame type and payload kind are inconsistent");
            }
            return payload;
        }

        private void validateCheckpointBinding(MetadataKey key, UUID token,
                SigningTransactionPayloadCodec.Payload payload) throws IOException {
            if (OUTCOME_NAMESPACE.equals(key.namespace())) {
                if (!key.equals(outcomeKey(token))
                        || payload.kind() == SigningTransactionPayloadCodec.Kind.ACK
                        || payload.kind() == SigningTransactionPayloadCodec.Kind.WATERMARK) {
                    throw new IOException("Metadata checkpoint outcome binding is invalid");
                }
                return;
            }
            if (key.equals(WATERMARK_KEY)) {
                if (payload.kind() != SigningTransactionPayloadCodec.Kind.WATERMARK
                        && (payload.kind() != SigningTransactionPayloadCodec.Kind.COMMIT
                                && payload.kind()
                                != SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT
                                || payload.watermark() < 0L)) {
                    throw new IOException("Metadata checkpoint watermark binding is invalid");
                }
                return;
            }
            if (payload.kind() != SigningTransactionPayloadCodec.Kind.COMMIT
                    && payload.kind() != SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT
                    || payload.mutations().stream().noneMatch(mutation -> mutation.key().equals(key)
                            && mutation.kind()
                            != SigningTransactionPayloadCodec.MutationKind.DELETE)) {
                throw new IOException("Metadata checkpoint mutation binding is invalid");
            }
        }

        private void installCheckpointOutcome(UUID token,
                SigningTransactionPayloadCodec.Payload payload, long outcomeRevision)
                throws IOException {
            MetadataTransactionId id = transactionId(storeId, token);
            MetadataCommitResult outcome = switch (payload.kind()) {
                case ISSUE -> unknown(id);
                case COMMIT, DIRECT_COMMIT -> new MetadataCommitResult(id,
                        MetadataCommitResult.Outcome.COMMITTED,
                        OptionalLong.of(outcomeRevision), Optional.empty());
                case REJECT -> notCommitted(id, payload.failure());
                case ACK, WATERMARK ->
                    throw new IOException("Metadata checkpoint outcome is invalid");
            };
            if (outcomes.put(token, outcome) != null) {
                throw new IOException("Metadata checkpoint outcome identity is duplicated");
            }
        }

        private void validateAndApplyCallerMutations(
                List<SigningTransactionPayloadCodec.Mutation> mutations,
                SigningMvccIndex.RecordPointer pointer, long mutationRevision) throws IOException {
            for (SigningTransactionPayloadCodec.Mutation mutation : mutations) {
                SigningMvccIndex.RecoveredRecord current = records.get(mutation.key());
                boolean valid = switch (mutation.kind()) {
                    case CREATE -> current == null;
                    case REPLACE, DELETE -> current != null
                            && current.revision() == mutation.expectedRevision();
                };
                if (!valid) {
                    throw new IOException("Metadata recovered mutation precondition is invalid");
                }
            }
            for (SigningTransactionPayloadCodec.Mutation mutation : mutations) {
                if (mutation.kind() == SigningTransactionPayloadCodec.MutationKind.DELETE) {
                    records.remove(mutation.key());
                } else {
                    records.put(mutation.key(), new SigningMvccIndex.RecoveredRecord(
                            mutation.key(), pointer, mutationRevision));
                }
            }
        }

        private void applyOutcomeLifecycle(UUID token,
                SigningTransactionPayloadCodec.Payload payload,
                SigningMvccIndex.RecordPointer pointer, long outcomeRevision) throws IOException {
            MetadataTransactionId id = transactionId(storeId, token);
            MetadataCommitResult existing = outcomes.get(token);
            switch (payload.kind()) {
                case ISSUE -> {
                    if (existing != null) {
                        throw new IOException("Metadata issuance is duplicated");
                    }
                    outcomes.put(token, unknown(id));
                    records.put(outcomeKey(token), new SigningMvccIndex.RecoveredRecord(
                            outcomeKey(token), pointer, outcomeRevision));
                }
                case COMMIT, REJECT -> {
                    if (existing == null
                            || existing.outcome() != MetadataCommitResult.Outcome.UNKNOWN) {
                        throw new IOException(
                                "Metadata terminal outcome has no active issuance");
                    }
                    MetadataCommitResult terminal = payload.kind()
                            == SigningTransactionPayloadCodec.Kind.COMMIT
                            ? new MetadataCommitResult(id,
                                    MetadataCommitResult.Outcome.COMMITTED,
                                    OptionalLong.of(outcomeRevision), Optional.empty())
                            : notCommitted(id, payload.failure());
                    outcomes.put(token, terminal);
                    records.put(outcomeKey(token), new SigningMvccIndex.RecoveredRecord(
                            outcomeKey(token), pointer, outcomeRevision));
                }
                case DIRECT_COMMIT -> {
                    if (existing != null) {
                        throw new IOException("Direct metadata identity is duplicated");
                    }
                }
                case ACK -> {
                    if (existing == null
                            || existing.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
                        throw new IOException(
                                "Metadata acknowledgement has no terminal outcome");
                    }
                    outcomes.remove(token);
                    records.remove(outcomeKey(token));
                }
                case WATERMARK -> {
                    if (payload.watermark() <= watermark) {
                        throw new IOException("Metadata watermark does not advance");
                    }
                    watermark = payload.watermark();
                    records.put(WATERMARK_KEY, new SigningMvccIndex.RecoveredRecord(
                            WATERMARK_KEY, pointer, outcomeRevision));
                }
            }
        }

        private long generationFor(long frameSequence) {
            List<SigningManifestCodec.Segment> segments = manifest.sealedSegments();
            while (generationSegmentIndex < segments.size()) {
                SigningManifestCodec.Segment segment = segments.get(generationSegmentIndex);
                long end = Math.addExact(segment.firstSequence(), segment.sequenceCount());
                if (frameSequence < segment.firstSequence()) {
                    break;
                }
                if (frameSequence < end) {
                    return segment.generationIdentity();
                }
                generationSegmentIndex++;
            }
            return manifest.activeWal().identity();
        }

        @Override public SigningLedgerRecovery.RecoverySink.Prepared prepare() throws IOException {
            if (manifest.checkpoint().isPresent() != checkpointBoundaryAccepted) {
                throw new IOException("Metadata checkpoint boundary is missing");
            }
            prepared = true;
            List<SigningMvccIndex.RecoveredRecord> ordered = new ArrayList<>(records.values());
            ordered.sort(Comparator.comparing(SigningMvccIndex.RecoveredRecord::key));
            State candidate = new State(revision, sequence, List.copyOf(ordered),
                    Map.copyOf(outcomes), watermark);
            return new SigningLedgerRecovery.RecoverySink.Prepared() {
                @Override public void publish() {
                    owner.state = candidate;
                }

                @Override public void close() {
                    // Immutable candidate owns no external resources.
                }
            };
        }

        @Override public void close() {
            if (!prepared) {
                records.clear();
                outcomes.clear();
            }
        }
    }

    /* default */ record State(long revision, long sequence,
            List<SigningMvccIndex.RecoveredRecord> records,
            Map<UUID, MetadataCommitResult> outcomes, long watermark) {
    }
}
