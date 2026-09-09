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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import zeroecho.pki.spi.store.MetadataCommitResult;

/** Streams one pinned logical revision directly into a fresh checkpoint ledger. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.ExhaustiveSwitchHasDefault" })
final class SigningLedgerSnapshotExporter {
    private static final long CHECKPOINT_IDENTITY = 1L;
    private static final long ACTIVE_IDENTITY = 2L;

    private SigningLedgerSnapshotExporter() {
        // utility class
    }

    /* default */ static void export(SigningLedgerStoreEngine engine, Path targetRoot,
            Set<String> excludedNamespaces) throws IOException {
        Set<String> excluded = Set.copyOf(excludedNamespaces);
        SigningLedgerRecovery.initializeFormat(targetRoot);
        try (SigningMvccIndex.Snapshot snapshot = engine.snapshot()) {
            SnapshotShape shape = shape(snapshot, excluded);
            Optional<SigningManifestCodec.Checkpoint> checkpoint = shape.count == 0
                    ? Optional.empty() : Optional.of(writeCheckpoint(
                            engine, snapshot, targetRoot, excluded, shape));
            long revision = shape.count;
            long sequence = shape.count == 0 ? 0L : shape.count - 1L;
            SigningManifestCodec.ActiveWal active = writeEmptyActive(targetRoot,
                    shape.count == 0 ? 0L : shape.count, revision);
            SigningManifestCodec.Manifest manifest = new SigningManifestCodec.Manifest(
                    revision, sequence, checkpoint, List.of(), active);
            byte[] encoded = SigningManifestCodec.encode(manifest);
            SigningFilePublisher.publishManifest(
                    targetRoot.resolve(SigningLedgerRecovery.MANIFEST_FILE),
                    channel -> SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(encoded)));
        }
    }

    private static SnapshotShape shape(SigningMvccIndex.Snapshot snapshot,
            Set<String> excluded) throws IOException {
        long[] count = { 0L };
        long[] indexBytes = { SigningCheckpointCodec.HEADER_BYTES };
        snapshot.visit(record -> {
            if (excluded.contains(record.key().namespace())) return;
            count[0] = Math.incrementExact(count[0]);
            indexBytes[0] = Math.addExact(indexBytes[0],
                    SigningCheckpointCodec.encodedIndexBytes(record.key().canonical()));
        });
        if (count[0] > SigningCheckpointCodec.MAX_ENTRIES) {
            throw new IOException("Snapshot metadata key capacity is exhausted");
        }
        return new SnapshotShape(Math.toIntExact(count[0]), indexBytes[0]);
    }

    private static SigningManifestCodec.Checkpoint writeCheckpoint(
            SigningLedgerStoreEngine engine, SigningMvccIndex.Snapshot snapshot,
            Path targetRoot, Set<String> excluded, SnapshotShape shape) throws IOException {
        long committedSequence = shape.count - 1L;
        SigningCheckpointCodec.Header header = new SigningCheckpointCodec.Header(
                CHECKPOINT_IDENTITY, shape.count, committedSequence,
                shape.count, shape.dataOffset);
        String name = SigningManifestCodec.checkpointName(shape.count, committedSequence);
        Path path = targetRoot.resolve(name);
        SigningFilePublisher.publishImmutable(path,
                channel -> writeCheckpoint(engine, snapshot, excluded, header, channel));
        byte[] commitment;
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            commitment = SigningFileCommitment.sha256(channel);
        }
        return new SigningManifestCodec.Checkpoint(CHECKPOINT_IDENTITY, shape.count,
                committedSequence, java.nio.file.Files.size(path), commitment, name);
    }

    private static void writeCheckpoint(SigningLedgerStoreEngine engine,
            SigningMvccIndex.Snapshot snapshot, Set<String> excluded,
            SigningCheckpointCodec.Header header, FileChannel channel) throws IOException {
        SigningCheckpointCodec.Writer writer = SigningCheckpointCodec.writer(channel, header);
        long[] ordinal = { 0L };
        long[] offset = { header.dataOffset() };
        snapshot.visit(record -> {
            if (excluded.contains(record.key().namespace())) return;
            byte[] frame = frame(engine, record, ordinal[0]);
            writer.writeIndex(descriptor(record, frame, ordinal[0], offset[0]));
            offset[0] = Math.addExact(offset[0], frame.length);
            ordinal[0] = Math.incrementExact(ordinal[0]);
        });
        writer.beginData();
        ordinal[0] = 0L;
        offset[0] = header.dataOffset();
        snapshot.visit(record -> {
            if (excluded.contains(record.key().namespace())) return;
            byte[] frame = frame(engine, record, ordinal[0]);
            SigningCheckpointCodec.EntryDescriptor descriptor =
                    descriptor(record, frame, ordinal[0], offset[0]);
            writer.writeValidatedFrame(descriptor, frame);
            offset[0] = Math.addExact(offset[0], frame.length);
            ordinal[0] = Math.incrementExact(ordinal[0]);
        });
        writer.finish();
    }

    private static SigningCheckpointCodec.EntryDescriptor descriptor(
            SigningMvccIndex.SnapshotRecord record, byte[] frame, long ordinal, long offset) {
        SigningWalFrameCodec.Frame decoded;
        try {
            decoded = SigningWalFrameCodec.decode(frame);
        } catch (IOException impossible) {
            throw new IllegalStateException("Synthesized snapshot frame is invalid", impossible);
        }
        return new SigningCheckpointCodec.EntryDescriptor(record.key().canonical(),
                decoded.recordType(), offset, frame.length, ordinal + 1L, ordinal);
    }

    private static byte[] frame(SigningLedgerStoreEngine engine,
            SigningMvccIndex.SnapshotRecord record, long sequence) throws IOException {
        Optional<SigningLedgerStoreEngine.SnapshotOutcome> outcome = engine.snapshotOutcome(record);
        if (outcome.isPresent()) {
            SigningLedgerStoreEngine.SnapshotOutcome retained = outcome.orElseThrow();
            MetadataCommitResult result = retained.result();
            SigningWalFrameCodec.RecordType type;
            byte[] payload;
            switch (result.outcome()) {
                case UNKNOWN -> {
                    type = SigningWalFrameCodec.RecordType.ISSUE;
                    payload = SigningTransactionPayloadCodec.issue();
                }
                case COMMITTED -> {
                    type = SigningWalFrameCodec.RecordType.COMMIT;
                    payload = SigningTransactionPayloadCodec.committedOutcome();
                }
                case NOT_COMMITTED -> {
                    type = SigningWalFrameCodec.RecordType.REJECT;
                    payload = SigningTransactionPayloadCodec.reject(
                            result.failureCategory().orElseThrow());
                }
                default -> throw new IllegalStateException("Snapshot outcome is unsupported");
            }
            return SigningWalFrameCodec.encode(new SigningWalFrameCodec.Frame(
                    type, retained.transactionId(), sequence, payload));
        }
        OptionalLong watermark = engine.snapshotWatermark(record);
        if (watermark.isPresent()) {
            return SigningWalFrameCodec.encode(new SigningWalFrameCodec.Frame(
                    SigningWalFrameCodec.RecordType.WATERMARK,
                    deterministicTransaction(record), sequence,
                    SigningTransactionPayloadCodec.watermark(watermark.getAsLong())));
        }
        byte[] value = engine.readValue(record);
        SigningTransactionPayloadCodec.Mutation mutation =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        record.key(), -1L, value);
        return SigningWalFrameCodec.encode(new SigningWalFrameCodec.Frame(
                SigningWalFrameCodec.RecordType.COMMIT,
                deterministicTransaction(record), sequence,
                SigningTransactionPayloadCodec.commit(List.of(mutation))));
    }

    private static UUID deterministicTransaction(SigningMvccIndex.SnapshotRecord record) {
        return UUID.nameUUIDFromBytes(record.key().canonical().getBytes(StandardCharsets.US_ASCII));
    }

    private static SigningManifestCodec.ActiveWal writeEmptyActive(Path targetRoot,
            long firstSequence, long baselineRevision) throws IOException {
        SigningActiveWal.Descriptor descriptor = new SigningActiveWal.Descriptor(
                ACTIVE_IDENTITY, firstSequence, baselineRevision);
        byte[] header = SigningWalContainerCodec.encode(new SigningWalContainerCodec.Header(
                descriptor.identity(), descriptor.firstSequence(), descriptor.baselineRevision()));
        String name = SigningManifestCodec.activeName(ACTIVE_IDENTITY);
        SigningFilePublisher.publishImmutable(targetRoot.resolve(name),
                channel -> SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(header)));
        return new SigningManifestCodec.ActiveWal(ACTIVE_IDENTITY, firstSequence,
                baselineRevision, header.length, SigningFormatSupport.sha256().digest(header), name);
    }

    private record SnapshotShape(int count, long dataOffset) { }
}
