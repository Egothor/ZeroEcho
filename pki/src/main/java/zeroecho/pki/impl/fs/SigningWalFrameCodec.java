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
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.zip.CRC32C;

/** Version-one, big-endian signing WAL frame, batch marker, and scanner codec. */
@SuppressWarnings("PMD.CyclomaticComplexity")
final class SigningWalFrameCodec {

    /* default */ static final int MAGIC = 0x5A455746;
    /* default */ static final short VERSION = 1;
    /* default */ static final int HEADER_BYTES = 44;
    /* default */ static final int CHECKSUM_BYTES = Integer.BYTES;
    /* default */ static final int MAX_PAYLOAD_BYTES = 2 * 1024 * 1024;
    /* default */ static final int MAX_FRAME_BYTES = HEADER_BYTES + MAX_PAYLOAD_BYTES + CHECKSUM_BYTES;
    /* default */ static final int MAX_BATCH_FRAMES = 32;

    private static final short FLAGS = 0;
    private static final int BATCH_MAGIC = 0x5A454243;
    private static final int BATCH_CORE_BYTES = 40;
    private static final int BATCH_PAYLOAD_BYTES = BATCH_CORE_BYTES + 3 * SigningFormatSupport.SHA_256_BYTES;
    private static final long NO_REMAINING_BYTES = 0L;
    /* default */ static final int BATCH_MARKER_BYTES = HEADER_BYTES + BATCH_PAYLOAD_BYTES + CHECKSUM_BYTES;
    private static final UUID STRUCTURAL_TRANSACTION = new UUID(0L, 0L);
    private static final byte[] GROUP_DOMAIN =
            "ZeroEcho signing WAL batch v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CHAIN_DOMAIN =
            "ZeroEcho signing WAL chain v1".getBytes(StandardCharsets.US_ASCII);

    private SigningWalFrameCodec() {
        // utility class
    }

    /* default */ static byte[] encode(Frame frame) {
        requireDataFrame(frame);
        ByteBuffer output = ByteBuffer.allocate(frameLength(frame.payloadInternal().length));
        CRC32C crc = new CRC32C();
        ByteBuffer header = encodeHeader(frame.recordType(), frame.transactionId(),
                frame.sequence(), frame.payloadInternal().length);
        update(crc, header.array(), 0, HEADER_BYTES);
        output.put(header);
        output.put(frame.payloadInternal());
        crc.update(frame.payloadInternal(), 0, frame.payloadInternal().length);
        output.putInt((int) crc.getValue());
        return output.array();
    }

    /* default */ static int encodedLength(Frame frame) {
        requireDataFrame(frame);
        return frameLength(frame.payloadInternal().length);
    }

    /* default */ static Frame decode(byte[] encoded) throws IOException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length < HEADER_BYTES + CHECKSUM_BYTES || encoded.length > MAX_FRAME_BYTES) {
            throw invalid("signing WAL frame length is invalid");
        }
        ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        Header header = decodeHeader(input);
        if (header.frameLength() != encoded.length || header.recordType() == RecordType.BATCH_COMMIT) {
            throw invalid("signing WAL frame boundary or type is invalid");
        }
        verifyChecksum(encoded);
        byte[] payload = new byte[header.payloadLength()];
        input.get(payload);
        input.getInt();
        return Frame.decoded(header.recordType(), header.transactionId(), header.sequence(), payload);
    }

    /**
     * Writes data frames followed by one integrity-covered commit marker. The
     * caller may force the channel once after this method returns.
     */
    /* default */ static BatchCommit writeCommittedBatch(WritableByteChannel channel,
            List<Frame> frames, long previousCommittedRevision, long committedRevision,
            byte[] previousCommitment) throws IOException {
        Objects.requireNonNull(channel, "channel");
        ByteBuffer encoded = ByteBuffer.allocate(encodedBatchLength(frames));
        BatchCommit commit = encodeCommittedBatch(encoded, frames, previousCommittedRevision,
                committedRevision, previousCommitment);
        encoded.flip();
        SigningFormatSupport.writeFully(channel, encoded);
        return commit;
    }

    /** Encodes one complete committed group into caller-owned contiguous storage. */
    /* default */ static BatchCommit encodeCommittedBatch(ByteBuffer output,
            List<Frame> frames, long previousCommittedRevision, long committedRevision,
            byte[] previousCommitment) {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(frames, "frames");
        requireCommitment(previousCommitment);
        if (frames.isEmpty() || frames.size() > MAX_BATCH_FRAMES
                || previousCommittedRevision < 0L || committedRevision <= previousCommittedRevision) {
            throw new IllegalArgumentException("signing WAL batch fields are invalid");
        }
        long start = frames.get(0).sequence();
        long expected = start;
        int required = encodedBatchLength(frames);
        if (!output.hasArray() || output.isReadOnly() || output.remaining() < required) {
            throw new IllegalArgumentException("signing WAL batch output capacity is insufficient");
        }
        for (int index = 0; index < frames.size(); index++) {
            Frame frame = frames.get(index);
            requireDataFrame(frame);
            if (frame.sequence() != expected) {
                throw new IllegalArgumentException("signing WAL batch sequence is not contiguous");
            }
            expected = incrementUnlessLast(expected, index + 1 < frames.size());
        }
        ByteOrder originalOrder = output.order();
        try {
            output.order(ByteOrder.BIG_ENDIAN);
            MessageDigest groupDigest = newGroupDigest(previousCommitment);
            for (Frame frame : frames) {
                encodeDataFrame(output, frame, groupDigest);
            }
            long end = frames.get(frames.size() - 1).sequence();
            byte[] core = batchCore(start, end, frames.size(), committedRevision);
            groupDigest.update(core);
            byte[] groupCommitment = groupDigest.digest();
            byte[] resultingCommitment = chainCommitment(previousCommitment, groupCommitment, core);
            BatchCommit commit = new BatchCommit(start, end, frames.size(), committedRevision,
                    previousCommitment, groupCommitment, resultingCommitment);
            encodeMarker(output, commit);
            return commit;
        } finally {
            output.order(originalOrder);
        }
    }

    private static int encodedBatchLength(List<Frame> frames) {
        Objects.requireNonNull(frames, "frames");
        int result = BATCH_MARKER_BYTES;
        for (Frame frame : frames) {
            result = Math.addExact(result, encodedLength(frame));
        }
        return result;
    }

    /* default */ static ScanResult scan(SeekableByteChannel channel, long expectedFirstSequence,
            boolean activeWal, java.util.function.Consumer<Frame> consumer) throws IOException {
        Objects.requireNonNull(consumer, "consumer");
        return scanGroups(channel, expectedFirstSequence, activeWal, (frames, commit) -> {
            for (ScannedFrame frame : frames) {
                consumer.accept(frame.frame());
            }
        }, false);
    }

    /** Scans and delivers each group only after its commit marker is validated. */
    /* default */ static ScanResult scanGroups(SeekableByteChannel channel,
            long expectedFirstSequence, boolean activeWal, GroupConsumer consumer) throws IOException {
        return scanGroups(channel, expectedFirstSequence, activeWal, consumer, false);
    }

    /** Scans with optional whole-file commitment calculation for immutable files. */
    @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.NcssCount" })
    /* default */ static ScanResult scanGroups(SeekableByteChannel channel,
            long expectedFirstSequence, boolean activeWal, GroupConsumer consumer,
            boolean calculateFileCommitment) throws IOException {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(consumer, "consumer");
        if (expectedFirstSequence < 0) {
            throw new IllegalArgumentException("expected sequence must be non-negative");
        }
        long fileSize = channel.size();
        channel.position(0L);
        BufferedInput input = new BufferedInput(channel, fileSize);
        byte[] containerBytes = new byte[SigningWalContainerCodec.HEADER_BYTES];
        input.readFully(containerBytes, "signing WAL container header is truncated");
        SigningWalContainerCodec.Header container = SigningWalContainerCodec.decode(containerBytes);
        if (container.firstSequence() != expectedFirstSequence) {
            throw invalid("signing WAL container sequence is inconsistent");
        }

        MessageDigest fileDigest = calculateFileCommitment ? SigningFormatSupport.sha256() : null;
        if (fileDigest != null) {
            fileDigest.update(containerBytes);
        }
        byte[] rollingCommitment = SigningFormatSupport.sha256().digest(containerBytes);
        long offset = SigningWalContainerCodec.HEADER_BYTES;
        long groupOffset = offset;
        long expected = expectedFirstSequence;
        long committedCount = 0L;
        long lastCommitted = -1L;
        long lastCommittedRevision = container.baselineRevision();
        List<ScannedFrame> pending = new ArrayList<>(MAX_BATCH_FRAMES);
        MessageDigest groupDigest = newGroupDigest(rollingCommitment);
        ByteBuffer headerBuffer = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        ByteBuffer checksumBuffer = ByteBuffer.allocate(CHECKSUM_BYTES).order(ByteOrder.BIG_ENDIAN);
        while (offset < fileSize) {
            headerBuffer.clear();
            if (!input.readFullyOrEnd(headerBuffer.array(), HEADER_BYTES)) {
                return uncommittedTail(activeWal, groupOffset, committedCount,
                        lastCommitted, lastCommittedRevision, rollingCommitment);
            }
            headerBuffer.position(0).limit(HEADER_BYTES);
            Header header = decodeHeader(headerBuffer);
            long nextOffset = checkedNextOffset(offset, header.frameLength());
            if (nextOffset > fileSize) {
                return uncommittedTail(activeWal, groupOffset, committedCount,
                        lastCommitted, lastCommittedRevision, rollingCommitment);
            }
            byte[] payload = new byte[header.payloadLength()];
            input.readFully(payload, "signing WAL frame is truncated");
            checksumBuffer.clear();
            input.readFully(checksumBuffer.array(), "signing WAL checksum is truncated");
            int suppliedChecksum = checksumBuffer.getInt(0);
            verifyChecksum(headerBuffer.array(), payload, suppliedChecksum);
            if (fileDigest != null) {
                fileDigest.update(headerBuffer.array(), 0, HEADER_BYTES);
                fileDigest.update(payload);
                fileDigest.update(checksumBuffer.array(), 0, CHECKSUM_BYTES);
            }

            if (header.recordType() == RecordType.BATCH_COMMIT) {
                BatchCommit commit = decodeBatchCommit(header, payload);
                validateBatchCommit(commit, pending, expected, lastCommittedRevision,
                        rollingCommitment, groupDigest);
                long firstRevision = Math.subtractExact(commit.committedRevision(),
                        pending.size() - 1L);
                List<ScannedFrame> committedFrames = new ArrayList<>(pending.size());
                for (int index = 0; index < pending.size(); index++) {
                    ScannedFrame scanned = pending.get(index);
                    committedFrames.add(new ScannedFrame(scanned.frame(), scanned.offset(),
                            scanned.encodedLength(), Math.addExact(firstRevision, index)));
                }
                consumer.accept(List.copyOf(committedFrames), commit);
                committedCount = Math.addExact(committedCount, pending.size());
                lastCommitted = commit.endSequence();
                lastCommittedRevision = commit.committedRevision();
                expected = incrementUnlessLast(commit.endSequence(), nextOffset < fileSize);
                rollingCommitment = commit.resultingCommitment();
                pending.clear();
                groupOffset = nextOffset;
                groupDigest = newGroupDigest(rollingCommitment);
            } else {
                if (pending.size() == MAX_BATCH_FRAMES || header.sequence() != expected) {
                    throw invalid("signing WAL batch sequence is invalid");
                }
                groupDigest.update(headerBuffer.array(), 0, HEADER_BYTES);
                groupDigest.update(payload);
                groupDigest.update(checksumBuffer.array(), 0, CHECKSUM_BYTES);
                Frame frame = Frame.decoded(header.recordType(), header.transactionId(),
                        header.sequence(), payload);
                pending.add(new ScannedFrame(frame, offset, header.frameLength(), -1L));
                expected = incrementUnlessLast(expected, true);
            }
            offset = nextOffset;
        }
        if (!pending.isEmpty()) {
            return uncommittedTail(activeWal, groupOffset, committedCount,
                    lastCommitted, lastCommittedRevision, rollingCommitment);
        }
        return new ScanResult(committedCount, lastCommitted, lastCommittedRevision,
                -1L, rollingCommitment,
                fileDigest == null ? new byte[0] : fileDigest.digest());
    }

    /**
     * Validates one lower-exclusive, forced-upper-inclusive committed suffix.
     * No channel read crosses the descriptor's forced-end offset.
     */
    @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.NcssCount" })
    /* default */ static PrefixScanResult scanCommittedPrefix(SeekableByteChannel channel,
            CommittedPrefixDescriptor descriptor, long maximumAcceptedRevision,
            PrefixGroupConsumer consumer) throws IOException {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(descriptor, "descriptor");
        Objects.requireNonNull(consumer, "consumer");
        if (maximumAcceptedRevision < descriptor.exclusiveStartRevision()) {
            throw new IllegalArgumentException(
                    "signing committed-prefix accepted revision is invalid");
        }
        long forcedEnd = descriptor.inclusiveForcedEndOffset();
        validatePrefixContainer(channel, descriptor, forcedEnd);

        channel.position(descriptor.exclusiveStartOffset());
        BufferedInput input = new BufferedInput(channel, forcedEnd);
        long offset = descriptor.exclusiveStartOffset();
        long groupOffset = offset;
        long expected = Math.incrementExact(descriptor.exclusiveStartSequence());
        long committedCount = 0L;
        long lastCommitted = descriptor.exclusiveStartSequence();
        long lastCommittedRevision = descriptor.exclusiveStartRevision();
        byte[] rollingCommitment = descriptor.exclusiveStartCommitment();
        List<ScannedFrame> pending = new ArrayList<>(MAX_BATCH_FRAMES);
        MessageDigest groupDigest = newGroupDigest(rollingCommitment);
        ByteBuffer headerBuffer = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        ByteBuffer checksumBuffer = ByteBuffer.allocate(CHECKSUM_BYTES).order(ByteOrder.BIG_ENDIAN);
        while (offset < forcedEnd) {
            headerBuffer.clear();
            if (!input.readFullyOrEnd(headerBuffer.array(), HEADER_BYTES)) {
                throw invalid("signing committed-prefix group is truncated");
            }
            headerBuffer.position(0).limit(HEADER_BYTES);
            Header header = decodeHeader(headerBuffer);
            long nextOffset = checkedNextOffset(offset, header.frameLength());
            if (nextOffset > forcedEnd) {
                throw invalid("signing committed-prefix frame crosses its forced end");
            }
            byte[] payload = new byte[header.payloadLength()];
            input.readFully(payload, "signing committed-prefix frame is truncated");
            checksumBuffer.clear();
            input.readFully(checksumBuffer.array(),
                    "signing committed-prefix checksum is truncated");
            verifyChecksum(headerBuffer.array(), payload, checksumBuffer.getInt(0));

            if (header.recordType() == RecordType.BATCH_COMMIT) {
                BatchCommit commit = decodeBatchCommit(header, payload);
                validateBatchCommit(commit, pending, expected, lastCommittedRevision,
                        rollingCommitment, groupDigest);
                if (commit.committedRevision()
                        != Math.addExact(lastCommittedRevision, pending.size())) {
                    throw invalid("signing committed-prefix revision is not contiguous");
                }
                if (commit.committedRevision() > maximumAcceptedRevision) {
                    return new PrefixScanResult(committedCount, lastCommitted,
                            lastCommittedRevision, groupOffset, rollingCommitment, false);
                }
                long firstRevision = Math.subtractExact(commit.committedRevision(),
                        pending.size() - 1L);
                List<ScannedFrame> committedFrames = new ArrayList<>(pending.size());
                for (int index = 0; index < pending.size(); index++) {
                    ScannedFrame scanned = pending.get(index);
                    committedFrames.add(new ScannedFrame(scanned.frame(), scanned.offset(),
                            scanned.encodedLength(), Math.addExact(firstRevision, index)));
                }
                consumer.accept(List.copyOf(committedFrames), commit, nextOffset);
                committedCount = Math.addExact(committedCount, pending.size());
                lastCommitted = commit.endSequence();
                lastCommittedRevision = commit.committedRevision();
                expected = incrementUnlessLast(commit.endSequence(), nextOffset < forcedEnd);
                rollingCommitment = commit.resultingCommitment();
                pending.clear();
                groupOffset = nextOffset;
                groupDigest = newGroupDigest(rollingCommitment);
            } else {
                if (pending.size() == MAX_BATCH_FRAMES || header.sequence() != expected) {
                    throw invalid("signing committed-prefix sequence is not contiguous");
                }
                groupDigest.update(headerBuffer.array(), 0, HEADER_BYTES);
                groupDigest.update(payload);
                groupDigest.update(checksumBuffer.array(), 0, CHECKSUM_BYTES);
                Frame frame = Frame.decoded(header.recordType(), header.transactionId(),
                        header.sequence(), payload);
                pending.add(new ScannedFrame(frame, offset, header.frameLength(), -1L));
                expected = incrementUnlessLast(expected, true);
            }
            offset = nextOffset;
        }
        if (!pending.isEmpty() || groupOffset != forcedEnd
                || lastCommitted != descriptor.inclusiveForcedEndSequence()
                || lastCommittedRevision != descriptor.inclusiveForcedEndRevision()
                || !MessageDigest.isEqual(rollingCommitment,
                        descriptor.inclusiveForcedEndCommitment())) {
            throw invalid("signing committed-prefix forced endpoint is inconsistent");
        }
        return new PrefixScanResult(committedCount, lastCommitted,
                lastCommittedRevision, forcedEnd, rollingCommitment, true);
    }

    private static void validatePrefixContainer(SeekableByteChannel channel,
            CommittedPrefixDescriptor descriptor, long forcedEnd) throws IOException {
        if (channel.size() < forcedEnd) {
            throw invalid("signing committed prefix is truncated");
        }
        channel.position(0L);
        ByteBuffer containerBuffer = ByteBuffer.allocate(SigningWalContainerCodec.HEADER_BYTES);
        while (containerBuffer.hasRemaining()) {
            int count = channel.read(containerBuffer);
            if (count <= 0) {
                throw invalid("signing committed-prefix container is truncated");
            }
        }
        byte[] containerBytes = containerBuffer.array();
        SigningWalContainerCodec.Header container = SigningWalContainerCodec.decode(containerBytes);
        long containerPredecessor = container.firstSequence() == 0L
                ? -1L : container.firstSequence() - 1L;
        if (container.identity() != descriptor.generationId()
                || descriptor.exclusiveStartSequence() < containerPredecessor
                || descriptor.exclusiveStartRevision() < container.baselineRevision()) {
            throw invalid("signing committed-prefix container is inconsistent");
        }
        if (descriptor.exclusiveStartOffset() == SigningWalContainerCodec.HEADER_BYTES
                && (descriptor.exclusiveStartSequence() != containerPredecessor
                || descriptor.exclusiveStartRevision() != container.baselineRevision()
                || !MessageDigest.isEqual(descriptor.exclusiveStartCommitment(),
                        SigningFormatSupport.sha256().digest(containerBytes)))) {
            throw invalid("signing committed-prefix baseline is inconsistent");
        }
    }

    private static void encodeDataFrame(ByteBuffer output, Frame frame,
            MessageDigest groupDigest) {
        byte[] payload = frame.payloadInternal();
        int frameStart = output.position();
        encodeHeaderInto(output, frame.recordType(), frame.transactionId(),
                frame.sequence(), payload.length);
        output.put(payload);
        CRC32C crc = new CRC32C();
        int arrayStart = Math.addExact(output.arrayOffset(), frameStart);
        int checkedBytes = Math.addExact(HEADER_BYTES, payload.length);
        update(crc, output.array(), arrayStart, checkedBytes);
        output.putInt((int) crc.getValue());
        groupDigest.update(output.array(), arrayStart,
                Math.addExact(checkedBytes, CHECKSUM_BYTES));
    }

    private static void encodeMarker(ByteBuffer output, BatchCommit commit) {
        byte[] payload = encodeBatchCommit(commit);
        int markerStart = output.position();
        encodeHeaderInto(output, RecordType.BATCH_COMMIT, STRUCTURAL_TRANSACTION,
                commit.endSequence(), payload.length);
        output.put(payload);
        CRC32C crc = new CRC32C();
        int arrayStart = Math.addExact(output.arrayOffset(), markerStart);
        int checkedBytes = Math.addExact(HEADER_BYTES, payload.length);
        update(crc, output.array(), arrayStart, checkedBytes);
        output.putInt((int) crc.getValue());
    }

    private static void encodeHeaderInto(ByteBuffer output, RecordType type,
            UUID transactionId, long sequence, int payloadLength) {
        output.putInt(MAGIC).putShort(VERSION).putShort((short) HEADER_BYTES)
                .putInt(frameLength(payloadLength)).putShort(type.wireCode()).putShort(FLAGS)
                .putLong(sequence).putLong(transactionId.getMostSignificantBits())
                .putLong(transactionId.getLeastSignificantBits()).putInt(payloadLength);
    }

    private static void validateBatchCommit(BatchCommit commit, List<ScannedFrame> pending,
            long expectedAfterData, long priorRevision, byte[] rollingCommitment,
            MessageDigest groupDigest) throws IOException {
        if (pending.isEmpty() || pending.size() != commit.frameCount()
                || pending.get(0).frame().sequence() != commit.startSequence()
                || pending.get(pending.size() - 1).frame().sequence() != commit.endSequence()
                || expectedAfterData != incrementUnlessLast(commit.endSequence(), true)
                || commit.committedRevision() <= priorRevision
                || !MessageDigest.isEqual(rollingCommitment, commit.previousCommitment())) {
            throw invalid("signing WAL batch marker is inconsistent");
        }
        byte[] core = batchCore(commit.startSequence(), commit.endSequence(),
                commit.frameCount(), commit.committedRevision());
        groupDigest.update(core);
        byte[] calculatedGroup = groupDigest.digest();
        byte[] calculatedChain = chainCommitment(rollingCommitment, calculatedGroup, core);
        if (!MessageDigest.isEqual(calculatedGroup, commit.groupCommitment())
                || !MessageDigest.isEqual(calculatedChain, commit.resultingCommitment())) {
            throw invalid("signing WAL batch commitment is invalid");
        }
    }

    private static BatchCommit decodeBatchCommit(Header header, byte[] payload) throws IOException {
        if (header.payloadLength() != BATCH_PAYLOAD_BYTES
                || !STRUCTURAL_TRANSACTION.equals(header.transactionId())) {
            throw invalid("signing WAL batch marker framing is invalid");
        }
        ByteBuffer input = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
        int magic = input.getInt();
        short version = input.getShort();
        short flags = input.getShort();
        long start = input.getLong();
        long end = input.getLong();
        int count = input.getInt();
        int reserved = input.getInt();
        long revision = input.getLong();
        byte[] previous = new byte[SigningFormatSupport.SHA_256_BYTES];
        byte[] group = new byte[SigningFormatSupport.SHA_256_BYTES];
        byte[] resulting = new byte[SigningFormatSupport.SHA_256_BYTES];
        input.get(previous).get(group).get(resulting);
        if (magic != BATCH_MAGIC || version != VERSION || flags != FLAGS || reserved != 0
                || start < 0L || end < start || count <= 0 || count > MAX_BATCH_FRAMES
                || revision < 0L || header.sequence() != end) {
            throw invalid("signing WAL batch marker fields are invalid");
        }
        return new BatchCommit(start, end, count, revision, previous, group, resulting);
    }

    private static byte[] encodeBatchCommit(BatchCommit commit) {
        ByteBuffer output = ByteBuffer.allocate(BATCH_PAYLOAD_BYTES).order(ByteOrder.BIG_ENDIAN);
        output.put(batchCore(commit.startSequence(), commit.endSequence(),
                commit.frameCount(), commit.committedRevision()));
        output.put(commit.previousCommitmentInternal());
        output.put(commit.groupCommitmentInternal());
        output.put(commit.resultingCommitmentInternal());
        return output.array();
    }

    private static byte[] batchCore(long start, long end, int count, long revision) {
        ByteBuffer core = ByteBuffer.allocate(BATCH_CORE_BYTES).order(ByteOrder.BIG_ENDIAN);
        core.putInt(BATCH_MAGIC).putShort(VERSION).putShort(FLAGS).putLong(start).putLong(end)
                .putInt(count).putInt(0).putLong(revision);
        return core.array();
    }

    private static MessageDigest newGroupDigest(byte[] previousCommitment) {
        MessageDigest digest = SigningFormatSupport.sha256();
        digest.update(GROUP_DOMAIN);
        digest.update(previousCommitment);
        return digest;
    }

    private static byte[] chainCommitment(byte[] previous, byte[] group, byte[] core) {
        MessageDigest digest = SigningFormatSupport.sha256();
        digest.update(CHAIN_DOMAIN);
        digest.update(previous);
        digest.update(group);
        digest.update(core);
        return digest.digest();
    }

    private static ByteBuffer encodeHeader(RecordType type, UUID transactionId,
            long sequence, int payloadLength) {
        ByteBuffer header = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.BIG_ENDIAN);
        header.putInt(MAGIC).putShort(VERSION).putShort((short) HEADER_BYTES)
                .putInt(frameLength(payloadLength)).putShort(type.wireCode()).putShort(FLAGS)
                .putLong(sequence).putLong(transactionId.getMostSignificantBits())
                .putLong(transactionId.getLeastSignificantBits()).putInt(payloadLength).flip();
        return header;
    }

    private static Header decodeHeader(ByteBuffer input) throws IOException {
        input.order(ByteOrder.BIG_ENDIAN);
        int magic = input.getInt();
        short version = input.getShort();
        int headerLength = Short.toUnsignedInt(input.getShort());
        int encodedLength = input.getInt();
        RecordType type = RecordType.fromWireCode(input.getShort());
        short flags = input.getShort();
        long sequence = input.getLong();
        UUID transactionId = new UUID(input.getLong(), input.getLong());
        int payloadLength = input.getInt();
        if (magic != MAGIC || version != VERSION || headerLength != HEADER_BYTES
                || flags != FLAGS || type == null || sequence < 0L || payloadLength < 0
                || payloadLength > MAX_PAYLOAD_BYTES || encodedLength != frameLength(payloadLength)) {
            throw invalid("signing WAL header is invalid or unsupported");
        }
        return new Header(type, transactionId, sequence, payloadLength, encodedLength);
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private static long checkedNextOffset(long offset, int length) throws IOException {
        try {
            return Math.addExact(offset, length);
        } catch (ArithmeticException failure) {
            throw invalid("signing WAL frame boundary overflows");
        }
    }

    private static int frameLength(int payloadLength) {
        return Math.addExact(HEADER_BYTES + CHECKSUM_BYTES, payloadLength);
    }

    private static void verifyChecksum(byte[] encoded) throws IOException {
        int supplied = ByteBuffer.wrap(encoded, encoded.length - CHECKSUM_BYTES,
                CHECKSUM_BYTES).order(ByteOrder.BIG_ENDIAN).getInt();
        verifyChecksum(Arrays.copyOf(encoded, HEADER_BYTES),
                Arrays.copyOfRange(encoded, HEADER_BYTES, encoded.length - CHECKSUM_BYTES), supplied);
    }

    private static void verifyChecksum(byte[] header, byte[] payload, int supplied) throws IOException {
        CRC32C crc = new CRC32C();
        update(crc, header, 0, header.length);
        crc.update(payload, 0, payload.length);
        if ((int) crc.getValue() != supplied) {
            throw invalid("signing WAL checksum is invalid");
        }
    }

    private static void update(CRC32C crc, byte[] bytes, int offset, int length) {
        crc.update(bytes, offset, length);
    }

    private static ScanResult uncommittedTail(boolean activeWal, long groupOffset,
            long count, long last, long revision, byte[] rollingCommitment) throws IOException {
        if (!activeWal) {
            throw invalid("sealed signing WAL has an uncommitted tail");
        }
        return new ScanResult(count, last, revision, groupOffset, rollingCommitment, new byte[0]);
    }

    private static long incrementUnlessLast(long value, boolean increment) {
        if (!increment) {
            return value;
        }
        try {
            return Math.incrementExact(value);
        } catch (ArithmeticException failure) {
            throw new IllegalArgumentException("signing WAL sequence exceeds its range", failure);
        }
    }

    private static void requireDataFrame(Frame frame) {
        Objects.requireNonNull(frame, "frame");
        if (frame.recordType() == RecordType.BATCH_COMMIT) {
            throw new IllegalArgumentException("batch commit is a structural WAL record");
        }
    }

    private static void requireCommitment(byte[] commitment) {
        if (commitment == null || commitment.length != SigningFormatSupport.SHA_256_BYTES) {
            throw new IllegalArgumentException("signing WAL commitment is invalid");
        }
    }

    private static IOException invalid(String diagnostic) {
        return SigningFormatSupport.invalid(diagnostic);
    }

    /** Closed structural record kinds; payload schemas are defined separately. */
    /* default */ enum RecordType {
        INTENT(1), MUTATION(2), PROVIDER_RESULT(3), TERMINAL(4),
        ISSUE(10), COMMIT(11), REJECT(12), ACK(13), WATERMARK(14),
        BATCH_COMMIT(127);

        private final short wireCode;

        RecordType(int wireCode) {
            this.wireCode = (short) wireCode;
        }

        /* default */ short wireCode() {
            return wireCode;
        }

        private static RecordType fromWireCode(short code) {
            return Arrays.stream(values()).filter(value -> value.wireCode == code).findFirst().orElse(null);
        }
    }

    /** Immutable data frame with single-owned decoded payload storage. */
    @SuppressWarnings("PMD.DataClass")
    /* default */ static final class Frame {
        private final RecordType recordType;
        private final UUID transactionId;
        private final long sequence;
        private final byte[] payload;

        /* default */ Frame(RecordType recordType, UUID transactionId, long sequence, byte[] payload) {
            this(recordType, transactionId, sequence, payload, false);
        }

        private Frame(RecordType recordType, UUID transactionId, long sequence,
                byte[] payload, boolean ownsPayload) {
            this.recordType = Objects.requireNonNull(recordType, "recordType");
            this.transactionId = Objects.requireNonNull(transactionId, "transactionId");
            Objects.requireNonNull(payload, "payload");
            if (sequence < 0L || payload.length > MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("signing WAL frame fields are invalid");
            }
            this.sequence = sequence;
            this.payload = ownsPayload ? payload : payload.clone();
        }

        private static Frame decoded(RecordType type, UUID transactionId,
                long sequence, byte[] payload) {
            return new Frame(type, transactionId, sequence, payload, true);
        }

        /** Accepts payload storage already copied and exclusively owned by the caller. */
        /* default */ static Frame owned(RecordType type, UUID transactionId,
                long sequence, byte[] payload) {
            return new Frame(type, transactionId, sequence, payload, true);
        }

        /* default */ RecordType recordType() {
            return recordType;
        }

        /* default */ UUID transactionId() {
            return transactionId;
        }

        /* default */ long sequence() {
            return sequence;
        }

        /* default */ byte[] payload() {
            return payload.clone();
        }

        private byte[] payloadInternal() {
            return payload;
        }
    }

    /* default */ record BatchCommit(long startSequence, long endSequence, int frameCount,
            long committedRevision, byte[] previousCommitment, byte[] groupCommitment,
            byte[] resultingCommitment) {
        BatchCommit {
            requireCommitment(previousCommitment);
            requireCommitment(groupCommitment);
            requireCommitment(resultingCommitment);
            previousCommitment = previousCommitment.clone();
            groupCommitment = groupCommitment.clone();
            resultingCommitment = resultingCommitment.clone();
        }

        @Override public byte[] previousCommitment() { return previousCommitment.clone(); }
        @Override public byte[] groupCommitment() { return groupCommitment.clone(); }
        @Override public byte[] resultingCommitment() { return resultingCommitment.clone(); }
        private byte[] previousCommitmentInternal() { return previousCommitment; }
        private byte[] groupCommitmentInternal() { return groupCommitment; }
        private byte[] resultingCommitmentInternal() { return resultingCommitment; }
    }

    /* default */ record ScanResult(long frameCount, long lastSequence, long committedRevision,
            long incompleteTailOffset, byte[] rollingCommitment, byte[] fileCommitment) {
        ScanResult {
            rollingCommitment = rollingCommitment.clone();
            fileCommitment = fileCommitment.clone();
        }
        /* default */ boolean hasIncompleteTail() { return incompleteTailOffset >= 0L; }
        @Override public byte[] rollingCommitment() { return rollingCommitment.clone(); }
        @Override public byte[] fileCommitment() { return fileCommitment.clone(); }
    }

    /* default */ record PrefixScanResult(long frameCount, long lastSequence,
            long committedRevision, long acceptedOffset, byte[] rollingCommitment,
            boolean forcedEndReached) {
        PrefixScanResult {
            rollingCommitment = rollingCommitment.clone();
        }

        @Override public byte[] rollingCommitment() { return rollingCommitment.clone(); }
    }

    /** Callback-scoped decoded frame and exact immutable-file location. */
    /* default */ record ScannedFrame(Frame frame, long offset, int encodedLength, long revision) {
        ScannedFrame {
            Objects.requireNonNull(frame, "frame");
            if (offset < SigningWalContainerCodec.HEADER_BYTES || encodedLength <= 0
                    || encodedLength > MAX_FRAME_BYTES || revision < -1L) {
                throw new IllegalArgumentException("signing scanned frame fields are invalid");
            }
        }

        /** Read-only payload view valid only for the current scanner callback. */
        /* default */ ByteBuffer payloadView() {
            return ByteBuffer.wrap(frame.payloadInternal()).asReadOnlyBuffer();
        }
    }

    /** Bounded committed-group delivery seam used by recovery. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface GroupConsumer {
        /** Receives one fully validated committed group. */
        void accept(List<ScannedFrame> frames, BatchCommit commit) throws IOException;
    }

    /** Committed-prefix callback including the validated exclusive next offset. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface PrefixGroupConsumer {
        /** Receives one validated group and its exclusive physical end. */
        void accept(List<ScannedFrame> frames, BatchCommit commit,
                long acceptedOffset) throws IOException;
    }

    /** Sequential buffered adapter that never seeks per frame. */
    private static final class BufferedInput {
        private final SeekableByteChannel channel;
        private final long limit;
        private final ByteBuffer buffer = ByteBuffer.allocate(SigningFormatSupport.TRANSFER_BYTES);

        private BufferedInput(SeekableByteChannel channel, long limit) {
            this.channel = channel;
            this.limit = limit;
            buffer.limit(0);
        }

        private void readFully(byte[] target, String diagnostic) throws IOException {
            if (!readFullyOrEnd(target, target.length)) {
                throw invalid(diagnostic);
            }
        }

        private boolean readFullyOrEnd(byte[] target, int length) throws IOException {
            int copied = 0;
            while (copied < length) {
                if (!buffer.hasRemaining() && !refill()) {
                    return false;
                }
                int count = Math.min(length - copied, buffer.remaining());
                buffer.get(target, copied, count);
                copied += count;
            }
            return true;
        }

        private boolean refill() throws IOException {
            long remaining = limit - channel.position();
            if (remaining <= NO_REMAINING_BYTES) {
                return false;
            }
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), remaining));
            int read = channel.read(buffer);
            if (read == 0) {
                throw invalid("signing WAL I/O made no read progress");
            }
            buffer.flip();
            return read >= 0;
        }
    }

    private record Header(RecordType recordType, UUID transactionId, long sequence,
            int payloadLength, int frameLength) {
    }
}
