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

/**
 * Version-one, big-endian signing WAL frame, batch marker, and scanner codec.
 */
@SuppressWarnings("PMD.CyclomaticComplexity")
final class SigningWalFrameCodec {

    /**
     * Fixed binary magic identifying this persisted format.
     */
    /* default */ static final int MAGIC = 0x5A455746;
    /**
     * Current binary format version encoded independently of enum ordering.
     */
    /* default */ static final short VERSION = 1;
    /**
     * Fixed encoded header length in bytes.
     */
    /* default */ static final int HEADER_BYTES = 44;
    /**
     * Encoded frame checksum length in bytes.
     */
    /* default */ static final int CHECKSUM_BYTES = Integer.BYTES;
    /**
     * Inclusive maximum encoded frame payload length in bytes.
     */
    /* default */ static final int MAX_PAYLOAD_BYTES = 2 * 1024 * 1024;
    /**
     * Inclusive maximum complete frame length, including header and checksum, in bytes.
     */
    /* default */ static final int MAX_FRAME_BYTES = HEADER_BYTES + MAX_PAYLOAD_BYTES + CHECKSUM_BYTES;
    /**
     * Inclusive maximum number of frames in one committed WAL batch.
     */
    /* default */ static final int MAX_BATCH_FRAMES = 32;

    private static final short FLAGS = 0;
    private static final int BATCH_MAGIC = 0x5A454243;
    private static final int BATCH_CORE_BYTES = 40;
    private static final int BATCH_PAYLOAD_BYTES = BATCH_CORE_BYTES + 3 * SigningFormatSupport.SHA_256_BYTES;
    private static final long NO_REMAINING_BYTES = 0L;
    /**
     * Encoded batch commit marker length in bytes.
     */
    /* default */ static final int BATCH_MARKER_BYTES = HEADER_BYTES + BATCH_PAYLOAD_BYTES + CHECKSUM_BYTES;
    private static final UUID STRUCTURAL_TRANSACTION = new UUID(0L, 0L);
    private static final byte[] GROUP_DOMAIN =
            "ZeroEcho signing WAL batch v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CHAIN_DOMAIN =
            "ZeroEcho signing WAL chain v1".getBytes(StandardCharsets.US_ASCII);

    private SigningWalFrameCodec() {
        // utility class
    }

    /**
     * Encodes one bounded WAL frame into an independent checksum-protected byte array.
     *
     * @param frame data frame to encode
     * @return newly allocated complete encoded bytes
     * @throws NullPointerException if frame is null
     * @throws IllegalArgumentException if frame is a structural batch-commit record
     */
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

    /**
     * Calculates the complete encoded frame length, including fixed framing and checksum bytes.
     *
     * @param frame data frame to encode
     * @return complete encoded byte length
     * @throws NullPointerException if frame is null
     * @throws IllegalArgumentException if frame is a structural batch-commit record
     */
    /* default */ static int encodedLength(Frame frame) {
        requireDataFrame(frame);
        return frameLength(frame.payloadInternal().length);
    }

    /**
     * Authenticates and decodes exactly one complete WAL frame, rejecting malformed or trailing data.
     *
     * @param encoded complete encoded payload
     * @return authenticated decoded value
     * @throws IOException if framing or integrity validation fails, or the required I/O cannot complete
     * @throws NullPointerException if encoded is null
     */
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
     * Encodes and writes one bounded committed group at the current position of the borrowed channel. This method does not force the channel; the caller must force the complete group before acknowledging durability.
     *
     * @param channel borrowed channel, which remains open
     * @param frames nonempty bounded list of consecutively sequenced data frames
     * @param previousCommittedRevision revision immediately before the group
     * @param committedRevision new revision committed by this group
     * @param previousCommitment preceding 32-byte group commitment
     * @return group boundaries and chained commitment
     * @throws IOException if framing or integrity validation fails, or the required I/O cannot complete
     * @throws NullPointerException if channel or frames is null
     * @throws IllegalArgumentException if the group, revisions or preceding commitment violate committed-group encoding requirements
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

    /**
     * Encodes one bounded committed group into the supplied writable, array-backed buffer and advances its position. Frames must have consecutive sequences and the new revision must advance the previous committed revision.
     *
     * @param output destination buffer or output stream, retained by the caller
     * @param frames nonempty bounded list of consecutively sequenced data frames
     * @param previousCommittedRevision revision immediately before the group
     * @param committedRevision new revision committed by this group
     * @param previousCommitment preceding 32-byte group commitment
     * @return group boundaries and chained commitment
     * @throws IllegalArgumentException if the group, revisions, commitment or destination-buffer capacity violates encoding requirements
     * @throws NullPointerException if output or frames is null
     */
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

    /**
     * Scans validated committed WAL groups and delivers their frames in order. An incomplete terminal suffix is reported for an active WAL and rejected for a sealed WAL; callbacks never receive an uncommitted group.
     *
     * @param channel borrowed channel, which remains open
     * @param expectedFirstSequence sequence required for the first WAL frame
     * @param activeWal whether an incomplete terminal suffix may be reported for active-WAL repair
     * @param consumer callback for validated committed data
     * @return validated scan endpoint, commitment and terminal-tail classification
     * @throws IOException if framing or integrity validation fails, or the required I/O cannot complete
     * @throws NullPointerException if channel or consumer is null
     * @throws IllegalArgumentException if expectedFirstSequence is negative
     */
    /* default */ static ScanResult scan(SeekableByteChannel channel, long expectedFirstSequence,
            boolean activeWal, java.util.function.Consumer<Frame> consumer) throws IOException {
        Objects.requireNonNull(consumer, "consumer");
        return scanGroups(channel, expectedFirstSequence, activeWal, (frames, commit) -> {
            for (ScannedFrame frame : frames) {
                consumer.accept(frame.frame());
            }
        }, false);
    }

    /**
     * Scans and authenticates complete committed groups in sequence, invoking the consumer only after each group commitment is validated. Active-WAL terminal incompleteness is reported for repair; sealed-WAL incompleteness is rejected.
     *
     * @param channel borrowed channel, which remains open
     * @param expectedFirstSequence sequence required for the first WAL frame
     * @param activeWal whether an incomplete terminal suffix may be reported for active-WAL repair
     * @param consumer callback for validated committed data
     * @return validated scan endpoint, commitment and terminal-tail classification
     * @throws IOException if framing or integrity validation fails, or the required I/O cannot complete
     * @throws NullPointerException if channel or consumer is null
     * @throws IllegalArgumentException if expectedFirstSequence is negative
     */
    /* default */ static ScanResult scanGroups(SeekableByteChannel channel,
            long expectedFirstSequence, boolean activeWal, GroupConsumer consumer) throws IOException {
        return scanGroups(channel, expectedFirstSequence, activeWal, consumer, false);
    }

    /**
     * Scans and authenticates complete committed groups in sequence, invoking the consumer only after each group commitment is validated. Active-WAL terminal incompleteness is reported for repair; sealed-WAL incompleteness is rejected.
     *
     * @param channel borrowed channel, which remains open
     * @param expectedFirstSequence sequence required for the first WAL frame
     * @param activeWal whether an incomplete terminal suffix may be reported for active-WAL repair
     * @param consumer callback for validated committed data
     * @param calculateFileCommitment whether to calculate the complete scanned-file commitment
     * @return validated scan endpoint, commitment and terminal-tail classification
     * @throws IOException if framing or integrity validation fails, or the required I/O cannot complete
     * @throws NullPointerException if channel or consumer is null
     * @throws IllegalArgumentException if expectedFirstSequence is negative
     */
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
     * Validates only the descriptor-bounded committed prefix and delivers accepted groups without reading beyond its forced endpoint. The supplied revision limit must not precede the descriptor's exclusive starting revision.
     *
     * @param channel borrowed channel, which remains open
     * @param descriptor authoritative committed-prefix boundaries and commitments
     * @param maximumAcceptedRevision inclusive maximum revision delivered to the consumer
     * @param consumer callback for validated committed data
     * @return validated accepted prefix endpoint and commitment
     * @throws IOException if framing or integrity validation fails, or the required I/O cannot complete
     * @throws NullPointerException if channel, descriptor or consumer is null
     * @throws IllegalArgumentException if maximumAcceptedRevision precedes the descriptor's exclusive starting revision
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

    /**
     * Closed structural record kinds; payload schemas are defined separately.
     */
    /* default */ enum RecordType {
        /**
         * Signing intent record.
         */
        INTENT(1),
        /**
         * Metadata mutation record.
         */
        MUTATION(2),
        /**
         * Retained provider observation record.
         */
        PROVIDER_RESULT(3),
        /**
         * Terminal signing outcome record.
         */
        TERMINAL(4),
        /**
         * Transaction issuance record.
         */
        ISSUE(10),
        /**
         * Committed transaction terminal record.
         */
        COMMIT(11),
        /**
         * Rejected transaction terminal record.
         */
        REJECT(12),
        /**
         * Retained transaction outcome acknowledgement record.
         */
        ACK(13),
        /**
         * Authoritative signing-time watermark record.
         */
        WATERMARK(14),
        /**
         * Commit marker covering a bounded batch of frames.
         */
        BATCH_COMMIT(127);

        private final short wireCode;

        RecordType(int wireCode) {
            this.wireCode = (short) wireCode;
        }

        /**
         * Returns the stable explicitly assigned binary record discriminator.
         *
         * @return stable explicitly assigned binary record discriminator
         */
        /* default */ short wireCode() {
            return wireCode;
        }

        private static RecordType fromWireCode(short code) {
            return Arrays.stream(values()).filter(value -> value.wireCode == code).findFirst().orElse(null);
        }
    }

    /**
     * Immutable data frame with single-owned decoded payload storage.
     */
    @SuppressWarnings("PMD.DataClass")
    /* default */ static final class Frame {
        private final RecordType recordType;
        private final UUID transactionId;
        private final long sequence;
        private final byte[] payload;

        /**
         * Creates an immutable frame, validating its nonnegative sequence and bounded payload and defensively copying the payload bytes.
         *
         * @param recordType data-frame discriminator
         * @param transactionId transaction identity associated with the frame
         * @param sequence nonnegative frame sequence
         * @param payload bounded frame payload bytes
         * @throws NullPointerException if a required argument is null
         * @throws IllegalArgumentException if the sequence is negative or the payload exceeds its bound
         */
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

        /**
         * Creates a frame by taking exclusive ownership of the supplied payload array. The caller must relinquish every mutable alias and must not modify the array afterward.
         *
         * @param type data-frame discriminator
         * @param transactionId transaction identity associated with the frame
         * @param sequence nonnegative frame sequence
         * @param payload bounded frame payload bytes
         * @return frame owning the supplied payload array
         */
        /* default */ static Frame owned(RecordType type, UUID transactionId,
                long sequence, byte[] payload) {
            return new Frame(type, transactionId, sequence, payload, true);
        }

        /**
         * Returns the closed persisted record discriminator.
         *
         * @return closed persisted record discriminator
         */
        /* default */ RecordType recordType() {
            return recordType;
        }

        /**
         * Returns the exact transaction UUID retained by the frame.
         *
         * @return exact transaction UUID retained by the frame
         */
        /* default */ UUID transactionId() {
            return transactionId;
        }

        /**
         * Returns the exact persisted frame sequence.
         *
         * @return exact persisted frame sequence
         */
        /* default */ long sequence() {
            return sequence;
        }

        /**
         * Returns the new independent copy of the complete encoded frame payload.
         *
         * @return new independent copy of the complete encoded frame payload
         */
        /* default */ byte[] payload() {
            return payload.clone();
        }

        private byte[] payloadInternal() {
            return payload;
        }
    }

    /**
     * Commit marker binding a bounded contiguous frame group to its prior and resulting commitments.
     *
     * @param startSequence first sequence included by the committed batch
     * @param endSequence last sequence included by the committed batch
     * @param frameCount number of frames included by the result
     * @param committedRevision authoritative committed revision
     * @param previousCommitment rolling commitment before the group
     * @param groupCommitment commitment to the exact grouped frames
     * @param resultingCommitment rolling commitment after the group
     */
    /* default */ record BatchCommit(long startSequence, long endSequence, int frameCount,
            long committedRevision, byte[] previousCommitment, byte[] groupCommitment,
            byte[] resultingCommitment) {
        /**
         * Creates the commit marker binding a bounded contiguous frame group to its prior and resulting commitments.
         *
         * @param startSequence first sequence included by the committed batch
         * @param endSequence last sequence included by the committed batch
         * @param frameCount number of frames included by the result
         * @param committedRevision authoritative committed revision
         * @param previousCommitment rolling commitment before the group
         * @param groupCommitment commitment to the exact grouped frames
         * @param resultingCommitment rolling commitment after the group
         */
        BatchCommit {
            requireCommitment(previousCommitment);
            requireCommitment(groupCommitment);
            requireCommitment(resultingCommitment);
            previousCommitment = previousCommitment.clone();
            groupCommitment = groupCommitment.clone();
            resultingCommitment = resultingCommitment.clone();
        }

        /**
         * Returns an independent copy of the retained previous rolling commitment bytes.
         *
         * @return newly allocated array containing the rolling commitment before the group
         */
        @Override public byte[] previousCommitment() { return previousCommitment.clone(); }
        /**
         * Returns an independent copy of the retained batch group commitment bytes.
         *
         * @return newly allocated array containing the commitment to the exact grouped frames
         */
        @Override public byte[] groupCommitment() { return groupCommitment.clone(); }
        /**
         * Returns an independent copy of the retained resulting rolling commitment bytes.
         *
         * @return newly allocated array containing the rolling commitment after the group
         */
        @Override public byte[] resultingCommitment() { return resultingCommitment.clone(); }
        private byte[] previousCommitmentInternal() { return previousCommitment; }
        private byte[] groupCommitmentInternal() { return groupCommitment; }
        private byte[] resultingCommitmentInternal() { return resultingCommitment; }
    }

    /**
     * Validated complete-WAL scan coordinates and integrity commitments.
     *
     * @param frameCount number of frames included by the result
     * @param lastSequence last validated sequence in the scanned prefix
     * @param committedRevision authoritative committed revision
     * @param incompleteTailOffset byte offset of the incomplete tail, using the scanner's absent-tail sentinel when complete
     * @param rollingCommitment rolling WAL commitment at the accepted end boundary
     * @param fileCommitment integrity commitment of the complete encoded file
     */
    /* default */ record ScanResult(long frameCount, long lastSequence, long committedRevision,
            long incompleteTailOffset, byte[] rollingCommitment, byte[] fileCommitment) {
        /**
         * Creates the validated complete-WAL scan coordinates and integrity commitments.
         *
         * @param frameCount number of frames included by the result
         * @param lastSequence last validated sequence in the scanned prefix
         * @param committedRevision authoritative committed revision
         * @param incompleteTailOffset byte offset of the incomplete tail, using the scanner's absent-tail sentinel when complete
         * @param rollingCommitment rolling WAL commitment at the accepted end boundary
         * @param fileCommitment integrity commitment of the complete encoded file
         */
        ScanResult {
            rollingCommitment = rollingCommitment.clone();
            fileCommitment = fileCommitment.clone();
        }
        /**
         * Tests whether scanning found a terminal suffix that does not contain a complete committed group.
         *
         * @return true if the scan found an incomplete terminal suffix
         */
        /* default */ boolean hasIncompleteTail() { return incompleteTailOffset >= 0L; }
        /**
         * Returns an independent copy of the retained rolling WAL commitment bytes.
         *
         * @return newly allocated array containing the rolling WAL commitment at the accepted end boundary
         */
        @Override public byte[] rollingCommitment() { return rollingCommitment.clone(); }
        /**
         * Returns an independent copy of the retained complete-file commitment bytes.
         *
         * @return newly allocated array containing the integrity commitment of the complete encoded file
         */
        @Override public byte[] fileCommitment() { return fileCommitment.clone(); }
    }

    /**
     * Validated committed-prefix scan coordinates and forced-boundary status.
     *
     * @param frameCount number of frames included by the result
     * @param lastSequence last validated sequence in the scanned prefix
     * @param committedRevision authoritative committed revision
     * @param acceptedOffset exclusive byte boundary of the accepted prefix
     * @param rollingCommitment rolling WAL commitment at the accepted end boundary
     * @param forcedEndReached whether scanning reached the required forced end boundary
     */
    /* default */ record PrefixScanResult(long frameCount, long lastSequence,
            long committedRevision, long acceptedOffset, byte[] rollingCommitment,
            boolean forcedEndReached) {
        /**
         * Creates the validated committed-prefix scan coordinates and forced-boundary status.
         *
         * @param frameCount number of frames included by the result
         * @param lastSequence last validated sequence in the scanned prefix
         * @param committedRevision authoritative committed revision
         * @param acceptedOffset exclusive byte boundary of the accepted prefix
         * @param rollingCommitment rolling WAL commitment at the accepted end boundary
         * @param forcedEndReached whether scanning reached the required forced end boundary
         */
        PrefixScanResult {
            rollingCommitment = rollingCommitment.clone();
        }

        /**
         * Returns an independent copy of the retained rolling WAL commitment bytes.
         *
         * @return newly allocated array containing the rolling WAL commitment at the accepted end boundary
         */
        @Override public byte[] rollingCommitment() { return rollingCommitment.clone(); }
    }

    /**
     * Callback-scoped decoded frame and exact immutable-file location.
     * @param frame decoded frame valid for the callback scope
     * @param offset zero-based encoded byte offset
     * @param encodedLength complete encoded frame length in bytes
     * @param revision authoritative metadata revision
     */
    /* default */ record ScannedFrame(Frame frame, long offset, int encodedLength, long revision) {
        /**
         * Creates the callback-scoped decoded frame and exact immutable-file location.
         *
         * @param frame decoded frame valid for the callback scope
         * @param offset zero-based encoded byte offset
         * @param encodedLength complete encoded frame length in bytes
         * @param revision authoritative metadata revision
         * @throws NullPointerException if {@code frame} is null
         * @throws IllegalArgumentException if {@code (offset < SigningWalContainerCodec.HEADER_BYTES || encodedLength <= 0 || encodedLength > MAX_FRAME_BYTES || revision < -1L)}
         */
        ScannedFrame {
            Objects.requireNonNull(frame, "frame");
            if (offset < SigningWalContainerCodec.HEADER_BYTES || encodedLength <= 0
                    || encodedLength > MAX_FRAME_BYTES || revision < -1L) {
                throw new IllegalArgumentException("signing scanned frame fields are invalid");
            }
        }

        /**
         * Creates a read-only view of this scanned frame's payload. The view is valid only during the consumer callback and must not be retained.
         *
         * @return read-only callback-scoped payload view
         */
        /* default */ ByteBuffer payloadView() {
            return ByteBuffer.wrap(frame.payloadInternal()).asReadOnlyBuffer();
        }
    }

    /**
     * Bounded committed-group delivery seam used by recovery.
     */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface GroupConsumer {
        /**
         * Consumes one fully validated bounded committed group. Frame payload views are callback-scoped and must not be retained.
         *
         * @param frames validated committed frames; their views must not escape the callback
         * @param commit authenticated group commit coordinates
         * @throws IOException if framing or integrity validation fails, or the required I/O cannot complete
         */
        void accept(List<ScannedFrame> frames, BatchCommit commit) throws IOException;
    }

    /**
     * Committed-prefix callback including the validated exclusive next offset.
     */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface PrefixGroupConsumer {
        /**
         * Consumes one fully validated bounded committed group. Frame payload views are callback-scoped and must not be retained.
         *
         * @param frames validated committed frames; their views must not escape the callback
         * @param commit authenticated group commit coordinates
         * @param acceptedOffset exclusive byte offset of the accepted committed group
         * @throws IOException if framing or integrity validation fails, or the required I/O cannot complete
         */
        void accept(List<ScannedFrame> frames, BatchCommit commit,
                long acceptedOffset) throws IOException;
    }

    /**
     * Sequential buffered adapter that never seeks per frame.
     */
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
