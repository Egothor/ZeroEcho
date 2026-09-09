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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransactionId;

final class DurableMetadataLogScannerTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("0123456789abcdeffedcba9876543210");
    private static final MetadataTransactionId TRANSACTION_ID =
            new MetadataTransactionId(STORE_ID, "00000000000000000000000000000001");
    private static final int HEADER_PAYLOAD_LENGTH_OFFSET = 32;
    private static final int DIGEST_BYTES = 32;

    @TempDir
    Path temporaryDirectory;

    @Test
    void validRecoveryIsDeterministicAcrossTerminalAndIssuedTransactions() throws IOException {
        System.out.print("validRecoveryIsDeterministicAcrossTerminalAndIssuedTransactions ");
        Path path = temporaryDirectory.resolve("valid.log");
        MetadataTransactionId committed;
        MetadataTransactionId rejected;
        MetadataTransactionId issued;
        try (DurableMetadataLog log = DurableMetadataLog.create(
                path, STORE_ID, supportedProfile(), DurableMetadataLog.FaultInjector.NONE)) {
            committed = log.issue();
            rejected = log.issue();
            try (ImmutableByteContent value = new ImmutableByteContent(new byte[] { 1, 2, 3 })) {
                log.appendMutation(committed, MetadataFrameCodec.FrameType.MUTATION_CREATE,
                        3L, value, CancellationSignal.NONE);
            }
            log.commit(committed, 6L);
            log.reject(rejected, 91);
            issued = log.issue();
        }
        DurableMetadataLogScanner.RecoveryResult first = scan(path);
        DurableMetadataLogScanner.RecoveryResult second = scan(path);
        assertEquals(first, second);
        assertEquals(DurableMetadataLogScanner.Tail.CLEAN_END, first.tail());
        assertEquals(Files.size(path), first.lastCompleteFrameBoundary());
        assertEquals(Files.size(path), first.physicalEnd());
        assertEquals(3, first.transactions().size());
        assertEquals(6L, first.transactions().get(committed).terminal()
                .orElseThrow().committedRevision().orElseThrow());
        assertEquals(91, first.transactions().get(rejected).terminal()
                .orElseThrow().failureCode().orElseThrow());
        assertTrue(first.transactions().get(issued).terminal().isEmpty());
        assertEquals("00000000000000000000000000000004", first.nextTransactionToken().orElseThrow());
        assertTrue(!first.transactionTokensExhausted());
        System.out.println("...ok");
    }

    @Test
    void incompleteTailReportsExactBoundaryAndWritableOpenRepairsIt() throws IOException {
        System.out.print("incompleteTailReportsExactBoundaryAndWritableOpenRepairsIt ");
        Path canonical = completeLog("tail-source.log");
        List<MetadataFrameCodec.FrameMetadata> frames = frames(canonical);
        int caseNumber = 0;
        for (int index = 1; index < frames.size(); index++) {
            MetadataFrameCodec.FrameMetadata frame = frames.get(index);
            long[] cuts = {
                frame.frameOffset() + 1L,
                frame.payloadOffset() + Math.max(1L, frame.payloadLength() / 2L),
                frame.payloadDigestOffset() + 1L
            };
            for (long cut : cuts) {
                Path truncated = copy(canonical, "tail-" + caseNumber++ + ".log");
                try (FileChannel channel = FileChannel.open(truncated, StandardOpenOption.WRITE)) {
                    channel.truncate(Math.min(cut, frame.frameEndOffset() - 1L));
                }
                DurableMetadataLogScanner.RecoveryResult recovered = scan(truncated);
                assertEquals(DurableMetadataLogScanner.Tail.INCOMPLETE_TAIL, recovered.tail());
                assertEquals(frame.frameOffset(), recovered.lastCompleteFrameBoundary());
                assertEquals(Files.size(truncated), recovered.physicalEnd());
                assertTrue(recovered.lastCompleteFrameBoundary() < recovered.physicalEnd());
                if (frame.frameType() == MetadataFrameCodec.FrameType.TRANSACTION_ISSUED) {
                    assertEquals(
                            "00000000000000000000000000000001",
                            recovered.nextTransactionToken().orElseThrow());
                    assertTrue(!recovered.transactionTokensExhausted());
                    assertTrue(recovered.transactions().isEmpty());
                }
                try (DurableMetadataLog ignored = DurableMetadataLog.open(
                        truncated, supportedProfile(), DurableMetadataLog.FaultInjector.NONE)) {
                    assertTrue(Files.size(truncated) > frame.frameOffset());
                }
                DurableMetadataLogScanner.RecoveryResult repaired = scan(truncated);
                assertEquals(DurableMetadataLogScanner.Tail.CLEAN_END, repaired.tail());
                assertEquals(repaired.lastCompleteFrameBoundary(), repaired.physicalEnd());
                assertEquals(1L, repaired.recoveryEpoch());
                assertEquals(0L, repaired.openTransactionCount());
            }
        }
        System.out.println("...ok");
    }

    @Test
    void restartEpochsAreStrictAndAbandonOnlyCurrentEpochTransactions() throws IOException {
        System.out.print("restartEpochsAreStrictAndAbandonOnlyCurrentEpochTransactions ");
        Path valid = temporaryDirectory.resolve("restart-valid.log");
        writeHeader(valid);
        try (FileChannel channel = FileChannel.open(valid, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.TRANSACTION_ISSUED,
                    TRANSACTION_ID.token(), 0L, DurableMetadataLogScanner.encodeIssuance(TRANSACTION_ID));
            writeFrame(channel, MetadataFrameCodec.FrameType.RECOVERY_RESTART,
                    DurableMetadataLogScanner.zeroToken(), 1L,
                    DurableMetadataLogScanner.encodeRestart(1L, 1L, 0L));
        }
        DurableMetadataLogScanner.RecoveryResult recovered = scan(valid);
        assertEquals(1L, recovered.recoveryEpoch());
        assertEquals(0L, recovered.openTransactionCount());
        assertEquals("00000000000000000000000000000002",
                recovered.nextTransactionToken().orElseThrow());

        Path skipped = copy(valid, "restart-skipped.log");
        try (FileChannel channel = FileChannel.open(skipped, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.RECOVERY_RESTART,
                    DurableMetadataLogScanner.zeroToken(), 3L,
                    DurableMetadataLogScanner.encodeRestart(3L, 0L, 0L));
        }
        assertIntegrity(skipped);

        Path invalidFirst = temporaryDirectory.resolve("restart-first.log");
        writeHeader(invalidFirst);
        try (FileChannel channel = FileChannel.open(
                invalidFirst, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.RECOVERY_RESTART,
                    DurableMetadataLogScanner.zeroToken(), 2L,
                    DurableMetadataLogScanner.encodeRestart(2L, 0L, 0L));
        }
        assertIntegrity(invalidFirst);

        Path trailing = temporaryDirectory.resolve("restart-trailing.log");
        writeHeader(trailing);
        byte[] restart = DurableMetadataLogScanner.encodeRestart(1L, 0L, 0L);
        byte[] oversized = java.util.Arrays.copyOf(restart, restart.length + 1);
        try (FileChannel channel = FileChannel.open(
                trailing, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.RECOVERY_RESTART,
                    DurableMetadataLogScanner.zeroToken(), 1L, oversized);
        }
        assertIntegrity(trailing);

        Path oldEpoch = copy(valid, "restart-old-epoch.log");
        try (FileChannel channel = FileChannel.open(oldEpoch, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.MUTATION_DELETE,
                    TRANSACTION_ID.token(), 1L, new byte[0]);
        }
        assertIntegrity(oldEpoch);
        System.out.println("...ok");
    }

    @Test
    void restartRetainsExactAbandonedOutcomeLedger() throws IOException {
        System.out.print("restartRetainsExactAbandonedOutcomeLedger ");
        Path path = temporaryDirectory.resolve("restart-ledger.log");
        MetadataTransactionId terminalized;
        MetadataTransactionId firstOpen;
        MetadataTransactionId secondOpen;
        try (DurableMetadataLog log = DurableMetadataLog.create(
                path, STORE_ID, supportedProfile(), DurableMetadataLog.FaultInjector.NONE)) {
            terminalized = log.issue();
            log.commit(terminalized, 1L);
            firstOpen = log.issue();
            secondOpen = log.issue();
        }
        assertEquals(2L, scan(path).openTransactionCount());
        try (DurableMetadataLog ignored = DurableMetadataLog.open(
                path, supportedProfile(), DurableMetadataLog.FaultInjector.NONE)) {
            // Opening publishes the recovery restart before exposing the writer.
        }
        DurableMetadataLogScanner.RecoveryResult recovered = scan(path);
        assertEquals(0L, recovered.openTransactionCount());
        assertEquals(3, recovered.transactions().size());
        assertEquals(DurableMetadataLogScanner.TerminalKind.COMMITTED,
                recovered.transactions().get(terminalized).terminal().orElseThrow().kind());
        assertAbandoned(recovered, firstOpen);
        assertAbandoned(recovered, secondOpen);

        Path oldFrame = copy(path, "restart-ledger-old-frame.log");
        try (FileChannel channel = FileChannel.open(
                oldFrame, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.MUTATION_DELETE,
                    firstOpen.token(), 1L, new byte[0]);
        }
        assertIntegrity(oldFrame);
        System.out.println("...ok");
    }

    @Test
    void recoveryEpochExhaustionAndInvalidTransitionsFailChecked() throws IOException {
        System.out.print("recoveryEpochExhaustionAndInvalidTransitionsFailChecked ");
        Path path = temporaryDirectory.resolve("epoch-boundary.log");
        writeHeader(path);
        long size = Files.size(path);
        MetadataStoreException writerFailure = assertThrows(
                MetadataStoreException.class,
                () -> DurableMetadataLog.checkedWritableRecoveryEpoch(Long.MAX_VALUE));
        assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED, writerFailure.category());
        assertEquals(size, Files.size(path));

        MetadataStoreException scannerFailure = assertThrows(
                MetadataStoreException.class,
                () -> DurableMetadataLogScanner.checkedNextRecoveryEpoch(Long.MAX_VALUE));
        assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, scannerFailure.category());
        assertTrue(scannerFailure.getCause() instanceof ArithmeticException);

        Path negative = temporaryDirectory.resolve("restart-negative.log");
        writeHeader(negative);
        ByteBuffer payload = ByteBuffer.allocate(28).order(ByteOrder.BIG_ENDIAN);
        payload.putShort((short) 1).putLong(-1L).putLong(0L).putLong(0L).putShort((short) 0);
        try (FileChannel channel = FileChannel.open(
                negative, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.RECOVERY_RESTART,
                    DurableMetadataLogScanner.zeroToken(), 1L, payload.array());
        }
        assertIntegrity(negative);
        System.out.println("...ok");
    }

    @Test
    void authenticatedLengthAndFrameChecksumCorruptionAlwaysFailClosed() throws IOException {
        System.out.print("authenticatedLengthAndFrameChecksumCorruptionAlwaysFailClosed ");
        Path source = completeLog("corrupt-source.log");
        List<MetadataFrameCodec.FrameMetadata> frames = frames(source);
        Path length = copy(source, "length.log");
        putLong(length, frames.get(1).frameOffset() + HEADER_PAYLOAD_LENGTH_OFFSET, Long.MAX_VALUE);
        assertIntegrity(length);
        Path header = copy(source, "header.log");
        xorByte(header, frames.get(0).frameOffset(), (byte) 1);
        assertIntegrity(header);
        Path payload = copy(source, "payload.log");
        xorByte(payload, frames.get(1).payloadOffset(), (byte) 1);
        assertIntegrity(payload);
        Path finalFrame = copy(source, "final.log");
        MetadataFrameCodec.FrameMetadata terminal = frames.get(frames.size() - 1);
        xorByte(finalFrame, terminal.payloadDigestOffset(), (byte) 1);
        assertIntegrity(finalFrame);
        System.out.println("...ok");
    }

    @Test
    void semanticVersionLengthAndTerminalChainMismatchFailClosed() throws IOException {
        System.out.print("semanticVersionLengthAndTerminalChainMismatchFailClosed ");
        Path source = completeLog("semantic-source.log");
        List<MetadataFrameCodec.FrameMetadata> frames = frames(source);
        MetadataFrameCodec.FrameMetadata issuance = frames.get(1);

        Path version = copy(source, "version.log");
        putByte(version, issuance.payloadOffset() + 1L, (byte) 2);
        refreshPayloadDigest(version, issuance);
        assertIntegrity(version);

        Path chain = copy(source, "chain.log");
        MetadataFrameCodec.FrameMetadata terminal = frames.get(frames.size() - 1);
        xorByte(chain, terminal.payloadDigestOffset() - 1L, (byte) 1);
        refreshPayloadDigest(chain, terminal);
        assertIntegrity(chain);

        Path trailing = temporaryDirectory.resolve("trailing-semantic.log");
        writeHeader(trailing);
        byte[] issuancePayload = DurableMetadataLogScanner.encodeIssuance(TRANSACTION_ID);
        byte[] oversized = java.util.Arrays.copyOf(issuancePayload, issuancePayload.length + 1);
        try (FileChannel channel = FileChannel.open(trailing, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.TRANSACTION_ISSUED,
                    TRANSACTION_ID.token(), 0L, oversized);
        }
        assertIntegrity(trailing);
        System.out.println("...ok");
    }

    @Test
    void sequenceUnknownTransactionDuplicateAndStoreMismatchFailClosed() throws IOException {
        System.out.print("sequenceUnknownTransactionDuplicateAndStoreMismatchFailClosed ");
        Path gap = structuralLog("gap.log", 2L, false);
        assertIntegrity(gap);
        Path duplicate = structuralLog("duplicate.log", 1L, true);
        assertIntegrity(duplicate);

        Path unknown = temporaryDirectory.resolve("unknown.log");
        writeHeader(unknown);
        try (FileChannel channel = FileChannel.open(unknown, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.MUTATION_DELETE,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1L, new byte[0]);
        }
        assertIntegrity(unknown);

        Path mismatch = temporaryDirectory.resolve("store-mismatch.log");
        writeHeader(mismatch);
        MetadataTransactionId foreign = new MetadataTransactionId(
                new MetadataStoreId("ffeeddccbbaa99887766554433221100"), TRANSACTION_ID.token());
        try (FileChannel channel = FileChannel.open(mismatch, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.TRANSACTION_ISSUED,
                    TRANSACTION_ID.token(), 0L, DurableMetadataLogScanner.encodeIssuance(foreign));
        }
        assertIntegrity(mismatch);

        Path zero = issuanceLog("zero-token.log", "00000000000000000000000000000000");
        assertIntegrity(zero);
        Path skippedFirst = issuanceLog("skipped-first.log", "00000000000000000000000000000002");
        assertIntegrity(skippedFirst);
        Path duplicateToken = issuanceLog(
                "duplicate-token.log",
                "00000000000000000000000000000001",
                "00000000000000000000000000000001");
        assertIntegrity(duplicateToken);
        Path decreased = issuanceLog(
                "decreased-token.log",
                "00000000000000000000000000000001",
                "00000000000000000000000000000002",
                "00000000000000000000000000000001");
        assertIntegrity(decreased);
        Path skipped = issuanceLog(
                "skipped-token.log",
                "00000000000000000000000000000001",
                "00000000000000000000000000000003");
        assertIntegrity(skipped);
        System.out.println("...ok");
    }

    private Path completeLog(String name) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        try (DurableMetadataLog log = DurableMetadataLog.create(
                path, STORE_ID, supportedProfile(), DurableMetadataLog.FaultInjector.NONE)) {
            MetadataTransactionId transactionId = log.issue();
            try (ImmutableByteContent content = new ImmutableByteContent(new byte[] { 4, 5, 6 })) {
                log.appendMutation(transactionId, MetadataFrameCodec.FrameType.MUTATION_REPLACE,
                        3L, content, CancellationSignal.NONE);
            }
            log.commit(transactionId, 3L);
        }
        return path;
    }

    private Path structuralLog(String name, long sequence, boolean duplicate) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        writeHeader(path);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            writeFrame(channel, MetadataFrameCodec.FrameType.TRANSACTION_ISSUED,
                    TRANSACTION_ID.token(), 0L, DurableMetadataLogScanner.encodeIssuance(TRANSACTION_ID));
            writeFrame(channel, MetadataFrameCodec.FrameType.MUTATION_CREATE,
                    TRANSACTION_ID.token(), sequence, new byte[] { 1 });
            if (duplicate) {
                writeFrame(channel, MetadataFrameCodec.FrameType.MUTATION_DELETE,
                        TRANSACTION_ID.token(), sequence, new byte[0]);
            }
        }
        return path;
    }

    private Path issuanceLog(String name, String... tokens) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        writeHeader(path);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(channel.size());
            for (String token : tokens) {
                MetadataTransactionId transactionId = transaction(token);
                writeFrame(channel, MetadataFrameCodec.FrameType.TRANSACTION_ISSUED,
                        token, 0L, DurableMetadataLogScanner.encodeIssuance(transactionId));
            }
        }
        return path;
    }

    private void writeHeader(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            writeFrame(channel, MetadataFrameCodec.FrameType.STORE_HEADER,
                    DurableMetadataLogScanner.zeroToken(), 0L,
                    DurableMetadataLogScanner.encodeStoreHeader(STORE_ID));
        }
    }

    private static void writeFrame(
            FileChannel channel,
            MetadataFrameCodec.FrameType type,
            String token,
            long sequence,
            byte[] payload) throws IOException {
        try (ImmutableByteContent content = new ImmutableByteContent(payload)) {
            new MetadataFrameCodec().write(
                    channel, type, token, sequence, payload.length, content, CancellationSignal.NONE);
        }
    }

    private static DurableMetadataLogScanner.RecoveryResult scan(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            return DurableMetadataLogScanner.scan(channel);
        }
    }

    private static List<MetadataFrameCodec.FrameMetadata> frames(Path path) throws IOException {
        List<MetadataFrameCodec.FrameMetadata> result = new ArrayList<>();
        MetadataFrameCodec codec = new MetadataFrameCodec();
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            long offset = 0L;
            while (true) {
                MetadataFrameCodec.ReadResult read = codec.read(channel, offset);
                if (read.classification() == MetadataFrameCodec.ReadClassification.END_OF_INPUT) {
                    return result;
                }
                assertEquals(MetadataFrameCodec.ReadClassification.COMPLETE_FRAME, read.classification());
                result.add(read.metadata());
                offset = read.metadata().frameEndOffset();
            }
        }
    }

    private Path copy(Path source, String name) throws IOException {
        Path target = temporaryDirectory.resolve(name);
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        return target;
    }

    private static void assertIntegrity(Path path) {
        MetadataStoreException failure = assertThrows(MetadataStoreException.class, () -> scan(path));
        assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, failure.category());
    }

    private static void assertAbandoned(
            DurableMetadataLogScanner.RecoveryResult recovered,
            MetadataTransactionId transactionId) {
        DurableMetadataLogScanner.Terminal terminal =
                recovered.transactions().get(transactionId).terminal().orElseThrow();
        assertEquals(DurableMetadataLogScanner.TerminalKind.NOT_COMMITTED, terminal.kind());
        assertEquals(
                DurableMetadataLogScanner.FailureReason.ABANDONED_BY_RECOVERY.code(),
                terminal.failureCode().orElseThrow());
    }

    private static void refreshPayloadDigest(Path path, MetadataFrameCodec.FrameMetadata frame) throws IOException {
        byte[] payload = new byte[Math.toIntExact(frame.payloadLength())];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(frame.payloadOffset());
            readFully(channel, ByteBuffer.wrap(payload));
            channel.position(frame.payloadDigestOffset());
            writeFully(channel, ByteBuffer.wrap(sha256(payload)));
        }
    }

    private static void putLong(Path path, long offset, long value) throws IOException {
        ByteBuffer encoded = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value);
        encoded.flip();
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
            channel.position(offset);
            writeFully(channel, encoded);
        }
    }

    private static void putByte(Path path, long offset, byte value) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
            channel.position(offset);
            writeFully(channel, ByteBuffer.wrap(new byte[] { value }));
        }
    }

    private static void xorByte(Path path, long offset, byte mask) throws IOException {
        ByteBuffer value = ByteBuffer.allocate(1);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.position(offset);
            readFully(channel, value);
            value.flip();
            channel.position(offset);
            writeFully(channel, ByteBuffer.wrap(new byte[] { (byte) (value.get() ^ mask) }));
        }
    }

    private static void readFully(FileChannel channel, ByteBuffer target) throws IOException {
        while (target.hasRemaining()) {
            if (channel.read(target) < 0) {
                throw new IOException("Unexpected test fixture truncation");
            }
        }
    }

    private static void writeFully(FileChannel channel, ByteBuffer source) throws IOException {
        while (source.hasRemaining()) {
            channel.write(source);
        }
    }

    private static byte[] sha256(byte[] payload) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(payload);
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }

    private static DurableMetadataLog.CapabilityProfile supportedProfile() {
        return new DurableMetadataLog.CapabilityProfile() {
            @Override
            public boolean posixAvailable(Path parent) throws IOException {
                return Files.getFileStore(parent).supportsFileAttributeView("posix");
            }

            @Override
            public boolean localFileSystem(Path parent) {
                return true;
            }

            @Override
            public void forceParent(Path parent) throws IOException {
                PlatformFs.forceDirectory(parent);
            }
        };
    }

    private static MetadataTransactionId transaction(String token) {
        return new MetadataTransactionId(STORE_ID, token);
    }
}
