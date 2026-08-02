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
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Immutable POSIX checkpoint view derived from the authoritative revocation log. */
final class FilesystemRevocationCheckpoint implements AutoCloseable {

    private static final Logger LOGGER =
            Logger.getLogger(FilesystemRevocationCheckpoint.class.getName());
    private static final String DIRECTORY_WARNING =
            "Revocation checkpoint directory durability is limited; continuing in best-effort mode";
    private static final String RETIREMENT_WARNING =
            "An obsolete revocation checkpoint generation could not be retired";
    private static final String FINAL_PREFIX = "g-";
    private static final String FINAL_SUFFIX = ".chk";
    private static final String BUILDING_PREFIX = ".building-";
    private static final int GENERATION_HEX_LENGTH = 64;
    private static final long ZERO_REVISION = 0L;
    private static final HexFormat HEX = HexFormat.of();

    private final FileChannel channel;
    private final RevocationCheckpointCodec codec;
    private final RevocationCheckpointCodec.ValidatedFile validated;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final Set<CursorState> cursors = new HashSet<>();
    private boolean closed;

    private FilesystemRevocationCheckpoint(
            FileChannel channel,
            RevocationCheckpointCodec codec,
            RevocationCheckpointCodec.ValidatedFile validated) {
        this.channel = channel;
        this.codec = codec;
        this.validated = validated;
    }

    /* default */ static PublishedGeneration publish(
            Path directory,
            Path logPath,
            FilesystemRevocationLog.RecoveryResult recovery,
            Coverage coverage,
            SortedSource source) throws IOException {
        return publish(directory, logPath, recovery, coverage, source,
                DefaultPublicationOperations.INSTANCE, FaultInjector.NONE);
    }

    /* default */ static PublishedGeneration publish(
            Path directory,
            Path logPath,
            FilesystemRevocationLog.RecoveryResult recovery,
            Coverage coverage,
            SortedSource source,
            PublicationOperations operations,
            FaultInjector faults) throws IOException {
        Objects.requireNonNull(directory, "directory");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(operations, "operations");
        Objects.requireNonNull(faults, "faults");
        Binding.requireCurrentPublication(recovery, coverage);
        Binding.validate(logPath, recovery, coverage);
        return publishBound(directory, coverage, source, operations, faults,
                checkpoint -> Binding.validateGeneration(checkpoint, logPath, recovery));
    }

    /* default */ static PublishedGeneration publishHistorical(
            Path directory,
            FilesystemRevocationCurrentIndex.FrozenSnapshot frozen,
            SortedSource source) throws IOException {
        Objects.requireNonNull(directory, "directory");
        Objects.requireNonNull(frozen, "frozen");
        Objects.requireNonNull(source, "source");
        Coverage coverage = frozen.coverage();
        return publishBound(
                directory, coverage, source,
                DefaultPublicationOperations.INSTANCE, FaultInjector.NONE,
                checkpoint -> HistoricalBinding.validateGeneration(
                        checkpoint, frozen));
    }

    private static PublishedGeneration publishBound(
            Path directory,
            Coverage coverage,
            SortedSource source,
            PublicationOperations operations,
            FaultInjector faults,
            GenerationValidator validator) throws IOException {
        Files.createDirectories(directory);
        requireDirectory(directory);
        long declaredCount = source.entryCount();
        if (declaredCount < ZERO_REVISION) {
            throw new IllegalArgumentException("Checkpoint source count must be non-negative");
        }
        RevocationCheckpointCodec.HeaderData header = coverage.header(declaredCount);
        Path temporary = directory.resolve(BUILDING_PREFIX + UUID.randomUUID());
        BuildResult build = buildTemporary(temporary, header, source, faults);
        Path target = directory.resolve(finalName(coverage.coveredRevision(), build.generationId()));
        boolean published = false;
        try {
            validator.validate(temporary);
            published = publishAtomically(temporary, target, operations, faults);
            forceDirectory(directory, operations, faults);
            return new PublishedGeneration(target, build.generationId(), coverage.coveredRevision(), published);
        } catch (IOException failure) {
            if (!published && Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) {
                try {
                    Files.delete(temporary);
                } catch (IOException cleanupFailure) {
                    failure.addSuppressed(cleanupFailure);
                }
            }
            throw failure;
        }
    }

    /** Exact post-build binding check selected by the publication boundary. */
    @FunctionalInterface
    private interface GenerationValidator {
        /** Validates the completed temporary generation before publication. */
        void validate(Path checkpoint) throws IOException;
    }

    /* default */ static Optional<FilesystemRevocationCheckpoint> discover(
            Path directory,
            Path logPath,
            FilesystemRevocationLog.RecoveryResult recovery) throws IOException {
        return Discovery.discover(directory, logPath, recovery);
    }

    /* default */ static FilesystemRevocationCheckpoint open(
            Path checkpointPath,
            Path logPath,
            FilesystemRevocationLog.RecoveryResult recovery) throws IOException {
        Objects.requireNonNull(checkpointPath, "checkpointPath");
        FinalName name = FinalName.parse(checkpointPath.getFileName().toString())
                .orElseThrow(() -> new IOException("Invalid revocation checkpoint generation name"));
        if (!Files.isRegularFile(checkpointPath, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(checkpointPath)) {
            throw new IOException("Revocation checkpoint generation is not a regular file");
        }
        FileChannel channel = FileChannel.open(checkpointPath, StandardOpenOption.READ);
        try {
            RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
            RevocationCheckpointCodec.ValidatedFile validated = codec.validate(channel);
            name.requireAgreement(validated);
            Binding.validate(logPath, recovery, Coverage.from(validated.header()));
            return new FilesystemRevocationCheckpoint(channel, codec, validated);
        } catch (IOException failure) {
            try {
                channel.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw failure;
        }
    }

    /* default */ static long retireObsolete(Path directory, PublishedGeneration retained) {
        return Retirement.retire(directory, retained);
    }

    /* default */ String generationId() {
        return validated.generationId();
    }

    /* default */ MetadataStoreId storeId() {
        return validated.header().storeId();
    }

    /* default */ long coveredRevision() {
        return validated.header().coveredRevision();
    }

    /* default */ long coveredBoundary() {
        return validated.header().coveredBoundary();
    }

    /* default */ RevocationTransitionFrameCodec.Commitment coveredCommitment() {
        return validated.header().globalCommitment();
    }

    /* default */ long entryCount() {
        return validated.header().entryCount();
    }

    /* default */ Cursor allCurrentStates() {
        return newCursor(false);
    }

    /* default */ Cursor currentRevokedStates() {
        return newCursor(true);
    }

    private Cursor newCursor(boolean revokedOnly) {
        lifecycleLock.lock();
        try {
            requireOpen();
            return new CheckpointCursor(revokedOnly);
        } finally {
            lifecycleLock.unlock();
        }
    }

    @Override
    public void close() throws IOException {
        lifecycleLock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            for (CursorState cursorState : cursors) {
                cursorState.closeFromOwner();
            }
            cursors.clear();
            channel.close();
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void requireOpen() {
        if (closed || !channel.isOpen()) {
            throw new IllegalStateException("Revocation checkpoint is closed");
        }
    }

    private static BuildResult buildTemporary(
            Path temporary,
            RevocationCheckpointCodec.HeaderData header,
            SortedSource source,
            FaultInjector faults) throws IOException {
        boolean complete = false;
        try {
            BuildResult result;
            try (SortedSource ownedSource = source;
                    FileChannel channel = FileChannel.open(temporary,
                            StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                            StandardOpenOption.WRITE);
                    SourceCursor cursor = ownedSource.openCursor()) {
                result = writeTemporary(channel, header, cursor, faults);
            }
            complete = true;
            return result;
        } finally {
            if (!complete) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                    // The primary build failure remains authoritative.
                }
            }
        }
    }

    private static BuildResult writeTemporary(
            FileChannel channel,
            RevocationCheckpointCodec.HeaderData header,
            SourceCursor cursor,
            FaultInjector faults) throws IOException {
        RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
        RevocationCheckpointCodec.Encoder encoder = codec.encoder(channel, header);
        byte[] previous = null;
        for (long index = 0L; index < header.entryCount(); index++) {
            if (!cursor.advance()) {
                throw new IOException("Checkpoint source ended before its declared count");
            }
            RevocationCheckpointCodec.CurrentStateEntry entry = Objects.requireNonNull(
                    cursor.current(), "checkpoint source current entry");
            byte[] identity = RevocationCheckpointCodec.strictUtf8(entry.credentialId().value());
            if (previous != null
                    && RevocationCheckpointCodec.compareUnsigned(previous, identity) >= 0) {
                throw new IOException("Checkpoint source identities are not strictly increasing");
            }
            faults.fail(FaultPoint.WRITE);
            encoder.write(entry);
            previous = identity;
        }
        if (cursor.advance()) {
            throw new IOException("Checkpoint source exceeds its declared count");
        }
        String generation = encoder.finish();
        faults.fail(FaultPoint.FILE_FORCE);
        channel.force(true);
        return new BuildResult(generation);
    }

    private static boolean publishAtomically(
            Path temporary,
            Path target,
            PublicationOperations operations,
            FaultInjector faults) throws IOException {
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            if (sameBytes(temporary, target)) {
                Files.delete(temporary);
                return false;
            }
            throw new IOException("Conflicting revocation checkpoint generation exists");
        }
        try {
            faults.fail(FaultPoint.ATOMIC_MOVE);
            operations.atomicMove(temporary, target);
            return true;
        } catch (FileAlreadyExistsException exists) {
            if (sameBytes(temporary, target)) {
                Files.delete(temporary);
                return false;
            }
            throw new IOException("Conflicting revocation checkpoint generation exists", exists);
        } catch (AtomicMoveNotSupportedException unsupported) {
            throw new IOException("Atomic revocation checkpoint publication is unsupported", unsupported);
        }
    }

    private static boolean sameBytes(Path first, Path second) throws IOException {
        if (Files.size(first) != Files.size(second)) {
            return false;
        }
        byte[] firstBytes = new byte[16 * 1024];
        byte[] secondBytes = new byte[firstBytes.length];
        try (FileChannel firstChannel = FileChannel.open(first, StandardOpenOption.READ);
                FileChannel secondChannel = FileChannel.open(second, StandardOpenOption.READ)) {
            long offset = 0L;
            long size = firstChannel.size();
            while (offset < size) {
                int requested = (int) Math.min(firstBytes.length, size - offset);
                readExact(firstChannel, firstBytes, requested, offset);
                readExact(secondChannel, secondBytes, requested, offset);
                if (!equalPrefix(firstBytes, secondBytes, requested)) {
                    return false;
                }
                offset += requested;
            }
        }
        return true;
    }

    private static boolean equalPrefix(byte[] first, byte[] second, int length) {
        for (int index = 0; index < length; index++) {
            if (first[index] != second[index]) {
                return false;
            }
        }
        return true;
    }

    private static void readExact(FileChannel channel, byte[] bytes, int length, long offset)
            throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes, 0, length);
        long position = offset;
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer, position);
            if (read <= 0) {
                throw new IOException("Checkpoint comparison made no read progress");
            }
            position += read;
        }
    }

    private static void forceDirectory(
            Path directory, PublicationOperations operations, FaultInjector faults) {
        try {
            faults.fail(FaultPoint.DIRECTORY_FORCE);
            operations.forceDirectory(directory);
        } catch (IOException | UnsupportedOperationException unavailable) {
            warn(DIRECTORY_WARNING);
        }
    }

    private static void warn(String message) {
        try {
            LOGGER.warning(message);
        } catch (IllegalStateException ignored) {
            // Advisory logging cannot change derived-state publication or retirement.
        }
    }

    private static void requireDirectory(Path directory) throws IOException {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(directory)) {
            throw new IOException("Revocation checkpoint directory is invalid");
        }
    }

    private static String finalName(long revision, String generationId) {
        return FINAL_PREFIX + revision + "-" + generationId + FINAL_SUFFIX;
    }

    /** Current-state source that transfers deterministic close ownership to publication. */
    /* default */ interface SortedSource extends AutoCloseable {
        /** Returns the exact non-negative entry count. */
        long entryCount();

        /** Opens the owned one-entry-at-a-time cursor. */
        SourceCursor openCursor() throws IOException;

        @Override
        void close() throws IOException;
    }

    /** One-entry-at-a-time source cursor; current is invalidated by advancement. */
    /* default */ interface SourceCursor extends AutoCloseable {
        /** Advances to the next source entry. */
        boolean advance() throws IOException;

        /** Returns the current source entry. */
        RevocationCheckpointCodec.CurrentStateEntry current();

        @Override
        void close() throws IOException;
    }

    /** Read-only ordered checkpoint cursor. */
    /* default */ interface Cursor extends AutoCloseable {
        /** Advances to the next matching checkpoint entry. */
        boolean advance(CancellationSignal cancellation) throws IOException;

        /** Returns the current checkpoint entry. */
        RevocationCheckpointCodec.CurrentStateEntry current();

        @Override
        void close();
    }

    /** Exact authoritative coverage declared by a derived generation. */
    /* default */ record Coverage(
            MetadataStoreId storeId,
            long coveredRevision,
            OptionalLong finalRecordStart,
            long coveredBoundary,
            RevocationTransitionFrameCodec.Commitment globalCommitment) {
        Coverage {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(finalRecordStart, "finalRecordStart");
            Objects.requireNonNull(globalCommitment, "globalCommitment");
        }

        private RevocationCheckpointCodec.HeaderData header(long count) {
            return new RevocationCheckpointCodec.HeaderData(
                    storeId, coveredRevision, finalRecordStart,
                    coveredBoundary, globalCommitment, count);
        }

        private static Coverage from(RevocationCheckpointCodec.HeaderData header) {
            return new Coverage(
                    header.storeId(), header.coveredRevision(), header.finalRecordStart(),
                    header.coveredBoundary(), header.globalCommitment());
        }
    }

    /** Immutable publication result; {@code newlyPublished} distinguishes idempotent reuse. */
    /* default */ record PublishedGeneration(
            Path path, String generationId, long coveredRevision, boolean newlyPublished) {
        PublishedGeneration {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(generationId, "generationId");
        }
    }

    /** Deterministic publication fault seam; not production API. */
    /* default */ @FunctionalInterface
    interface FaultInjector {
        FaultInjector NONE = point -> { };

        /** Fails one deterministic lifecycle point. */
        void fail(FaultPoint point) throws IOException;
    }

    /** Finite lifecycle fault points used by deterministic tests. */
    /* default */ enum FaultPoint {
        WRITE,
        FILE_FORCE,
        ATOMIC_MOVE,
        DIRECTORY_FORCE
    }

    /** POSIX publication operations isolated for deterministic fault validation. */
    /* default */ interface PublicationOperations {
        /** Publishes one completed file using an atomic move. */
        void atomicMove(Path source, Path target) throws IOException;

        /** Forces the containing directory when supported. */
        void forceDirectory(Path directory) throws IOException;
    }

    /** Default POSIX publication operations. */
    private enum DefaultPublicationOperations implements PublicationOperations {
        /** Stateless singleton. */
        INSTANCE;

        @Override
        public void atomicMove(Path source, Path target) throws IOException {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        }

        @Override
        public void forceDirectory(Path directory) throws IOException {
            try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
                channel.force(true);
            }
        }
    }

    /** Log-binding validation never replays the covered authoritative prefix. */
    private static final class Binding {
        private static void validateGeneration(
                Path checkpointPath,
                Path logPath,
                FilesystemRevocationLog.RecoveryResult recovery) throws IOException {
            try (FileChannel checkpoint = FileChannel.open(
                    checkpointPath, StandardOpenOption.READ)) {
                RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
                RevocationCheckpointCodec.ValidatedFile validated = codec.validate(checkpoint);
                validate(logPath, recovery, Coverage.from(validated.header()));
                validateCurrentEntries(logPath, recovery, checkpoint, codec, validated);
            }
        }

        private static void requireCurrentPublication(
                FilesystemRevocationLog.RecoveryResult recovery,
                Coverage coverage) throws IOException {
            Objects.requireNonNull(recovery, "recovery");
            Objects.requireNonNull(coverage, "coverage");
            if (coverage.coveredRevision() != recovery.globalRevision()
                    || coverage.coveredBoundary() != recovery.lastCompleteRecordBoundary()
                    || !coverage.globalCommitment().equals(recovery.globalCommitment())) {
                throw new IOException(
                        "Checkpoint publication must cover the complete validated log state");
            }
        }

        private static void validateCurrentEntries(
                Path logPath,
                FilesystemRevocationLog.RecoveryResult recovery,
                FileChannel checkpoint,
                RevocationCheckpointCodec checkpointCodec,
                RevocationCheckpointCodec.ValidatedFile validated) throws IOException {
            if (validated.header().entryCount() != recovery.latestStates().size()) {
                throw new IOException("Checkpoint omits current revocation state");
            }
            try (FileChannel log = FileChannel.open(logPath, StandardOpenOption.READ)) {
                long offset = RevocationCheckpointCodec.HEADER_BYTES;
                RevocationCheckpointCodec.SequentialDecoder decoder =
                        checkpointCodec.sequentialDecoder();
                for (long index = 0L; index < validated.header().entryCount(); index++) {
                    RevocationCheckpointCodec.DecodedRecord decoded = decoder.read(
                            checkpoint, offset, validated.trailerOffset());
                    validateCurrentEntry(log, recovery, decoded.entry());
                    offset = decoded.nextOffset();
                }
            }
        }

        private static void validateCurrentEntry(
                FileChannel log,
                FilesystemRevocationLog.RecoveryResult recovery,
                RevocationCheckpointCodec.CurrentStateEntry entry) throws IOException {
            FilesystemRevocationLog.LatestState latest = recovery.latestStates().get(entry.credentialId());
            if (latest == null
                    || latest.globalRevision() != entry.globalRevision()
                    || latest.recordOffset() != entry.frameStart()
                    || !latest.commitment().equals(entry.transitionCommitment())
                    || !RevocationTransitionFrameCodec.transitionsEqual(
                            latest.transition(), entry.transition())) {
                throw new IOException("Checkpoint entry is not the current authoritative state");
            }
            RevocationTransitionFrameCodec.ReadResult result =
                    new RevocationTransitionFrameCodec().read(log, entry.frameStart());
            if (result.classification()
                    != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD
                    || result.record().orElseThrow().recordEnd() != entry.frameEnd()) {
                throw new IOException("Checkpoint entry has an invalid authoritative frame boundary");
            }
        }

        private static void validate(
                Path logPath,
                FilesystemRevocationLog.RecoveryResult recovery,
                Coverage coverage) throws IOException {
            Objects.requireNonNull(logPath, "logPath");
            Objects.requireNonNull(recovery, "recovery");
            Objects.requireNonNull(coverage, "coverage");
            if (!coverage.storeId().equals(recovery.storeId())
                    || coverage.coveredRevision() > recovery.globalRevision()
                    || coverage.coveredBoundary() > recovery.lastCompleteRecordBoundary()) {
                throw new IOException("Checkpoint does not match the validated revocation log");
            }
            try (FileChannel log = FileChannel.open(logPath, StandardOpenOption.READ)) {
                RevocationTransitionFrameCodec frameCodec = new RevocationTransitionFrameCodec();
                if (!coverage.storeId().equals(frameCodec.readPreamble(log))) {
                    throw new IOException("Checkpoint belongs to another revocation log");
                }
                if (coverage.coveredRevision() == ZERO_REVISION) {
                    validateGenesis(coverage);
                } else {
                    validateFrame(log, frameCodec, coverage);
                }
            }
        }

        private static void validateGenesis(Coverage coverage) throws IOException {
            if (coverage.finalRecordStart().isPresent()
                    || coverage.coveredBoundary() != RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || !coverage.globalCommitment().equals(
                            RevocationTransitionFrameCodec.initialCommitment(coverage.storeId()))) {
                throw new IOException("Checkpoint genesis binding is invalid");
            }
        }

        private static void validateFrame(
                FileChannel log,
                RevocationTransitionFrameCodec codec,
                Coverage coverage) throws IOException {
            if (coverage.finalRecordStart().isEmpty()) {
                throw new IOException("Checkpoint final-frame binding is absent");
            }
            RevocationTransitionFrameCodec.ReadResult result =
                    codec.read(log, coverage.finalRecordStart().getAsLong());
            if (result.classification()
                    != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                throw new IOException("Checkpoint final-frame binding is invalid");
            }
            RevocationTransitionFrameCodec.CompleteRecord frame = result.record().orElseThrow();
            if (frame.data().globalRevision() != coverage.coveredRevision()
                    || !frame.commitment().equals(coverage.globalCommitment())
                    || frame.recordEnd() != coverage.coveredBoundary()) {
                throw new IOException("Checkpoint final-frame binding does not match the log");
            }
        }

    }

    /** Exact set-equality proof between a generation and its immutable frozen index. */
    private static final class HistoricalBinding {
        private static void validateGeneration(
                Path checkpointPath,
                FilesystemRevocationCurrentIndex.FrozenSnapshot frozen) throws IOException {
            try (FileChannel checkpoint = FileChannel.open(
                    checkpointPath, StandardOpenOption.READ)) {
                RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
                RevocationCheckpointCodec.ValidatedFile validated = codec.validate(checkpoint);
                Coverage expectedCoverage = frozen.coverage();
                Coverage actualCoverage = Coverage.from(validated.header());
                if (!actualCoverage.equals(expectedCoverage)) {
                    throw new IOException("Checkpoint coverage changed during construction");
                }
                if (validated.header().entryCount() != frozen.entryCount()) {
                    throw new IOException("Checkpoint count differs from its frozen index");
                }
                validateEntries(frozen, checkpoint, codec, validated);
            }
        }

        private static void validateEntries(
                FilesystemRevocationCurrentIndex.FrozenSnapshot frozen,
                FileChannel checkpoint,
                RevocationCheckpointCodec checkpointCodec,
                RevocationCheckpointCodec.ValidatedFile validated) throws IOException {
            long offset = RevocationCheckpointCodec.HEADER_BYTES;
            RevocationCheckpointCodec.SequentialDecoder decoder =
                    checkpointCodec.sequentialDecoder();
            for (long index = 0L; index < validated.header().entryCount(); index++) {
                RevocationCheckpointCodec.DecodedRecord decoded = decoder.read(
                        checkpoint, offset, validated.trailerOffset());
                validateEntry(frozen, decoded.entry());
                offset = decoded.nextOffset();
            }
        }

        private static void validateEntry(
                FilesystemRevocationCurrentIndex.FrozenSnapshot frozen,
                RevocationCheckpointCodec.CurrentStateEntry entry) throws IOException {
            RevocationTransitionFrameCodec.CompleteRecord frame = frozen.lookup(
                    entry.credentialId()).orElseThrow(
                            () -> new IOException(
                                    "Checkpoint entry is absent from its frozen index"));
            if (!frame.data().credentialId().equals(entry.credentialId())
                    || frame.data().globalRevision() != entry.globalRevision()
                    || frame.data().transition().revision() != entry.credentialRevision()
                    || !frame.commitment().equals(entry.transitionCommitment())
                    || !RevocationTransitionFrameCodec.transitionsEqual(
                            frame.data().transition(), entry.transition())
                    || !new FrameBounds(frame.recordOffset(), frame.recordEnd()).equals(
                            new FrameBounds(entry.frameStart(), entry.frameEnd()))) {
                throw new IOException("Checkpoint entry disagrees with its frozen current state");
            }
        }

        private record FrameBounds(long start, long end) {
        }
    }

    /** Streaming discovery keeps one candidate descriptor and repeats only for ambiguity fallback. */
    private static final class Discovery {
        private static Optional<FilesystemRevocationCheckpoint> discover(
                Path directory,
                Path logPath,
                FilesystemRevocationLog.RecoveryResult recovery) throws IOException {
            Objects.requireNonNull(directory, "directory");
            Objects.requireNonNull(logPath, "logPath");
            Objects.requireNonNull(recovery, "recovery");
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                return Optional.empty();
            }
            long upperExclusive = Long.MAX_VALUE;
            boolean includeMaximum = true;
            while (true) {
                Selection selection = select(
                        directory, logPath, recovery, upperExclusive, includeMaximum);
                if (selection.candidate().isEmpty()) {
                    return Optional.empty();
                }
                if (!selection.ambiguous()) {
                    return Optional.of(openSelected(selection.candidate().orElseThrow()));
                }
                upperExclusive = selection.revision();
                includeMaximum = false;
            }
        }

        private static Selection select(
                Path directory,
                Path logPath,
                FilesystemRevocationLog.RecoveryResult recovery,
                long upper,
                boolean includeUpper) throws IOException {
            long selectedRevision = -1L;
            Path selectedPath = null;
            RevocationCheckpointCodec.ValidatedFile selectedValidated = null;
            String selectedGeneration = null;
            boolean ambiguous = false;
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path candidate : entries) {
                    Optional<FinalName> parsed = FinalName.parse(candidate.getFileName().toString());
                    if (parsed.isEmpty() || !eligible(parsed.orElseThrow().revision(), upper, includeUpper)) {
                        continue;
                    }
                    Optional<RevocationCheckpointCodec.ValidatedFile> validated =
                            validateCandidate(candidate, logPath, recovery, parsed.orElseThrow());
                    if (validated.isEmpty()) {
                        continue;
                    }
                    long revision = validated.orElseThrow().header().coveredRevision();
                    if (revision > selectedRevision) {
                        selectedRevision = revision;
                        selectedPath = candidate;
                        selectedValidated = validated.orElseThrow();
                        selectedGeneration = validated.orElseThrow().generationId();
                        ambiguous = false;
                    } else if (revision == selectedRevision
                            && !validated.orElseThrow().generationId().equals(selectedGeneration)) {
                        ambiguous = true;
                    }
                }
            }
            Candidate selected = selectedPath == null
                    ? null : new Candidate(selectedPath, selectedValidated);
            return new Selection(Optional.ofNullable(selected), selectedRevision, ambiguous);
        }

        private static FilesystemRevocationCheckpoint openSelected(Candidate selected)
                throws IOException {
            FileChannel channel = FileChannel.open(selected.path(), StandardOpenOption.READ);
            return new FilesystemRevocationCheckpoint(
                    channel, new RevocationCheckpointCodec(), selected.validated());
        }

        private static boolean eligible(long revision, long upper, boolean includeUpper) {
            return includeUpper ? revision <= upper : revision < upper;
        }

        private static Optional<RevocationCheckpointCodec.ValidatedFile> validateCandidate(
                Path candidate,
                Path logPath,
                FilesystemRevocationLog.RecoveryResult recovery,
                FinalName name) {
            try (FileChannel channel = FileChannel.open(candidate, StandardOpenOption.READ)) {
                RevocationCheckpointCodec.ValidatedFile validated =
                        new RevocationCheckpointCodec().validate(channel);
                name.requireAgreement(validated);
                Binding.validate(logPath, recovery, Coverage.from(validated.header()));
                return Optional.of(validated);
            } catch (IOException invalid) {
                return Optional.empty();
            }
        }
    }

    /** Sequential cursor with lifecycle ownership held by its checkpoint. */
    private final class CheckpointCursor implements Cursor, CursorState {
        private final boolean revokedOnly;
        private long offset = RevocationCheckpointCodec.HEADER_BYTES;
        private long visited;
        private final RevocationCheckpointCodec.SequentialDecoder decoder =
                codec.sequentialDecoder();
        private RevocationCheckpointCodec.CurrentStateEntry current;
        private boolean cursorClosed;

        private CheckpointCursor(boolean revokedOnly) {
            this.revokedOnly = revokedOnly;
            cursors.add(this);
        }

        @Override
        public boolean advance(CancellationSignal cancellation) throws IOException {
            Objects.requireNonNull(cancellation, "cancellation");
            lifecycleLock.lock();
            try {
                requireCursorOpen();
                invalidateCurrent();
                cancellation.throwIfCancelled();
                while (visited < validated.header().entryCount()) {
                    RevocationCheckpointCodec.DecodedRecord record =
                            decoder.read(channel, offset, validated.trailerOffset());
                    offset = record.nextOffset();
                    visited++;
                    if (!revokedOnly || record.entry().transition().state() != RevocationState.CLEAR) {
                        current = record.entry();
                        return true;
                    }
                    cancellation.throwIfCancelled();
                }
                return false;
            } finally {
                lifecycleLock.unlock();
            }
        }

        private void invalidateCurrent() {
            current = null;
        }

        @Override
        public RevocationCheckpointCodec.CurrentStateEntry current() {
            lifecycleLock.lock();
            try {
                requireCursorOpen();
                if (current == null) {
                    throw new IllegalStateException("Checkpoint cursor has no current entry");
                }
                return current;
            } finally {
                lifecycleLock.unlock();
            }
        }

        @Override
        public void close() {
            lifecycleLock.lock();
            try {
                if (cursorClosed) {
                    return;
                }
                cursorClosed = true;
                current = null;
                cursors.remove(this);
            } finally {
                lifecycleLock.unlock();
            }
        }

        @Override
        public void closeFromOwner() {
            cursorClosed = true;
            current = null;
        }

        private void requireCursorOpen() {
            requireOpen();
            if (cursorClosed) {
                throw new IllegalStateException("Revocation checkpoint cursor is closed");
            }
        }
    }

    /** Non-resource invalidation view retained by the checkpoint owner. */
    @FunctionalInterface
    private interface CursorState {
        /** Invalidates the cursor without touching the shared file channel. */
        void closeFromOwner();
    }

    /** Non-authoritative retirement of exact obsolete generation names. */
    private static final class Retirement {
        private static long retire(Path directory, PublishedGeneration retained) {
            Objects.requireNonNull(directory, "directory");
            Objects.requireNonNull(retained, "retained");
            long retired = 0L;
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                return retired;
            }
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path candidate : entries) {
                    if (candidate.equals(retained.path())
                            || FinalName.parse(candidate.getFileName().toString()).isEmpty()) {
                        continue;
                    }
                    retired = retireCandidate(candidate, retired);
                }
            } catch (IOException failure) {
                warn(RETIREMENT_WARNING);
            }
            return retired;
        }

        private static long retireCandidate(Path candidate, long retired) {
            try {
                return Files.deleteIfExists(candidate) ? Math.addExact(retired, 1L) : retired;
            } catch (IOException | ArithmeticException failure) {
                warn(RETIREMENT_WARNING);
                return retired;
            }
        }
    }

    private record BuildResult(String generationId) {
    }

    private record Candidate(Path path, RevocationCheckpointCodec.ValidatedFile validated) {
        private Candidate {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(validated, "validated");
        }
    }

    private record Selection(Optional<Candidate> candidate, long revision, boolean ambiguous) {
        private Selection {
            Objects.requireNonNull(candidate, "candidate");
        }
    }

    private record FinalName(long revision, String generationId) {
        private void requireAgreement(RevocationCheckpointCodec.ValidatedFile validated)
                throws IOException {
            if (revision != validated.header().coveredRevision()
                    || !generationId.equals(validated.generationId())) {
                throw new IOException("Revocation checkpoint filename and contents disagree");
            }
        }

        private static Optional<FinalName> parse(String value) {
            if (!value.startsWith(FINAL_PREFIX) || !value.endsWith(FINAL_SUFFIX)) {
                return Optional.empty();
            }
            int separator = value.indexOf('-', FINAL_PREFIX.length());
            if (separator < 0) {
                return Optional.empty();
            }
            String revisionText = value.substring(FINAL_PREFIX.length(), separator);
            String generation = value.substring(separator + 1, value.length() - FINAL_SUFFIX.length());
            if (generation.length() != GENERATION_HEX_LENGTH || !isLowerHex(generation)) {
                return Optional.empty();
            }
            try {
                long revision = Long.parseLong(revisionText);
                return revision < 0L ? Optional.empty() : Optional.of(new FinalName(revision, generation));
            } catch (NumberFormatException invalid) {
                return Optional.empty();
            }
        }

        private static boolean isLowerHex(String value) {
            try {
                return HEX.formatHex(HEX.parseHex(value)).equals(value);
            } catch (IllegalArgumentException invalid) {
                return false;
            }
        }
    }
}
