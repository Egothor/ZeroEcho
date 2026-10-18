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
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.store.MetadataStoreId;

/**
 * Rebuildable, disk-backed current-state index for the authoritative revocation log.
 *
 * <p>The index never owns revocation authority. Every lookup revalidates the indexed
 * locator against an authenticated transition frame, and rebuild always derives from
 * the log beginning. Two superblocks and two cells per logical slot keep the preceding
 * generation usable until both durability boundaries for an update succeed.</p>
 */
final class FilesystemRevocationCurrentIndex implements AutoCloseable {

    /* default */ static final int SUPERBLOCK_BYTES = 160;
    /* default */ static final int CELL_BYTES = 160;
    /* default */ static final int CELLS_PER_SLOT = 2;

    private static final String ENTRY_COUNT_OVERFLOW =
            "Revocation index entry count overflow";
    private static final int MAGIC_SUPERBLOCK = 0x5A455249;
    private static final int MAGIC_CELL = 0x5A45524A;
    private static final short FORMAT_VERSION = 1;
    private static final short RESERVED_FLAGS = 0;
    private static final int DIGEST_BYTES = 32;
    private static final int STORE_ID_BYTES = 16;
    private static final int SUPERBLOCK_FIELDS_BYTES = SUPERBLOCK_BYTES - DIGEST_BYTES;
    private static final int CELL_FIELDS_BYTES = CELL_BYTES - DIGEST_BYTES;
    private static final int KEY_DIGEST_HEX_CHARACTERS = DIGEST_BYTES * 2;
    private static final int PRESENT = 1;
    private static final int ABSENT = 0;
    private static final int FIRST_GENERATION = 0;
    private static final int SECOND_GENERATION = 1;
    private static final int SINGLE_BYTE = 1;
    private static final long NO_SLOT = -1L;
    private static final long MINIMUM_FILE_SIZE = 1L;
    private static final long GENESIS_REVISION = 0L;
    private static final byte[] SUPERBLOCK_DOMAIN =
            "ZeroEcho revocation current index superblock v1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CELL_DOMAIN =
            "ZeroEcho revocation current index cell v1".getBytes(StandardCharsets.US_ASCII);
    private static final HexFormat HEX = HexFormat.of();

    private final Path indexPath;
    private final Path logPath;
    private final MetadataStoreId storeId;
    private final Configuration configuration;
    private final PublicationOperations operations;
    private final FaultInjector faults;
    private FileChannel indexChannel;
    private final StableIndexLock stableLock;
    private final FileChannel logChannel;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final RevocationTransitionFrameCodec frameCodec = new RevocationTransitionFrameCodec();
    private Superblock active;
    private int activeSuperblock;
    private State state = State.OPEN;

    private FilesystemRevocationCurrentIndex(
            Path indexPath,
            Path logPath,
            MetadataStoreId storeId,
            Configuration configuration,
            PublicationOperations operations,
            FaultInjector faults,
            FileChannel indexChannel,
            StableIndexLock stableLock,
            FileChannel logChannel,
            SelectedSuperblock selected) {
        this.indexPath = indexPath;
        this.logPath = logPath;
        this.storeId = storeId;
        this.configuration = configuration;
        this.operations = operations;
        this.faults = faults;
        this.indexChannel = indexChannel;
        this.stableLock = stableLock;
        this.logChannel = logChannel;
        active = selected.value();
        activeSuperblock = selected.index();
    }

    /* default */ static FilesystemRevocationCurrentIndex open(
            Path indexPath,
            Path logPath,
            MetadataStoreId expectedStoreId,
            Configuration configuration) throws IOException {
        return open(indexPath, logPath, expectedStoreId, configuration,
                DefaultPublicationOperations.INSTANCE, FaultInjector.NONE);
    }

    /* default */ static FilesystemRevocationCurrentIndex open(
            Path indexPath,
            Path logPath,
            MetadataStoreId expectedStoreId,
            Configuration configuration,
            PublicationOperations operations,
            FaultInjector faults) throws IOException {
        Objects.requireNonNull(indexPath, "indexPath");
        Objects.requireNonNull(logPath, "logPath");
        Objects.requireNonNull(expectedStoreId, "expectedStoreId");
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(operations, "operations");
        Objects.requireNonNull(faults, "faults");
        configuration.requireValid();
        IoOperations.requireRegular(indexPath, "Revocation current index");
        IoOperations.requireRegular(logPath, "Revocation transition log");
        try (OpenResources resources = OpenResources.acquire(indexPath, logPath)) {
            return openLocked(indexPath, logPath, expectedStoreId, configuration,
                    operations, faults, resources);
        }
    }

    private static FilesystemRevocationCurrentIndex openLocked(
            Path indexPath,
            Path logPath,
            MetadataStoreId expectedStoreId,
            Configuration configuration,
            PublicationOperations operations,
            FaultInjector faults,
            OpenResources resources) throws IOException {
            IoOperations.requireLogStore(resources.logChannel(), expectedStoreId);
            SuperblockCandidates candidates =
                    IndexOperations.selectSuperblocks(
                            resources.indexChannel(), expectedStoreId, configuration);
            SelectedSuperblock selected = CandidateSelection.select(
                    resources, expectedStoreId, candidates);
            FilesystemRevocationCurrentIndex opened = new FilesystemRevocationCurrentIndex(
                    indexPath, logPath, expectedStoreId, configuration, operations, faults,
                    resources.indexChannel(), resources.stableLock(),
                    resources.logChannel(), selected);
            opened.new IndexAccess().applySuffix();
            resources.transferOwnership();
            return opened;
    }

    /* default */ static FilesystemRevocationCurrentIndex rebuild(
            Path indexPath,
            Path logPath,
            MetadataStoreId expectedStoreId,
            Configuration configuration) throws IOException {
        return rebuild(indexPath, logPath, expectedStoreId, configuration,
                DefaultPublicationOperations.INSTANCE, FaultInjector.NONE);
    }

    /* default */ static FilesystemRevocationCurrentIndex recover(
            Path indexPath,
            Path checkpointDirectory,
            Path logPath,
            MetadataStoreId expectedStoreId,
            Configuration configuration,
            RecoveryBoundary target) throws IOException {
        return recover(indexPath, checkpointDirectory, logPath, expectedStoreId,
                configuration, target, DefaultPublicationOperations.INSTANCE,
                FaultInjector.NONE);
    }

    /* default */ static FilesystemRevocationCurrentIndex recover(
            Path indexPath,
            Path checkpointDirectory,
            Path logPath,
            MetadataStoreId expectedStoreId,
            Configuration configuration,
            RecoveryBoundary target,
            PublicationOperations operations,
            FaultInjector faults) throws IOException {
        return RecoveryCoordinator.recover(
                indexPath, checkpointDirectory, logPath, expectedStoreId,
                configuration, target, operations, faults);
    }

    /* default */ static FilesystemRevocationCurrentIndex rebuild(
            Path indexPath,
            Path logPath,
            MetadataStoreId expectedStoreId,
            Configuration configuration,
            PublicationOperations operations,
            FaultInjector faults) throws IOException {
        Objects.requireNonNull(indexPath, "indexPath");
        Objects.requireNonNull(logPath, "logPath");
        Objects.requireNonNull(expectedStoreId, "expectedStoreId");
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(operations, "operations");
        Objects.requireNonNull(faults, "faults");
        configuration.requireValid();
        IoOperations.requireRegular(logPath, "Revocation transition log");
        Path parent = Objects.requireNonNull(indexPath.getParent(), "index parent");
        Files.createDirectories(parent);
        IoOperations.requireDirectory(parent);
        Path temporary = parent.resolve("." + indexPath.getFileName() + ".building-" + UUID.randomUUID());
        boolean published = false;
        try (StableIndexLock stable = StableIndexLock.acquire(indexPath)) {
            try {
                build(temporary, logPath, expectedStoreId, configuration, operations, faults);
                faults.fail(FaultPoint.PUBLISH_ATOMIC_MOVE);
                try {
                    operations.atomicReplace(temporary, indexPath);
                } catch (AtomicMoveNotSupportedException unsupported) {
                    throw new IOException("Atomic revocation index publication is unsupported", unsupported);
                }
                published = true;
                IoOperations.forceDirectory(parent, operations, faults);
                try (OpenResources resources = OpenResources.acquireLocked(
                        stable, indexPath, logPath)) {
                    return openLocked(indexPath, logPath, expectedStoreId, configuration,
                            operations, faults, resources);
                }
            } finally {
                if (!published) {
                    try {
                        Files.deleteIfExists(temporary);
                    } catch (IOException ignored) {
                        // The authoritative rebuild failure remains primary.
                    }
                }
            }
        }
    }

    /* default */ Optional<RevocationTransitionFrameCodec.CompleteRecord> lookup(PkiId credentialId)
            throws IOException {
        Objects.requireNonNull(credentialId, "credentialId");
        lifecycleLock.lock();
        try {
            requireOperational();
            IndexAccess access = new IndexAccess();
            ProbeResult probe = access.probe(credentialId, active);
            if (probe.match().isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(access.readAuthoritative(
                    probe.match().orElseThrow().cell(), credentialId));
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ void update(RevocationTransitionFrameCodec.CompleteRecord supplied)
            throws IOException {
        Objects.requireNonNull(supplied, "supplied");
        lifecycleLock.lock();
        try {
            requireOperational();
            try {
                RevocationTransitionFrameCodec.CompleteRecord authoritative =
                        new IndexAccess().requireSuppliedAuthoritative(supplied);
                new IndexAccess().updateValidated(authoritative);
            } catch (IOException failure) {
                state = State.UNUSABLE;
                throw failure;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ long coveredGlobalRevision() {
        lifecycleLock.lock();
        try {
            requireOperational();
            return active.coveredRevision();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ long entryCount() {
        lifecycleLock.lock();
        try {
            requireOperational();
            return active.entryCount();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ boolean unusable() {
        lifecycleLock.lock();
        try {
            return state == State.UNUSABLE;
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ FrozenSnapshot freeze(Path snapshotPath, int transferBufferBytes)
            throws IOException {
        return freeze(snapshotPath, transferBufferBytes, FrozenFaultInjector.NONE);
    }

    /* default */ FrozenSnapshot freeze(
            Path snapshotPath,
            int transferBufferBytes,
            FrozenFaultInjector faults) throws IOException {
        Objects.requireNonNull(snapshotPath, "snapshotPath");
        Objects.requireNonNull(faults, "faults");
        if (transferBufferBytes <= 0) {
            throw new IllegalArgumentException("Freeze transfer buffer must be positive");
        }
        lifecycleLock.lock();
        try {
            requireOperational();
            try (FrozenResources resources = FrozenResources.create(snapshotPath, logPath)) {
                long expectedSize = IoOperations.expectedSize(active.capacity());
                faults.fail(FrozenFaultPoint.COPY);
                IoOperations.copyExact(
                        indexChannel, resources.indexChannel(), expectedSize, transferBufferBytes);
                faults.fail(FrozenFaultPoint.FORCE);
                resources.indexChannel().force(true);
                IndexValidation.validate(
                        resources.indexChannel(), resources.logChannel(), storeId, active);
                FrozenSnapshot snapshot = new FrozenSnapshot(
                        snapshotPath, logPath,
                        resources.indexChannel(), resources.logChannel(), active);
                resources.transferOwnership();
                return snapshot;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    @Override
    public void close() throws IOException {
        lifecycleLock.lock();
        try {
            if (state == State.CLOSED) {
                return;
            }
            state = State.CLOSED;
            IOException failure = null;
            try {
                logChannel.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                indexChannel.close();
            } catch (IOException closeFailure) {
                failure = IoOperations.appendFailure(failure, closeFailure);
            }
            try {
                stableLock.closeOwned();
            } catch (IOException closeFailure) {
                failure = IoOperations.appendFailure(failure, closeFailure);
            }
            if (failure != null) {
                throw failure;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /** Validates and advances one retained index without adding facade complexity. */
    private final class IndexAccess {
    private void applySuffix() throws IOException {
        RevocationTransitionFrameCodec.ReadResult first =
                frameCodec.read(logChannel, active.coveredBoundary());
        switch (first.classification()) {
            case END_OF_INPUT, INCOMPLETE_TAIL:
                return;
            case CORRUPT_RECORD:
                throw new IOException("Revocation log suffix is corrupt");
            case COMPLETE_RECORD:
                publishSuffix(first.record().orElseThrow());
        }
    }

    private void publishSuffix(RevocationTransitionFrameCodec.CompleteRecord first)
            throws IOException {
        Path parent = Objects.requireNonNull(indexPath.getParent(), "index parent");
        Path temporary = parent.resolve(
                "." + indexPath.getFileName() + ".suffix-" + UUID.randomUUID());
        Superblock next;
        boolean published = false;
        try {
            try (BuildIndex builder = BuildIndex.resume(
                    indexPath, temporary, storeId, configuration, operations,
                    faults, logChannel, active)) {
                acceptSuffix(builder, first);
                builder.finish();
                next = builder.state();
            }
            faults.fail(FaultPoint.PUBLISH_ATOMIC_MOVE);
            // Release the retained index handle before the atomic replace: Windows
            // refuses to replace a file this process still holds open, whereas POSIX
            // tolerates rename-over-open. Closing first is correct on both platforms
            // because this operation runs under lifecycleLock (no concurrent reader
            // can touch the channel) and installPublished reopens a fresh handle on
            // the replaced file; on failure update() marks the index UNUSABLE.
            indexChannel.close();
            try {
                operations.atomicReplace(temporary, indexPath);
            } catch (AtomicMoveNotSupportedException unsupported) {
                throw new IOException(
                        "Atomic revocation index suffix publication is unsupported", unsupported);
            }
            published = true;
            installPublished(next);
            IoOperations.forceDirectory(parent, operations, faults);
        } finally {
            if (!published) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                    // The derived suffix-publication failure remains primary.
                }
            }
        }
    }

    private void acceptSuffix(
            BuildIndex builder,
            RevocationTransitionFrameCodec.CompleteRecord first) throws IOException {
        builder.accept(first);
        long offset = first.recordEnd();
        while (true) {
            RevocationTransitionFrameCodec.ReadResult result = frameCodec.read(logChannel, offset);
            switch (result.classification()) {
                case END_OF_INPUT, INCOMPLETE_TAIL:
                    return;
                case CORRUPT_RECORD:
                    throw new IOException("Revocation log suffix is corrupt");
                case COMPLETE_RECORD:
                    RevocationTransitionFrameCodec.CompleteRecord record = result.record().orElseThrow();
                    builder.accept(record);
                    offset = record.recordEnd();
                    break;
            }
        }
    }

    private void installPublished(Superblock next) throws IOException {
        try (ReplacementChannel replacement = ReplacementChannel.open(indexPath)) {
            IndexValidation.validate(replacement.channel(), logChannel, storeId, next);
            indexChannel.close();
            indexChannel = replacement.transferOwnership();
            active = next;
            activeSuperblock = FIRST_GENERATION;
        }
    }

    private void updateValidated(RevocationTransitionFrameCodec.CompleteRecord record)
            throws IOException {
        IoOperations.requireNextGlobal(
                record, active.coveredRevision(), active.coveredCommitment());
        PkiId credentialId = record.data().credentialId();
        ProbeResult probe = probe(credentialId, active);
        RevocationTransitionFrameCodec.CompleteRecord previous = null;
        if (probe.match().isPresent()) {
            previous = readAuthoritative(probe.match().orElseThrow().cell(), credentialId);
        }
        FilesystemRevocationLog.validateTransition(record.data(), previous);
        boolean insertion = probe.match().isEmpty();
        if (insertion && IoOperations.addExact(active.entryCount(), 1L,
                ENTRY_COUNT_OVERFLOW) > active.loadThreshold()) {
            applySuffix();
            return;
        }
        long slot = insertion ? probe.insertionSlot() : probe.match().orElseThrow().slot();
        ActiveCell prior = IndexOperations.activeCell(
                indexChannel, slot, active.coveredRevision());
        int inactiveCell = prior.cellIndex() == FIRST_GENERATION
                ? SECOND_GENERATION : FIRST_GENERATION;
        Cell nextCell = Cell.occupied(record, IoOperations.keyDigest(credentialId));
        faults.fail(FaultPoint.CELL_WRITE);
        IndexOperations.writeCell(indexChannel, slot, inactiveCell, nextCell);
        faults.fail(FaultPoint.CELL_FORCE);
        indexChannel.force(true);
        long nextCount = insertion ? IoOperations.addExact(active.entryCount(), 1L,
                ENTRY_COUNT_OVERFLOW) : active.entryCount();
        Superblock next = active.advance(record, nextCount);
        int inactiveSuperblock = activeSuperblock == FIRST_GENERATION
                ? SECOND_GENERATION : FIRST_GENERATION;
        faults.fail(FaultPoint.SUPERBLOCK_WRITE);
        IndexOperations.writeSuperblock(indexChannel, inactiveSuperblock, next);
        faults.fail(FaultPoint.SUPERBLOCK_FORCE);
        indexChannel.force(true);
        active = next;
        activeSuperblock = inactiveSuperblock;
    }

    private RevocationTransitionFrameCodec.CompleteRecord requireSuppliedAuthoritative(
            RevocationTransitionFrameCodec.CompleteRecord supplied) throws IOException {
        RevocationTransitionFrameCodec.ReadResult decoded =
                frameCodec.read(logChannel, supplied.recordOffset());
        if (decoded.classification() != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
            throw new IOException("Supplied revocation transition is not authoritative log content");
        }
        RevocationTransitionFrameCodec.CompleteRecord actual = decoded.record().orElseThrow();
        if (actual.recordEnd() != supplied.recordEnd()
                || !actual.commitment().equals(supplied.commitment())
                || !actual.data().equals(supplied.data())) {
            throw new IOException("Supplied revocation transition disagrees with the log");
        }
        return actual;
    }

    private ProbeResult probe(PkiId credentialId, Superblock superblock) throws IOException {
        String digest = IoOperations.keyDigest(credentialId);
        long first = IoOperations.initialSlot(digest, superblock.capacity());
        long tombstone = NO_SLOT;
        for (long distance = 0L; distance < superblock.capacity(); distance++) {
            long slot = IoOperations.wrapSlot(first, distance, superblock.capacity());
            ActiveCell selected = IndexOperations.activeCell(
                    indexChannel, slot, superblock.coveredRevision());
            Cell cell = selected.cell();
            if (cell.state() == SlotState.EMPTY) {
                return ProbeResult.absent(
                        IoOperations.preferredInsertionSlot(tombstone, slot));
            }
            if (cell.state() == SlotState.TOMBSTONE) {
                if (tombstone == NO_SLOT) {
                    tombstone = slot;
                }
                continue;
            }
            if (cell.keyDigest().equals(digest)) {
                RevocationTransitionFrameCodec.CompleteRecord frame = readAuthoritative(cell, null);
                if (frame.data().credentialId().equals(credentialId)) {
                    return ProbeResult.present(slot, selected.cellIndex(), cell);
                }
            }
        }
        if (tombstone != NO_SLOT) {
            return ProbeResult.absent(tombstone);
        }
        throw new IOException("Revocation current index probe exhausted its finite capacity");
    }

    private RevocationTransitionFrameCodec.CompleteRecord readAuthoritative(
            Cell cell, PkiId expectedIdentity) throws IOException {
        if (cell.state() != SlotState.OCCUPIED) {
            throw new IOException("Revocation current index cell is not occupied");
        }
        RevocationTransitionFrameCodec.ReadResult result = frameCodec.read(logChannel, cell.frameStart());
        if (result.classification() != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
            throw new IOException("Revocation current index frame locator is invalid");
        }
        RevocationTransitionFrameCodec.CompleteRecord record = result.record().orElseThrow();
        PkiId actualIdentity = record.data().credentialId();
        if (record.recordEnd() != cell.frameEnd()
                || record.data().globalRevision() != cell.globalRevision()
                || record.data().transition().revision() != cell.credentialRevision()
                || !record.commitment().equals(cell.frameCommitment())
                || !IoOperations.keyDigest(actualIdentity).equals(cell.keyDigest())
                || expectedIdentity != null && !expectedIdentity.equals(actualIdentity)) {
            throw new IOException("Revocation current index cell disagrees with its authoritative frame");
        }
        return record;
    }

    }

    private void requireOperational() {
        if (state != State.OPEN || !indexChannel.isOpen() || !logChannel.isOpen()) {
            throw new IllegalStateException("Revocation current index is not operational");
        }
    }

    private static void build(
            Path temporary,
            Path logPath,
            MetadataStoreId expectedStoreId,
            Configuration configuration,
            PublicationOperations operations,
            FaultInjector faults) throws IOException {
        RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        try (FileChannel log = FileChannel.open(logPath, StandardOpenOption.READ);
                BuildIndex builder = BuildIndex.create(
                        temporary, expectedStoreId, configuration, operations, faults, log)) {
            MetadataStoreId actual = codec.readPreamble(log);
            if (!expectedStoreId.equals(actual)) {
                throw new IOException("Revocation current-index rebuild log authority is foreign");
            }
            long offset = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
            while (true) {
                RevocationTransitionFrameCodec.ReadResult result = codec.read(log, offset);
                switch (result.classification()) {
                    case END_OF_INPUT, INCOMPLETE_TAIL:
                        builder.finish();
                        return;
                    case CORRUPT_RECORD:
                        throw new IOException("Revocation log is corrupt during current-index rebuild");
                    case COMPLETE_RECORD:
                        RevocationTransitionFrameCodec.CompleteRecord record =
                                result.record().orElseThrow();
                        builder.accept(record);
                        offset = record.recordEnd();
                        break;
                }
            }
        }
    }

    /** Bounded recovery orchestration over one immutable authoritative prefix. */
    private static final class RecoveryCoordinator {
        private final Path indexPath;
        private final Path checkpointDirectory;
        private final Path logPath;
        private final MetadataStoreId storeId;
        private final Configuration configuration;
        private final RecoveryBoundary target;
        private final PublicationOperations operations;
        private final FaultInjector faults;
        private Optional<String> originalFingerprint = Optional.empty();
        private Optional<Superblock> publishedState = Optional.empty();

        private RecoveryCoordinator(
                Path indexPath,
                Path checkpointDirectory,
                Path logPath,
                MetadataStoreId storeId,
                Configuration configuration,
                RecoveryBoundary target,
                PublicationOperations operations,
                FaultInjector faults) {
            this.indexPath = indexPath;
            this.checkpointDirectory = checkpointDirectory;
            this.logPath = logPath;
            this.storeId = storeId;
            this.configuration = configuration;
            this.target = target;
            this.operations = operations;
            this.faults = faults;
        }

        private static FilesystemRevocationCurrentIndex recover(
                Path indexPath,
                Path checkpointDirectory,
                Path logPath,
                MetadataStoreId expectedStoreId,
                Configuration configuration,
                RecoveryBoundary target,
                PublicationOperations operations,
                FaultInjector faults) throws IOException {
            requireArguments(indexPath, checkpointDirectory, logPath, expectedStoreId,
                    configuration, target, operations, faults);
            return new RecoveryCoordinator(
                    indexPath, checkpointDirectory, logPath, expectedStoreId,
                    configuration, target, operations, faults).execute();
        }

        private FilesystemRevocationCurrentIndex execute() throws IOException {
            Path parent = Objects.requireNonNull(indexPath.getParent(), "index parent");
            Files.createDirectories(parent);
            IoOperations.requireDirectory(parent);
            Path seedCopy = parent.resolve("." + indexPath.getFileName()
                    + ".seed-" + UUID.randomUUID());
            Path temporary = parent.resolve("." + indexPath.getFileName()
                    + ".recovering-" + UUID.randomUUID());
            Optional<FilesystemRevocationCurrentIndex> exact =
                    capturePublishedSeed(seedCopy);
            if (exact.isPresent()) {
                return exact.orElseThrow();
            }
            boolean published = false;
            try {
                buildTarget(temporary, seedCopy);
                FilesystemRevocationCurrentIndex result = publish(
                        temporary, originalFingerprint);
                published = true;
                return result;
            } finally {
                deleteDerived(seedCopy);
                if (!published) {
                    deleteDerived(temporary);
                }
            }
        }

        private static void requireArguments(
                Path indexPath,
                Path checkpointDirectory,
                Path logPath,
                MetadataStoreId expectedStoreId,
                Configuration configuration,
                RecoveryBoundary target,
                PublicationOperations operations,
                FaultInjector faults) throws IOException {
            Objects.requireNonNull(indexPath, "indexPath");
            Objects.requireNonNull(checkpointDirectory, "checkpointDirectory");
            Objects.requireNonNull(logPath, "logPath");
            Objects.requireNonNull(expectedStoreId, "expectedStoreId");
            Objects.requireNonNull(configuration, "configuration");
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(operations, "operations");
            Objects.requireNonNull(faults, "faults");
            configuration.requireValid();
            IoOperations.requireRegular(logPath, "Revocation transition log");
            if (!expectedStoreId.equals(target.storeId())) {
                throw new IOException("Revocation recovery target belongs to another store");
            }
        }

        private Optional<FilesystemRevocationCurrentIndex> capturePublishedSeed(
                Path seedCopy) throws IOException {
            try (StableIndexLock stable = StableIndexLock.acquire(indexPath)) {
                originalFingerprint = fingerprint(indexPath);
                if (originalFingerprint.isEmpty()) {
                    return Optional.empty();
                }
                try (FileChannel index = FileChannel.open(indexPath, StandardOpenOption.READ);
                        FileChannel log = FileChannel.open(logPath, StandardOpenOption.READ)) {
                    Optional<SelectedSuperblock> selected = selectDerivedSeed(
                            index, log, storeId, configuration);
                    if (selected.isEmpty()) {
                        return Optional.empty();
                    }
                    Superblock state = selected.orElseThrow().value();
                    if (state.coveredRevision() > target.globalRevision()) {
                        throw new IOException(
                                "Published revocation index is newer than the recovery target");
                    }
                    if (matches(state, target)) {
                        return Optional.of(openExactWhileLocked(
                                stable, indexPath, logPath, storeId,
                                configuration, target, operations, faults));
                    }
                    Files.copy(indexPath, seedCopy);
                    publishedState = Optional.of(state);
                    return Optional.empty();
                }
            }
        }

        private static Optional<SelectedSuperblock> selectDerivedSeed(
                FileChannel index,
                FileChannel log,
                MetadataStoreId storeId,
                Configuration configuration) {
            try {
                SuperblockCandidates candidates = IndexOperations.selectSuperblocks(
                        index, storeId, configuration);
                return Optional.of(selectValid(index, log, storeId, candidates));
            } catch (IOException invalidDerived) {
                return Optional.empty();
            }
        }

        private static SelectedSuperblock selectValid(
                FileChannel index,
                FileChannel log,
                MetadataStoreId storeId,
                SuperblockCandidates candidates) throws IOException {
            IOException newestFailure = validateCandidate(
                    index, log, storeId, candidates.newest());
            if (newestFailure == null) {
                return candidates.newest();
            }
            if (candidates.older().isPresent()) {
                SelectedSuperblock older = candidates.older().orElseThrow();
                IOException olderFailure = validateCandidate(index, log, storeId, older);
                if (olderFailure == null) {
                    return older;
                }
                newestFailure.addSuppressed(olderFailure);
            }
            throw newestFailure;
        }

        private static IOException validateCandidate(
                FileChannel index,
                FileChannel log,
                MetadataStoreId storeId,
                SelectedSuperblock selected) {
            try {
                IndexValidation.validate(index, log, storeId, selected.value());
                return null;
            } catch (IOException invalid) {
                return invalid;
            }
        }

        private static FilesystemRevocationCurrentIndex openExactWhileLocked(
                StableIndexLock stable,
                Path indexPath,
                Path logPath,
                MetadataStoreId storeId,
                Configuration configuration,
                RecoveryBoundary target,
                PublicationOperations operations,
                FaultInjector faults) throws IOException {
            try (OpenResources resources = OpenResources.acquireLocked(
                    stable, indexPath, logPath)) {
                IoOperations.requireLogStore(resources.logChannel(), storeId);
                SuperblockCandidates candidates = IndexOperations.selectSuperblocks(
                        resources.indexChannel(), storeId, configuration);
                SelectedSuperblock selected = CandidateSelection.select(
                        resources, storeId, candidates);
                requireTarget(selected.value(), target);
                FilesystemRevocationCurrentIndex opened = new FilesystemRevocationCurrentIndex(
                        indexPath, logPath, storeId, configuration,
                        operations, faults,
                        resources.indexChannel(), resources.stableLock(),
                        resources.logChannel(), selected);
                resources.transferOwnership();
                return opened;
            }
        }

        private void buildTarget(Path temporary, Path seedCopy) throws IOException {
            try (FileChannel log = FileChannel.open(
                    logPath, StandardOpenOption.READ)) {
                IoOperations.requireLogStore(log, storeId);
                if (publishedState.isPresent()) {
                    try (BuildIndex builder = BuildIndex.resume(
                            seedCopy, temporary, storeId,
                            configuration, operations, faults,
                            log, publishedState.orElseThrow())) {
                        replayToTarget(builder, log, target, faults);
                    }
                    return;
                }
                if (buildFromCheckpoint(temporary, log)) {
                    return;
                }
                try (BuildIndex builder = BuildIndex.create(
                        temporary, storeId, configuration,
                        operations, faults, log)) {
                    replayToTarget(builder, log, target, faults);
                }
            }
        }

        private boolean buildFromCheckpoint(
                Path temporary, FileChannel log) throws IOException {
            if (!Files.isDirectory(
                    checkpointDirectory, LinkOption.NOFOLLOW_LINKS)) {
                return false;
            }
            long upper = target.globalRevision();
            boolean includeUpper = true;
            while (true) {
                Optional<FilesystemRevocationCheckpoint> candidate =
                        FilesystemRevocationCheckpoint.discoverBelow(
                                checkpointDirectory, logPath, target, upper,
                                includeUpper, faults);
                if (candidate.isEmpty()) {
                    return false;
                }
                try (FilesystemRevocationCheckpoint checkpoint = candidate.orElseThrow()) {
                    try (BuildIndex builder = BuildIndex.createSeeded(
                            temporary, storeId, configuration,
                            operations, faults, log, checkpoint)) {
                        seed(builder, checkpoint, faults);
                        replayToTarget(builder, log, target, faults);
                        return true;
                    } catch (CheckpointRejectedException rejected) {
                        deleteDerived(temporary);
                        if (Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) {
                            throw new IOException(
                                    "Rejected checkpoint recovery file could not be removed",
                                    rejected);
                        }
                        upper = checkpoint.coveredRevision();
                        includeUpper = false;
                    }
                }
            }
        }

        private static void seed(
                BuildIndex builder,
                FilesystemRevocationCheckpoint checkpoint,
                FaultInjector faults) throws IOException {
            builder.seed(checkpoint, faults);
        }

        private static void replayToTarget(
                BuildIndex builder,
                FileChannel log,
                RecoveryBoundary target,
                FaultInjector faults) throws IOException {
            RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
            long offset = builder.state().coveredBoundary();
            while (offset < target.boundary()) {
                faults.observeRecoveryLogOffset(offset);
                RevocationTransitionFrameCodec.ReadResult result = codec.read(log, offset);
                if (result.classification()
                        != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                    throw new IOException(
                            "Authoritative revocation log ends before the recovery target");
                }
                RevocationTransitionFrameCodec.CompleteRecord record =
                        result.record().orElseThrow();
                if (record.recordEnd() > target.boundary()) {
                    throw new IOException(
                            "Authoritative revocation frame crosses the recovery target");
                }
                builder.accept(record);
                offset = record.recordEnd();
            }
            requireTarget(builder.state(), target);
            builder.finish();
        }

        private FilesystemRevocationCurrentIndex publish(
                Path temporary,
                Optional<String> originalFingerprint) throws IOException {
            Path parent = Objects.requireNonNull(indexPath.getParent(), "index parent");
            try (StableIndexLock stable = StableIndexLock.acquire(indexPath)) {
                Optional<String> currentFingerprint = fingerprint(indexPath);
                if (!currentFingerprint.equals(originalFingerprint)) {
                    Optional<FilesystemRevocationCurrentIndex> exact = tryOpenExact(
                            stable);
                    if (exact.isPresent()) {
                        deleteDerived(temporary);
                        return exact.orElseThrow();
                    }
                    throw new IOException(
                            "Published revocation index changed during bounded recovery");
                }
                requireSeedUnchanged();
                faults.fail(FaultPoint.PUBLISH_ATOMIC_MOVE);
                try {
                    operations.atomicReplace(temporary, indexPath);
                } catch (AtomicMoveNotSupportedException unsupported) {
                    throw new IOException(
                            "Atomic revocation index recovery publication is unsupported",
                            unsupported);
                }
                IoOperations.forceDirectory(parent, operations, faults);
                return openExactWhileLocked(
                        stable, indexPath, logPath, storeId, configuration,
                        target, operations, faults);
            }
        }

        private void requireSeedUnchanged() throws IOException {
            if (publishedState.isEmpty()) {
                return;
            }
            try (FileChannel index = FileChannel.open(indexPath, StandardOpenOption.READ);
                    FileChannel log = FileChannel.open(logPath, StandardOpenOption.READ)) {
                SuperblockCandidates candidates = IndexOperations.selectSuperblocks(
                        index, storeId, configuration);
                SelectedSuperblock selected = selectValid(
                        index, log, storeId, candidates);
                if (!selected.value().equals(publishedState.orElseThrow())) {
                    throw new IOException(
                            "Published revocation index seed changed during recovery");
                }
            }
        }

        private Optional<FilesystemRevocationCurrentIndex> tryOpenExact(
                StableIndexLock stable) {
            try {
                return Optional.of(openExactWhileLocked(
                        stable, indexPath, logPath, storeId, configuration,
                        target, operations, faults));
            } catch (IOException notExact) {
                return Optional.empty();
            }
        }

        private static Optional<String> fingerprint(Path path) throws IOException {
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                return Optional.empty();
            }
            IoOperations.requireRegular(path, "Revocation current index");
            MessageDigest digest = IoOperations.sha256();
            ByteBuffer buffer = ByteBuffer.allocate(8192);
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                long offset = 0L;
                while (offset < channel.size()) {
                    buffer.clear();
                    int read = channel.read(buffer, offset);
                    if (read <= 0) {
                        throw new IOException(
                                "Revocation current-index fingerprint made no progress");
                    }
                    digest.update(buffer.array(), 0, read);
                    offset += read;
                }
            }
            return Optional.of(HEX.formatHex(digest.digest()));
        }

        private static boolean matches(
                Superblock state,
                RecoveryBoundary target) {
            return state.storeId().equals(target.storeId())
                    && state.coveredRevision() == target.globalRevision()
                    && state.finalRecordStart().equals(target.finalRecordStart())
                    && state.coveredBoundary() == target.boundary()
                    && state.coveredCommitment().equals(target.globalCommitment());
        }

        private static void requireTarget(
                Superblock state,
                RecoveryBoundary target) throws IOException {
            if (!matches(state, target)) {
                throw new IOException(
                        "Recovered revocation index does not match its immutable target");
            }
        }

        private static void deleteDerived(Path path) {
            try {
                Files.deleteIfExists(path);
            } catch (IOException ignored) {
                // Derived temporary cleanup cannot alter revocation authority.
            }
        }
    }

    /** A self-consistent derived checkpoint cannot seed the exact authoritative frames. */
    private static final class CheckpointRejectedException extends IOException {
        private static final long serialVersionUID = 2411479676961225172L;

        private CheckpointRejectedException(String message) {
            super(message);
        }
    }

    /** Strict binary format, probing, arithmetic, and local filesystem primitives. */
    private static final class IndexOperations {
    private static SuperblockCandidates selectSuperblocks(
            FileChannel channel, MetadataStoreId expectedStore, Configuration configuration)
            throws IOException {
        Optional<Superblock> first = decodeSuperblock(
                IoOperations.readAt(channel, GENESIS_REVISION, SUPERBLOCK_BYTES));
        Optional<Superblock> second = decodeSuperblock(
                IoOperations.readAt(channel, SUPERBLOCK_BYTES, SUPERBLOCK_BYTES));
        first = matching(first, expectedStore, configuration);
        second = matching(second, expectedStore, configuration);
        if (first.isEmpty() && second.isEmpty()) {
            throw new IOException("Revocation current index has no valid superblock");
        }
        if (first.isEmpty()) {
            return new SuperblockCandidates(
                    new SelectedSuperblock(SECOND_GENERATION, second.orElseThrow()), Optional.empty());
        }
        if (second.isEmpty()) {
            return new SuperblockCandidates(
                    new SelectedSuperblock(FIRST_GENERATION, first.orElseThrow()), Optional.empty());
        }
        Superblock left = first.orElseThrow();
        Superblock right = second.orElseThrow();
        if (left.coveredRevision() == right.coveredRevision() && !left.equals(right)) {
            throw new IOException("Revocation current index superblocks are ambiguous");
        }
        if (left.equals(right)) {
            return new SuperblockCandidates(
                    new SelectedSuperblock(FIRST_GENERATION, left), Optional.empty());
        }
        SelectedSuperblock leftSelected = new SelectedSuperblock(FIRST_GENERATION, left);
        SelectedSuperblock rightSelected = new SelectedSuperblock(SECOND_GENERATION, right);
        return right.coveredRevision() > left.coveredRevision()
                ? new SuperblockCandidates(rightSelected, Optional.of(leftSelected))
                : new SuperblockCandidates(leftSelected, Optional.of(rightSelected));
    }

    private static Optional<Superblock> matching(
            Optional<Superblock> candidate,
            MetadataStoreId storeId,
            Configuration configuration) {
        return candidate.filter(value -> value.storeId().equals(storeId)
                && value.loadNumerator() == configuration.loadNumerator()
                && value.loadDenominator() == configuration.loadDenominator());
    }

    private static Optional<Superblock> decodeSuperblock(byte[] encoded) throws IOException {
        if (IoOperations.allZero(encoded)) {
            return Optional.empty();
        }
        if (!IoOperations.verifyDigest(
                encoded, SUPERBLOCK_FIELDS_BYTES, SUPERBLOCK_DOMAIN)) {
            return Optional.empty();
        }
        try {
            ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
            if (input.getInt() != MAGIC_SUPERBLOCK
                    || input.getShort() != FORMAT_VERSION
                    || input.getShort() != RESERVED_FLAGS) {
                return Optional.empty();
            }
            byte[] rawStore = new byte[STORE_ID_BYTES];
            input.get(rawStore);
            long capacity = input.getLong();
            long count = input.getLong();
            long revision = input.getLong();
            int present = Byte.toUnsignedInt(input.get());
            byte[] reservedPresence = new byte[7];
            input.get(reservedPresence);
            long finalStart = input.getLong();
            long boundary = input.getLong();
            byte[] rawCommitment = new byte[DIGEST_BYTES];
            input.get(rawCommitment);
            int numerator = input.getInt();
            int denominator = input.getInt();
            byte[] reserved = new byte[16];
            input.get(reserved);
            if (!IoOperations.allZero(reservedPresence)
                    || !IoOperations.allZero(reserved)) {
                return Optional.empty();
            }
            OptionalLong start;
            if (revision == GENESIS_REVISION && present == ABSENT && finalStart == 0L) {
                start = OptionalLong.empty();
            } else if (revision > GENESIS_REVISION && present == PRESENT
                    && finalStart >= RevocationTransitionFrameCodec.PREAMBLE_BYTES) {
                start = OptionalLong.of(finalStart);
            } else {
                return Optional.empty();
            }
            Superblock value = new Superblock(
                    new MetadataStoreId(HEX.formatHex(rawStore)), capacity, count, revision,
                    start, boundary,
                    new RevocationTransitionFrameCodec.Commitment(HEX.formatHex(rawCommitment)),
                    numerator, denominator);
            value.requireValid();
            return Optional.of(value);
        } catch (IllegalArgumentException malformed) {
            return Optional.empty();
        }
    }

    private static void writeSuperblock(FileChannel channel, int index, Superblock value)
            throws IOException {
        ByteBuffer output = ByteBuffer.allocate(SUPERBLOCK_BYTES).order(ByteOrder.BIG_ENDIAN);
        output.putInt(MAGIC_SUPERBLOCK);
        output.putShort(FORMAT_VERSION);
        output.putShort(RESERVED_FLAGS);
        output.put(HEX.parseHex(value.storeId().value()));
        output.putLong(value.capacity());
        output.putLong(value.entryCount());
        output.putLong(value.coveredRevision());
        output.put((byte) (value.finalRecordStart().isPresent() ? PRESENT : ABSENT));
        output.put(new byte[7]);
        output.putLong(value.finalRecordStart().orElse(0L));
        output.putLong(value.coveredBoundary());
        output.put(HEX.parseHex(value.coveredCommitment().value()));
        output.putInt(value.loadNumerator());
        output.putInt(value.loadDenominator());
        output.put(new byte[16]);
        IoOperations.appendDigest(output, SUPERBLOCK_FIELDS_BYTES, SUPERBLOCK_DOMAIN);
        output.flip();
        IoOperations.writeFully(
                channel, output, Math.multiplyExact((long) index, SUPERBLOCK_BYTES));
    }

    private static ActiveCell activeCell(
            FileChannel channel, long slot, long coveredRevision) throws IOException {
        DecodedCell first = decodeCell(IoOperations.readAt(
                channel, IoOperations.cellOffset(slot, FIRST_GENERATION), CELL_BYTES));
        DecodedCell second = decodeCell(IoOperations.readAt(
                channel, IoOperations.cellOffset(slot, SECOND_GENERATION), CELL_BYTES));
        Optional<Cell> left = eligible(first, coveredRevision);
        Optional<Cell> right = eligible(second, coveredRevision);
        if (left.isEmpty() && right.isEmpty()) {
            return new ActiveCell(0, Cell.empty());
        }
        if (left.isEmpty()) {
            return new ActiveCell(1, right.orElseThrow());
        }
        if (right.isEmpty()) {
            return new ActiveCell(0, left.orElseThrow());
        }
        Cell leftCell = left.orElseThrow();
        Cell rightCell = right.orElseThrow();
        if (leftCell.generation() == rightCell.generation() && !leftCell.equals(rightCell)) {
            throw new IOException("Revocation current index slot generations are ambiguous");
        }
        return rightCell.generation() > leftCell.generation()
                ? new ActiveCell(1, rightCell) : new ActiveCell(0, leftCell);
    }

    private static Optional<Cell> eligible(DecodedCell decoded, long coveredRevision) {
        return decoded.valid() && decoded.cell().generation() <= coveredRevision
                ? Optional.of(decoded.cell()) : Optional.empty();
    }

    private static DecodedCell decodeCell(byte[] encoded) {
        if (IoOperations.allZero(encoded)) {
            return new DecodedCell(true, Cell.empty());
        }
        if (!IoOperations.verifyDigest(encoded, CELL_FIELDS_BYTES, CELL_DOMAIN)) {
            return new DecodedCell(false, Cell.empty());
        }
        try {
            ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
            if (input.getInt() != MAGIC_CELL || input.getShort() != FORMAT_VERSION) {
                return new DecodedCell(false, Cell.empty());
            }
            SlotState state = SlotState.decode(Byte.toUnsignedInt(input.get()));
            if (input.get() != 0) {
                return new DecodedCell(false, Cell.empty());
            }
            long generation = input.getLong();
            byte[] key = new byte[DIGEST_BYTES];
            input.get(key);
            long globalRevision = input.getLong();
            long credentialRevision = input.getLong();
            long frameStart = input.getLong();
            long frameEnd = input.getLong();
            byte[] commitment = new byte[DIGEST_BYTES];
            input.get(commitment);
            byte[] reserved = new byte[16];
            input.get(reserved);
            if (!IoOperations.allZero(reserved)) {
                return new DecodedCell(false, Cell.empty());
            }
            Cell cell = new Cell(state, generation, HEX.formatHex(key), globalRevision,
                    credentialRevision, frameStart, frameEnd,
                    new RevocationTransitionFrameCodec.Commitment(HEX.formatHex(commitment)));
            cell.requireValid();
            return new DecodedCell(true, cell);
        } catch (IllegalArgumentException malformed) {
            return new DecodedCell(false, Cell.empty());
        }
    }

    private static void writeCell(
            FileChannel channel, long slot, int cellIndex, Cell cell) throws IOException {
        ByteBuffer output = ByteBuffer.allocate(CELL_BYTES).order(ByteOrder.BIG_ENDIAN);
        output.putInt(MAGIC_CELL);
        output.putShort(FORMAT_VERSION);
        output.put((byte) cell.state().code());
        output.put((byte) 0);
        output.putLong(cell.generation());
        output.put(HEX.parseHex(cell.keyDigest()));
        output.putLong(cell.globalRevision());
        output.putLong(cell.credentialRevision());
        output.putLong(cell.frameStart());
        output.putLong(cell.frameEnd());
        output.put(HEX.parseHex(cell.frameCommitment().value()));
        output.put(new byte[16]);
        IoOperations.appendDigest(output, CELL_FIELDS_BYTES, CELL_DOMAIN);
        output.flip();
        IoOperations.writeFully(
                channel, output, IoOperations.cellOffset(slot, cellIndex));
    }

    }

    /** Checked I/O, hashing, path, and durability utilities. */
    private static final class IoOperations {

    private static String keyDigest(PkiId credentialId) throws IOException {
        return FilesystemRevocationLog.indexKeyDigest(credentialId);
    }

    private static long initialSlot(String keyDigest, long capacity) {
        long hash = ByteBuffer.wrap(HEX.parseHex(keyDigest)).order(ByteOrder.BIG_ENDIAN).getLong();
        return Long.remainderUnsigned(hash, capacity);
    }

    private static long wrapSlot(long first, long distance, long capacity) {
        long remaining = capacity - first;
        return distance < remaining ? first + distance : distance - remaining;
    }

    private static long preferredInsertionSlot(long tombstone, long emptySlot) {
        if (tombstone == NO_SLOT) {
            return emptySlot;
        }
        return tombstone;
    }

    private static long cellOffset(long slot, int cell) throws IOException {
        try {
            long slotBytes = Math.multiplyExact(
                    slot, Math.multiplyExact((long) CELL_BYTES, CELLS_PER_SLOT));
            long base = Math.multiplyExact((long) SUPERBLOCK_BYTES, 2L);
            return Math.addExact(Math.addExact(base, slotBytes),
                    Math.multiplyExact((long) cell, CELL_BYTES));
        } catch (ArithmeticException overflow) {
            throw new IOException("Revocation current index offset exceeds the supported range", overflow);
        }
    }

    private static long expectedSize(long capacity) throws IOException {
        try {
            return Math.addExact(Math.multiplyExact((long) SUPERBLOCK_BYTES, 2L),
                    Math.multiplyExact(capacity,
                            Math.multiplyExact((long) CELL_BYTES, CELLS_PER_SLOT)));
        } catch (ArithmeticException overflow) {
            throw new IOException("Revocation current index capacity exceeds the supported range", overflow);
        }
    }

    private static void copyExact(
            FileChannel source,
            FileChannel target,
            long length,
            int transferBufferBytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(transferBufferBytes);
        long offset = 0L;
        while (offset < length) {
            buffer.clear();
            buffer.limit((int) Math.min((long) buffer.capacity(), length - offset));
            int read = source.read(buffer, offset);
            if (read <= 0) {
                throw new IOException("Revocation current-index freeze made no read progress");
            }
            buffer.flip();
            long writeOffset = offset;
            while (buffer.hasRemaining()) {
                int written = target.write(buffer, writeOffset);
                if (written <= 0) {
                    throw new IOException("Revocation current-index freeze made no write progress");
                }
                writeOffset += written;
            }
            offset = writeOffset;
        }
        target.truncate(length);
    }

    private static void requireExpectedSize(FileChannel channel, long capacity) throws IOException {
        if (channel.size() != expectedSize(capacity)) {
            throw new IOException("Revocation current index physical size is invalid");
        }
    }

    private static void extend(FileChannel channel, long size) throws IOException {
        if (size < MINIMUM_FILE_SIZE) {
            throw new IOException("Revocation current index size is invalid");
        }
        ByteBuffer zero = ByteBuffer.allocate(SINGLE_BYTE);
        writeFully(channel, zero, size - SINGLE_BYTE);
    }

    private static byte[] readAt(FileChannel channel, long offset, int length) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(length);
        long position = offset;
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer, position);
            if (read <= 0) {
                throw new IOException("Revocation current index read made no progress");
            }
            position += read;
        }
        return buffer.array();
    }

    private static void writeFully(FileChannel channel, ByteBuffer source, long offset)
            throws IOException {
        long position = offset;
        while (source.hasRemaining()) {
            int written = channel.write(source, position);
            if (written <= 0) {
                throw new IOException("Revocation current index write made no progress");
            }
            position += written;
        }
    }

    private static void appendDigest(ByteBuffer output, int fieldsLength, byte[] domain) {
        MessageDigest digest = sha256();
        digest.update(domain);
        digest.update(output.array(), 0, fieldsLength);
        output.put(digest.digest());
    }

    private static boolean verifyDigest(byte[] encoded, int fieldsLength, byte[] domain) {
        MessageDigest digest = sha256();
        digest.update(domain);
        digest.update(encoded, 0, fieldsLength);
        return MessageDigest.isEqual(digest.digest(),
                Arrays.copyOfRange(encoded, fieldsLength, encoded.length));
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }

    private static boolean allZero(byte[] value) {
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }

    private static long addExact(long first, long second, String message) throws IOException {
        try {
            return Math.addExact(first, second);
        } catch (ArithmeticException overflow) {
            throw new IOException(message, overflow);
        }
    }

    private static void requireNextGlobal(
            RevocationTransitionFrameCodec.CompleteRecord record,
            long currentRevision,
            RevocationTransitionFrameCodec.Commitment currentCommitment) throws IOException {
        long expected = addExact(currentRevision, 1L,
                "Global revocation revision is exhausted");
        if (record.data().globalRevision() != expected
                || !record.data().previousGlobalCommitment().equals(currentCommitment)) {
            throw new IOException("Revocation current index global chain is invalid");
        }
    }

    private static void requireRegular(Path path, String description) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw new IOException(description + " is not a regular file");
        }
    }

    private static void requireDirectory(Path directory) throws IOException {
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(directory)) {
            throw new IOException("Revocation current-index directory is invalid");
        }
    }

    private static Path stableLockPath(Path indexPath) {
        return indexPath.resolveSibling(indexPath.getFileName() + ".lock");
    }

    private static FileLock acquireLock(FileChannel channel) throws IOException {
        try {
            FileLock lock = WriterExclusionLock.tryAcquire(channel);
            if (lock == null) {
                throw new IOException("Revocation current index is already open for writing");
            }
            return lock;
        } catch (OverlappingFileLockException overlapping) {
            throw new IOException("Revocation current index is already open for writing", overlapping);
        }
    }

    private static void requireLogStore(FileChannel log, MetadataStoreId expectedStoreId)
            throws IOException {
        MetadataStoreId actualStore = new RevocationTransitionFrameCodec().readPreamble(log);
        if (!expectedStoreId.equals(actualStore)) {
            throw new IOException("Revocation current index log authority is foreign");
        }
    }

    private static void forceDirectory(
            Path parent, PublicationOperations operations, FaultInjector faults) {
        try {
            faults.fail(FaultPoint.DIRECTORY_FORCE);
            operations.forceDirectory(parent);
        } catch (IOException unsupported) {
            FilesystemRevocationLog.warnIndexDirectoryDurability();
        }
    }

    private static IOException appendFailure(IOException primary, IOException secondary) {
        if (primary == null) {
            return secondary;
        }
        primary.addSuppressed(secondary);
        return primary;
    }

    }

    /** Exact construction capacity and rational load threshold. */
    /* default */ record Configuration(
            long initialCapacity, int loadNumerator, int loadDenominator) {
        Configuration {
            require(initialCapacity, loadNumerator, loadDenominator);
        }

        private void requireValid() throws IOException {
            try {
                require(initialCapacity, loadNumerator, loadDenominator);
                IoOperations.expectedSize(initialCapacity);
            } catch (IllegalArgumentException invalid) {
                throw new IOException("Invalid revocation current-index configuration", invalid);
            }
        }

        private static void require(long capacity, int numerator, int denominator) {
            if (capacity < 2L || (capacity & (capacity - 1L)) != 0L
                    || numerator <= 0 || denominator <= numerator) {
                throw new IllegalArgumentException(
                        "Index capacity must be a power of two with a proper load fraction");
            }
        }

        private long threshold(long capacity) throws IOException {
            long whole = Math.multiplyExact(capacity / loadDenominator, loadNumerator);
            long remainder = Math.multiplyExact(capacity % loadDenominator, loadNumerator)
                    / loadDenominator;
            long threshold = IoOperations.addExact(whole, remainder,
                    "Revocation index load threshold overflow");
            if (threshold <= 0L || threshold >= capacity) {
                throw new IOException("Revocation index load threshold is invalid");
            }
            return threshold;
        }
    }

    /** Immutable scalar prefix accepted by bounded derived-index recovery. */
    /* default */ interface RecoveryBoundary {
        /** Returns the authoritative store identity. */
        MetadataStoreId storeId();

        /** Returns the covered global revision. */
        long globalRevision();

        /** Returns the final covered frame start, when one exists. */
        OptionalLong finalRecordStart();

        /** Returns the exact covered log boundary. */
        long boundary();

        /** Returns the covered global commitment. */
        RevocationTransitionFrameCodec.Commitment globalCommitment();
    }

    /** Deterministic lifecycle fault seam; it is not a production extension point. */
    /* default */ @FunctionalInterface
    interface FaultInjector {
        FaultInjector NONE = point -> { };

        /** Fails one exact derived-index lifecycle boundary. */
        void fail(FaultPoint point) throws IOException;

        /** Observes one checkpoint entry admitted during bounded recovery. */
        default void observeRecoveryCheckpointEntry(long index) {
            // Optional structural test observation.
        }

        /** Observes one checkpoint generation selected for full validation. */
        default void observeRecoveryCheckpointCandidate(long revision) {
            // Optional structural test observation.
        }

        /** Observes one authoritative suffix offset read during bounded recovery. */
        default void observeRecoveryLogOffset(long offset) {
            // Optional structural test observation.
        }
    }

    /** Exact durability and publication boundaries available to deterministic tests. */
    /* default */ enum FaultPoint {
        CELL_WRITE,
        CELL_FORCE,
        SUPERBLOCK_WRITE,
        SUPERBLOCK_FORCE,
        REBUILD_WRITE,
        REBUILD_FORCE,
        GROW_FORCE,
        GROW_ATOMIC_MOVE,
        PUBLISH_ATOMIC_MOVE,
        DIRECTORY_FORCE
    }

    /** publication operations isolated for deterministic atomic-publication tests. */
    /* default */ interface PublicationOperations {
        /** Atomically replaces the target with a completed derived generation. */
        void atomicReplace(Path source, Path target) throws IOException;

        /** Forces the containing directory when supported. */
        void forceDirectory(Path directory) throws IOException;
    }

    /** Default local atomic publication operations. */
    private enum DefaultPublicationOperations implements PublicationOperations {
        INSTANCE;

        @Override
        public void atomicReplace(Path source, Path target) throws IOException {
            Files.move(source, target,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }

        @Override
        public void forceDirectory(Path directory) throws IOException {
            PlatformFs.forceDirectory(directory);
        }
    }

    /** Terminal lifecycle state of one retained index handle. */
    private enum State {
        OPEN,
        UNUSABLE,
        CLOSED
    }

    /** Explicit persisted logical-slot state; tombstones preserve probe continuity. */
    private enum SlotState {
        EMPTY(0),
        OCCUPIED(1),
        TOMBSTONE(2);

        private final int code;

        SlotState(int code) {
            this.code = code;
        }

        private int code() {
            return code;
        }

        private static SlotState decode(int code) {
            return switch (code) {
                case 0 -> EMPTY;
                case 1 -> OCCUPIED;
                case 2 -> TOMBSTONE;
                default -> throw new IllegalArgumentException("Unknown revocation index slot state");
            };
        }
    }

    private record Superblock(
            MetadataStoreId storeId,
            long capacity,
            long entryCount,
            long coveredRevision,
            OptionalLong finalRecordStart,
            long coveredBoundary,
            RevocationTransitionFrameCodec.Commitment coveredCommitment,
            int loadNumerator,
            int loadDenominator) {
        private Superblock {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(finalRecordStart, "finalRecordStart");
            Objects.requireNonNull(coveredCommitment, "coveredCommitment");
        }

        private static Superblock genesis(
                MetadataStoreId storeId, long capacity, Configuration configuration)
                throws IOException {
            return new Superblock(storeId, capacity, 0L, GENESIS_REVISION,
                    OptionalLong.empty(), RevocationTransitionFrameCodec.PREAMBLE_BYTES,
                    RevocationTransitionFrameCodec.initialCommitment(storeId),
                    configuration.loadNumerator(), configuration.loadDenominator());
        }

        private static Superblock checkpoint(
                FilesystemRevocationCheckpoint checkpoint,
                long capacity,
                Configuration configuration) {
            return new Superblock(
                    checkpoint.storeId(), capacity, 0L,
                    checkpoint.coveredRevision(),
                    OptionalLong.empty(),
                    checkpoint.coveredBoundary(), checkpoint.coveredCommitment(),
                    configuration.loadNumerator(), configuration.loadDenominator());
        }

        private Superblock withEntryCount(long count) {
            return new Superblock(
                    storeId, capacity, count, coveredRevision, finalRecordStart,
                    coveredBoundary, coveredCommitment,
                    loadNumerator, loadDenominator);
        }

        private Superblock withFinalRecordStart(OptionalLong start) {
            return new Superblock(
                    storeId, capacity, entryCount, coveredRevision, start,
                    coveredBoundary, coveredCommitment,
                    loadNumerator, loadDenominator);
        }

        private Superblock advance(
                RevocationTransitionFrameCodec.CompleteRecord record, long newCount) {
            return new Superblock(storeId, capacity, newCount,
                    record.data().globalRevision(), OptionalLong.of(record.recordOffset()),
                    record.recordEnd(), record.commitment(), loadNumerator, loadDenominator);
        }

        private long loadThreshold() throws IOException {
            return new Configuration(capacity, loadNumerator, loadDenominator).threshold(capacity);
        }

        private void requireValid() throws IOException {
            new Configuration(capacity, loadNumerator, loadDenominator).requireValid();
            if (entryCount < 0L || entryCount > loadThreshold() || coveredRevision < 0L
                    || coveredBoundary < RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || coveredRevision == 0L != finalRecordStart.isEmpty()) {
                throw new IOException("Revocation current index superblock fields are invalid");
            }
        }
    }

    private record Cell(
            SlotState state,
            long generation,
            String keyDigest,
            long globalRevision,
            long credentialRevision,
            long frameStart,
            long frameEnd,
            RevocationTransitionFrameCodec.Commitment frameCommitment) {
        private Cell {
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(keyDigest, "keyDigest");
            Objects.requireNonNull(frameCommitment, "frameCommitment");
        }

        private static Cell empty() {
            return new Cell(SlotState.EMPTY, 0L, "0".repeat(KEY_DIGEST_HEX_CHARACTERS),
                    0L, 0L, 0L, 0L,
                    new RevocationTransitionFrameCodec.Commitment(
                            "0".repeat(KEY_DIGEST_HEX_CHARACTERS)));
        }

        private static Cell occupied(
                RevocationTransitionFrameCodec.CompleteRecord record, String keyDigest) {
            return new Cell(SlotState.OCCUPIED, record.data().globalRevision(), keyDigest,
                    record.data().globalRevision(), record.data().transition().revision(),
                    record.recordOffset(), record.recordEnd(), record.commitment());
        }

        private void requireValid() {
            if (state == SlotState.EMPTY) {
                if (generation != 0L || globalRevision != 0L || credentialRevision != 0L
                        || frameStart != 0L || frameEnd != 0L) {
                    throw new IllegalArgumentException("Invalid empty revocation index cell");
                }
                return;
            }
            if (generation <= 0L || keyDigest.length() != KEY_DIGEST_HEX_CHARACTERS
                    || globalRevision <= 0L || generation != globalRevision
                    || credentialRevision <= 0L
                    || frameStart < RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || frameEnd <= frameStart) {
                throw new IllegalArgumentException("Invalid occupied revocation index cell");
            }
            HEX.parseHex(keyDigest);
        }
    }

    private record DecodedCell(boolean valid, Cell cell) {
    }

    private record ActiveCell(int cellIndex, Cell cell) {
    }

    private record SlotMatch(long slot, int cellIndex, Cell cell) {
    }

    private record ProbeResult(Optional<SlotMatch> match, long insertionSlot) {
        private ProbeResult {
            Objects.requireNonNull(match, "match");
        }

        private static ProbeResult absent(long insertionSlot) {
            return new ProbeResult(Optional.empty(), insertionSlot);
        }

        private static ProbeResult present(long slot, int cellIndex, Cell cell) {
            return new ProbeResult(Optional.of(new SlotMatch(slot, cellIndex, cell)), slot);
        }
    }

    private record SelectedSuperblock(int index, Superblock value) {
    }

    private record SuperblockCandidates(
            SelectedSuperblock newest, Optional<SelectedSuperblock> older) {
        private SuperblockCandidates {
            Objects.requireNonNull(newest, "newest");
            Objects.requireNonNull(older, "older");
        }
    }

    /** Independently checks one candidate without acquiring or transferring resource ownership. */
    private static final class IndexValidation {
        private static void validate(
                FileChannel index,
                FileChannel log,
                MetadataStoreId storeId,
                Superblock superblock) throws IOException {
            IoOperations.requireExpectedSize(index, superblock.capacity());
            validateBinding(log, storeId, superblock);
            long occupied = GENESIS_REVISION;
            for (long slot = GENESIS_REVISION; slot < superblock.capacity(); slot++) {
                Cell cell = IndexOperations.activeCell(
                        index, slot, superblock.coveredRevision()).cell();
                if (cell.state() == SlotState.OCCUPIED) {
                    occupied = IoOperations.addExact(occupied, 1L, ENTRY_COUNT_OVERFLOW);
                    RevocationTransitionFrameCodec.CompleteRecord frame = readFrame(log, cell);
                    if (probeSlot(index, log, superblock,
                            frame.data().credentialId()) != slot) {
                        throw new IOException(
                                "Revocation current index contains a duplicate or misplaced key");
                    }
                }
            }
            if (occupied != superblock.entryCount()) {
                throw new IOException("Revocation current index entry count is inconsistent");
            }
        }

        private static void validateBinding(
                FileChannel log, MetadataStoreId storeId, Superblock superblock)
                throws IOException {
            IoOperations.requireLogStore(log, storeId);
            if (superblock.coveredBoundary() > log.size()) {
                throw new IOException("Revocation current index exceeds the authoritative log");
            }
            if (superblock.coveredRevision() == GENESIS_REVISION) {
                validateGenesis(storeId, superblock);
            } else {
                validateFinalFrame(log, superblock);
            }
        }

        private static void validateGenesis(
                MetadataStoreId storeId, Superblock superblock) throws IOException {
            if (superblock.finalRecordStart().isPresent()
                    || superblock.coveredBoundary() != RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || !superblock.coveredCommitment().equals(
                            RevocationTransitionFrameCodec.initialCommitment(storeId))) {
                throw new IOException("Revocation current index genesis binding is invalid");
            }
        }

        private static void validateFinalFrame(FileChannel log, Superblock superblock)
                throws IOException {
            long start = superblock.finalRecordStart().orElseThrow(
                    () -> new IOException("Revocation current index final-frame binding is absent"));
            RevocationTransitionFrameCodec.ReadResult result =
                    new RevocationTransitionFrameCodec().read(log, start);
            if (result.classification()
                    != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                throw new IOException("Revocation current index final-frame binding is invalid");
            }
            RevocationTransitionFrameCodec.CompleteRecord frame = result.record().orElseThrow();
            if (frame.data().globalRevision() != superblock.coveredRevision()
                    || frame.recordEnd() != superblock.coveredBoundary()
                    || !frame.commitment().equals(superblock.coveredCommitment())) {
                throw new IOException(
                        "Revocation current index final-frame binding disagrees with the log");
            }
        }

        private static long probeSlot(
                FileChannel index,
                FileChannel log,
                Superblock superblock,
                PkiId identity) throws IOException {
            String digest = IoOperations.keyDigest(identity);
            long first = IoOperations.initialSlot(digest, superblock.capacity());
            for (long distance = GENESIS_REVISION;
                    distance < superblock.capacity(); distance++) {
                long slot = IoOperations.wrapSlot(first, distance, superblock.capacity());
                Cell cell = IndexOperations.activeCell(
                        index, slot, superblock.coveredRevision()).cell();
                if (cell.state() == SlotState.EMPTY) {
                    return NO_SLOT;
                }
                if (cell.state() == SlotState.OCCUPIED
                        && cell.keyDigest().equals(digest)
                        && readFrame(log, cell).data().credentialId().equals(identity)) {
                    return slot;
                }
            }
            return NO_SLOT;
        }

        private static RevocationTransitionFrameCodec.CompleteRecord readFrame(
                FileChannel log, Cell cell) throws IOException {
            RevocationTransitionFrameCodec.ReadResult result =
                    new RevocationTransitionFrameCodec().read(log, cell.frameStart());
            if (result.classification()
                    != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                throw new IOException("Revocation current index frame locator is invalid");
            }
            RevocationTransitionFrameCodec.CompleteRecord frame = result.record().orElseThrow();
            if (frame.recordEnd() != cell.frameEnd()
                    || frame.data().globalRevision() != cell.globalRevision()
                    || frame.data().transition().revision() != cell.credentialRevision()
                    || !frame.commitment().equals(cell.frameCommitment())
                    || !IoOperations.keyDigest(
                            frame.data().credentialId()).equals(cell.keyDigest())) {
                throw new IOException(
                        "Revocation current index cell disagrees with its authoritative frame");
            }
            return frame;
        }
    }

    /** Chooses the newest completely valid generation and falls back only to its predecessor. */
    private static final class CandidateSelection {
        private static SelectedSuperblock select(
                OpenResources resources,
                MetadataStoreId storeId,
                SuperblockCandidates candidates) throws IOException {
            IOException newestFailure = validate(
                    resources, storeId, candidates.newest());
            if (newestFailure == null) {
                return candidates.newest();
            }
            if (candidates.older().isEmpty()) {
                throw newestFailure;
            }
            SelectedSuperblock older = candidates.older().orElseThrow();
            IOException olderFailure = validate(resources, storeId, older);
            if (olderFailure == null) {
                return older;
            }
            newestFailure.addSuppressed(olderFailure);
            throw newestFailure;
        }

        private static IOException validate(
                OpenResources resources,
                MetadataStoreId storeId,
                SelectedSuperblock selected) {
            try {
                IndexValidation.validate(
                        resources.indexChannel(), resources.logChannel(), storeId, selected.value());
                return null;
            } catch (IOException invalid) {
                return invalid;
            }
        }
    }

    /** Deterministic frozen-copy failure seam; package access is intentional for tests. */
    /* default */ @FunctionalInterface
    interface FrozenFaultInjector {
        FrozenFaultInjector NONE = point -> { };

        /** Fails at one copy or force boundary. */
        void fail(FrozenFaultPoint point) throws IOException;
    }

    /** Finite lifecycle boundaries for the frozen derived-index copy. */
    /* default */ enum FrozenFaultPoint {
        COPY,
        FORCE
    }

    /** Immutable physical-slot copy used by bounded checkpoint construction. */
    /* default */ static final class FrozenSnapshot implements AutoCloseable {
        private final Path path;
        private final Path logPath;
        private final FileChannel indexChannel;
        private final FileChannel logChannel;
        private final Superblock state;
        private boolean closed;

        private FrozenSnapshot(
                Path path,
                Path logPath,
                FileChannel indexChannel,
                FileChannel logChannel,
                Superblock state) {
            this.path = path;
            this.logPath = logPath;
            this.indexChannel = indexChannel;
            this.logChannel = logChannel;
            this.state = state;
        }

        /* default */ long entryCount() {
            requireOpen();
            return state.entryCount();
        }

        /* default */ FilesystemRevocationCheckpoint.Coverage coverage() {
            requireOpen();
            return new FilesystemRevocationCheckpoint.Coverage(
                    state.storeId(), state.coveredRevision(), state.finalRecordStart(),
                    state.coveredBoundary(), state.coveredCommitment());
        }

        /* default */ FrozenCursor openCursor() {
            requireOpen();
            return new PhysicalCursor(this);
        }

        /* default */ Path logPath() {
            requireOpen();
            return logPath;
        }

        /* default */ Optional<RevocationTransitionFrameCodec.CompleteRecord> lookup(
                PkiId credentialId) throws IOException {
            Objects.requireNonNull(credentialId, "credentialId");
            requireOpen();
            long slot = IndexValidation.probeSlot(
                    indexChannel, logChannel, state, credentialId);
            if (slot == NO_SLOT) {
                return Optional.empty();
            }
            Cell cell = IndexOperations.activeCell(
                    indexChannel, slot, state.coveredRevision()).cell();
            return Optional.of(IndexValidation.readFrame(logChannel, cell));
        }

        private void requireOpen() {
            if (closed || !indexChannel.isOpen() || !logChannel.isOpen()) {
                throw new IllegalStateException("Frozen revocation current index is closed");
            }
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            IOException failure = null;
            try {
                logChannel.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                indexChannel.close();
            } catch (IOException closeFailure) {
                failure = IoOperations.appendFailure(failure, closeFailure);
            }
            try {
                Files.deleteIfExists(path);
            } catch (IOException closeFailure) {
                failure = IoOperations.appendFailure(failure, closeFailure);
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /** One-entry-at-a-time physical-slot cursor over a frozen index. */
    /* default */ interface FrozenCursor extends AutoCloseable {
        /** Advances to the next occupied physical slot. */
        boolean advance() throws IOException;

        /** Returns the entry selected by the most recent successful advancement. */
        RevocationCheckpointCodec.CurrentStateEntry current();

        @Override
        void close();
    }

    /** Cursor state remains constant regardless of frozen index population. */
    private static final class PhysicalCursor implements FrozenCursor {
        private final FrozenSnapshot owner;
        private long slot;
        private long emitted;
        private RevocationCheckpointCodec.CurrentStateEntry current;
        private boolean closed;

        private PhysicalCursor(FrozenSnapshot owner) {
            this.owner = owner;
        }

        @Override
        public boolean advance() throws IOException {
            requireOpen();
            while (slot < owner.state.capacity()) {
                Cell cell = IndexOperations.activeCell(
                        owner.indexChannel, slot, owner.state.coveredRevision()).cell();
                slot++;
                if (cell.state() == SlotState.OCCUPIED) {
                    RevocationTransitionFrameCodec.CompleteRecord record =
                            IndexValidation.readFrame(owner.logChannel, cell);
                    emitted = IoOperations.addExact(
                            emitted, 1L, ENTRY_COUNT_OVERFLOW);
                    if (emitted > owner.state.entryCount()) {
                        throw new IOException("Frozen revocation index contains excess entries");
                    }
                    current = checkpointEntry(record);
                    return true;
                }
            }
            if (emitted != owner.state.entryCount()) {
                throw new IOException("Frozen revocation index entry count is inconsistent");
            }
            current = null;
            return false;
        }

        @Override
        public RevocationCheckpointCodec.CurrentStateEntry current() {
            requireOpen();
            if (current == null) {
                throw new IllegalStateException("Frozen revocation cursor has no current entry");
            }
            return current;
        }

        @Override
        public void close() {
            closed = true;
            current = null;
        }

        private void requireOpen() {
            if (closed) {
                throw new IllegalStateException("Frozen revocation cursor is closed");
            }
            owner.requireOpen();
        }

        private static RevocationCheckpointCodec.CurrentStateEntry checkpointEntry(
                RevocationTransitionFrameCodec.CompleteRecord record) {
            return new RevocationCheckpointCodec.CurrentStateEntry(
                    record.data().credentialId(), record.data().globalRevision(),
                    record.data().transition().revision(), record.commitment(),
                    record.data().transition(), record.recordOffset(), record.recordEnd());
        }
    }

    /** Owns a frozen copy and independent log reader until snapshot transfer. */
    private static final class FrozenResources implements AutoCloseable {
        private final Path path;
        private final FileChannel indexChannel;
        private final FileChannel logChannel;
        private boolean transferred;

        private FrozenResources(
                Path path, FileChannel indexChannel, FileChannel logChannel) {
            this.path = path;
            this.indexChannel = indexChannel;
            this.logChannel = logChannel;
        }

        private static FrozenResources create(Path path, Path logPath) throws IOException {
            FileChannel index = FileChannel.open(path,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            try {
                FileChannel log = FileChannel.open(
                        logPath, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
                return new FrozenResources(path, index, log);
            } catch (IOException failure) {
                try {
                    index.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                try {
                    Files.deleteIfExists(path);
                } catch (IOException cleanupFailure) {
                    failure.addSuppressed(cleanupFailure);
                }
                throw failure;
            }
        }

        private FileChannel indexChannel() {
            return indexChannel;
        }

        private FileChannel logChannel() {
            return logChannel;
        }

        private void transferOwnership() {
            transferred = true;
        }

        @Override
        public void close() throws IOException {
            if (transferred) {
                return;
            }
            IOException failure = null;
            try {
                logChannel.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                indexChannel.close();
            } catch (IOException closeFailure) {
                failure = IoOperations.appendFailure(failure, closeFailure);
            }
            try {
                Files.deleteIfExists(path);
            } catch (IOException cleanupFailure) {
                failure = IoOperations.appendFailure(failure, cleanupFailure);
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /** Stable adjacent lock whose inode is never replaced with an index generation. */
    private static final class StableIndexLock implements AutoCloseable {
        private final FileChannel channel;
        private final FileLock lock;
        private boolean transferred;
        private boolean closed;

        private StableIndexLock(FileChannel channel, FileLock lock) {
            this.channel = channel;
            this.lock = lock;
        }

        private static StableIndexLock acquire(Path indexPath) throws IOException {
            Path lockPath = IoOperations.stableLockPath(indexPath);
            FileChannel channel = FileChannel.open(lockPath,
                    StandardOpenOption.CREATE, StandardOpenOption.READ,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            try {
                IoOperations.requireRegular(lockPath, "Revocation current-index lock");
                return new StableIndexLock(channel, IoOperations.acquireLock(channel));
            } catch (IOException failure) {
                try {
                    channel.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }
        }

        private void transferOwnership() {
            transferred = true;
        }

        @Override
        public void close() throws IOException {
            if (transferred) {
                return;
            }
            closeOwned();
        }

        private void closeOwned() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            IOException failure = null;
            try {
                if (lock.isValid()) {
                    lock.release();
                }
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                channel.close();
            } catch (IOException closeFailure) {
                failure = IoOperations.appendFailure(failure, closeFailure);
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /** Owns a replacement channel until validated installation transfers it. */
    private static final class ReplacementChannel implements AutoCloseable {
        private final FileChannel channel;
        private boolean transferred;

        private ReplacementChannel(FileChannel channel) {
            this.channel = channel;
        }

        private static ReplacementChannel open(Path indexPath) throws IOException {
            return new ReplacementChannel(FileChannel.open(indexPath,
                    StandardOpenOption.READ, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS));
        }

        private FileChannel channel() {
            return channel;
        }

        private FileChannel transferOwnership() {
            transferred = true;
            return channel;
        }

        @Override
        public void close() throws IOException {
            if (!transferred) {
                channel.close();
            }
        }
    }

    /** Transfers the stable lock and opened files only after validation succeeds. */
    private static final class OpenResources implements AutoCloseable {
        private final StableIndexLock stableLock;
        private final FileChannel indexChannel;
        private final FileChannel logChannel;
        private boolean transferred;

        private OpenResources(
                StableIndexLock stableLock, FileChannel indexChannel, FileChannel logChannel) {
            this.stableLock = stableLock;
            this.indexChannel = indexChannel;
            this.logChannel = logChannel;
        }

        private static OpenResources acquire(Path indexPath, Path logPath) throws IOException {
            StableIndexLock stable = StableIndexLock.acquire(indexPath);
            try {
                return acquireLocked(stable, indexPath, logPath);
            } catch (IOException failure) {
                try {
                    stable.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }
        }

        private static OpenResources acquireLocked(
                StableIndexLock stable, Path indexPath, Path logPath)
                throws IOException {
            FileChannel index = FileChannel.open(indexPath,
                    StandardOpenOption.READ, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS);
            try {
                FileChannel log = FileChannel.open(logPath, StandardOpenOption.READ);
                return new OpenResources(stable, index, log);
            } catch (IOException failure) {
                try {
                    index.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }
        }

        private FileChannel indexChannel() {
            return indexChannel;
        }

        private StableIndexLock stableLock() {
            return stableLock;
        }

        private FileChannel logChannel() {
            return logChannel;
        }

        private void transferOwnership() {
            transferred = true;
            stableLock.transferOwnership();
        }

        @Override
        public void close() throws IOException {
            if (transferred) {
                return;
            }
            IOException failure = null;
            try {
                logChannel.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                indexChannel.close();
            } catch (IOException closeFailure) {
                failure = IoOperations.appendFailure(failure, closeFailure);
            }
            try {
                stableLock.closeOwned();
            } catch (IOException closeFailure) {
                failure = IoOperations.appendFailure(failure, closeFailure);
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /** Bounded-memory temporary generation builder backed solely by its slot file. */
    private static final class BuildIndex implements AutoCloseable {
        private final Path path;
        private final MetadataStoreId storeId;
        private final Configuration configuration;
        private final PublicationOperations operations;
        private final FaultInjector faults;
        private final FileChannel log;
        private FileChannel channel;
        private Superblock state;
        private OptionalLong seededFinalStart = OptionalLong.empty();

        private BuildIndex(
                Path path,
                MetadataStoreId storeId,
                Configuration configuration,
                PublicationOperations operations,
                FaultInjector faults,
                FileChannel log,
                FileChannel channel,
                Superblock state) {
            this.path = path;
            this.storeId = storeId;
            this.configuration = configuration;
            this.operations = operations;
            this.faults = faults;
            this.log = log;
            this.channel = channel;
            this.state = state;
        }

        private static BuildIndex create(
                Path path,
                MetadataStoreId storeId,
                Configuration configuration,
                PublicationOperations operations,
                FaultInjector faults,
                FileChannel log) throws IOException {
            FileChannel channel = FileChannel.open(path,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE);
            try {
                IoOperations.extend(
                        channel, IoOperations.expectedSize(configuration.initialCapacity()));
                Superblock genesis = Superblock.genesis(
                        storeId, configuration.initialCapacity(), configuration);
                return new BuildIndex(path, storeId, configuration,
                        operations, faults, log, channel, genesis);
            } catch (IOException failure) {
                try {
                    channel.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }
        }

        private static BuildIndex createSeeded(
                Path path,
                MetadataStoreId storeId,
                Configuration configuration,
                PublicationOperations operations,
                FaultInjector faults,
                FileChannel log,
                FilesystemRevocationCheckpoint checkpoint) throws IOException {
            long capacity = capacityFor(
                    checkpoint.entryCount(), configuration);
            FileChannel channel = FileChannel.open(path,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE);
            try {
                IoOperations.extend(channel, IoOperations.expectedSize(capacity));
                Superblock state = Superblock.checkpoint(
                        checkpoint, capacity, configuration);
                return new BuildIndex(path, storeId, configuration,
                        operations, faults, log, channel, state);
            } catch (IOException failure) {
                try {
                    channel.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }
        }

        private static long capacityFor(
                long entryCount, Configuration configuration) throws IOException {
            long capacity = configuration.initialCapacity();
            while (configuration.threshold(capacity) < entryCount) {
                try {
                    capacity = Math.multiplyExact(capacity, 2L);
                } catch (ArithmeticException overflow) {
                    throw new IOException(
                            "Revocation current index capacity is exhausted", overflow);
                }
            }
            return capacity;
        }

        private static BuildIndex resume(
                Path source,
                Path temporary,
                MetadataStoreId storeId,
                Configuration configuration,
                PublicationOperations operations,
                FaultInjector faults,
                FileChannel log,
                Superblock state) throws IOException {
            Files.copy(source, temporary);
            try {
                FileChannel channel = FileChannel.open(temporary,
                        StandardOpenOption.READ, StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS);
                return new BuildIndex(temporary, storeId, configuration,
                        operations, faults, log, channel, state);
            } catch (IOException failure) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException cleanupFailure) {
                    failure.addSuppressed(cleanupFailure);
                }
                throw failure;
            }
        }

        private Superblock state() {
            return state;
        }

        private void seed(
                FilesystemRevocationCheckpoint checkpoint,
                FaultInjector recoveryFaults) throws IOException {
            long count = 0L;
            try (FilesystemRevocationCheckpoint.Cursor cursor =
                    checkpoint.allCurrentStates()) {
                while (cursor.advance()) {
                    recoveryFaults.observeRecoveryCheckpointEntry(count);
                    seedCurrent(cursor);
                    count = IoOperations.addExact(count, 1L, ENTRY_COUNT_OVERFLOW);
                }
            }
            if (count != checkpoint.entryCount() || state.entryCount() != count) {
                throw new CheckpointRejectedException(
                        "Revocation checkpoint entry count is inconsistent");
            }
            if (state.coveredRevision() > GENESIS_REVISION) {
                if (seededFinalStart.isEmpty()) {
                    throw new CheckpointRejectedException(
                            "Checkpoint omits its covered final record");
                }
                state = state.withFinalRecordStart(seededFinalStart);
            }
        }

        private void seedCurrent(FilesystemRevocationCheckpoint.Cursor cursor)
                throws IOException {
            if (cursor.current().globalRevision() > state.coveredRevision()) {
                throw new CheckpointRejectedException(
                        "Checkpoint entry exceeds its declared coverage");
            }
            RevocationTransitionFrameCodec.ReadResult result =
                    new RevocationTransitionFrameCodec().read(
                            log, cursor.current().frameStart());
            if (result.classification()
                    != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                throw new IOException(
                        "Checkpoint locator reaches corrupt authoritative log content");
            }
            RevocationTransitionFrameCodec.CompleteRecord record =
                    result.record().orElseThrow();
            if (!entryMatches(cursor, record)) {
                throw new CheckpointRejectedException(
                        "Checkpoint entry disagrees with its authoritative frame");
            }
            if (record.data().globalRevision() == state.coveredRevision()) {
                if (seededFinalStart.isPresent()) {
                    throw new CheckpointRejectedException(
                            "Checkpoint duplicates its covered final record");
                }
                seededFinalStart = OptionalLong.of(record.recordOffset());
            }
            String digest = IoOperations.keyDigest(cursor.current().credentialId());
            BuildProbe probe = probe(cursor.current().credentialId(), digest);
            if (probe.match().isPresent()) {
                throw new CheckpointRejectedException(
                        "Checkpoint contains a duplicate current-state identity");
            }
            long nextCount = IoOperations.addExact(
                    state.entryCount(), 1L, ENTRY_COUNT_OVERFLOW);
            if (nextCount > state.loadThreshold()) {
                grow();
                probe = probe(cursor.current().credentialId(), digest);
            }
            faults.fail(FaultPoint.REBUILD_WRITE);
            IndexOperations.writeCell(
                    channel, probe.insertionSlot(), FIRST_GENERATION,
                    Cell.occupied(record, digest));
            state = state.withEntryCount(nextCount);
        }

        private static boolean entryMatches(
                FilesystemRevocationCheckpoint.Cursor cursor,
                RevocationTransitionFrameCodec.CompleteRecord record) {
            return record.recordOffset() == cursor.current().frameStart()
                    && record.recordEnd() == cursor.current().frameEnd()
                    && record.data().credentialId().equals(
                            cursor.current().credentialId())
                    && record.data().globalRevision()
                            == cursor.current().globalRevision()
                    && record.data().transition().revision()
                            == cursor.current().credentialRevision()
                    && record.commitment().equals(
                            cursor.current().transitionCommitment())
                    && RevocationTransitionFrameCodec.transitionsEqual(
                            record.data().transition(), cursor.current().transition());
        }


        private void accept(RevocationTransitionFrameCodec.CompleteRecord record)
                throws IOException {
            IoOperations.requireNextGlobal(
                    record, state.coveredRevision(), state.coveredCommitment());
            String digest = IoOperations.keyDigest(record.data().credentialId());
            BuildProbe probe = probe(record.data().credentialId(), digest);
            RevocationTransitionFrameCodec.CompleteRecord previous = probe.match().isPresent()
                    ? readFrame(probe.match().orElseThrow().cell(), record.data().credentialId()) : null;
            FilesystemRevocationLog.validateTransition(record.data(), previous);
            boolean insertion = probe.match().isEmpty();
            if (insertion && IoOperations.addExact(state.entryCount(), 1L,
                    ENTRY_COUNT_OVERFLOW) > state.loadThreshold()) {
                grow();
                probe = probe(record.data().credentialId(), digest);
            }
            long slot = probe.match().isPresent()
                    ? probe.match().orElseThrow().slot() : probe.insertionSlot();
            faults.fail(FaultPoint.REBUILD_WRITE);
            IndexOperations.writeCell(
                    channel, slot, FIRST_GENERATION, Cell.occupied(record, digest));
            long count = insertion ? IoOperations.addExact(state.entryCount(), 1L,
                    ENTRY_COUNT_OVERFLOW) : state.entryCount();
            state = state.advance(record, count);
        }

        private BuildProbe probe(PkiId identity, String digest) throws IOException {
            long first = IoOperations.initialSlot(digest, state.capacity());
            long tombstone = NO_SLOT;
            for (long distance = 0L; distance < state.capacity(); distance++) {
                long slot = IoOperations.wrapSlot(first, distance, state.capacity());
                ActiveCell activeCell = IndexOperations.activeCell(
                        channel, slot, state.coveredRevision());
                Cell cell = activeCell.cell();
                if (cell.state() == SlotState.EMPTY) {
                    return BuildProbe.absent(
                            IoOperations.preferredInsertionSlot(tombstone, slot));
                }
                if (cell.state() == SlotState.TOMBSTONE) {
                    if (tombstone == NO_SLOT) {
                        tombstone = slot;
                    }
                } else if (cell.keyDigest().equals(digest)
                        && readFrame(cell, null).data().credentialId().equals(identity)) {
                    return BuildProbe.present(slot, cell);
                }
            }
            if (tombstone != NO_SLOT) {
                return BuildProbe.absent(tombstone);
            }
            throw new IOException("Revocation current-index build probe exhausted capacity");
        }

        private RevocationTransitionFrameCodec.CompleteRecord readFrame(Cell cell, PkiId identity)
                throws IOException {
            RevocationTransitionFrameCodec.ReadResult result =
                    new RevocationTransitionFrameCodec().read(log, cell.frameStart());
            if (result.classification()
                    != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                throw new IOException("Revocation current-index build locator is invalid");
            }
            RevocationTransitionFrameCodec.CompleteRecord frame = result.record().orElseThrow();
            if (frame.recordEnd() != cell.frameEnd()
                    || frame.data().globalRevision() != cell.globalRevision()
                    || frame.data().transition().revision() != cell.credentialRevision()
                    || !frame.commitment().equals(cell.frameCommitment())
                    || !IoOperations.keyDigest(
                            frame.data().credentialId()).equals(cell.keyDigest())
                    || identity != null && !identity.equals(frame.data().credentialId())) {
                throw new IOException("Revocation current-index build cell disagrees with the log");
            }
            return frame;
        }

        private void grow() throws IOException {
            long nextCapacity;
            try {
                nextCapacity = Math.multiplyExact(state.capacity(), 2L);
            } catch (ArithmeticException overflow) {
                throw new IOException("Revocation current index capacity is exhausted", overflow);
            }
            configuration.threshold(nextCapacity);
            Path growing = path.resolveSibling(path.getFileName() + ".growing-" + UUID.randomUUID());
            boolean moved = false;
            try (FileChannel target = FileChannel.open(growing,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE)) {
                IoOperations.extend(target, IoOperations.expectedSize(nextCapacity));
                for (long slot = 0L; slot < state.capacity(); slot++) {
                    Cell cell = IndexOperations.activeCell(
                            channel, slot, state.coveredRevision()).cell();
                    if (cell.state() == SlotState.OCCUPIED) {
                        insertRehashed(target, nextCapacity, cell);
                    }
                }
                Superblock grown = new Superblock(storeId, nextCapacity, state.entryCount(),
                        state.coveredRevision(), state.finalRecordStart(), state.coveredBoundary(),
                        state.coveredCommitment(), configuration.loadNumerator(),
                        configuration.loadDenominator());
                IndexOperations.writeSuperblock(target, FIRST_GENERATION, grown);
                IndexOperations.writeSuperblock(target, SECOND_GENERATION, grown);
            }
            try {
                channel.close();
                faults.fail(FaultPoint.GROW_ATOMIC_MOVE);
                operations.atomicReplace(growing, path);
                moved = true;
                channel = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE);
                state = new Superblock(storeId, nextCapacity, state.entryCount(),
                        state.coveredRevision(), state.finalRecordStart(), state.coveredBoundary(),
                        state.coveredCommitment(), configuration.loadNumerator(),
                        configuration.loadDenominator());
            } finally {
                if (!moved) {
                    try {
                        Files.deleteIfExists(growing);
                    } catch (IOException ignored) {
                        // The growth failure remains primary.
                    }
                }
            }
        }

        private static void insertRehashed(FileChannel target, long capacity, Cell cell)
                throws IOException {
            long first = IoOperations.initialSlot(cell.keyDigest(), capacity);
            for (long distance = 0L; distance < capacity; distance++) {
                long slot = IoOperations.wrapSlot(first, distance, capacity);
                if (IndexOperations.activeCell(
                        target, slot, cell.generation()).cell().state() == SlotState.EMPTY) {
                    IndexOperations.writeCell(target, slot, FIRST_GENERATION, cell);
                    return;
                }
            }
            throw new IOException("Revocation current-index growth has no free slot");
        }

        private void finish() throws IOException {
            IndexOperations.writeSuperblock(channel, FIRST_GENERATION, state);
            IndexOperations.writeSuperblock(channel, SECOND_GENERATION, state);
            faults.fail(FaultPoint.REBUILD_FORCE);
            channel.force(true);
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }

    private record BuildMatch(long slot, Cell cell) {
    }

    private record BuildProbe(Optional<BuildMatch> match, long insertionSlot) {
        private BuildProbe {
            Objects.requireNonNull(match, "match");
        }

        private static BuildProbe absent(long insertionSlot) {
            return new BuildProbe(Optional.empty(), insertionSlot);
        }

        private static BuildProbe present(long slot, Cell cell) {
            return new BuildProbe(Optional.of(new BuildMatch(slot, cell)), slot);
        }
    }

}
