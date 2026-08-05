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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.pki.spi.store.RevocationView;

/** Store-owned coordination of the authoritative log and its derived state. */
@SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources", "PMD.AvoidSynchronizedAtMethodLevel",
        "PMD.UnusedAssignment", "PMD.ControlStatementBraces" })
final class FilesystemRevocationAuthority implements AutoCloseable {

    private static final FilesystemRevocationCurrentIndex.Configuration INDEX_CONFIGURATION =
            new FilesystemRevocationCurrentIndex.Configuration(1024L, 1, 2);
    private static final long CHECKPOINT_RUN_BYTES = 16L * 1024L * 1024L;
    private static final int CHECKPOINT_MERGE_INPUTS = 32;
    private static final int TRANSFER_BYTES = 16 * 1024;

    private final FsPaths paths;
    private final MetadataStoreId storeId;
    private final FilesystemRevocationLog log;
    private final IndexUpdateFaultInjector indexUpdateFaults;
    private final ReentrantReadWriteLock lifecycle = new ReentrantReadWriteLock();
    private final Set<OwnedResource> activeResources = new HashSet<>();
    private FilesystemRevocationCurrentIndex index;
    private boolean closed;

    private FilesystemRevocationAuthority(FsPaths paths, MetadataStoreId storeId,
            FilesystemRevocationLog log, FilesystemRevocationCurrentIndex index,
            IndexUpdateFaultInjector indexUpdateFaults) {
        this.paths = paths;
        this.storeId = storeId;
        this.log = log;
        this.index = index;
        this.indexUpdateFaults = indexUpdateFaults;
    }

    /* default */ static FilesystemRevocationAuthority open(FsPaths paths, MetadataStoreId storeId,
            FilesystemRevocationLog.CredentialAuthority credentials, boolean create) throws IOException {
        return open(paths, storeId, credentials, create, IndexUpdateFaultInjector.NONE);
    }

    /* default */ static FilesystemRevocationAuthority open(FsPaths paths, MetadataStoreId storeId,
            FilesystemRevocationLog.CredentialAuthority credentials, boolean create,
            IndexUpdateFaultInjector indexUpdateFaults) throws IOException {
        Objects.requireNonNull(paths, "paths");
        Objects.requireNonNull(storeId, "storeId");
        Objects.requireNonNull(credentials, "credentials");
        Objects.requireNonNull(indexUpdateFaults, "indexUpdateFaults");
        Path logPath = paths.revocationTransitionLog();
        Files.createDirectories(Objects.requireNonNull(logPath.getParent(), "revocation directory"));
        FilesystemRevocationLog openedLog = create
                ? FilesystemRevocationLog.createProduction(logPath, storeId, credentials)
                : FilesystemRevocationLog.openProduction(logPath, storeId, credentials);
        boolean complete = false;
        try {
            FilesystemRevocationLog.RecoveryTarget target = openedLog.recoveryTarget();
            FilesystemRevocationCurrentIndex openedIndex = FilesystemRevocationCurrentIndex.recover(
                    paths.revocationCurrentIndex(), paths.revocationCheckpointDirectory(), logPath,
                    storeId, INDEX_CONFIGURATION, target);
            FilesystemRevocationAuthority authority = new FilesystemRevocationAuthority(
                    paths, storeId, openedLog, openedIndex, indexUpdateFaults);
            complete = true;
            return authority;
        } finally {
            if (!complete) {
                openedLog.close();
            }
        }
    }

    /* default */ Optional<RevocationRecord> current(PkiId credentialId) throws IOException {
        Objects.requireNonNull(credentialId, "credentialId");
        lifecycle.writeLock().lock();
        try {
            requireOperational();
            ensureIndex();
            return index.lookup(credentialId).map(FilesystemRevocationAuthority::record);
        } finally {
            lifecycle.writeLock().unlock();
        }
    }

    /* default */ RevocationTransitionFrameCodec.CompleteRecord append(
            PkiId credentialId, RevocationTransition transition) throws IOException {
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(transition, "transition");
        lifecycle.writeLock().lock();
        try {
            requireOperational();
            ensureIndex();
            RevocationTransitionFrameCodec.CompleteRecord previous =
                    index.lookup(credentialId).orElse(null);
            RevocationTransitionFrameCodec.CompleteRecord committed =
                    log.append(credentialId, transition, previous);
            try {
                indexUpdateFaults.afterAppend();
                index.update(committed);
            } catch (IOException derivedFailure) {
                invalidateIndex(derivedFailure);
            }
            return committed;
        } finally {
            lifecycle.writeLock().unlock();
        }
    }

    /** Instance-scoped deterministic seam for derived-update failure tests. */
    /* default */
    @FunctionalInterface
    interface IndexUpdateFaultInjector {
        IndexUpdateFaultInjector NONE = () -> { };

        /** Runs after authoritative append and before derived index update. */
        void afterAppend() throws IOException;
    }

    /* default */ RevocationHistory history(PkiId credentialId) throws IOException {
        Objects.requireNonNull(credentialId, "credentialId");
        lifecycle.writeLock().lock();
        try {
            requireOperational();
            HistoryCursor cursor = new HistoryCursor(this, credentialId, log.recoveryTarget());
            activeResources.add(cursor);
            return cursor;
        } finally {
            lifecycle.writeLock().unlock();
        }
    }

    /* default */ RevocationSnapshot snapshot() throws IOException {
        lifecycle.writeLock().lock();
        try {
            requireOperational();
            FilesystemRevocationLog.RecoveryTarget head = log.recoveryTarget();
            ensureIndex();
            if (index.coveredGlobalRevision() != head.globalRevision()) {
                recoverIndex(head);
            }
            Files.createDirectories(paths.revocationCheckpointDirectory());
            Optional<FilesystemRevocationCheckpoint> selected = FilesystemRevocationCheckpoint.discoverBelow(
                    paths.revocationCheckpointDirectory(), paths.revocationTransitionLog(), head,
                    head.globalRevision(), true, FilesystemRevocationCurrentIndex.FaultInjector.NONE);
            FilesystemRevocationCheckpoint checkpoint = exact(selected, head).orElse(null);
            if (checkpoint == null) {
                FilesystemRevocationCheckpointBuilder.Configuration configuration =
                        new FilesystemRevocationCheckpointBuilder.Configuration(
                                CHECKPOINT_RUN_BYTES, CHECKPOINT_MERGE_INPUTS, TRANSFER_BYTES,
                                paths.revocationCheckpointWorkDirectory());
                FilesystemRevocationCheckpointBuilder.build(
                        index, paths.revocationCheckpointDirectory(), configuration);
                selected = FilesystemRevocationCheckpoint.discoverBelow(
                        paths.revocationCheckpointDirectory(), paths.revocationTransitionLog(), head,
                        head.globalRevision(), true, FilesystemRevocationCurrentIndex.FaultInjector.NONE);
                checkpoint = exact(selected, head).orElseThrow(
                        () -> new IOException("Exact revocation checkpoint publication failed"));
            }
            StableView view = new StableView(this, checkpoint, head);
            activeResources.add(view);
            return view;
        } finally {
            lifecycle.writeLock().unlock();
        }
    }

    /* default */ RevocationView view() throws IOException {
        lifecycle.writeLock().lock();
        try {
            requireOperational();
            ensureIndex();
            FilesystemRevocationLog.RecoveryTarget head = log.recoveryTarget();
            if (index.coveredGlobalRevision() != head.globalRevision()) recoverIndex(head);
            DirectView view = new DirectView(this, head);
            view.acquire();
            return view;
        } finally {
            lifecycle.writeLock().unlock();
        }
    }

    /* default */ FilesystemRevocationLog.RecoveryTarget head() throws IOException {
        lifecycle.readLock().lock();
        try {
            requireOperational();
            return log.recoveryTarget();
        } finally {
            lifecycle.readLock().unlock();
        }
    }

    /* default */ FilesystemRevocationLog.RecoveryTarget copyAuthoritativePrefix(Path target) throws IOException {
        Objects.requireNonNull(target, "target");
        lifecycle.readLock().lock();
        try {
            requireOperational();
            FilesystemRevocationLog.RecoveryTarget captured = log.recoveryTarget();
            Files.createDirectories(Objects.requireNonNull(target.getParent(), "snapshot prefix parent"));
            try (FileChannel source = FileChannel.open(paths.revocationTransitionLog(), StandardOpenOption.READ);
                    FileChannel destination = FileChannel.open(target, StandardOpenOption.CREATE_NEW,
                            StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.allocate(TRANSFER_BYTES);
                long position = 0L;
                while (position < captured.boundary()) {
                    buffer.clear();
                    buffer.limit((int) Math.min(buffer.capacity(), captured.boundary() - position));
                    int read = source.read(buffer, position);
                    if (read <= 0) {
                        throw new IOException("Revocation snapshot prefix made no read progress");
                    }
                    buffer.flip();
                    while (buffer.hasRemaining()) {
                        destination.write(buffer);
                    }
                    position = Math.addExact(position, read);
                }
                destination.force(true);
            }
            validateCopiedPrefix(target, captured);
            return captured;
        } finally {
            lifecycle.readLock().unlock();
        }
    }

    private static void validateCopiedPrefix(Path path,
            FilesystemRevocationLog.RecoveryTarget expected) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
            MetadataStoreId store = codec.readPreamble(channel);
            if (!expected.storeId().equals(store) || channel.size() != expected.boundary()) {
                throw new IOException("Copied revocation prefix identity or boundary is invalid");
            }
            long offset = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
            long revision = 0L;
            RevocationTransitionFrameCodec.Commitment commitment =
                    RevocationTransitionFrameCodec.initialCommitment(store);
            while (offset < expected.boundary()) {
                RevocationTransitionFrameCodec.ReadResult read = codec.read(channel, offset);
                if (read.classification() != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                    throw new IOException("Copied revocation prefix contains an invalid frame");
                }
                RevocationTransitionFrameCodec.CompleteRecord frame = read.record().orElseThrow();
                if (frame.data().globalRevision() != Math.addExact(revision, 1L)
                        || !frame.data().previousGlobalCommitment().equals(commitment)
                        || frame.recordEnd() > expected.boundary()) {
                    throw new IOException("Copied revocation prefix continuity is invalid");
                }
                offset = frame.recordEnd();
                revision = frame.data().globalRevision();
                commitment = frame.commitment();
            }
            if (offset != expected.boundary() || revision != expected.globalRevision()
                    || !commitment.equals(expected.globalCommitment())) {
                throw new IOException("Copied revocation prefix does not match its captured head");
            }
        }
    }

    private Optional<FilesystemRevocationCheckpoint> exact(
            Optional<FilesystemRevocationCheckpoint> candidate,
            FilesystemRevocationLog.RecoveryTarget head) throws IOException {
        if (candidate.isEmpty()) {
            return Optional.empty();
        }
        FilesystemRevocationCheckpoint checkpoint = candidate.orElseThrow();
        if (checkpoint.storeId().equals(head.storeId())
                && checkpoint.coveredRevision() == head.globalRevision()
                && checkpoint.coveredBoundary() == head.boundary()
                && checkpoint.coveredCommitment().equals(head.globalCommitment())) {
            return Optional.of(checkpoint);
        }
        checkpoint.close();
        return Optional.empty();
    }

    private void ensureIndex() throws IOException {
        if (index == null) {
            recoverIndex(log.recoveryTarget());
        }
    }

    private void recoverIndex(FilesystemRevocationLog.RecoveryTarget target) throws IOException {
        if (index != null) {
            index.close();
        }
        index = FilesystemRevocationCurrentIndex.recover(
                paths.revocationCurrentIndex(), paths.revocationCheckpointDirectory(),
                paths.revocationTransitionLog(), storeId, INDEX_CONFIGURATION, target);
    }

    private void invalidateIndex(IOException failure) {
        FilesystemRevocationCurrentIndex invalid = index;
        index = null;
        if (invalid != null) {
            try {
                invalid.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
        }
    }

    private void requireOperational() throws IOException {
        if (closed) {
            throw new IllegalStateException("Revocation authority is closed");
        }
        if (log.recoveryRequired()) {
            throw new IOException("Revocation authority requires close and recovery");
        }
    }

    private void release(OwnedResource resource) {
        lifecycle.writeLock().lock();
        try {
            activeResources.remove(resource);
        } finally {
            lifecycle.writeLock().unlock();
        }
    }

    @Override
    public synchronized void close() throws IOException {
        Set<OwnedResource> resources;
        lifecycle.writeLock().lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            resources = Set.copyOf(activeResources);
            activeResources.clear();
        } finally {
            lifecycle.writeLock().unlock();
        }

        IOException failure = null;
        for (OwnedResource resource : resources) {
            try {
                resource.closeFromOwner();
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
        }

        lifecycle.writeLock().lock();
        try {
            if (index != null) {
                try {
                    index.close();
                } catch (IOException closeFailure) {
                    failure = appendFailure(failure, closeFailure);
                }
                index = null;
            }
            try {
                log.close();
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
            if (failure != null) {
                throw failure;
            }
        } finally {
            lifecycle.writeLock().unlock();
        }
    }

    private static RevocationRecord record(RevocationTransitionFrameCodec.CompleteRecord frame) {
        return new RevocationRecord(frame.data().credentialId(), frame.data().transition());
    }

    private static IOException appendFailure(IOException first, IOException later) {
        if (first == null) {
            return later;
        }
        first.addSuppressed(later);
        return first;
    }

    /** Resource registered for deterministic owner-driven closure. */
    @SuppressWarnings("PMD.ImplicitFunctionalInterface")
    private interface OwnedResource {
        /** Closes the resource without reentering owner deregistration. */
        void closeFromOwner() throws IOException;
    }

    /** Read-lock-backed direct view; callers close it before external signing. */
    private static final class DirectView implements RevocationView {
        private final FilesystemRevocationAuthority owner;
        private final FilesystemRevocationLog.RecoveryTarget head;
        private boolean closed;

        private DirectView(FilesystemRevocationAuthority owner,
                FilesystemRevocationLog.RecoveryTarget head) {
            this.owner = owner;
            this.head = head;
        }

        private void acquire() { owner.lifecycle.readLock().lock(); }
        @Override public long revision() { requireOpen(); return head.globalRevision(); }
        @Override public String commitment() { requireOpen(); return head.globalCommitment().value(); }
        @Override public Optional<RevocationRecord> get(PkiId credentialId) throws IOException {
            requireOpen();
            return owner.index.lookup(Objects.requireNonNull(credentialId, "credentialId"))
                    .map(FilesystemRevocationAuthority::record);
        }
        @Override public void close() {
            if (closed) return;
            closed = true;
            owner.lifecycle.readLock().unlock();
        }
        private void requireOpen() {
            if (closed) throw new IllegalStateException("Revocation view is closed");
        }
    }

    /** Immutable checkpoint-backed current-state view. */
    private static final class StableView implements RevocationSnapshot, OwnedResource {
        private final FilesystemRevocationAuthority owner;
        private final FilesystemRevocationCheckpoint checkpoint;
        private final FilesystemRevocationLog.RecoveryTarget head;
        private final Set<ViewCursor> cursors = new HashSet<>();
        private boolean closed;

        private StableView(FilesystemRevocationAuthority owner,
                FilesystemRevocationCheckpoint checkpoint,
                FilesystemRevocationLog.RecoveryTarget head) {
            this.owner = owner;
            this.checkpoint = checkpoint;
            this.head = head;
        }

        @Override
        public String snapshotId() {
            return checkpoint.generationId();
        }

        @Override
        public long revision() {
            return head.globalRevision();
        }

        @Override
        public long boundary() {
            return head.boundary();
        }

        @Override
        public String commitment() {
            return head.globalCommitment().value();
        }

        @Override
        public OptionalLong count() {
            return OptionalLong.of(checkpoint.entryCount());
        }

        @Override
        public synchronized Cursor openCursor() throws IOException {
            requireOpen();
            ViewCursor cursor = new ViewCursor(this, checkpoint.allCurrentStates(),
                    FileChannel.open(owner.paths.revocationTransitionLog(), StandardOpenOption.READ));
            cursors.add(cursor);
            return cursor;
        }

        @Override
        public void close() throws IOException {
            closeInternal(true);
        }

        @Override
        public void closeFromOwner() throws IOException {
            closeInternal(false);
        }

        private synchronized void closeInternal(boolean release) throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            IOException failure = null;
            for (ViewCursor cursor : Set.copyOf(cursors)) {
                try {
                    cursor.closeFromOwner();
                } catch (IOException closeFailure) {
                    failure = appendFailure(failure, closeFailure);
                }
            }
            cursors.clear();
            try {
                checkpoint.close();
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
            if (release) {
                owner.release(this);
            }
            if (failure != null) {
                throw failure;
            }
        }

        private synchronized void cursorClosed(ViewCursor cursor) {
            cursors.remove(cursor);
        }

        private void requireOpen() {
            if (closed) {
                throw new IllegalStateException("Revocation snapshot is closed");
            }
        }
    }

    /** Ordered view cursor that revalidates every derived entry against its exact frame. */
    private static final class ViewCursor implements RevocationSnapshot.Cursor {
        private final StableView owner;
        private final FilesystemRevocationCheckpoint.Cursor cursor;
        private final FileChannel logChannel;
        private RevocationRecord current;
        private long ordinal = -1L;
        private boolean closed;

        private ViewCursor(StableView owner, FilesystemRevocationCheckpoint.Cursor cursor,
                FileChannel logChannel) {
            this.owner = owner;
            this.cursor = cursor;
            this.logChannel = logChannel;
        }

        @Override
        public boolean next(CancellationSignal cancellation) throws IOException {
            requireOpen();
            current = null;
            if (!cursor.advance(cancellation)) {
                return false;
            }
            RevocationCheckpointCodec.CurrentStateEntry entry = cursor.current();
            RevocationTransitionFrameCodec.ReadResult read = new RevocationTransitionFrameCodec()
                    .read(logChannel, entry.frameStart());
            if (read.classification() != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                throw new IOException("Checkpoint current state has no authoritative frame");
            }
            RevocationTransitionFrameCodec.CompleteRecord frame = read.record().orElseThrow();
            if (!frame.data().credentialId().equals(entry.credentialId())
                    || frame.data().globalRevision() != entry.globalRevision()
                    || frame.data().transition().revision() != entry.credentialRevision()
                    || frame.recordEnd() != entry.frameEnd()
                    || !frame.commitment().equals(entry.transitionCommitment())
                    || !RevocationTransitionFrameCodec.transitionsEqual(
                            frame.data().transition(), entry.transition())) {
                throw new IOException("Checkpoint current state disagrees with authoritative frame");
            }
            ordinal = Math.addExact(ordinal, 1L);
            current = record(frame);
            return true;
        }

        @Override
        public RevocationRecord current() {
            if (current == null) {
                throw new IllegalStateException("Revocation cursor is not positioned");
            }
            return current;
        }

        @Override
        public long ordinal() {
            if (current == null) {
                throw new IllegalStateException("Revocation cursor is not positioned");
            }
            return ordinal;
        }

        @Override
        public void close() throws IOException {
            closeInternal(true);
        }

        private void closeFromOwner() throws IOException {
            closeInternal(false);
        }

        private void closeInternal(boolean release) throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            current = null;
            cursor.close();
            logChannel.close();
            if (release) {
                owner.cursorClosed(this);
            }
        }

        private void requireOpen() {
            if (closed) {
                throw new IllegalStateException("Revocation cursor is closed");
            }
        }
    }

    /** Two-pass bounded-memory history cursor over one captured authoritative prefix. */
    private static final class HistoryCursor implements RevocationHistory, OwnedResource {
        private final FilesystemRevocationAuthority owner;
        private final PkiId credentialId;
        private final FilesystemRevocationLog.RecoveryTarget head;
        private final FileChannel channel;
        private final RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
        private long offset = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
        private RevocationTransitionFrameCodec.Commitment globalCommitment;
        private long globalRevision;
        private RevocationTransitionFrameCodec.CompleteRecord previousCredential;
        private RevocationTransition current;
        private boolean validated;
        private boolean closed;

        private HistoryCursor(FilesystemRevocationAuthority owner, PkiId credentialId,
                FilesystemRevocationLog.RecoveryTarget head) throws IOException {
            this.owner = owner;
            this.credentialId = credentialId;
            this.head = head;
            channel = FileChannel.open(owner.paths.revocationTransitionLog(), StandardOpenOption.READ);
            boolean valid = false;
            try {
                reset();
                valid = true;
            } finally {
                if (!valid) {
                    channel.close();
                }
            }
        }

        @Override
        public PkiId credentialId() {
            return credentialId;
        }

        @Override
        public boolean next(CancellationSignal cancellation) throws IOException {
            Objects.requireNonNull(cancellation, "cancellation");
            requireOpen();
            if (!validated) {
                validatePrefix(cancellation);
                reset();
                validated = true;
            }
            current = null;
            while (offset < head.boundary()) {
                cancellation.throwIfCancelled();
                RevocationTransitionFrameCodec.CompleteRecord frame = readNext();
                if (frame.data().credentialId().equals(credentialId)) {
                    FilesystemRevocationLog.validateTransition(frame.data(), previousCredential);
                    previousCredential = frame;
                    current = frame.data().transition();
                    return true;
                }
            }
            requireExactHead();
            return false;
        }

        @Override
        public RevocationTransition current() {
            if (current == null) {
                throw new IllegalStateException("Revocation history is not positioned");
            }
            return current;
        }

        @Override
        public void close() throws IOException {
            closeInternal(true);
        }

        @Override
        public void closeFromOwner() throws IOException {
            closeInternal(false);
        }

        private void validatePrefix(CancellationSignal cancellation) throws IOException {
            reset();
            while (offset < head.boundary()) {
                cancellation.throwIfCancelled();
                RevocationTransitionFrameCodec.CompleteRecord frame = readNext();
                if (frame.data().credentialId().equals(credentialId)) {
                    FilesystemRevocationLog.validateTransition(frame.data(), previousCredential);
                    previousCredential = frame;
                }
            }
            requireExactHead();
        }

        private void reset() throws IOException {
            MetadataStoreId actual = codec.readPreamble(channel);
            if (!head.storeId().equals(actual)) {
                throw new IOException("Revocation history belongs to another store");
            }
            offset = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
            globalRevision = 0L;
            globalCommitment = RevocationTransitionFrameCodec.initialCommitment(actual);
            previousCredential = null;
            current = null;
        }

        private RevocationTransitionFrameCodec.CompleteRecord readNext() throws IOException {
            RevocationTransitionFrameCodec.ReadResult read = codec.read(channel, offset);
            if (read.classification() != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                throw new IOException("Revocation history contains an incomplete or corrupt frame");
            }
            RevocationTransitionFrameCodec.CompleteRecord frame = read.record().orElseThrow();
            if (frame.recordEnd() > head.boundary()
                    || frame.data().globalRevision() != Math.addExact(globalRevision, 1L)
                    || !frame.data().previousGlobalCommitment().equals(globalCommitment)) {
                throw new IOException("Revocation history continuity is invalid");
            }
            offset = frame.recordEnd();
            globalRevision = frame.data().globalRevision();
            globalCommitment = frame.commitment();
            return frame;
        }

        private void requireExactHead() throws IOException {
            if (offset != head.boundary() || globalRevision != head.globalRevision()
                    || !globalCommitment.equals(head.globalCommitment())) {
                throw new IOException("Revocation history does not match its captured head");
            }
        }

        private void closeInternal(boolean release) throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            current = null;
            channel.close();
            if (release) {
                owner.release(this);
            }
        }

        private void requireOpen() {
            if (closed) {
                throw new IllegalStateException("Revocation history is closed");
            }
        }
    }
}
