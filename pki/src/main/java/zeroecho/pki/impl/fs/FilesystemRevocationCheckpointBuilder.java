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
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * Builds one immutable checkpoint from a frozen disk copy of the derived current index.
 *
 * <p>Run formation and merge fan-in are explicitly bounded. Temporary run files reuse
 * the strict checkpoint record codec but remain outside the discoverable checkpoint
 * directory. The authoritative revocation log is only read and is never modified.</p>
 */
final class FilesystemRevocationCheckpointBuilder {

    private static final Logger LOGGER =
            Logger.getLogger(FilesystemRevocationCheckpointBuilder.class.getName());
    private static final String CLEANUP_WARNING =
            "Revocation checkpoint temporary cleanup was incomplete";
    private static final long ZERO = 0L;

    private FilesystemRevocationCheckpointBuilder() {
        // Static package implementation.
    }

    /* default */ static FilesystemRevocationCheckpoint.PublishedGeneration build(
            FilesystemRevocationCurrentIndex index,
            Path checkpointDirectory,
            Configuration configuration) throws IOException {
        return build(index, checkpointDirectory, configuration, FaultInjector.NONE);
    }

    /* default */ static FilesystemRevocationCheckpoint.PublishedGeneration build(
            FilesystemRevocationCurrentIndex index,
            Path checkpointDirectory,
            Configuration configuration,
            FaultInjector faults) throws IOException {
        Objects.requireNonNull(index, "index");
        Objects.requireNonNull(checkpointDirectory, "checkpointDirectory");
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(faults, "faults");
        configuration.requireValid();
        try (Workspace workspace = Workspace.create(
                configuration.temporaryDirectory(), faults)) {
            return buildInWorkspace(
                    index, checkpointDirectory, configuration, faults, workspace);
        }
    }

    private static FilesystemRevocationCheckpoint.PublishedGeneration buildInWorkspace(
            FilesystemRevocationCurrentIndex index,
            Path checkpointDirectory,
            Configuration configuration,
            FaultInjector faults,
        Workspace workspace) throws IOException {
        faults.fail(FaultPoint.BEFORE_FREEZE);
        try (FrozenBuild frozenBuild = FrozenBuild.open(
                index, workspace.frozenPath(), configuration.transferBufferBytes(), faults)) {
            FilesystemRevocationCheckpoint.PublishedGeneration result = buildFrozen(
                    checkpointDirectory, configuration, faults, workspace,
                    frozenBuild.snapshot());
            workspace.markOutcomeAuthoritative();
            frozenBuild.markOutcomeAuthoritative();
            return result;
        }
    }

    private static FilesystemRevocationCheckpoint.PublishedGeneration buildFrozen(
            Path checkpointDirectory,
            Configuration configuration,
            FaultInjector faults,
            Workspace workspace,
            FilesystemRevocationCurrentIndex.FrozenSnapshot frozen) throws IOException {
            RunFormation formation = new RunFormation(
                    workspace, frozen.coverage(), configuration, faults);
            long runCount = formation.createRuns(frozen);
            Path finalRun = new MergePass(
                    workspace, frozen.coverage(), configuration, faults)
                    .merge(runCount);
            faults.fail(FaultPoint.BEFORE_PUBLICATION);
            FilesystemRevocationCheckpoint.SortedSource source = runCount == ZERO
                    ? new EmptySource() : new RunSource(finalRun);
            return FilesystemRevocationCheckpoint.publishHistorical(
                    checkpointDirectory, frozen, source);
    }

    private static void warnCleanup() {
        try {
            LOGGER.warning(CLEANUP_WARNING);
        } catch (IllegalStateException ignored) {
            // Advisory logging cannot change an already published derived checkpoint.
        }
    }

    /** Explicit resource bounds and temporary location for one build. */
    /* default */ record Configuration(
            long maxEncodedRunBytes,
            int maxOpenMergeInputs,
            int transferBufferBytes,
            Path temporaryDirectory) {
        Configuration {
            Objects.requireNonNull(temporaryDirectory, "temporaryDirectory");
            if (maxEncodedRunBytes <= ZERO || maxOpenMergeInputs < 2
                    || transferBufferBytes <= 0) {
                throw new IllegalArgumentException("Invalid revocation checkpoint builder bounds");
            }
        }

        private void requireValid() throws IOException {
            if (Files.exists(temporaryDirectory, LinkOption.NOFOLLOW_LINKS)
                    && (!Files.isDirectory(temporaryDirectory, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(temporaryDirectory))) {
                throw new IOException("Revocation checkpoint temporary root is invalid");
            }
        }
    }

    /** Deterministic builder lifecycle faults; not production API. */
    /* default */ @FunctionalInterface
    interface FaultInjector {
        FaultInjector NONE = point -> { };

        /** Fails at one deterministic lifecycle boundary. */
        void fail(FaultPoint point) throws IOException;

        /** Observes the bounded entry buffer after one encoded entry is admitted. */
        default void observeRunBuffer(long entryCount, long encodedBytes) {
            // Optional structural test observation.
        }

        /** Observes one merge group after all of its bounded readers are open. */
        default void observeOpenMergeInputs(int openInputs) {
            // Optional structural test observation.
        }

        /** Observes one completed temporary run and its strict encoded size. */
        default void observeTemporaryRun(int pass, long entryCount, long encodedBytes) {
            // Optional structural test observation.
        }

        /** Observes population conservation across one complete merge pass. */
        default void observeMergePass(
                int pass,
                long inputRuns,
                long outputRuns,
                long inputEntries,
                long outputEntries) {
            // Optional structural test observation.
        }

        /** Records one strict UTF-8 encoding used to create a merge head. */
        default void observeMergeHeadEncoding() {
            // Optional structural test observation.
        }

        /** Observes one completed strict run before it is consumed or published. */
        default void afterRunWritten(Path run) throws IOException {
            // Optional deterministic corruption seam.
        }
    }

    /** Finite fault points for frozen-copy, run, merge, publication, and cleanup tests. */
    /* default */ enum FaultPoint {
        BEFORE_FREEZE,
        FROZEN_COPY,
        FROZEN_FORCE,
        FROZEN_CLOSE,
        RUN_WRITE,
        RUN_FORCE,
        MERGE_WRITE,
        MERGE_FORCE,
        BEFORE_PUBLICATION,
        CLEANUP
    }

    /** Forms individually authenticated sorted runs with a bounded entry buffer. */
    private static final class RunFormation {
        private final Workspace workspace;
        private final FilesystemRevocationCheckpoint.Coverage coverage;
        private final Configuration configuration;
        private final FaultInjector faults;

        private RunFormation(
                Workspace workspace,
                FilesystemRevocationCheckpoint.Coverage coverage,
                Configuration configuration,
                FaultInjector faults) {
            this.workspace = workspace;
            this.coverage = coverage;
            this.configuration = configuration;
            this.faults = faults;
        }

        private long createRuns(FilesystemRevocationCurrentIndex.FrozenSnapshot frozen)
                throws IOException {
            if (frozen.entryCount() == ZERO) {
                return ZERO;
            }
            long run = ZERO;
            try (FilesystemRevocationCurrentIndex.FrozenCursor cursor = frozen.openCursor();
                    RunAccumulator accumulator = new RunAccumulator(
                            workspace.measurementPath(), coverage,
                            configuration.maxEncodedRunBytes(), faults)) {
                while (cursor.advance()) {
                    if (accumulator.add(cursor.current())) {
                        writeRun(accumulator.drain(), workspace.runPath(0, run));
                        run = addExact(run, 1L, "Revocation checkpoint run count overflow");
                    }
                }
                if (!accumulator.isEmpty()) {
                    writeRun(accumulator.drain(), workspace.runPath(0, run));
                    run = addExact(run, 1L, "Revocation checkpoint run count overflow");
                }
            }
            return run;
        }

        private void writeRun(List<SortableEntry> entries, Path path) throws IOException {
            entries.sort(SortableEntry.ORDER);
            byte[] previous = null;
            try (FileChannel channel = FileChannel.open(path,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE)) {
                RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
                RevocationCheckpointCodec.Encoder encoder = codec.encoder(
                        channel, header(coverage, entries.size()));
                for (SortableEntry sortable : entries) {
                    if (previous != null
                            && RevocationCheckpointCodec.compareUnsigned(
                                    previous, sortable.identity()) >= 0) {
                        throw new IOException("Frozen revocation index contains duplicate identities");
                    }
                    faults.fail(FaultPoint.RUN_WRITE);
                    encoder.write(sortable.entry());
                    previous = sortable.identity();
                }
                encoder.finish();
                faults.fail(FaultPoint.RUN_FORCE);
                channel.force(true);
                codec.validate(channel);
            }
            faults.observeTemporaryRun(0, entries.size(), Files.size(path));
            faults.afterRunWritten(path);
        }
    }

    /** Measures actual encoded records while retaining only one configured run. */
    private static final class RunAccumulator implements AutoCloseable {
        private final Path measurementPath;
        private final FilesystemRevocationCheckpoint.Coverage coverage;
        private final long limit;
        private final FaultInjector faults;
        private List<SortableEntry> entries = new ArrayList<>();
        private FileChannel channel;
        private RevocationCheckpointCodec.Encoder encoder;

        private RunAccumulator(
                Path measurementPath,
                FilesystemRevocationCheckpoint.Coverage coverage,
                long limit,
                FaultInjector faults) throws IOException {
            this.measurementPath = measurementPath;
            this.coverage = coverage;
            this.limit = limit;
            this.faults = faults;
            openMeasurement();
        }

        private boolean add(RevocationCheckpointCodec.CurrentStateEntry entry)
                throws IOException {
            encoder.write(entry);
            entries.add(new SortableEntry(
                    RevocationCheckpointCodec.strictUtf8(entry.credentialId().value()), entry));
            long encodedBytes = channel.position() - RevocationCheckpointCodec.HEADER_BYTES;
            faults.observeRunBuffer(entries.size(), encodedBytes);
            return encodedBytes >= limit;
        }

        private boolean isEmpty() {
            return entries.isEmpty();
        }

        private List<SortableEntry> drain() throws IOException {
            List<SortableEntry> result = entries;
            entries = new ArrayList<>();
            channel.close();
            Files.deleteIfExists(measurementPath);
            openMeasurement();
            return result;
        }

        private void openMeasurement() throws IOException {
            channel = FileChannel.open(measurementPath,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE);
            encoder = new RevocationCheckpointCodec().encoder(
                    channel, header(coverage, Long.MAX_VALUE));
        }

        @Override
        public void close() throws IOException {
            IOException failure = null;
            try {
                channel.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                Files.deleteIfExists(measurementPath);
            } catch (IOException cleanupFailure) {
                failure = appendFailure(failure, cleanupFailure);
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    private record SortableEntry(
            byte[] identity,
            RevocationCheckpointCodec.CurrentStateEntry entry) {
        private static final Comparator<SortableEntry> ORDER =
                (first, second) -> RevocationCheckpointCodec.compareUnsigned(
                        first.identity, second.identity);

        private SortableEntry {
            identity = identity.clone();
            Objects.requireNonNull(entry, "entry");
        }

        @Override
        public byte[] identity() {
            return identity.clone();
        }
    }

    /** Multi-pass bounded fan-in merge over strict temporary run files. */
    private static final class MergePass {
        private final Workspace workspace;
        private final FilesystemRevocationCheckpoint.Coverage coverage;
        private final Configuration configuration;
        private final FaultInjector faults;

        private MergePass(
                Workspace workspace,
                FilesystemRevocationCheckpoint.Coverage coverage,
                Configuration configuration,
                FaultInjector faults) {
            this.workspace = workspace;
            this.coverage = coverage;
            this.configuration = configuration;
            this.faults = faults;
        }

        private Path merge(long initialRunCount) throws IOException {
            long runCount = initialRunCount;
            int pass = 0;
            while (runCount > 1L) {
                long outputCount = ZERO;
                long inputEntries = ZERO;
                long outputEntries = ZERO;
                long first = ZERO;
                while (first < runCount) {
                    int groupSize = (int) Math.min(
                            (long) configuration.maxOpenMergeInputs(), runCount - first);
                    Path output = workspace.runPath(
                            addExact(pass, 1, "Revocation checkpoint merge pass overflow"),
                            outputCount);
                    long mergedEntries = mergeGroup(pass, first, groupSize, output);
                    inputEntries = addExact(
                            inputEntries, mergedEntries,
                            "Revocation checkpoint merge input population overflow");
                    outputEntries = addExact(
                            outputEntries, mergedEntries,
                            "Revocation checkpoint merge output population overflow");
                    outputCount = addExact(
                            outputCount, 1L, "Revocation checkpoint merge count overflow");
                    first = addExact(first, groupSize,
                            "Revocation checkpoint merge offset overflow");
                }
                int completedPass = addExact(
                        pass, 1, "Revocation checkpoint merge pass overflow");
                faults.observeMergePass(
                        completedPass, runCount, outputCount, inputEntries, outputEntries);
                runCount = outputCount;
                pass = completedPass;
            }
            return initialRunCount == ZERO ? null : workspace.runPath(pass, ZERO);
        }

        private long mergeGroup(
                int pass, long first, int groupSize, Path output) throws IOException {
            long count;
            try (MergeInputs inputs = MergeInputs.open(
                    workspace, pass, first, groupSize, faults)) {
                count = inputs.entryCount();
                try (FileChannel channel = FileChannel.open(output,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                        StandardOpenOption.WRITE)) {
                    RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
                    RevocationCheckpointCodec.Encoder encoder =
                            codec.encoder(channel, header(coverage, count));
                    Queue<RunHead> queue = inputs.initialQueue(faults);
                    byte[] previous = null;
                    while (!queue.isEmpty()) {
                        RunHead head = queue.remove();
                        byte[] identity = head.identity;
                        if (previous != null
                                && RevocationCheckpointCodec.compareUnsigned(
                                        previous, identity) >= 0) {
                            throw new IOException("Revocation checkpoint merge contains duplicates");
                        }
                        faults.fail(FaultPoint.MERGE_WRITE);
                        encoder.write(head.entry());
                        previous = identity;
                        if (head.input().advance()) {
                            queue.add(RunHead.create(
                                    head.input(), head.input().current(), faults));
                        }
                    }
                    encoder.finish();
                    faults.fail(FaultPoint.MERGE_FORCE);
                    channel.force(true);
                    codec.validate(channel);
                }
            }
            for (int index = 0; index < groupSize; index++) {
                Files.delete(workspace.runPath(pass, addExact(
                        first, index, "Revocation checkpoint merge input overflow")));
            }
            faults.observeTemporaryRun(
                    addExact(pass, 1, "Revocation checkpoint merge pass overflow"),
                    count, Files.size(output));
            return count;
        }
    }

    /** Owns at most the configured fan-in of run readers. */
    private static final class MergeInputs implements AutoCloseable {
        private final List<RunCursor> inputs;
        private final long entryCount;

        private MergeInputs(List<RunCursor> inputs, long entryCount) {
            this.inputs = inputs;
            this.entryCount = entryCount;
        }

        private static MergeInputs open(
                Workspace workspace,
                int pass,
                long first,
                int groupSize,
                FaultInjector faults) throws IOException {
            List<RunCursor> inputs = new ArrayList<>(groupSize);
            long count = ZERO;
            try {
                for (int index = 0; index < groupSize; index++) {
                    RunCursor input = RunCursor.open(
                            workspace.runPath(pass, addExact(
                                    first, index,
                                    "Revocation checkpoint merge input overflow")));
                    inputs.add(input);
                    count = addExact(count, input.entryCount(),
                            "Revocation checkpoint merge entry count overflow");
                }
                faults.observeOpenMergeInputs(inputs.size());
                return new MergeInputs(inputs, count);
            } catch (IOException failure) {
                closeInputs(inputs, failure);
                throw failure;
            }
        }

        private long entryCount() {
            return entryCount;
        }

        private Queue<RunHead> initialQueue(FaultInjector faults) throws IOException {
            Queue<RunHead> queue = new PriorityQueue<>(
                    Math.max(1, inputs.size()), RunHead.ORDER);
            for (RunCursor input : inputs) {
                if (input.advance()) {
                    queue.add(RunHead.create(input, input.current(), faults));
                }
            }
            return queue;
        }

        @Override
        public void close() throws IOException {
            IOException failure = null;
            for (RunCursor input : inputs) {
                try {
                    input.close();
                } catch (IOException closeFailure) {
                    failure = appendFailure(failure, closeFailure);
                }
            }
            if (failure != null) {
                throw failure;
            }
        }

        private static void closeInputs(List<RunCursor> inputs, IOException failure) {
            for (RunCursor input : inputs) {
                try {
                    input.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
            }
        }
    }

    private record RunHead(
            RunCursor input,
            RevocationCheckpointCodec.CurrentStateEntry entry,
            byte[] identity) {
        private static final Comparator<RunHead> ORDER = (first, second) ->
                RevocationCheckpointCodec.compareUnsigned(
                        first.identity, second.identity);

        private RunHead {
            Objects.requireNonNull(input, "input");
            Objects.requireNonNull(entry, "entry");
            identity = identity.clone();
        }

        private static RunHead create(
                RunCursor input,
                RevocationCheckpointCodec.CurrentStateEntry entry,
                FaultInjector faults) {
            faults.observeMergeHeadEncoding();
            return new RunHead(input, entry, RevocationCheckpointCodec.strictUtf8(
                    entry.credentialId().value()));
        }

        @Override
        public byte[] identity() {
            return identity.clone();
        }
    }

    /** Sequential reader for one validated temporary run. */
    private static final class RunCursor {
        private final FileChannel channel;
        private final RevocationCheckpointCodec.SequentialDecoder decoder;
        private final long trailerOffset;
        private final long entryCount;
        private long offset = RevocationCheckpointCodec.HEADER_BYTES;
        private long readCount;
        private RevocationCheckpointCodec.CurrentStateEntry current;

        private RunCursor(
                FileChannel channel,
                RevocationCheckpointCodec.SequentialDecoder decoder,
                long trailerOffset,
                long entryCount) {
            this.channel = channel;
            this.decoder = decoder;
            this.trailerOffset = trailerOffset;
            this.entryCount = entryCount;
        }

        private static RunCursor open(Path path) throws IOException {
            FileChannel channel = FileChannel.open(path, StandardOpenOption.READ);
            try {
                RevocationCheckpointCodec codec = new RevocationCheckpointCodec();
                RevocationCheckpointCodec.ValidatedFile validated = codec.validate(channel);
                return new RunCursor(
                        channel, codec.sequentialDecoder(), validated.trailerOffset(),
                        validated.header().entryCount());
            } catch (IOException failure) {
                try {
                    channel.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }
        }

        private long entryCount() {
            return entryCount;
        }

        private boolean advance() throws IOException {
            if (readCount == entryCount) {
                current = null;
                return false;
            }
            RevocationCheckpointCodec.DecodedRecord decoded =
                    decoder.read(channel, offset, trailerOffset);
            current = decoded.entry();
            offset = decoded.nextOffset();
            readCount = addExact(
                    readCount, 1L, "Revocation checkpoint run count overflow");
            return true;
        }

        private RevocationCheckpointCodec.CurrentStateEntry current() {
            if (current == null) {
                throw new IllegalStateException("Temporary revocation run has no current entry");
            }
            return current;
        }

        private void close() throws IOException {
            channel.close();
        }
    }

    /** Final merged run transferred to the existing checkpoint publisher. */
    private static final class RunSource implements FilesystemRevocationCheckpoint.SortedSource {
        private final Path path;
        private final long count;
        private boolean opened;
        private boolean closed;

        private RunSource(Path path) throws IOException {
            this.path = Objects.requireNonNull(path, "path");
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
                count = new RevocationCheckpointCodec().validate(channel).header().entryCount();
            }
        }

        @Override
        public long entryCount() {
            requireOpen();
            return count;
        }

        @Override
        public FilesystemRevocationCheckpoint.SourceCursor openCursor() throws IOException {
            requireOpen();
            if (opened) {
                throw new IllegalStateException("Revocation run source cursor is already opened");
            }
            opened = true;
            return new SourceCursorAdapter(RunCursor.open(path));
        }

        @Override
        public void close() {
            closed = true;
        }

        private void requireOpen() {
            if (closed) {
                throw new IllegalStateException("Revocation run source is closed");
            }
        }
    }

    /** Transfers one temporary run reader into the checkpoint source cursor contract. */
    private static final class SourceCursorAdapter
            implements FilesystemRevocationCheckpoint.SourceCursor {
        private final RunCursor cursor;

        private SourceCursorAdapter(RunCursor cursor) {
            this.cursor = cursor;
        }

        @Override
        public boolean advance() throws IOException {
            return cursor.advance();
        }

        @Override
        public RevocationCheckpointCodec.CurrentStateEntry current() {
            return cursor.current();
        }

        @Override
        public void close() throws IOException {
            cursor.close();
        }
    }

    /** Zero-entry source for an authenticated genesis checkpoint. */
    private static final class EmptySource implements FilesystemRevocationCheckpoint.SortedSource {
        @Override
        public long entryCount() {
            return ZERO;
        }

        @Override
        public FilesystemRevocationCheckpoint.SourceCursor openCursor() {
            return new EmptyCursor();
        }

        @Override
        public void close() {
            // No resource.
        }
    }

    /** Stateless cursor paired with the zero-entry source. */
    private static final class EmptyCursor implements FilesystemRevocationCheckpoint.SourceCursor {
        @Override
        public boolean advance() {
            return false;
        }

        @Override
        public RevocationCheckpointCodec.CurrentStateEntry current() {
            throw new IllegalStateException("Empty revocation source has no current entry");
        }

        @Override
        public void close() {
            // No resource.
        }
    }

    /** One isolated build directory; cleanup never touches published generations. */
    private static final class Workspace implements AutoCloseable {
        private final Path root;
        private final FaultInjector faults;
        private boolean closed;
        private boolean outcomeAuthoritative;

        private Workspace(Path root, FaultInjector faults) {
            this.root = root;
            this.faults = faults;
        }

        private static Workspace create(Path temporaryRoot, FaultInjector faults)
                throws IOException {
            Files.createDirectories(temporaryRoot);
            if (!Files.isDirectory(temporaryRoot, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(temporaryRoot)) {
                throw new IOException("Revocation checkpoint temporary root is invalid");
            }
            Path root = temporaryRoot.resolve(".checkpoint-build-" + UUID.randomUUID());
            Files.createDirectory(root);
            return new Workspace(root, faults);
        }

        private Path frozenPath() {
            return root.resolve("frozen-index");
        }

        private Path measurementPath() {
            return root.resolve("measurement");
        }

        private Path runPath(int pass, long run) {
            return root.resolve("p-" + pass + "-r-" + run + ".run");
        }

        private void markOutcomeAuthoritative() {
            outcomeAuthoritative = true;
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            IOException failure = null;
            try {
                faults.fail(FaultPoint.CLEANUP);
            } catch (IOException cleanupFailure) {
                failure = cleanupFailure;
            }
            try (DirectoryStream<Path> paths = Files.newDirectoryStream(root)) {
                for (Path path : paths) {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException cleanupFailure) {
                        failure = appendFailure(failure, cleanupFailure);
                    }
                }
            } catch (IOException cleanupFailure) {
                failure = appendFailure(failure, cleanupFailure);
            }
            try {
                Files.deleteIfExists(root);
            } catch (IOException cleanupFailure) {
                failure = appendFailure(failure, cleanupFailure);
            }
            if (failure != null) {
                if (outcomeAuthoritative) {
                    warnCleanup();
                } else {
                    throw failure;
                }
            }
        }
    }

    /** Owns the immutable index copy and preserves an established publication outcome. */
    private static final class FrozenBuild implements AutoCloseable {
        private final FilesystemRevocationCurrentIndex.FrozenSnapshot snapshot;
        private final FaultInjector faults;
        private boolean outcomeAuthoritative;
        private boolean closed;

        private FrozenBuild(
                FilesystemRevocationCurrentIndex.FrozenSnapshot snapshot,
                FaultInjector faults) {
            this.snapshot = snapshot;
            this.faults = faults;
        }

        private static FrozenBuild open(
                FilesystemRevocationCurrentIndex index,
                Path frozenPath,
                int transferBufferBytes,
                FaultInjector faults) throws IOException {
            FilesystemRevocationCurrentIndex.FrozenSnapshot snapshot = index.freeze(
                    frozenPath, transferBufferBytes, point -> {
                        if (point == FilesystemRevocationCurrentIndex.FrozenFaultPoint.COPY) {
                            faults.fail(FaultPoint.FROZEN_COPY);
                        } else {
                            faults.fail(FaultPoint.FROZEN_FORCE);
                        }
                    });
            return new FrozenBuild(snapshot, faults);
        }

        private FilesystemRevocationCurrentIndex.FrozenSnapshot snapshot() {
            return snapshot;
        }

        private void markOutcomeAuthoritative() {
            outcomeAuthoritative = true;
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            IOException failure = null;
            try {
                faults.fail(FaultPoint.FROZEN_CLOSE);
            } catch (IOException injected) {
                failure = injected;
            }
            try {
                snapshot.close();
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
            if (failure != null) {
                if (outcomeAuthoritative) {
                    warnCleanup();
                } else {
                    throw failure;
                }
            }
        }
    }

    private static RevocationCheckpointCodec.HeaderData header(
            FilesystemRevocationCheckpoint.Coverage coverage, long count) {
        return new RevocationCheckpointCodec.HeaderData(
                coverage.storeId(), coverage.coveredRevision(), coverage.finalRecordStart(),
                coverage.coveredBoundary(), coverage.globalCommitment(), count);
    }

    private static long addExact(long first, long second, String message) throws IOException {
        try {
            return Math.addExact(first, second);
        } catch (ArithmeticException overflow) {
            throw new IOException(message, overflow);
        }
    }

    private static int addExact(int first, int second, String message) throws IOException {
        try {
            return Math.addExact(first, second);
        } catch (ArithmeticException overflow) {
            throw new IOException(message, overflow);
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
