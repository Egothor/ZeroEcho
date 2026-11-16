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
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manifest-authoritative, package-internal recovery for the segmented signing ledger.
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidLiteralsInIfCondition", "PMD.AvoidSynchronizedAtMethodLevel",
        "PMD.CloseResource", "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity",
        "PMD.PreserveStackTrace" })
final class SigningLedgerRecovery {

    /**
     * File name of the signing ledger format marker.
     */
    /* default */ static final String FORMAT_FILE = "FORMAT";
    /**
     * File name of the authoritative signing ledger manifest.
     */
    /* default */ static final String MANIFEST_FILE = "manifest.zem";
    private static final byte[] FORMAT_CONTENT =
            "ZeroEcho signing ledger\nformat=1\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int MAXIMUM_ROOT_ENTRIES = 16_384;
    private static final SigningActiveWal.NanoClock SYSTEM_CLOCK = System::nanoTime;
    private static final SigningActiveWal.GroupWaitStrategy SYSTEM_WAIT =
            java.util.concurrent.TimeUnit.NANOSECONDS::timedWait;
    private static final RecoveryFaultInjector NO_RECOVERY_FAULT = (stage, registry) -> { };
    private static final ThreadLocal<RecoveryFaultInjector> RECOVERY_FAULTS = new ThreadLocal<>();

    private SigningLedgerRecovery() {
        // utility class
    }

    /**
     * Creates and forces the clean-format marker in an otherwise empty ledger root.
     *
     * @param root existing ledger directory; symbolic-link roots are rejected
     * @throws NullPointerException if the root is null
     * @throws IllegalArgumentException if the root is not an existing nonsymlink directory
     * @throws IllegalStateException if the root already contains any entry
     * @throws IOException if marker creation or file/directory durability fails
     */
    /* default */ static void initializeFormat(Path root) throws IOException {
        requireRoot(root);
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(root)) {
            if (entries.iterator().hasNext()) {
                throw new IllegalStateException("signing format root is not empty");
            }
        }
        Path marker = root.resolve(FORMAT_FILE);
        Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS);
        try (FileChannel channel = FileChannel.open(marker, options)) {
            SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(FORMAT_CONTENT));
            channel.force(true);
        }
        SigningFormatSupport.forceDirectory(root);
    }

    /**
     * Recovers and publishes the ledger, then starts its active WAL writer.
     *
     * <p>Only manifest-referenced committed artifacts are replayed. Resources acquired before a failed handoff are cleaned up. Recovery-stage faults are inherited from the current thread when no explicit observer is supplied. Publication and ordered lifecycle transitions complete before the ready handle is returned.</p>
     *
     * @param root existing ledger directory; symbolic-link roots are rejected
     * @param configuration validated limits for layout, replay, and active WAL resources
     * @param sink transactional replay sink; prepared publication must be failure-free
     * @return owned ready recovery handle; the caller must close it
     * @throws NullPointerException if a required configuration, sink, or injected collaborator is null
     * @throws IOException if bounded validation, replay, activation, or recovery ownership preparation fails
     */
    /* default */ static Handle recover(Path root, Configuration configuration,
            RecoverySink sink) throws IOException {
        return recover(root, configuration, sink, new SystemActiveOperations(), SYSTEM_CLOCK,
                SYSTEM_WAIT);
    }

    /**
     * Validates the complete root and manifest layout without opening or repairing the active WAL.
     *
     * @param root existing ledger directory; symbolic-link roots are rejected
     * @param configuration validated limits for layout, replay, and active WAL resources
     * @throws NullPointerException if configuration or root is null
     * @throws IOException if layout, referenced artifacts, orphan classification, or bounded filesystem access fails
     */
    /* default */ static void validateExistingLayout(Path root, Configuration configuration)
            throws IOException {
        Objects.requireNonNull(configuration, "configuration");
        try {
            requireRoot(root);
        } catch (IllegalArgumentException malformed) {
            throw failure(Code.ROOT_ENTRY_INVALID);
        }
        RootIndex rootIndex = enumerate(root, configuration.maximumRootEntries());
        validateFormat(root, rootIndex);
        SigningManifestCodec.Manifest manifest = readManifest(root, rootIndex);
        validateReferencedArtifacts(root, manifest, rootIndex, configuration);
        classifyOrphans(root, manifest, rootIndex, configuration);
    }

    /**
     * Recovers and publishes the ledger, then starts its active WAL writer.
     *
     * <p>Only manifest-referenced committed artifacts are replayed. Resources acquired before a failed handoff are cleaned up. Recovery-stage faults are inherited from the current thread when no explicit observer is supplied. Publication and ordered lifecycle transitions complete before the ready handle is returned.</p>
     *
     * @param root existing ledger directory; symbolic-link roots are rejected
     * @param configuration validated limits for layout, replay, and active WAL resources
     * @param sink transactional replay sink; prepared publication must be failure-free
     * @param activeOperations borrowed filesystem/channel operations used for passive WAL activation
     * @param clock monotonic nanosecond source for active-WAL grouping and metrics
     * @param waitStrategy interruptible monitor-wait strategy used by the active WAL writer
     * @return owned ready recovery handle; the caller must close it
     * @throws NullPointerException if a required configuration, sink, or injected collaborator is null
     * @throws IOException if bounded validation, replay, activation, or recovery ownership preparation fails
     */
    /* default */ static Handle recover(Path root, Configuration configuration,
            RecoverySink sink, SigningActiveWal.Operations activeOperations,
            SigningActiveWal.NanoClock clock,
            SigningActiveWal.GroupWaitStrategy waitStrategy) throws IOException {
        PreparedOpen prepared = prepare(root, configuration, sink, activeOperations, clock,
                waitStrategy);
        ActivatedOpen activated = null;
        try {
            activated = prepared.activate();
            activated.publishRecoveredState();
            activated.markEngineReconstructed();
            activated.markRecoveryWritesForced();
            activated.activeWal().startWriter();
            activated.markThreadsStarted();
            Handle result = activated.transferToStartedEngine();
            activated = null;
            return result;
        } finally {
            closeSuppressing(activated);
            closeSuppressing(prepared);
        }
    }

    /**
     * Validates and replays the authoritative ledger into isolated state without starting a writer.
     *
     * <p>Only manifest-referenced committed artifacts are replayed. Resources acquired before a failed handoff are cleaned up. Recovery-stage faults are inherited from the current thread when no explicit observer is supplied. Active-WAL suffix repair is deferred until activation; this pass does not publish recovered state.</p>
     *
     * @param root existing ledger directory; symbolic-link roots are rejected
     * @param configuration validated limits for layout, replay, and active WAL resources
     * @param sink transactional replay sink; prepared publication must be failure-free
     * @return owned read-only prepared candidate; activate or close it before discarding
     * @throws NullPointerException if a required configuration, sink, or injected collaborator is null
     * @throws IOException if bounded validation, replay, activation, or recovery ownership preparation fails
     */
    /* default */ static PreparedOpen prepare(Path root, Configuration configuration,
            RecoverySink sink) throws IOException {
        return prepare(root, configuration, sink, new SystemActiveOperations(), SYSTEM_CLOCK,
                SYSTEM_WAIT, recoveryFault());
    }

    /**
     * Validates and replays the authoritative ledger into isolated state without starting a writer.
     *
     * <p>Only manifest-referenced committed artifacts are replayed. Resources acquired before a failed handoff are cleaned up. Recovery-stage faults are inherited from the current thread when no explicit observer is supplied. Active-WAL suffix repair is deferred until activation; this pass does not publish recovered state.</p>
     *
     * @param root existing ledger directory; symbolic-link roots are rejected
     * @param configuration validated limits for layout, replay, and active WAL resources
     * @param sink transactional replay sink; prepared publication must be failure-free
     * @param activeOperations borrowed filesystem/channel operations used for passive WAL activation
     * @param clock monotonic nanosecond source for active-WAL grouping and metrics
     * @param waitStrategy interruptible monitor-wait strategy used by the active WAL writer
     * @return owned read-only prepared candidate; activate or close it before discarding
     * @throws NullPointerException if a required configuration, sink, or injected collaborator is null
     * @throws IOException if bounded validation, replay, activation, or recovery ownership preparation fails
     */
    /* default */ static PreparedOpen prepare(Path root, Configuration configuration,
            RecoverySink sink, SigningActiveWal.Operations activeOperations,
            SigningActiveWal.NanoClock clock,
            SigningActiveWal.GroupWaitStrategy waitStrategy) throws IOException {
        return prepare(root, configuration, sink, activeOperations, clock, waitStrategy,
                recoveryFault());
    }

    /**
     * Installs a recovery-stage fault observer for the current thread only.
     *
     * <p>Tests must call clearRecoveryFault in a finally block to avoid retaining the observer for later work.</p>
     *
     * @param fault non-null recovery-stage observer installed only for the current thread
     * @throws NullPointerException if the observer is null
     */
    /* default */ static void installRecoveryFault(RecoveryFaultInjector fault) {
        RECOVERY_FAULTS.set(Objects.requireNonNull(fault, "fault"));
    }

    /**
     * Removes the current thread's recovery-stage observer, restoring the no-op observer.
     */
    /* default */ static void clearRecoveryFault() {
        RECOVERY_FAULTS.remove();
    }

    private static RecoveryFaultInjector recoveryFault() {
        RecoveryFaultInjector fault = RECOVERY_FAULTS.get();
        return fault == null ? NO_RECOVERY_FAULT : fault;
    }

    /**
     * Validates and replays the authoritative ledger into isolated state without starting a writer.
     *
     * <p>Only manifest-referenced committed artifacts are replayed. Resources acquired before a failed handoff are cleaned up. Recovery-stage faults are inherited from the current thread when no explicit observer is supplied. Active-WAL suffix repair is deferred until activation; this pass does not publish recovered state.</p>
     *
     * @param root existing ledger directory; symbolic-link roots are rejected
     * @param configuration validated limits for layout, replay, and active WAL resources
     * @param sink transactional replay sink; prepared publication must be failure-free
     * @param activeOperations borrowed filesystem/channel operations used for passive WAL activation
     * @param clock monotonic nanosecond source for active-WAL grouping and metrics
     * @param waitStrategy interruptible monitor-wait strategy used by the active WAL writer
     * @param faults recovery-stage observer used for deterministic cleanup-failure tests
     * @return owned read-only prepared candidate; activate or close it before discarding
     * @throws NullPointerException if a required configuration, sink, or injected collaborator is null
     * @throws IOException if bounded validation, replay, activation, or recovery ownership preparation fails
     */
    /* default */ static PreparedOpen prepare(Path root, Configuration configuration,
            RecoverySink sink, SigningActiveWal.Operations activeOperations,
            SigningActiveWal.NanoClock clock,
            SigningActiveWal.GroupWaitStrategy waitStrategy,
            RecoveryFaultInjector faults) throws IOException {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(sink, "sink");
        Objects.requireNonNull(activeOperations, "activeOperations");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(waitStrategy, "waitStrategy");
        Objects.requireNonNull(faults, "faults");
        try {
            requireRoot(root);
            RootIndex rootIndex = enumerate(root, configuration.maximumRootEntries());
            validateFormat(root, rootIndex);
            SigningManifestCodec.Manifest manifest = readManifest(root, rootIndex);
            validateReferencedArtifacts(root, manifest, rootIndex, configuration);

            SigningGenerationRegistry registry = new SigningGenerationRegistry();
            SigningGenerationRegistry.CurrentReferences currentReferences = null;
            SigningGenerationRegistry.SnapshotPins pins = null;
            RecoverySink.Session session = null;
            RecoverySink.Prepared prepared = null;
            try {
                List<Long> identities = generationIdentities(manifest);
                for (Long identity : identities) {
                    registry.create(identity);
                    registry.publish(identity);
                }
                currentReferences = registry.acquireCurrent(
                        SigningGenerationRegistry.Owner.RECOVERY_TEMPORARY, identities);
                pins = registry.pinSnapshot(identities);
                CleanupPlan cleanupPlan = classifyOrphans(root, manifest, rootIndex,
                        configuration);
                session = sink.begin(manifest);
                CheckpointBoundary checkpoint = replayCheckpoint(root, manifest,
                        configuration, session);
                long sealedFrames = replaySealed(root, manifest, configuration,
                        checkpoint, session);
                ActiveValidation active = replayActive(root, manifest, configuration, session);
                prepared = session.prepare();
                session = null;
                faults.after(RecoveryStage.AFTER_READ_ONLY_REPLAY, registry);

                Statistics statistics = new Statistics(rootIndex.entries().size(),
                        manifest.sealedSegments().size(), checkpoint.entryCount(), sealedFrames,
                        active.frameCount(),
                        active.truncatedBytes(), cleanupPlan.staleTemporaryCount(),
                        cleanupPlan.unreferencedArtifactCount());
                PreparedOpen result = new PreparedOpen(root, configuration, manifest,
                        cleanupPlan, registry, currentReferences, pins, prepared, statistics,
                        active.validatedState(), activeOperations, clock, waitStrategy, faults);
                registry = null;
                currentReferences = null;
                pins = null;
                prepared = null;
                return result;
            } finally {
                closeSuppressing(prepared);
                closeSuppressing(session);
                closeSuppressing(pins);
                closeSuppressing(currentReferences);
                closeSuppressing(registry);
            }
        } catch (RuntimeException failure) {
            throw failure(Code.RECOVERY_INVALID);
        }
    }

    private static void validateReferencedArtifacts(Path root,
            SigningManifestCodec.Manifest manifest, RootIndex rootIndex,
            Configuration configuration) throws IOException {
        Set<String> authoritative = authoritativeNames(manifest);
        for (String name : authoritative) {
            RootEntry entry = rootIndex.byName().get(name);
            if (entry == null) {
                throw failure(Code.REFERENCED_MISSING);
            }
            requireRegular(entry, Code.REFERENCED_INVALID);
        }

        validateSealedHeaders(root, manifest, configuration);
        validateActiveHeader(root, manifest.activeWal(), configuration);
    }

    private static CleanupPlan classifyOrphans(Path root,
            SigningManifestCodec.Manifest manifest, RootIndex rootIndex,
            Configuration configuration) throws IOException {
        Set<String> authoritative = authoritativeNames(manifest);
        List<CleanupEntry> classifications = new ArrayList<>();
        for (RootEntry entry : rootIndex.entries()) {
            String name = entry.name();
            if (authoritative.contains(name)) {
                continue;
            } else if (isStrictTemporaryName(name)) {
                requireRegular(entry, Code.ORPHAN_INVALID);
                classifications.add(new CleanupEntry(name, Category.SAFE_STALE_TEMPORARY));
            } else if (isKnownArtifactName(name)) {
                requireRegular(entry, Code.ORPHAN_INVALID);
                validateUnreferenced(root.resolve(name), name, configuration);
                classifications.add(new CleanupEntry(name,
                        Category.ORPHAN_ARTIFACT_DEFERRED));
            } else {
                throw failure(Code.ORPHAN_UNSUPPORTED);
            }
        }
        classifications.sort(Comparator.comparing(CleanupEntry::name));
        return new CleanupPlan(classifications);
    }

    private static void validateSealedHeaders(Path root, SigningManifestCodec.Manifest manifest,
            Configuration configuration) throws IOException {
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            Path path = root.resolve(segment.name());
            requireExactSize(path, segment.length(), configuration.maximumArtifactBytes());
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                    LinkOption.NOFOLLOW_LINKS)) {
                SigningWalContainerCodec.Header header = readWalHeader(channel);
                if (header.identity() != segment.generationIdentity()
                        || header.firstSequence() != segment.firstSequence()) {
                    throw failure(Code.REFERENCED_INVALID);
                }
            }
        }
    }

    private static void validateActiveHeader(Path root, SigningManifestCodec.ActiveWal descriptor,
            Configuration configuration) throws IOException {
        Path path = root.resolve(descriptor.name());
        long size = Files.size(path);
        if (size < descriptor.length() || size > configuration.maximumArtifactBytes()) {
            throw failure(Code.REFERENCED_INVALID);
        }
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            SigningWalContainerCodec.Header header = readWalHeader(channel);
            byte[] encoded = SigningWalContainerCodec.encode(header);
            if (header.identity() != descriptor.identity()
                    || header.firstSequence() != descriptor.firstSequence()
                    || header.baselineRevision() != descriptor.baselineRevision()
                    || descriptor.length() != SigningWalContainerCodec.HEADER_BYTES
                    || !MessageDigest.isEqual(SigningFormatSupport.sha256().digest(encoded),
                            descriptor.commitment())) {
                throw failure(Code.REFERENCED_INVALID);
            }
        }
    }

    private static CheckpointBoundary replayCheckpoint(Path root,
            SigningManifestCodec.Manifest manifest,
            Configuration configuration, RecoverySink.Session session) throws IOException {
        if (manifest.checkpoint().isEmpty()) {
            return CheckpointBoundary.empty();
        }
        SigningManifestCodec.Checkpoint descriptor = manifest.checkpoint().orElseThrow();
        Path path = root.resolve(descriptor.name());
        requireExactSize(path, descriptor.length(), configuration.maximumArtifactBytes());
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            try {
                SigningCheckpointCodec.Reader reader = SigningCheckpointCodec.reader(channel);
                SigningCheckpointCodec.Header header = reader.header();
                if (header.generationIdentity() != descriptor.generationIdentity()
                        || header.revision() != descriptor.revision()
                        || header.committedSequence() != descriptor.coveredSequence()
                        || header.entryCount() > configuration.maximumCheckpointEntries()) {
                    throw failure(Code.REFERENCED_INVALID);
                }
                Optional<SigningCheckpointCodec.EntryDescriptor> entry;
                while ((entry = reader.next()).isPresent()) {
                    SigningCheckpointCodec.EntryDescriptor descriptorEntry = entry.orElseThrow();
                    SigningWalFrameCodec.Frame frame = reader.readFrame(descriptorEntry);
                    acceptCheckpoint(session, header, descriptorEntry, frame);
                }
                reader.verifyComplete();
                if (!MessageDigest.isEqual(reader.fileCommitment(), descriptor.commitment())) {
                    throw failure(Code.REFERENCED_INVALID);
                }
                acceptCheckpointBoundary(session, header);
                return new CheckpointBoundary(header.entryCount(), header.revision(),
                        header.committedSequence());
            } catch (SigningCheckpointCodec.MalformedCheckpointException malformed) {
                throw failure(Code.RECOVERY_INVALID);
            }
        }
    }

    private static long replaySealed(Path root, SigningManifestCodec.Manifest manifest,
            Configuration configuration, CheckpointBoundary checkpoint,
            RecoverySink.Session session) throws IOException {
        long frameCount = 0L;
        long expectedRevision = checkpoint.revision();
        long expectedSequence = checkpoint.nextSequence();
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            Path path = root.resolve(segment.name());
            requireExactSize(path, segment.length(), configuration.maximumArtifactBytes());
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                    LinkOption.NOFOLLOW_LINKS)) {
                SigningWalContainerCodec.Header header = readWalHeader(channel);
                if (header.identity() != segment.generationIdentity()
                        || header.firstSequence() != expectedSequence
                        || header.baselineRevision() != expectedRevision) {
                    throw failure(Code.REFERENCED_INVALID);
                }
                long[] nextRevision = { Math.incrementExact(expectedRevision) };
                SigningWalFrameCodec.ScanResult scan = scanGroups(channel,
                        segment.firstSequence(), false, (frames, marker) -> {
                            List<SigningWalFrameCodec.ScannedFrame> suffix = new ArrayList<>();
                            for (SigningWalFrameCodec.ScannedFrame scanned : frames) {
                                long revision = scanned.revision();
                                if (revision != nextRevision[0]) {
                                    throw failure(Code.REPLAY_CONTINUITY_INVALID);
                                }
                                nextRevision[0] = Math.incrementExact(revision);
                                suffix.add(scanned);
                            }
                            if (!suffix.isEmpty()) {
                                acceptWalGroup(session, List.copyOf(suffix),
                                        marker.committedRevision());
                            }
                        }, true);
                long last = Math.addExact(segment.firstSequence(), segment.sequenceCount() - 1L);
                if (scan.frameCount() != segment.sequenceCount() || scan.lastSequence() != last
                        || !MessageDigest.isEqual(scan.fileCommitment(), segment.commitment())
                        || scan.committedRevision() < expectedRevision) {
                    throw failure(Code.REFERENCED_INVALID);
                }
                expectedRevision = scan.committedRevision();
                expectedSequence = Math.incrementExact(last);
                frameCount = Math.addExact(frameCount, scan.frameCount());
            }
        }
        if (expectedRevision != manifest.committedRevision()
                || expectedSequence != manifest.activeWal().firstSequence()) {
            throw failure(Code.REPLAY_CONTINUITY_INVALID);
        }
        return frameCount;
    }

    private static ActiveValidation replayActive(Path root,
            SigningManifestCodec.Manifest manifest, Configuration configuration,
            RecoverySink.Session session) throws IOException {
        SigningManifestCodec.ActiveWal descriptor = manifest.activeWal();
        Path path = root.resolve(descriptor.name());
        long observedLength = Files.size(path);
        if (observedLength < SigningWalContainerCodec.HEADER_BYTES
                || observedLength > configuration.maximumArtifactBytes()) {
            throw failure(Code.ACTIVE_INVALID);
        }
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            long[] currentRevision = { manifest.committedRevision() };
            SigningWalFrameCodec.ScanResult scan = scanGroups(channel,
                    descriptor.firstSequence(), true,
                    (frames, marker) -> {
                        for (SigningWalFrameCodec.ScannedFrame scanned : frames) {
                            if (scanned.revision() != Math.incrementExact(currentRevision[0])) {
                                throw failure(Code.REPLAY_CONTINUITY_INVALID);
                            }
                            currentRevision[0] = scanned.revision();
                        }
                        acceptWalGroup(session, frames, marker.committedRevision());
                    });
            long end = scan.hasIncompleteTail() ? scan.incompleteTailOffset() : observedLength;
            long lastSequence = scan.frameCount() == 0L
                    ? predecessor(descriptor.firstSequence()) : scan.lastSequence();
            SigningActiveWal.ValidatedState validated = new SigningActiveWal.ValidatedState(
                    observedLength, end, lastSequence, scan.committedRevision(),
                    scan.rollingCommitment());
            return new ActiveValidation(validated, scan.frameCount(), observedLength - end);
        }
    }

    private static SigningWalFrameCodec.ScanResult scanGroups(FileChannel channel,
            long expectedFirstSequence, boolean activeWal,
            SigningWalFrameCodec.GroupConsumer consumer) throws IOException {
        return scanGroups(channel, expectedFirstSequence, activeWal, consumer, false);
    }

    private static SigningWalFrameCodec.ScanResult scanGroups(FileChannel channel,
            long expectedFirstSequence, boolean activeWal,
            SigningWalFrameCodec.GroupConsumer consumer,
            boolean calculateFileCommitment) throws IOException {
        try {
            return SigningWalFrameCodec.scanGroups(new OperationalSeekableChannel(channel),
                    expectedFirstSequence, activeWal, consumer, calculateFileCommitment);
        } catch (OperationalChannelException operational) {
            throw operational.failure();
        } catch (RecoveryException malformed) {
            throw malformed;
        } catch (IOException malformed) {
            throw failure(Code.RECOVERY_INVALID);
        }
    }

    private static void acceptCheckpoint(RecoverySink.Session session,
            SigningCheckpointCodec.Header header,
            SigningCheckpointCodec.EntryDescriptor entry,
            SigningWalFrameCodec.Frame frame) throws RecoveryException {
        try {
            session.acceptCheckpoint(header, entry, frame);
        } catch (RecoveryException malformed) {
            throw malformed;
        } catch (IOException malformed) {
            throw failure(Code.RECOVERY_INVALID);
        }
    }

    private static void acceptCheckpointBoundary(RecoverySink.Session session,
            SigningCheckpointCodec.Header header) throws RecoveryException {
        try {
            session.acceptCheckpointBoundary(header);
        } catch (RecoveryException malformed) {
            throw malformed;
        } catch (IOException malformed) {
            throw failure(Code.RECOVERY_INVALID);
        }
    }

    private static void acceptWalGroup(RecoverySink.Session session,
            List<SigningWalFrameCodec.ScannedFrame> frames,
            long committedRevision) throws RecoveryException {
        try {
            session.acceptWalGroup(frames, committedRevision);
        } catch (RecoveryException malformed) {
            throw malformed;
        } catch (IOException malformed) {
            throw failure(Code.RECOVERY_INVALID);
        }
    }

    private static void validateUnreferenced(Path path, String name,
            Configuration configuration) throws IOException {
        long size = Files.size(path);
        if (size <= 0L || size > configuration.maximumArtifactBytes()) {
            throw failure(Code.ORPHAN_INVALID);
        }
        if (name.startsWith("checkpoint-")) {
            long[] fields = parseTwoFields(name, "checkpoint-", ".zec");
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                    LinkOption.NOFOLLOW_LINKS)) {
                try {
                    SigningCheckpointCodec.Reader reader = SigningCheckpointCodec.reader(channel);
                    if (reader.header().revision() != fields[0]
                            || reader.header().committedSequence() != fields[1]
                            || reader.header().entryCount()
                                    > configuration.maximumCheckpointEntries()) {
                        throw failure(Code.ORPHAN_INVALID);
                    }
                } catch (SigningCheckpointCodec.MalformedCheckpointException malformed) {
                    throw failure(Code.ORPHAN_INVALID);
                }
            }
            return;
        }
        if (name.startsWith("wal-active-")) {
            long identity = parseOneField(name, "wal-active-", ".zew");
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                    LinkOption.NOFOLLOW_LINKS)) {
                SigningWalContainerCodec.Header header = readWalHeader(channel);
                if (header.identity() != identity) {
                    throw failure(Code.ORPHAN_INVALID);
                }
            }
            return;
        }
        long[] fields = parseTwoFields(name, "wal-", ".zew");
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            SigningWalContainerCodec.Header header = readWalHeader(channel);
            if (header.firstSequence() != fields[0]) {
                throw failure(Code.ORPHAN_INVALID);
            }
        }
    }

    private static SigningWalContainerCodec.Header readWalHeader(FileChannel channel)
            throws IOException {
        channel.position(0L);
        ByteBuffer encoded = ByteBuffer.allocate(SigningWalContainerCodec.HEADER_BYTES);
        if (SigningFormatSupport.readAvailable(channel, encoded)
                != SigningWalContainerCodec.HEADER_BYTES) {
            throw failure(Code.REFERENCED_INVALID);
        }
        try {
            return SigningWalContainerCodec.decode(encoded.array());
        } catch (IOException malformed) {
            throw failure(Code.REFERENCED_INVALID);
        }
    }

    private static void requireExactSize(Path path, long expected, long maximum) throws IOException {
        long actual = Files.size(path);
        if (actual != expected || actual > maximum) {
            throw failure(Code.REFERENCED_INVALID);
        }
    }

    private static SigningManifestCodec.Manifest readManifest(Path root, RootIndex rootIndex)
            throws IOException {
        RootEntry entry = rootIndex.byName().get(MANIFEST_FILE);
        if (entry == null) {
            throw failure(Code.MANIFEST_MISSING);
        }
        requireRegular(entry, Code.MANIFEST_INVALID);
        Path path = root.resolve(MANIFEST_FILE);
        long size = Files.size(path);
        if (size <= 0L || size > SigningManifestCodec.MAX_ENCODED_BYTES) {
            throw failure(Code.MANIFEST_INVALID);
        }
        byte[] encoded = new byte[Math.toIntExact(size)];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            if (SigningFormatSupport.readAvailable(channel, ByteBuffer.wrap(encoded)) != size) {
                throw failure(Code.MANIFEST_INVALID);
            }
        }
        try {
            return SigningManifestCodec.decode(encoded);
        } catch (IOException malformed) {
            throw failure(Code.MANIFEST_INVALID);
        }
    }

    private static void validateFormat(Path root, RootIndex rootIndex) throws IOException {
        if (rootIndex.entries().isEmpty()) {
            throw failure(Code.EMPTY_ROOT);
        }
        RootEntry marker = rootIndex.byName().get(FORMAT_FILE);
        if (marker == null) {
            throw failure(Code.LEGACY_OR_UNKNOWN_ROOT);
        }
        requireRegular(marker, Code.FORMAT_UNSUPPORTED);
        Path path = root.resolve(FORMAT_FILE);
        if (Files.size(path) != FORMAT_CONTENT.length) {
            throw failure(Code.FORMAT_UNSUPPORTED);
        }
        byte[] actual = new byte[FORMAT_CONTENT.length];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            if (SigningFormatSupport.readAvailable(channel, ByteBuffer.wrap(actual))
                    != FORMAT_CONTENT.length) {
                throw failure(Code.FORMAT_UNSUPPORTED);
            }
        }
        if (!Arrays.equals(actual, FORMAT_CONTENT)) {
            throw failure(Code.FORMAT_UNSUPPORTED);
        }
    }

    private static RootIndex enumerate(Path root, int maximumEntries) throws IOException {
        List<RootEntry> entries = new ArrayList<>();
        Map<String, RootEntry> byName = new HashMap<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(root)) {
            for (Path path : stream) {
                if (entries.size() == maximumEntries) {
                    throw failure(Code.ROOT_ENTRY_LIMIT);
                }
                BasicFileAttributes attributes = Files.readAttributes(path,
                        BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                RootEntry entry = new RootEntry(path.getFileName().toString(), attributes);
                entries.add(entry);
                if (byName.put(entry.name(), entry) != null) {
                    throw failure(Code.ROOT_ENTRY_INVALID);
                }
            }
        }
        return new RootIndex(List.copyOf(entries), Map.copyOf(byName));
    }

    private static Set<String> authoritativeNames(SigningManifestCodec.Manifest manifest) {
        Set<String> names = new HashSet<>();
        names.add(FORMAT_FILE);
        names.add(MANIFEST_FILE);
        manifest.checkpoint().ifPresent(value -> names.add(value.name()));
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            names.add(segment.name());
        }
        names.add(manifest.activeWal().name());
        return Set.copyOf(names);
    }

    private static List<Long> generationIdentities(SigningManifestCodec.Manifest manifest) {
        List<Long> identities = new ArrayList<>(manifest.sealedSegments().size() + 2);
        manifest.checkpoint().ifPresent(value -> identities.add(value.generationIdentity()));
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            identities.add(segment.generationIdentity());
        }
        identities.add(manifest.activeWal().identity());
        return List.copyOf(identities);
    }

    private static void requireRegular(RootEntry entry, Code code) throws RecoveryException {
        if (!entry.attributes().isRegularFile() || entry.attributes().isSymbolicLink()
                || entry.attributes().isDirectory()) {
            throw failure(code);
        }
    }

    private static boolean isStrictTemporaryName(String name) {
        if (!name.startsWith(".") || !name.endsWith(".tmp") || name.length() < 42) {
            return false;
        }
        int uuidStart = name.length() - 40;
        if (name.charAt(uuidStart - 1) != '-') {
            return false;
        }
        String target = name.substring(1, uuidStart - 1);
        if (!MANIFEST_FILE.equals(target) && !isKnownArtifactName(target)) {
            return false;
        }
        try {
            UUID.fromString(name.substring(uuidStart, name.length() - 4));
            return true;
        } catch (IllegalArgumentException failure) {
            return false;
        }
    }

    private static boolean isKnownArtifactName(String name) {
        try {
            if (name.startsWith("checkpoint-")) {
                parseTwoFields(name, "checkpoint-", ".zec");
                return true;
            }
            if (name.startsWith("wal-active-")) {
                parseOneField(name, "wal-active-", ".zew");
                return true;
            }
            if (name.startsWith("wal-")) {
                long[] fields = parseTwoFields(name, "wal-", ".zew");
                return fields[1] >= fields[0];
            }
            return false;
        } catch (IOException failure) {
            return false;
        }
    }

    private static long parseOneField(String name, String prefix, String suffix) throws IOException {
        if (name.length() != prefix.length() + 20 + suffix.length()
                || !name.startsWith(prefix) || !name.endsWith(suffix)) {
            throw failure(Code.ORPHAN_INVALID);
        }
        return parseTwentyDigits(name, prefix.length());
    }

    private static long[] parseTwoFields(String name, String prefix, String suffix)
            throws IOException {
        if (name.length() != prefix.length() + 41 + suffix.length()
                || !name.startsWith(prefix) || !name.endsWith(suffix)
                || name.charAt(prefix.length() + 20) != '-') {
            throw failure(Code.ORPHAN_INVALID);
        }
        return new long[] { parseTwentyDigits(name, prefix.length()),
                parseTwentyDigits(name, prefix.length() + 21) };
    }

    private static long parseTwentyDigits(String value, int offset) throws IOException {
        long result = 0L;
        try {
            for (int index = 0; index < 20; index++) {
                char character = value.charAt(offset + index);
                if (character < '0' || character > '9') {
                    throw failure(Code.ORPHAN_INVALID);
                }
                result = Math.addExact(Math.multiplyExact(result, 10L), character - '0');
            }
            return result;
        } catch (ArithmeticException failure) {
            throw failure(Code.ORPHAN_INVALID);
        }
    }

    private static long predecessor(long value) {
        return value == 0L ? -1L : value - 1L;
    }

    private static void requireRoot(Path root) {
        Objects.requireNonNull(root, "root");
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(root)) {
            throw new IllegalArgumentException("signing ledger root is invalid");
        }
    }

    private static RecoveryException failure(Code code) {
        return new RecoveryException(code);
    }

    /**
     * Marks only failures emitted by the underlying filesystem channel.
     */
    private static final class OperationalChannelException extends IOException {
        private static final long serialVersionUID = 1L;
        private final IOException failure;

        private OperationalChannelException(IOException failure) {
            super();
            this.failure = failure;
        }

        private IOException failure() {
            return failure;
        }
    }

    /**
     * Preserves the origin of channel I/O while the WAL codec classifies malformed bytes.
     */
    private static final class OperationalSeekableChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;

        private OperationalSeekableChannel(SeekableByteChannel delegate) {
            this.delegate = delegate;
        }

        /**
         * {@inheritDoc}
         */
        @Override public int read(ByteBuffer target) throws IOException {
            try {
                return delegate.read(target);
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override public int write(ByteBuffer source) {
            throw new UnsupportedOperationException("read-only recovery channel");
        }

        /**
         * {@inheritDoc}
         */
        @Override public long position() throws IOException {
            try {
                return delegate.position();
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override public SeekableByteChannel position(long newPosition) throws IOException {
            try {
                delegate.position(newPosition);
                return this;
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override public long size() throws IOException {
            try {
                return delegate.size();
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override public SeekableByteChannel truncate(long size) {
            throw new UnsupportedOperationException("read-only recovery channel");
        }

        /**
         * {@inheritDoc}
         */
        @Override public boolean isOpen() {
            return delegate.isOpen();
        }

        /**
         * Closes the wrapped filesystem channel without affecting other recovery resources.
         *
         * @throws IOException if delegate closure fails; the failure is wrapped in OperationalChannelException
         */
        @Override public void close() throws IOException {
            try {
                delegate.close();
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }
    }

    @SuppressWarnings("PMD.EmptyCatchBlock")
    private static void closeSuppressing(AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception failure) {
                // A primary stable recovery result remains authoritative.
            }
        }
    }

    /**
     * Explicit recovery bounds and active-WAL resource configuration.
     *
     * @param maximumRootEntries maximum permitted number of root entries
     * @param maximumArtifactBytes inclusive maximum length in bytes of one recovery artifact
     * @param maximumCheckpointEntries inclusive maximum checkpoint record count
     * @param activeWalConfiguration resource and batching bounds used when activating the recovered WAL
     */
    /* default */ record Configuration(int maximumRootEntries, long maximumArtifactBytes,
            int maximumCheckpointEntries,
            SigningActiveWal.Configuration activeWalConfiguration) {
        /**
         * Creates a {@code Configuration} value from the supplied component coordinates.
         *
         * @param maximumRootEntries maximum permitted number of root entries
         * @param maximumArtifactBytes inclusive maximum length in bytes of one recovery artifact
         * @param maximumCheckpointEntries inclusive maximum checkpoint record count
         * @param activeWalConfiguration resource and batching bounds used when activating the recovered WAL
         * @throws NullPointerException if {@code activeWalConfiguration} is null
         * @throws IllegalArgumentException if root-entry, artifact-size, or checkpoint-entry limits fall outside the supported format bounds
         */
        Configuration {
            Objects.requireNonNull(activeWalConfiguration, "activeWalConfiguration");
            if (maximumRootEntries <= 0 || maximumRootEntries > MAXIMUM_ROOT_ENTRIES
                    || maximumArtifactBytes < SigningWalContainerCodec.HEADER_BYTES
                    || maximumArtifactBytes > SigningManifestCodec.MAX_FILE_BYTES
                    || maximumCheckpointEntries < 0
                    || maximumCheckpointEntries > SigningCheckpointCodec.MAX_ENTRIES) {
                throw new IllegalArgumentException("signing recovery configuration is invalid");
            }
        }

        /**
         * Creates standard recovery limits and the default bounded active-WAL configuration.
         *
         * @return immutable configuration allowing 8192 root entries and the format-defined artifact/checkpoint limits
         */
        /* default */ static Configuration defaults() {
            return new Configuration(8192, SigningManifestCodec.MAX_FILE_BYTES,
                    SigningCheckpointCodec.MAX_ENTRIES,
                    SigningActiveWal.Configuration.defaults());
        }
    }

    /**
     * Transactional bounded replay seam. Publish must be failure-free after prepare succeeds.
     */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface RecoverySink {
        /**
         * Begins an isolated transactional fold for one validated manifest.
         *
         * @param manifest validated manifest identifying the authoritative artifact generation set
         * @return owned replay session; close it on failure or transfer ownership through prepare
         * @throws IOException if an isolated recovery transaction cannot be created
         */
        Session begin(SigningManifestCodec.Manifest manifest) throws IOException;

        /**
         * Receives bounded validated input and can roll it back until prepared.
         */
        interface Session extends AutoCloseable {
            /**
             * Folds one validated checkpoint record into the unpublished recovery transaction.
             *
             * @param header validated checkpoint header carrying the exact generation/revision boundary
             * @param entry validated descriptor locating the record in its checkpoint
             * @param frame decoded checkpoint frame to fold into isolated recovered state
             * @throws IOException if the checkpoint record contradicts recovered state or cannot be staged
             */
            void acceptCheckpoint(SigningCheckpointCodec.Header header,
                    SigningCheckpointCodec.EntryDescriptor entry,
                    SigningWalFrameCodec.Frame frame) throws IOException;
            /**
             * Installs the fully verified checkpoint sequence and revision boundary.
             *
             * @param header validated checkpoint header carrying the exact generation/revision boundary
             * @throws IOException if the checkpoint boundary contradicts the staged record set
             */
            void acceptCheckpointBoundary(SigningCheckpointCodec.Header header)
                    throws IOException;
            /**
             * Folds one fully committed bounded WAL group into the recovery transaction.
             *
             * @param frames ordered fully committed WAL data frames; at most 32 per replay group
             * @param committedRevision revision covered by the validated WAL commit marker
             * @throws IOException if replayed records, transaction identity, or committed revision are inconsistent
             */
            void acceptWalGroup(List<SigningWalFrameCodec.ScannedFrame> frames,
                    long committedRevision) throws IOException;
            /**
             * Seals the isolated replay result after complete input validation.
             *
             * <p>The prepared candidate assumes the recovered-state resources previously owned by this session.</p>
             *
             * @return owned candidate whose publish operation must complete atomically without failure
             * @throws IOException if the staged state is incomplete or internally inconsistent
             */
            Prepared prepare() throws IOException;
            /**
             * Discards resources still owned by the unpublished replay session.
             */
            @Override void close();
        }

        /**
         * Prepared recovered state owned by the returned recovery handle.
         */
        interface Prepared extends AutoCloseable {
            /**
             * Atomically makes the prepared recovered state visible and must not fail.
             */
            void publish();
            /**
             * Releases resources retained by the prepared recovered-state candidate.
             */
            @Override void close();
        }
    }

    /**
     * Monotonic lifecycle of a recovered ledger before it becomes externally usable.
     */
    /* default */ enum OpenState {
        /**
         * Read-only replay has prepared recovery state without activating writers.
         */
        PREPARED_READ_ONLY,
        /**
         * The passive WAL has been activated for recovery.
         */
        PASSIVE_ACTIVATED,
        /**
         * The store engine has been reconstructed from retained evidence.
         */
        ENGINE_RECONSTRUCTED,
        /**
         * Recovery writes have crossed their durability barriers.
         */
        RECOVERY_WRITES_FORCED,
        /**
         * Owned runtime threads have been started.
         */
        THREADS_STARTED,
        /**
         * Recovered resources have transferred to the running store engine.
         */
        OWNERSHIP_TRANSFERRED
    }

    /**
     * Deterministic recovery boundaries used by ownership cleanup tests.
     */
    /* default */ enum RecoveryStage {
        /**
         * Observation point after read-only replay.
         */
        AFTER_READ_ONLY_REPLAY,
        /**
         * Observation point before opening the passive WAL.
         */
        BEFORE_PASSIVE_WAL_OPEN,
        /**
         * Observation point after opening the passive WAL.
         */
        AFTER_PASSIVE_WAL_OPEN,
        /**
         * Observation point after repairing the incomplete WAL tail.
         */
        AFTER_TAIL_REPAIR
    }

    /**
     * Package-local fault seam for recovery ownership cleanup verification.
     */
    /* default */
    @FunctionalInterface
    interface RecoveryFaultInjector {
        /**
         * Observes a recovery boundary and may inject a cleanup-test failure.
         *
         * @param stage recovery boundary that has just completed
         * @param registry borrowed generation registry whose ownership is being observed
         * @throws IOException if failure is requested at this recovery boundary
         */
        void after(RecoveryStage stage, SigningGenerationRegistry registry) throws IOException;
    }

    /**
     * Small shared transition guard carried across each ownership handoff.
     */
    private static final class OpenLifecycle {
        private OpenState state = OpenState.PREPARED_READ_ONLY;

        private synchronized OpenState state() {
            return state;
        }

        private synchronized void advance(OpenState expected, OpenState next) {
            if (state != expected) {
                throw new IllegalStateException("signing recovery lifecycle transition is invalid");
            }
            state = next;
        }
    }

    /**
     * Read-only validated recovery ownership before the active WAL is opened for repair.
     */
    /* default */ static final class PreparedOpen implements AutoCloseable {
        private final Path root;
        private final Configuration configuration;
        private final SigningManifestCodec.Manifest manifest;
        private final CleanupPlan cleanupPlan;
        private final SigningGenerationRegistry registry;
        private final SigningGenerationRegistry.CurrentReferences currentReferences;
        private final SigningGenerationRegistry.SnapshotPins pins;
        private final RecoverySink.Prepared recoveredState;
        private final Statistics statistics;
        private final SigningActiveWal.ValidatedState validatedActive;
        private final SigningActiveWal.Operations activeOperations;
        private final SigningActiveWal.NanoClock clock;
        private final SigningActiveWal.GroupWaitStrategy waitStrategy;
        private final RecoveryFaultInjector faults;
        private final OpenLifecycle lifecycle = new OpenLifecycle();
        private boolean transferred;
        private boolean closed;

        private PreparedOpen(Path root, Configuration configuration,
                SigningManifestCodec.Manifest manifest, CleanupPlan cleanupPlan,
                SigningGenerationRegistry registry,
                SigningGenerationRegistry.CurrentReferences currentReferences,
                SigningGenerationRegistry.SnapshotPins pins,
                RecoverySink.Prepared recoveredState, Statistics statistics,
                SigningActiveWal.ValidatedState validatedActive,
                SigningActiveWal.Operations activeOperations, SigningActiveWal.NanoClock clock,
                SigningActiveWal.GroupWaitStrategy waitStrategy,
                RecoveryFaultInjector faults) {
            this.root = root;
            this.configuration = configuration;
            this.manifest = manifest;
            this.cleanupPlan = cleanupPlan;
            this.registry = registry;
            this.currentReferences = currentReferences;
            this.pins = pins;
            this.recoveredState = recoveredState;
            this.statistics = statistics;
            this.validatedActive = validatedActive;
            this.activeOperations = activeOperations;
            this.clock = clock;
            this.waitStrategy = waitStrategy;
            this.faults = faults;
        }

        /**
         * Returns the last completed shared recovery-lifecycle transition.
         *
         * @return current monotonic lifecycle state; ownership closure is tracked separately
         */
        /* default */ synchronized OpenState state() {
            return lifecycle.state();
        }

        /**
         * Returns a small immutable view of the still-owned read-only recovery result.
         *
         * @return manifest, cleanup plan, and replay statistics without transferring resources
         * @throws IllegalStateException if the candidate was closed, transferred, or activated
         */
        /* default */ synchronized PreparedView view() {
            if (closed || transferred || lifecycle.state() != OpenState.PREPARED_READ_ONLY) {
                throw new IllegalStateException("signing recovery prepared view is unavailable");
            }
            return new PreparedView(manifest, cleanupPlan, statistics);
        }

        /**
         * Opens the validated WAL passively and durably repairs only its proven incomplete suffix.
         *
         * <p>Failure closes resources still owned by this candidate. The writer remains stopped until reconstruction, recovery writes, and explicit thread startup complete.</p>
         *
         * @return owned passive activation; this prepared owner becomes transferred on success
         * @throws IllegalStateException if this candidate is no longer owned in the read-only prepared state
         * @throws IOException if the WAL changed, repair durability is uncertain, or activation cannot complete
         */
        /* default */ synchronized ActivatedOpen activate() throws IOException {
            if (closed || transferred || lifecycle.state() != OpenState.PREPARED_READ_ONLY) {
                throw new IllegalStateException("signing recovery activation is invalid");
            }
            SigningManifestCodec.ActiveWal activeDescriptor = manifest.activeWal();
            SigningActiveWal.Descriptor descriptor = new SigningActiveWal.Descriptor(
                    activeDescriptor.identity(), activeDescriptor.firstSequence(),
                    activeDescriptor.baselineRevision());
            SigningActiveWal activeWal = null;
            try {
                faults.after(RecoveryStage.BEFORE_PASSIVE_WAL_OPEN, registry);
                activeWal = SigningActiveWal.reopenValidatedPassive(
                        root.resolve(activeDescriptor.name()), descriptor,
                        configuration.activeWalConfiguration(), validatedActive,
                        activeOperations, clock, waitStrategy,
                        (stage, channel) -> faults.after(switch (stage) {
                            case AFTER_PASSIVE_WAL_OPEN ->
                                RecoveryStage.AFTER_PASSIVE_WAL_OPEN;
                            case AFTER_TAIL_REPAIR -> RecoveryStage.AFTER_TAIL_REPAIR;
                        }, registry));
                lifecycle.advance(OpenState.PREPARED_READ_ONLY, OpenState.PASSIVE_ACTIVATED);
                ActivatedOpen result = new ActivatedOpen(manifest, cleanupPlan, registry,
                        currentReferences, pins, activeWal, recoveredState, statistics, lifecycle);
                transferred = true;
                return result;
            } catch (SigningActiveWal.MalformedRecoveryDataException malformed) {
                cleanupActivationFailure(activeWal, malformed);
                throw failure(Code.RECOVERY_INVALID);
            } catch (IOException operationalFailure) {
                cleanupActivationFailure(activeWal, operationalFailure);
                throw operationalFailure;
            } catch (RuntimeException activationFailure) {
                cleanupActivationFailure(activeWal, activationFailure);
                if (activationFailure instanceof IllegalStateException invalidTransition) {
                    throw invalidTransition;
                }
                throw failure(Code.RECOVERY_INVALID);
            }
        }

        private void cleanupActivationFailure(SigningActiveWal activeWal, Throwable failure) {
            if (activeWal != null) {
                try {
                    activeWal.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
            }
            close();
        }

        /**
         * Discards this candidate's unpublished recovered state and generation references.
         *
         * <p>Closure is idempotent. After successful activation transfers the resources,
         * this method does nothing; the activated owner must close them.</p>
         */
        @Override
        public synchronized void close() {
            if (closed || transferred) {
                return;
            }
            closed = true;
            recoveredState.close();
            pins.close();
            currentReferences.close();
            registry.close();
        }
    }

    /**
     * Immutable metadata exposed by the read-only prepared recovery phase.
     * @param manifest validated authoritative signing manifest
     * @param cleanupPlan classified immutable recovery cleanup inventory
     * @param statistics constant-size artifact and replay counters
     */
    /* default */ record PreparedView(SigningManifestCodec.Manifest manifest,
            CleanupPlan cleanupPlan, Statistics statistics) {
    }

    /**
     * Passive recovered ownership used while the engine reconstructs deterministic state.
     */
    /* default */ static final class ActivatedOpen implements AutoCloseable {
        private final SigningManifestCodec.Manifest manifest;
        private final CleanupPlan cleanupPlan;
        private final SigningGenerationRegistry registry;
        private final SigningGenerationRegistry.CurrentReferences currentReferences;
        private final SigningGenerationRegistry.SnapshotPins pins;
        private final SigningActiveWal activeWal;
        private final RecoverySink.Prepared recoveredState;
        private final Statistics statistics;
        private final OpenLifecycle lifecycle;
        private boolean recoveredStatePublished;
        private boolean transferred;
        private boolean closed;

        private ActivatedOpen(SigningManifestCodec.Manifest manifest, CleanupPlan cleanupPlan,
                SigningGenerationRegistry registry,
                SigningGenerationRegistry.CurrentReferences currentReferences,
                SigningGenerationRegistry.SnapshotPins pins, SigningActiveWal activeWal,
                RecoverySink.Prepared recoveredState, Statistics statistics,
                OpenLifecycle lifecycle) {
            this.manifest = manifest;
            this.cleanupPlan = cleanupPlan;
            this.registry = registry;
            this.currentReferences = currentReferences;
            this.pins = pins;
            this.activeWal = activeWal;
            this.recoveredState = recoveredState;
            this.statistics = statistics;
            this.lifecycle = lifecycle;
        }

        /**
         * Returns the last completed shared recovery-lifecycle transition.
         *
         * @return current monotonic lifecycle state; ownership closure is tracked separately
         */
        /* default */ synchronized OpenState state() { return lifecycle.state(); }
        /**
         * Returns the manifest used to validate this recovery generation.
         *
         * @return immutable authoritative manifest
         */
        /* default */ SigningManifestCodec.Manifest manifest() { return manifest; }
        /**
         * Returns the classified cleanup inventory without deleting any files.
         *
         * @return immutable cleanup plan
         */
        /* default */ CleanupPlan cleanupPlan() { return cleanupPlan; }
        /**
         * Returns the generation registry retained by this recovery owner.
         *
         * @return borrowed registry; its lifecycle remains with the recovery owner
         */
        /* default */ SigningGenerationRegistry registry() { return registry; }
        /**
         * Returns the active-WAL resource retained by this recovery owner.
         *
         * @return borrowed WAL; activation/startup state follows the shared lifecycle
         */
        /* default */ SigningActiveWal activeWal() { return activeWal; }
        /**
         * Returns the statistics captured by the completed read-only replay.
         *
         * @return immutable bounded replay statistics
         */
        /* default */ Statistics statistics() { return statistics; }

        /**
         * Releases recovery-wide temporary generation pins after exact indexes acquire their own references.
         *
         * @throws IllegalStateException if this activated owner was closed or transferred
         */
        /* default */ synchronized void releaseTemporaryOwnership() {
            requireOwned();
            pins.close();
            currentReferences.close();
        }

        /**
         * Atomically publishes the prepared recovered state exactly once during passive activation.
         *
         * <p>This does not start a writer. The sink contract requires prepared publication to be failure-free.</p>
         *
         * @throws IllegalStateException if ownership is unavailable, activation is incomplete, or publication already occurred
         */
        /* default */ synchronized void publishRecoveredState() {
            requireOwnedState(OpenState.PASSIVE_ACTIVATED);
            if (recoveredStatePublished) {
                throw new IllegalStateException("signing recovered state publication is invalid");
            }
            recoveredState.publish();
            recoveredStatePublished = true;
        }

        /**
         * Advances passive activation after the engine has been reconstructed from published state.
         *
         * @throws IllegalStateException if state was not published or the owner is not in passive activation
         */
        /* default */ synchronized void markEngineReconstructed() {
            if (!recoveredStatePublished) {
                throw new IllegalStateException("signing recovered state is not published");
            }
            requireOwnedState(OpenState.PASSIVE_ACTIVATED);
            lifecycle.advance(OpenState.PASSIVE_ACTIVATED, OpenState.ENGINE_RECONSTRUCTED);
        }

        /**
         * Records that deterministic recovery writes have crossed their durability barriers.
         *
         * <p>The caller must force the recovery writes before invoking this transition; this method does not itself perform I/O.</p>
         *
         * @throws IllegalStateException if ownership is unavailable or engine reconstruction is not the current state
         */
        /* default */ synchronized void markRecoveryWritesForced() {
            requireOwnedState(OpenState.ENGINE_RECONSTRUCTED);
            lifecycle.advance(OpenState.ENGINE_RECONSTRUCTED,
                    OpenState.RECOVERY_WRITES_FORCED);
        }

        /**
         * Records writer startup after recovery durability has been established.
         *
         * @throws IllegalStateException if ownership is unavailable, writes are not marked forced, or the WAL writer is not open
         */
        /* default */ synchronized void markThreadsStarted() {
            requireOwnedState(OpenState.RECOVERY_WRITES_FORCED);
            if (activeWal.snapshot().state() != SigningActiveWal.State.OPEN) {
                throw new IllegalStateException("signing recovery writer is not started");
            }
            lifecycle.advance(OpenState.RECOVERY_WRITES_FORCED, OpenState.THREADS_STARTED);
        }

        /**
         * Transfers all remaining recovery resources to the ready engine handle.
         *
         * @return owned handle replacing this activated owner
         * @throws IllegalStateException if ownership is unavailable or writer startup is not the current lifecycle state
         */
        /* default */ synchronized Handle transferToStartedEngine() {
            requireOwnedState(OpenState.THREADS_STARTED);
            lifecycle.advance(OpenState.THREADS_STARTED, OpenState.OWNERSHIP_TRANSFERRED);
            Handle result = new Handle(manifest, cleanupPlan, registry, currentReferences,
                    pins, activeWal, recoveredState, statistics, lifecycle);
            transferred = true;
            return result;
        }

        private void requireOwnedState(OpenState expected) {
            requireOwned();
            if (lifecycle.state() != expected) {
                throw new IllegalStateException("signing recovery lifecycle transition is invalid");
            }
        }

        private void requireOwned() {
            if (closed || transferred) {
                throw new IllegalStateException("signing recovery ownership is unavailable");
            }
        }

        /**
         * Closes the WAL and recovery resources still owned by this activation.
         *
         * <p>Closure is idempotent. A successful transfer leaves resource closure with
         * the ready engine handle. WAL close failures are propagated after attempting
         * release of the prepared state and generation references.</p>
         *
         * @throws IOException if the owned WAL cannot drain or close cleanly
         */
        @Override
        @SuppressWarnings("PMD.UseTryWithResources")
        public synchronized void close() throws IOException {
            if (closed || transferred) {
                return;
            }
            closed = true;
            IOException failure = null;
            try {
                activeWal.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            } finally {
                recoveredState.close();
                pins.close();
                currentReferences.close();
                registry.close();
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /**
     * Closeable ownership of the validated generation set and ready active writer.
     */
    /* default */ static final class Handle implements AutoCloseable {
        private final SigningManifestCodec.Manifest manifest;
        private final CleanupPlan cleanupPlan;
        private final SigningGenerationRegistry registry;
        private final SigningGenerationRegistry.CurrentReferences currentReferences;
        private final SigningGenerationRegistry.SnapshotPins pins;
        private final SigningActiveWal activeWal;
        private final RecoverySink.Prepared recoveredState;
        private final Statistics statistics;
        private final OpenLifecycle lifecycle;
        private final AtomicBoolean closed = new AtomicBoolean();

        private Handle(SigningManifestCodec.Manifest manifest, CleanupPlan cleanupPlan,
                SigningGenerationRegistry registry,
                SigningGenerationRegistry.CurrentReferences currentReferences,
                SigningGenerationRegistry.SnapshotPins pins, SigningActiveWal activeWal,
                RecoverySink.Prepared recoveredState, Statistics statistics,
                OpenLifecycle lifecycle) {
            this.manifest = manifest;
            this.cleanupPlan = cleanupPlan;
            this.registry = registry;
            this.currentReferences = currentReferences;
            this.pins = pins;
            this.activeWal = activeWal;
            this.recoveredState = recoveredState;
            this.statistics = statistics;
            this.lifecycle = lifecycle;
        }

        /**
         * Returns the manifest used to validate this recovery generation.
         *
         * @return immutable authoritative manifest
         */
        /* default */ SigningManifestCodec.Manifest manifest() { return manifest; }
        /**
         * Returns the classified cleanup inventory without deleting any files.
         *
         * @return immutable cleanup plan
         */
        /* default */ CleanupPlan cleanupPlan() { return cleanupPlan; }
        /**
         * Captures the current generation-reference accounting.
         *
         * @return immutable generation ownership statistics
         */
        /* default */ SigningGenerationRegistry.Snapshot generationSnapshot() {
            return registry.statistics();
        }
        /**
         * Returns the active-WAL resource retained by this recovery owner.
         *
         * @return borrowed WAL; activation/startup state follows the shared lifecycle
         */
        /* default */ SigningActiveWal activeWal() { return activeWal; }
        /**
         * Returns the generation registry retained by this recovery owner.
         *
         * @return borrowed registry; its lifecycle remains with the recovery owner
         */
        /* default */ SigningGenerationRegistry registry() { return registry; }
        /**
         * Releases recovery-wide temporary ownership after exact indexes acquire references.
         */
        /* default */ void releaseTemporaryOwnership() {
            pins.close();
            currentReferences.close();
        }
        /**
         * Returns the statistics captured by the completed read-only replay.
         *
         * @return immutable bounded replay statistics
         */
        /* default */ Statistics statistics() { return statistics; }
        /**
         * Returns the last completed shared recovery-lifecycle transition.
         *
         * @return current monotonic lifecycle state; ownership closure is tracked separately
         */
        /* default */ OpenState state() { return lifecycle.state(); }

        /**
         * Closes the ready WAL and releases all recovered-state and generation ownership.
         *
         * <p>Only the first caller performs cleanup. WAL failure is retained while nested
         * finally blocks attempt the remaining resource closures.</p>
         *
         * @throws IOException if WAL draining, interruption, or channel closure fails
         */
        @Override
        @SuppressWarnings("PMD.UseTryWithResources")
        public void close() throws IOException {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            IOException failure = null;
            try {
                activeWal.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            } finally {
                try {
                    recoveredState.close();
                } finally {
                    try {
                        pins.close();
                    } finally {
                        try {
                            currentReferences.close();
                        } finally {
                            registry.close();
                        }
                    }
                }
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /**
     * Immutable inventory of recovery artifacts eligible for classified cleanup.
     *
     * @param entries immutable ordered cleanup entries
     */
    /* default */ record CleanupPlan(List<CleanupEntry> entries) {
        /**
         * Creates a {@code CleanupPlan} value from the supplied component coordinates.
         *
         * @param entries immutable ordered cleanup entries
         * @throws NullPointerException if the entry list or an entry is null
         */
        CleanupPlan {
            entries = List.copyOf(entries);
        }

        /**
         * Counts temporary artifacts classified as safe stale cleanup candidates.
         *
         * @return number of entries with SAFE_STALE_TEMPORARY classification
         */
        /* default */ long staleTemporaryCount() {
            return entries.stream().filter(value -> value.category()
                    == Category.SAFE_STALE_TEMPORARY).count();
        }

        /**
         * Counts orphan artifacts whose cleanup is deliberately deferred.
         *
         * @return number of entries with ORPHAN_ARTIFACT_DEFERRED classification
         */
        /* default */ long unreferencedArtifactCount() {
            return entries.stream().filter(value -> value.category()
                    == Category.ORPHAN_ARTIFACT_DEFERRED).count();
        }
    }

    /**
     * Validated local artifact name and its recovery cleanup classification.
     *
     * @param name validated store-local artifact name
     * @param category closed cleanup safety classification
     */
    /* default */ record CleanupEntry(String name, Category category) {
        /**
         * Creates a {@code CleanupEntry} value from the supplied component coordinates.
         *
         * @param name validated store-local artifact name
         * @param category closed cleanup safety classification
         * @throws NullPointerException if {@code name} is null; or if {@code category} is null
         */
        CleanupEntry {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(category, "category");
        }
    }

    /**
     * Deterministic root-entry classification.
     */
    /* default */ enum Category {
        /**
         * A stale temporary artifact can be removed without changing authoritative state.
         */
        SAFE_STALE_TEMPORARY,
        /**
         * An unreferenced artifact is retained for deferred reclamation.
         */
        ORPHAN_ARTIFACT_DEFERRED
    }

    /**
     * Constant-size artifact, replay and cleanup counters captured by recovery.
     *
     * @param rootEntries number of root directory entries observed
     * @param sealedSegments ordered immutable sealed segment descriptors
     * @param checkpointEntries number of checkpoint entries validated
     * @param sealedFrames number of frames replayed from sealed segments
     * @param activeFrames number of frames replayed from the active WAL
     * @param truncatedBytes number of incomplete-tail bytes removed during recovery
     * @param staleTemporaryFiles number of stale temporary artifacts classified during recovery
     * @param unreferencedArtifacts number of artifacts not referenced by authoritative state
     */
    /* default */ record Statistics(int rootEntries, int sealedSegments,
            int checkpointEntries, long sealedFrames, long activeFrames,
            long truncatedBytes, long staleTemporaryFiles, long unreferencedArtifacts) {
    }

    /**
     * Stable redacted recovery failure code.
     */
    /* default */ enum Code {
        /**
         * No signing ledger format is present in the root.
         */
        EMPTY_ROOT,
        /**
         * The root contains a legacy or unrecognized signing layout.
         */
        LEGACY_OR_UNKNOWN_ROOT,
        /**
         * The persisted format identifier is unsupported.
         */
        FORMAT_UNSUPPORTED,
        /**
         * The authoritative manifest is absent.
         */
        MANIFEST_MISSING,
        /**
         * The authoritative manifest fails validation.
         */
        MANIFEST_INVALID,
        /**
         * A manifest-referenced artifact is absent.
         */
        REFERENCED_MISSING,
        /**
         * A referenced artifact fails validation.
         */
        REFERENCED_INVALID,
        /**
         * The active WAL fails validation.
         */
        ACTIVE_INVALID,
        /**
         * Durability of active-WAL repair cannot be confirmed.
         */
        ACTIVE_REPAIR_UNCERTAIN,
        /**
         * An orphan artifact uses an unsupported representation.
         */
        ORPHAN_UNSUPPORTED,
        /**
         * An orphan artifact fails validation.
         */
        ORPHAN_INVALID,
        /**
         * The root contains more entries than recovery permits.
         */
        ROOT_ENTRY_LIMIT,
        /**
         * A root entry violates the signing ledger layout.
         */
        ROOT_ENTRY_INVALID,
        /**
         * The checkpoint pointer fails validation.
         */
        CHECKPOINT_POINTER_INVALID,
        /**
         * Replayed records do not maintain the required continuity.
         */
        REPLAY_CONTINUITY_INVALID,
        /**
         * Recovery evidence is inconsistent with the required ledger state.
         */
        RECOVERY_INVALID
    }

    /**
     * Stable path-, key-, payload-, and identity-free recovery failure.
     */
    /* default */ static final class RecoveryException extends IOException {
        private static final long serialVersionUID = 8405320823990651930L;
        private final Code code;

        private RecoveryException(Code code) {
            super("signing recovery failed: " + code.name());
            this.code = code;
        }

        /**
         * Returns the stable redacted classification of this recovery failure.
         *
         * @return closed recovery failure code without artifact paths or private payload data
         */
        /* default */ Code code() { return code; }
    }

    private record RootEntry(String name, BasicFileAttributes attributes) {
    }

    private record RootIndex(List<RootEntry> entries, Map<String, RootEntry> byName) {
    }

    private record ActiveValidation(SigningActiveWal.ValidatedState validatedState,
            long frameCount, long truncatedBytes) {
    }

    /**
     * Logical checkpoint boundary; no external-frame pointer join is retained.
     */
    private record CheckpointBoundary(int entryCount, long revision, long coveredSequence) {
        private static CheckpointBoundary empty() {
            return new CheckpointBoundary(0, 0L, -1L);
        }

        private long nextSequence() {
            return coveredSequence < 0L ? 0L : Math.incrementExact(coveredSequence);
        }
    }

    /**
     * JDK filesystem operations used only after read-only validation.
     */
    private static final class SystemActiveOperations implements SigningActiveWal.Operations {
        /**
         * {@inheritDoc}
         */
        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        /**
         * {@inheritDoc}
         */
        @Override public boolean isRegularFile(Path path) {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
        }
        /**
         * {@inheritDoc}
         */
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            throw new IOException("signing recovery never creates an active WAL");
        }
        /**
         * {@inheritDoc}
         */
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            Set<OpenOption> options = Set.of(StandardOpenOption.READ, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS);
            return new RecoveryWalChannel(FileChannel.open(path, options));
        }
        /**
         * {@inheritDoc}
         */
        @Override public void forceDirectory(Path directory) {
            // Existing WAL recovery never publishes a directory entry.
        }
    }

    /**
     * File-channel adapter for the validated active WAL.
     */
    private static final class RecoveryWalChannel implements SigningActiveWal.WalChannel {
        private final FileChannel delegate;
        private RecoveryWalChannel(FileChannel delegate) { this.delegate = delegate; }
        /**
         * {@inheritDoc}
         */
        @Override public int read(ByteBuffer target) throws IOException { return delegate.read(target); }
        /**
         * {@inheritDoc}
         */
        @Override public int write(ByteBuffer source) throws IOException { return delegate.write(source); }
        /**
         * {@inheritDoc}
         */
        @Override public long position() throws IOException { return delegate.position(); }
        /**
         * {@inheritDoc}
         */
        @Override public SigningActiveWal.WalChannel position(long position) throws IOException {
            delegate.position(position);
            return this;
        }
        /**
         * {@inheritDoc}
         */
        @Override public long size() throws IOException { return delegate.size(); }
        /**
         * {@inheritDoc}
         */
        @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException {
            delegate.truncate(size);
            return this;
        }
        /**
         * {@inheritDoc}
         */
        @Override public boolean isOpen() { return delegate.isOpen(); }
        /**
         * {@inheritDoc}
         */
        @Override public void close() throws IOException { delegate.close(); }
        /**
         * {@inheritDoc}
         */
        @Override public void force(boolean metadata) throws IOException { delegate.force(metadata); }
    }
}
