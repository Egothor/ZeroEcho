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

/** Manifest-authoritative, package-internal recovery for the segmented signing ledger. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidLiteralsInIfCondition", "PMD.AvoidSynchronizedAtMethodLevel",
        "PMD.CloseResource", "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity",
        "PMD.PreserveStackTrace" })
final class SigningLedgerRecovery {

    /* default */ static final String FORMAT_FILE = "FORMAT";
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

    /** Explicitly creates and forces the clean-format identity in an empty root. */
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

    /* default */ static Handle recover(Path root, Configuration configuration,
            RecoverySink sink) throws IOException {
        return recover(root, configuration, sink, new SystemActiveOperations(), SYSTEM_CLOCK,
                SYSTEM_WAIT);
    }

    /** Performs the complete root/layout pass without opening or repairing the active WAL. */
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

    /* default */ static PreparedOpen prepare(Path root, Configuration configuration,
            RecoverySink sink) throws IOException {
        return prepare(root, configuration, sink, new SystemActiveOperations(), SYSTEM_CLOCK,
                SYSTEM_WAIT, recoveryFault());
    }

    /* default */ static PreparedOpen prepare(Path root, Configuration configuration,
            RecoverySink sink, SigningActiveWal.Operations activeOperations,
            SigningActiveWal.NanoClock clock,
            SigningActiveWal.GroupWaitStrategy waitStrategy) throws IOException {
        return prepare(root, configuration, sink, activeOperations, clock, waitStrategy,
                recoveryFault());
    }

    /* default */ static void installRecoveryFault(RecoveryFaultInjector fault) {
        RECOVERY_FAULTS.set(Objects.requireNonNull(fault, "fault"));
    }

    /* default */ static void clearRecoveryFault() {
        RECOVERY_FAULTS.remove();
    }

    private static RecoveryFaultInjector recoveryFault() {
        RecoveryFaultInjector fault = RECOVERY_FAULTS.get();
        return fault == null ? NO_RECOVERY_FAULT : fault;
    }

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

    /** Marks only failures emitted by the underlying filesystem channel. */
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

    /** Preserves the origin of channel I/O while the WAL codec classifies malformed bytes. */
    private static final class OperationalSeekableChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;

        private OperationalSeekableChannel(SeekableByteChannel delegate) {
            this.delegate = delegate;
        }

        @Override public int read(ByteBuffer target) throws IOException {
            try {
                return delegate.read(target);
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }

        @Override public int write(ByteBuffer source) {
            throw new UnsupportedOperationException("read-only recovery channel");
        }

        @Override public long position() throws IOException {
            try {
                return delegate.position();
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }

        @Override public SeekableByteChannel position(long newPosition) throws IOException {
            try {
                delegate.position(newPosition);
                return this;
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }

        @Override public long size() throws IOException {
            try {
                return delegate.size();
            } catch (IOException failure) {
                throw new OperationalChannelException(failure);
            }
        }

        @Override public SeekableByteChannel truncate(long size) {
            throw new UnsupportedOperationException("read-only recovery channel");
        }

        @Override public boolean isOpen() {
            return delegate.isOpen();
        }

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

    /* default */ record Configuration(int maximumRootEntries, long maximumArtifactBytes,
            int maximumCheckpointEntries,
            SigningActiveWal.Configuration activeWalConfiguration) {
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

        /* default */ static Configuration defaults() {
            return new Configuration(8192, SigningManifestCodec.MAX_FILE_BYTES,
                    SigningCheckpointCodec.MAX_ENTRIES,
                    SigningActiveWal.Configuration.defaults());
        }
    }

    /** Transactional bounded replay seam. Publish must be failure-free after prepare succeeds. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    /* default */ interface RecoverySink {
        /** Begins one isolated recovery transaction. */
        Session begin(SigningManifestCodec.Manifest manifest) throws IOException;

        /** Receives bounded validated input and can roll it back until prepared. */
        interface Session extends AutoCloseable {
            /** Accepts one validated checkpoint descriptor. */
            void acceptCheckpoint(SigningCheckpointCodec.Header header,
                    SigningCheckpointCodec.EntryDescriptor entry,
                    SigningWalFrameCodec.Frame frame) throws IOException;
            /** Installs the completely verified checkpoint revision and sequence boundary. */
            void acceptCheckpointBoundary(SigningCheckpointCodec.Header header)
                    throws IOException;
            /** Accepts one fully committed group containing at most 32 frames. */
            void acceptWalGroup(List<SigningWalFrameCodec.ScannedFrame> frames,
                    long committedRevision) throws IOException;
            /** Seals an atomic candidate after all validation succeeds. */
            Prepared prepare() throws IOException;
            @Override void close();
        }

        /** Prepared recovered state owned by the returned recovery handle. */
        interface Prepared extends AutoCloseable {
            /** Atomically makes the prepared recovered state visible and must not fail. */
            void publish();
            @Override void close();
        }
    }

    /** Monotonic lifecycle of a recovered ledger before it becomes externally usable. */
    /* default */ enum OpenState {
        PREPARED_READ_ONLY,
        PASSIVE_ACTIVATED,
        ENGINE_RECONSTRUCTED,
        RECOVERY_WRITES_FORCED,
        THREADS_STARTED,
        OWNERSHIP_TRANSFERRED
    }

    /** Deterministic recovery boundaries used by ownership cleanup tests. */
    /* default */ enum RecoveryStage {
        AFTER_READ_ONLY_REPLAY,
        BEFORE_PASSIVE_WAL_OPEN,
        AFTER_PASSIVE_WAL_OPEN,
        AFTER_TAIL_REPAIR
    }

    /** Package-local fault seam for recovery ownership cleanup verification. */
    /* default */
    @FunctionalInterface
    interface RecoveryFaultInjector {
        /** Runs after the selected recovery stage with its generation registry. */
        void after(RecoveryStage stage, SigningGenerationRegistry registry) throws IOException;
    }

    /** Small shared transition guard carried across each ownership handoff. */
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

    /** Read-only validated recovery ownership before the active WAL is opened for repair. */
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

        /* default */ synchronized OpenState state() {
            return lifecycle.state();
        }

        /* default */ synchronized PreparedView view() {
            if (closed || transferred || lifecycle.state() != OpenState.PREPARED_READ_ONLY) {
                throw new IllegalStateException("signing recovery prepared view is unavailable");
            }
            return new PreparedView(manifest, cleanupPlan, statistics);
        }

        /** Opens the validated WAL passively and repairs only its proven incomplete suffix. */
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

    /** Immutable metadata exposed by the read-only prepared recovery phase. */
    /* default */ record PreparedView(SigningManifestCodec.Manifest manifest,
            CleanupPlan cleanupPlan, Statistics statistics) {
    }

    /** Passive recovered ownership used while the engine reconstructs deterministic state. */
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

        /* default */ synchronized OpenState state() { return lifecycle.state(); }
        /* default */ SigningManifestCodec.Manifest manifest() { return manifest; }
        /* default */ CleanupPlan cleanupPlan() { return cleanupPlan; }
        /* default */ SigningGenerationRegistry registry() { return registry; }
        /* default */ SigningActiveWal activeWal() { return activeWal; }
        /* default */ Statistics statistics() { return statistics; }

        /** Releases recovery-wide temporary ownership after exact indexes acquire references. */
        /* default */ synchronized void releaseTemporaryOwnership() {
            requireOwned();
            pins.close();
            currentReferences.close();
        }

        /* default */ synchronized void publishRecoveredState() {
            requireOwnedState(OpenState.PASSIVE_ACTIVATED);
            if (recoveredStatePublished) {
                throw new IllegalStateException("signing recovered state publication is invalid");
            }
            recoveredState.publish();
            recoveredStatePublished = true;
        }

        /* default */ synchronized void markEngineReconstructed() {
            if (!recoveredStatePublished) {
                throw new IllegalStateException("signing recovered state is not published");
            }
            requireOwnedState(OpenState.PASSIVE_ACTIVATED);
            lifecycle.advance(OpenState.PASSIVE_ACTIVATED, OpenState.ENGINE_RECONSTRUCTED);
        }

        /* default */ synchronized void markRecoveryWritesForced() {
            requireOwnedState(OpenState.ENGINE_RECONSTRUCTED);
            lifecycle.advance(OpenState.ENGINE_RECONSTRUCTED,
                    OpenState.RECOVERY_WRITES_FORCED);
        }

        /* default */ synchronized void markThreadsStarted() {
            requireOwnedState(OpenState.RECOVERY_WRITES_FORCED);
            if (activeWal.snapshot().state() != SigningActiveWal.State.OPEN) {
                throw new IllegalStateException("signing recovery writer is not started");
            }
            lifecycle.advance(OpenState.RECOVERY_WRITES_FORCED, OpenState.THREADS_STARTED);
        }

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

    /** Closeable ownership of the validated generation set and ready active writer. */
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

        /* default */ SigningManifestCodec.Manifest manifest() { return manifest; }
        /* default */ CleanupPlan cleanupPlan() { return cleanupPlan; }
        /* default */ SigningGenerationRegistry.Snapshot generationSnapshot() {
            return registry.statistics();
        }
        /* default */ SigningActiveWal activeWal() { return activeWal; }
        /* default */ SigningGenerationRegistry registry() { return registry; }
        /** Releases recovery-wide temporary ownership after exact indexes acquire references. */
        /* default */ void releaseTemporaryOwnership() {
            pins.close();
            currentReferences.close();
        }
        /* default */ Statistics statistics() { return statistics; }
        /* default */ OpenState state() { return lifecycle.state(); }

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

    /* default */ record CleanupPlan(List<CleanupEntry> entries) {
        CleanupPlan {
            entries = List.copyOf(entries);
        }

        /* default */ long staleTemporaryCount() {
            return entries.stream().filter(value -> value.category()
                    == Category.SAFE_STALE_TEMPORARY).count();
        }

        /* default */ long unreferencedArtifactCount() {
            return entries.stream().filter(value -> value.category()
                    == Category.ORPHAN_ARTIFACT_DEFERRED).count();
        }
    }

    /* default */ record CleanupEntry(String name, Category category) {
        CleanupEntry {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(category, "category");
        }
    }

    /** Deterministic root-entry classification. */
    /* default */ enum Category {
        SAFE_STALE_TEMPORARY,
        ORPHAN_ARTIFACT_DEFERRED
    }

    /* default */ record Statistics(int rootEntries, int sealedSegments,
            int checkpointEntries, long sealedFrames, long activeFrames,
            long truncatedBytes, long staleTemporaryFiles, long unreferencedArtifacts) {
    }

    /** Stable redacted recovery failure code. */
    /* default */ enum Code {
        EMPTY_ROOT,
        LEGACY_OR_UNKNOWN_ROOT,
        FORMAT_UNSUPPORTED,
        MANIFEST_MISSING,
        MANIFEST_INVALID,
        REFERENCED_MISSING,
        REFERENCED_INVALID,
        ACTIVE_INVALID,
        ACTIVE_REPAIR_UNCERTAIN,
        ORPHAN_UNSUPPORTED,
        ORPHAN_INVALID,
        ROOT_ENTRY_LIMIT,
        ROOT_ENTRY_INVALID,
        CHECKPOINT_POINTER_INVALID,
        REPLAY_CONTINUITY_INVALID,
        RECOVERY_INVALID
    }

    /** Stable path-, key-, payload-, and identity-free recovery failure. */
    /* default */ static final class RecoveryException extends IOException {
        private static final long serialVersionUID = 8405320823990651930L;
        private final Code code;

        private RecoveryException(Code code) {
            super("signing recovery failed: " + code.name());
            this.code = code;
        }

        /* default */ Code code() { return code; }
    }

    private record RootEntry(String name, BasicFileAttributes attributes) {
    }

    private record RootIndex(List<RootEntry> entries, Map<String, RootEntry> byName) {
    }

    private record ActiveValidation(SigningActiveWal.ValidatedState validatedState,
            long frameCount, long truncatedBytes) {
    }

    /** Logical checkpoint boundary; no external-frame pointer join is retained. */
    private record CheckpointBoundary(int entryCount, long revision, long coveredSequence) {
        private static CheckpointBoundary empty() {
            return new CheckpointBoundary(0, 0L, -1L);
        }

        private long nextSequence() {
            return coveredSequence < 0L ? 0L : Math.incrementExact(coveredSequence);
        }
    }

    /** JDK filesystem operations used only after read-only validation. */
    private static final class SystemActiveOperations implements SigningActiveWal.Operations {
        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
        }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            throw new IOException("signing recovery never creates an active WAL");
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            Set<OpenOption> options = Set.of(StandardOpenOption.READ, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS);
            return new RecoveryWalChannel(FileChannel.open(path, options));
        }
        @Override public void forceDirectory(Path directory) {
            // Existing WAL recovery never publishes a directory entry.
        }
    }

    /** File-channel adapter for the validated active WAL. */
    private static final class RecoveryWalChannel implements SigningActiveWal.WalChannel {
        private final FileChannel delegate;
        private RecoveryWalChannel(FileChannel delegate) { this.delegate = delegate; }
        @Override public int read(ByteBuffer target) throws IOException { return delegate.read(target); }
        @Override public int write(ByteBuffer source) throws IOException { return delegate.write(source); }
        @Override public long position() throws IOException { return delegate.position(); }
        @Override public SigningActiveWal.WalChannel position(long position) throws IOException {
            delegate.position(position);
            return this;
        }
        @Override public long size() throws IOException { return delegate.size(); }
        @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException {
            delegate.truncate(size);
            return this;
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() throws IOException { delegate.close(); }
        @Override public void force(boolean metadata) throws IOException { delegate.force(metadata); }
    }
}
