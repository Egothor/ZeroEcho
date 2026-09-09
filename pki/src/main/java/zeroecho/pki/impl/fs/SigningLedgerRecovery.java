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
        "PMD.AvoidLiteralsInIfCondition", "PMD.CloseResource", "PMD.CyclomaticComplexity",
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
        return recover(root, configuration, sink, new SystemActiveOperations(),
                SYSTEM_CLOCK, SYSTEM_WAIT);
    }

    /** Performs the complete root/layout pass without opening or repairing the active WAL. */
    /* default */ static void validateExistingLayout(Path root, Configuration configuration)
            throws IOException {
        Objects.requireNonNull(configuration, "configuration");
        requireRoot(root);
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
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(sink, "sink");
        Objects.requireNonNull(activeOperations, "activeOperations");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(waitStrategy, "waitStrategy");
        try {
            requireRoot(root);
            RootIndex rootIndex = enumerate(root, configuration.maximumRootEntries());
            validateFormat(root, rootIndex);
            SigningManifestCodec.Manifest manifest = readManifest(root, rootIndex);
            validateReferencedArtifacts(root, manifest, rootIndex, configuration);

            SigningGenerationRegistry registry = new SigningGenerationRegistry();
            SigningGenerationRegistry.CurrentReferences currentReferences = null;
            SigningGenerationRegistry.SnapshotPins pins = null;
            SigningActiveWal activeWal = null;
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

                SigningManifestCodec.ActiveWal activeDescriptor = manifest.activeWal();
                SigningActiveWal.Descriptor descriptor = new SigningActiveWal.Descriptor(
                        activeDescriptor.identity(), activeDescriptor.firstSequence(),
                        activeDescriptor.baselineRevision());
                try {
                    activeWal = SigningActiveWal.reopenValidated(root.resolve(activeDescriptor.name()),
                            descriptor, configuration.activeWalConfiguration(), active.validatedState(),
                            activeOperations, clock, waitStrategy);
                } catch (SigningActiveWal.RecoveryRequiredException uncertain) {
                    throw failure(Code.ACTIVE_REPAIR_UNCERTAIN);
                }
                prepared.publish();
                Statistics statistics = new Statistics(rootIndex.entries().size(),
                        manifest.sealedSegments().size(), checkpoint.entryCount(), sealedFrames,
                        active.frameCount(),
                        active.truncatedBytes(), cleanupPlan.staleTemporaryCount(),
                        cleanupPlan.unreferencedArtifactCount());
                Handle handle = new Handle(manifest, cleanupPlan, registry, currentReferences,
                        pins, activeWal, prepared, statistics);
                registry = null;
                currentReferences = null;
                pins = null;
                activeWal = null;
                prepared = null;
                return handle;
            } finally {
                closeSuppressing(prepared);
                closeSuppressing(session);
                closeSuppressing(activeWal);
                closeSuppressing(pins);
                closeSuppressing(currentReferences);
                closeSuppressing(registry);
            }
        } catch (RecoveryException failure) {
            throw failure;
        } catch (IOException | RuntimeException failure) {
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
                session.acceptCheckpoint(header, descriptorEntry, frame);
            }
            reader.verifyComplete();
            if (!MessageDigest.isEqual(reader.fileCommitment(), descriptor.commitment())) {
                throw failure(Code.REFERENCED_INVALID);
            }
            session.acceptCheckpointBoundary(header);
            return new CheckpointBoundary(header.entryCount(), header.revision(),
                    header.committedSequence());
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
                SigningWalFrameCodec.ScanResult scan = SigningWalFrameCodec.scanGroups(channel,
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
                                session.acceptWalGroup(List.copyOf(suffix),
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
            SigningWalFrameCodec.ScanResult scan = SigningWalFrameCodec.scanGroups(channel,
                    descriptor.firstSequence(), true,
                    (frames, marker) -> {
                        for (SigningWalFrameCodec.ScannedFrame scanned : frames) {
                            if (scanned.revision() != Math.incrementExact(currentRevision[0])) {
                                throw failure(Code.REPLAY_CONTINUITY_INVALID);
                            }
                            currentRevision[0] = scanned.revision();
                        }
                        session.acceptWalGroup(frames, marker.committedRevision());
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
                SigningCheckpointCodec.Reader reader = SigningCheckpointCodec.reader(channel);
                if (reader.header().revision() != fields[0]
                        || reader.header().committedSequence() != fields[1]
                        || reader.header().entryCount() > configuration.maximumCheckpointEntries()) {
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
        SigningFormatSupport.readFully(channel, encoded, "signing WAL container is truncated");
        return SigningWalContainerCodec.decode(encoded.array());
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
            SigningFormatSupport.readFully(channel, ByteBuffer.wrap(encoded),
                    "signing manifest is truncated");
        }
        return SigningManifestCodec.decode(encoded);
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
            SigningFormatSupport.readFully(channel, ByteBuffer.wrap(actual),
                    "signing format marker is truncated");
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
        private final AtomicBoolean closed = new AtomicBoolean();

        private Handle(SigningManifestCodec.Manifest manifest, CleanupPlan cleanupPlan,
                SigningGenerationRegistry registry,
                SigningGenerationRegistry.CurrentReferences currentReferences,
                SigningGenerationRegistry.SnapshotPins pins, SigningActiveWal activeWal,
                RecoverySink.Prepared recoveredState, Statistics statistics) {
            this.manifest = manifest;
            this.cleanupPlan = cleanupPlan;
            this.registry = registry;
            this.currentReferences = currentReferences;
            this.pins = pins;
            this.activeWal = activeWal;
            this.recoveredState = recoveredState;
            this.statistics = statistics;
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
