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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import zeroecho.pki.spi.store.MetadataKey;

final class SigningFilePublicationRecoveryTest {

    private static final MetadataKey KEY = new MetadataKey(
            "restart-matrix-secret", "credential-secret");
    private static final UUID TRANSACTION_ID = UUID.fromString(
            "a4dd657d-ebf4-43f7-b9d0-65886cf01cb4");
    private static final byte[] CONTENT = { 11, 22, 33 };

    @TempDir
    private Path temporaryDirectory;

    @ParameterizedTest(name = "manifest publication/restart boundary: {0}")
    @EnumSource(Boundary.class)
    void manifestPublicationRestartSelectsOneCompleteEquivalentTopology(Boundary boundary)
            throws Exception {
        Fixture fixture = createFixture(boundary);
        MatrixOperations operations = new MatrixOperations(boundary);

        SigningFilePublisher.PublicationException failure = assertThrows(
                SigningFilePublisher.PublicationException.class,
                () -> SigningFilePublisher.publish(fixture.manifestPath(), true,
                        channel -> SigningFormatSupport.writeFully(channel,
                                ByteBuffer.wrap(fixture.newManifestEncoded())),
                        operations));

        assertPublicationDiagnostic(boundary, fixture, failure);
        CollectingSink sink = new CollectingSink();
        try (SigningLedgerRecovery.Handle recovered = SigningLedgerRecovery.recover(
                fixture.root(), recoveryConfiguration(), sink)) {
            assertTopology(boundary.expectedTopology(), fixture, recovered.manifest());
            assertEquivalentCommittedData(sink.frames());
            assertManifestArtifactsExist(fixture.root(), recovered.manifest());
            assertExactCleanupPlan(boundary, fixture, operations, recovered.cleanupPlan());
        }
    }

    private Fixture createFixture(Boundary boundary) throws Exception {
        Path root = Files.createDirectory(temporaryDirectory.resolve(
                "publisher-recovery-" + boundary.name().toLowerCase(java.util.Locale.ROOT)));
        SigningLedgerRecovery.initializeFormat(root);

        byte[] payload = SigningTransactionPayloadCodec.directCommit(List.of(
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        KEY, -1L, CONTENT)), -1L);
        SigningWalFrameCodec.Frame frame = new SigningWalFrameCodec.Frame(
                SigningWalFrameCodec.RecordType.MUTATION, TRANSACTION_ID, 0L, payload);

        SigningManifestCodec.ActiveWal oldActive = writeActiveWithFrame(root, 1L, frame);
        SigningManifestCodec.Manifest oldManifest = new SigningManifestCodec.Manifest(
                0L, 0L, Optional.empty(), List.of(), oldActive);
        Path manifestPath = root.resolve(SigningLedgerRecovery.MANIFEST_FILE);
        byte[] oldManifestEncoded = SigningManifestCodec.encode(oldManifest);
        SigningFilePublisher.publishManifest(manifestPath, channel ->
                SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(oldManifestEncoded)));

        SigningManifestCodec.Checkpoint checkpoint = writeCheckpoint(root, 2L, frame);
        SigningManifestCodec.ActiveWal newActive = writeEmptyActive(root, 3L, 1L, 1L);
        SigningManifestCodec.Manifest newManifest = new SigningManifestCodec.Manifest(
                1L, 0L, Optional.of(checkpoint), List.of(), newActive);
        return new Fixture(root, manifestPath, oldManifest, newManifest, checkpoint, newActive,
                root.resolve(newActive.name()), SigningManifestCodec.encode(newManifest));
    }

    private static SigningManifestCodec.ActiveWal writeActiveWithFrame(Path root, long identity,
            SigningWalFrameCodec.Frame frame) throws IOException {
        byte[] header = SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(identity, 0L, 0L));
        Path path = root.resolve(SigningManifestCodec.activeName(identity));
        SigningFilePublisher.publishImmutable(path, channel -> {
            SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(header));
            SigningWalFrameCodec.writeCommittedBatch(channel, List.of(frame), 0L, 1L,
                    SigningFormatSupport.sha256().digest(header));
        });
        return new SigningManifestCodec.ActiveWal(identity, 0L, 0L, header.length,
                SigningFormatSupport.sha256().digest(header), path.getFileName().toString());
    }

    private static SigningManifestCodec.Checkpoint writeCheckpoint(Path root, long identity,
            SigningWalFrameCodec.Frame frame) throws IOException {
        byte[] encodedFrame = SigningWalFrameCodec.encode(frame);
        long dataOffset = SigningCheckpointCodec.HEADER_BYTES
                + SigningCheckpointCodec.encodedIndexBytes(KEY.canonical());
        SigningCheckpointCodec.Header header = new SigningCheckpointCodec.Header(
                identity, 1L, 0L, 1, dataOffset);
        SigningCheckpointCodec.EntryDescriptor entry =
                new SigningCheckpointCodec.EntryDescriptor(KEY.canonical(),
                        frame.recordType(), dataOffset, encodedFrame.length, 1L, 0L);
        Path path = root.resolve(SigningManifestCodec.checkpointName(1L, 0L));
        SigningFilePublisher.publishImmutable(path, channel -> {
            SigningCheckpointCodec.Writer writer = SigningCheckpointCodec.writer(channel, header);
            writer.writeIndex(entry);
            writer.beginData();
            writer.writeFrame(entry, encodedFrame);
            writer.finish();
        });
        return new SigningManifestCodec.Checkpoint(identity, 1L, 0L, Files.size(path),
                commitment(path), path.getFileName().toString());
    }

    private static SigningManifestCodec.ActiveWal writeEmptyActive(Path root, long identity,
            long firstSequence, long baselineRevision) throws IOException {
        byte[] header = SigningWalContainerCodec.encode(new SigningWalContainerCodec.Header(
                identity, firstSequence, baselineRevision));
        Path path = root.resolve(SigningManifestCodec.activeName(identity));
        SigningFilePublisher.publishImmutable(path, channel ->
                SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(header)));
        return new SigningManifestCodec.ActiveWal(identity, firstSequence, baselineRevision,
                header.length, SigningFormatSupport.sha256().digest(header),
                path.getFileName().toString());
    }

    private static void assertPublicationDiagnostic(Boundary boundary, Fixture fixture,
            SigningFilePublisher.PublicationException failure) throws IOException {
        assertEquals(boundary.stage(), failure.stage());
        assertEquals(boundary.uncertain(), failure.durabilityUncertain());
        assertEquals(boundary.uncertain()
                ? "signing file publication durability is uncertain"
                : "signing file publication failed before commit", failure.getMessage());
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);

        String diagnostic = failure.getMessage();
        List<String> sensitiveValues = List.of(
                fixture.root().toString(), fixture.manifestPath().toString(),
                SigningLedgerRecovery.MANIFEST_FILE, fixture.newCheckpoint().name(),
                KEY.canonical(), KEY.namespace(), KEY.key(), TRANSACTION_ID.toString(),
                HexFormat.of().formatHex(fixture.newCheckpoint().commitment()),
                HexFormat.of().formatHex(commitment(fixture.manifestPath())));
        for (String sensitive : sensitiveValues) {
            assertFalse(diagnostic.contains(sensitive));
        }
    }

    private static void assertTopology(Topology expected, Fixture fixture,
            SigningManifestCodec.Manifest recovered) {
        if (expected == Topology.OLD) {
            assertEquals(fixture.oldManifest().committedRevision(),
                    recovered.committedRevision());
            assertEquals(fixture.oldManifest().committedSequence(),
                    recovered.committedSequence());
            assertTrue(recovered.checkpoint().isEmpty());
            assertEquals(1L, recovered.activeWal().identity());
            assertEquals(0L, recovered.activeWal().firstSequence());
            assertEquals(0L, recovered.activeWal().baselineRevision());
        } else {
            assertEquals(fixture.newManifest().committedRevision(),
                    recovered.committedRevision());
            assertEquals(fixture.newManifest().committedSequence(),
                    recovered.committedSequence());
            assertEquals(2L, recovered.checkpoint().orElseThrow().generationIdentity());
            assertEquals(3L, recovered.activeWal().identity());
            assertEquals(1L, recovered.activeWal().firstSequence());
            assertEquals(1L, recovered.activeWal().baselineRevision());
        }
        assertTrue(recovered.sealedSegments().isEmpty());
    }

    private static void assertEquivalentCommittedData(List<SigningWalFrameCodec.Frame> frames)
            throws IOException {
        assertEquals(1, frames.size());
        SigningWalFrameCodec.Frame recovered = frames.getFirst();
        assertEquals(SigningWalFrameCodec.RecordType.MUTATION, recovered.recordType());
        assertEquals(TRANSACTION_ID, recovered.transactionId());
        assertEquals(0L, recovered.sequence());
        SigningTransactionPayloadCodec.Payload payload =
                SigningTransactionPayloadCodec.decode(recovered.payload());
        assertEquals(SigningTransactionPayloadCodec.Kind.DIRECT_COMMIT, payload.kind());
        assertEquals(1, payload.mutations().size());
        SigningTransactionPayloadCodec.Mutation mutation = payload.mutations().getFirst();
        assertEquals(SigningTransactionPayloadCodec.MutationKind.CREATE, mutation.kind());
        assertEquals(KEY, mutation.key());
        assertEquals(-1L, mutation.expectedRevision());
        assertArrayEquals(CONTENT, mutation.content());
    }

    private static void assertExactCleanupPlan(Boundary boundary, Fixture fixture,
            MatrixOperations operations, SigningLedgerRecovery.CleanupPlan cleanupPlan) {
        SigningLedgerRecovery.CleanupEntry checkpoint = new SigningLedgerRecovery.CleanupEntry(
                fixture.newCheckpoint().name(),
                SigningLedgerRecovery.Category.ORPHAN_ARTIFACT_DEFERRED);
        assertEquals(fixture.root().resolve(fixture.newActive().name()),
                fixture.newActivePath());
        SigningLedgerRecovery.CleanupEntry newActive = new SigningLedgerRecovery.CleanupEntry(
                fixture.newActive().name(),
                SigningLedgerRecovery.Category.ORPHAN_ARTIFACT_DEFERRED);
        Set<SigningLedgerRecovery.CleanupEntry> expected;
        if (boundary.expectedTopology() == Topology.OLD) {
            expected = Set.of(checkpoint, newActive, new SigningLedgerRecovery.CleanupEntry(
                    operations.temporaryPath().getFileName().toString(),
                    SigningLedgerRecovery.Category.SAFE_STALE_TEMPORARY));
            assertTrue(Files.exists(operations.temporaryPath(), LinkOption.NOFOLLOW_LINKS));
        } else {
            expected = Set.of(new SigningLedgerRecovery.CleanupEntry(
                    fixture.oldManifest().activeWal().name(),
                    SigningLedgerRecovery.Category.ORPHAN_ARTIFACT_DEFERRED));
            assertFalse(cleanupPlan.entries().contains(checkpoint));
            assertFalse(cleanupPlan.entries().contains(newActive));
        }
        assertEquals(expected.size(), cleanupPlan.entries().size());
        assertEquals(expected, Set.copyOf(cleanupPlan.entries()));
    }

    private static void assertManifestArtifactsExist(Path root,
            SigningManifestCodec.Manifest manifest) {
        manifest.checkpoint().ifPresent(checkpoint ->
                assertTrue(Files.exists(root.resolve(checkpoint.name()))));
        assertTrue(Files.exists(root.resolve(manifest.activeWal().name())));
    }

    private static byte[] commitment(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            return SigningFileCommitment.sha256(channel);
        }
    }

    private static SigningLedgerRecovery.Configuration recoveryConfiguration() {
        return new SigningLedgerRecovery.Configuration(64, 64L * 1024L * 1024L, 100,
                SigningActiveWal.Configuration.defaults());
    }

    private enum Topology {
        OLD,
        NEW
    }

    private enum Boundary {
        WRITE(SigningFilePublisher.PublicationStage.WRITE, false, Topology.OLD),
        FILE_FORCE(SigningFilePublisher.PublicationStage.FILE_FORCE, false, Topology.OLD),
        FILE_FORCE_COMPLETES_THEN_THROWS(SigningFilePublisher.PublicationStage.FILE_FORCE,
                false, Topology.OLD),
        ATOMIC_MOVE_BEFORE_VISIBILITY(SigningFilePublisher.PublicationStage.ATOMIC_MOVE,
                true, Topology.OLD),
        MOVE_COMPLETES_THEN_THROWS(SigningFilePublisher.PublicationStage.ATOMIC_MOVE,
                true, Topology.NEW),
        DIRECTORY_FORCE_AFTER_MOVE(SigningFilePublisher.PublicationStage.DIRECTORY_FORCE,
                true, Topology.NEW);

        private final SigningFilePublisher.PublicationStage stage;
        private final boolean uncertain;
        private final Topology expectedTopology;

        Boundary(SigningFilePublisher.PublicationStage stage, boolean uncertain,
                Topology expectedTopology) {
            this.stage = stage;
            this.uncertain = uncertain;
            this.expectedTopology = expectedTopology;
        }

        private SigningFilePublisher.PublicationStage stage() {
            return stage;
        }

        private boolean uncertain() {
            return uncertain;
        }

        private Topology expectedTopology() {
            return expectedTopology;
        }
    }

    private static final class MatrixOperations
            implements SigningFilePublisher.PublicationOperations {
        private static final UUID TEMPORARY_ID = UUID.fromString(
                "cd7f3d12-2fe5-4d84-85f7-127513398f7c");

        private final Boundary boundary;
        private Path temporaryPath;

        private MatrixOperations(Boundary boundary) {
            this.boundary = boundary;
        }

        @Override
        public SigningFilePublisher.TemporaryFile createTemporary(Path parent, String prefix)
                throws IOException {
            temporaryPath = parent.resolve(prefix + TEMPORARY_ID + ".tmp");
            FileChannel channel = FileChannel.open(temporaryPath, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            BasicFileAttributes attributes = Files.readAttributes(temporaryPath,
                    BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return new SigningFilePublisher.TemporaryFile(
                    temporaryPath, channel, attributes.fileKey());
        }

        @Override
        public void write(FileChannel channel, SigningFilePublisher.ContentWriter writer)
                throws IOException {
            failBefore(SigningFilePublisher.PublicationStage.WRITE);
            writer.write(channel);
        }

        @Override
        public void forceFile(FileChannel channel) throws IOException {
            if (boundary == Boundary.FILE_FORCE_COMPLETES_THEN_THROWS) {
                channel.force(true);
                throw new IOException("injected after manifest temporary file force");
            }
            failBefore(SigningFilePublisher.PublicationStage.FILE_FORCE);
            channel.force(true);
        }

        @Override
        public void validateTemporary(SigningFilePublisher.TemporaryFile temporary)
                throws IOException {
            BasicFileAttributes attributes = Files.readAttributes(temporary.path(),
                    BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            // fileKey() is null where the filesystem has no stable file identity
            // (e.g. Windows); the regular-file check is the strongest guard there.
            if (!attributes.isRegularFile()
                    || (temporary.fileKey() != null
                            && !temporary.fileKey().equals(attributes.fileKey()))) {
                throw new IOException("test publication temporary changed");
            }
        }

        @Override
        public void atomicMove(Path source, Path target, boolean replace) throws IOException {
            if (boundary == Boundary.ATOMIC_MOVE_BEFORE_VISIBILITY) {
                throw new IOException("injected before atomic move visibility");
            }
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            if (boundary == Boundary.MOVE_COMPLETES_THEN_THROWS) {
                throw new IOException("injected after atomic move visibility");
            }
        }

        @Override
        public void forceDirectory(Path directory) throws IOException {
            if (boundary == Boundary.DIRECTORY_FORCE_AFTER_MOVE) {
                throw new IOException("injected after manifest visibility");
            }
            SigningFormatSupport.forceDirectory(directory);
        }

        private void failBefore(SigningFilePublisher.PublicationStage stage) throws IOException {
            if (boundary.stage() == stage) {
                throw new IOException("injected publication boundary");
            }
        }

        private Path temporaryPath() {
            return temporaryPath;
        }
    }

    private static final class CollectingSink implements SigningLedgerRecovery.RecoverySink {
        private final List<SigningWalFrameCodec.Frame> frames = new ArrayList<>();

        @Override
        public Session begin(SigningManifestCodec.Manifest manifest) {
            return new Session() {
                @Override
                public void acceptCheckpoint(SigningCheckpointCodec.Header header,
                        SigningCheckpointCodec.EntryDescriptor entry,
                        SigningWalFrameCodec.Frame frame) {
                    frames.add(frame);
                }

                @Override
                public void acceptCheckpointBoundary(SigningCheckpointCodec.Header header) {
                    // This sink collects logical frames only.
                }

                @Override
                public void acceptWalGroup(List<SigningWalFrameCodec.ScannedFrame> group,
                        long committedRevision) {
                    group.forEach(frame -> frames.add(frame.frame()));
                }

                @Override
                public Prepared prepare() {
                    return new Prepared() {
                        @Override public void publish() { }
                        @Override public void close() { }
                    };
                }

                @Override public void close() { }
            };
        }

        private List<SigningWalFrameCodec.Frame> frames() {
            return List.copyOf(frames);
        }
    }

    private record Fixture(Path root, Path manifestPath,
            SigningManifestCodec.Manifest oldManifest,
            SigningManifestCodec.Manifest newManifest,
            SigningManifestCodec.Checkpoint newCheckpoint,
            SigningManifestCodec.ActiveWal newActive,
            Path newActivePath,
            byte[] newManifestEncoded) {
        private Fixture {
            newManifestEncoded = newManifestEncoded.clone();
        }

        @Override
        public byte[] newManifestEncoded() {
            return newManifestEncoded.clone();
        }
    }
}
