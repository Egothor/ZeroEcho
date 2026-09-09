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
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.CRC32C;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import zeroecho.pki.spi.store.MetadataKey;

final class SigningLedgerRecoveryTest {
    @TempDir
    private Path temporaryDirectory;

    @ParameterizedTest(name = "integrity/restart image: {0}")
    @EnumSource(IntegrityImage.class)
    void integrityRestartMatrix(IntegrityImage image) throws Exception {
        Path root = createRoot("integrity-" + image.name().toLowerCase(java.util.Locale.ROOT));
        IntegrityFixture fixture = integrityFixture(root, image);
        image.mutate(fixture);
        Map<String, byte[]> before = inventory(root);
        CollectingSink sink = new CollectingSink();

        if (image == IntegrityImage.INCOMPLETE_ACTIVE_SUFFIX) {
            try (SigningLedgerRecovery.Handle handle = SigningLedgerRecovery.recover(root,
                    configuration(), sink)) {
                assertTrue(sink.published.get());
                assertEquals(List.of(0L, 1L, 2L, 3L, 4L), sink.sequences);
                assertTrue(handle.statistics().truncatedBytes() > 0L);
            }
            Map<String, byte[]> after = inventory(root);
            assertEquals(before.keySet(), after.keySet());
            for (String name : before.keySet()) {
                if (name.equals(fixture.manifest().activeWal().name())) {
                    assertArrayEquals(fixture.committedActive(), after.get(name));
                } else {
                    assertArrayEquals(before.get(name), after.get(name));
                }
            }
            return;
        }

        SigningLedgerRecovery.RecoveryException failure = assertThrows(
                SigningLedgerRecovery.RecoveryException.class,
                () -> SigningLedgerRecovery.recover(root, configuration(), sink));
        assertEquals(image.code(), failure.code());
        assertEquals("signing recovery failed: " + image.code().name(), failure.getMessage());
        assertFalse(sink.published.get());
        if (image == IntegrityImage.CHECKPOINT_FRAME_CRC32C
                || image == IntegrityImage.CHECKPOINT_SHA256) {
            assertTrue(sink.boundaries.isEmpty());
        }
        assertInventoryEquals(before, inventory(root));
        assertRedacted(failure, fixture);
    }

    @Test
    void selfContainedCheckpointAndPostBoundarySuffixRecoverWithoutPointerJoin() throws Exception {
        Path root = createRoot("checkpoint-suffix");
        byte[] checkpointFrame = SigningWalFrameCodec.encode(frame(0L, 1));
        String key = "mk1:7:1:examplea";
        long dataOffset = SigningCheckpointCodec.HEADER_BYTES
                + SigningCheckpointCodec.encodedIndexBytes(key);
        Path checkpoint = root.resolve(SigningManifestCodec.checkpointName(1L, 0L));
        writeCheckpoint(checkpoint, new SigningCheckpointCodec.Header(
                100L, 1L, 0L, 1, dataOffset),
                new SigningCheckpointCodec.EntryDescriptor(key,
                        SigningWalFrameCodec.RecordType.MUTATION, dataOffset,
                        checkpointFrame.length, 1L, 0L), checkpointFrame);

        Path sealed = root.resolve(SigningManifestCodec.segmentName(1L, 1L));
        Files.write(sealed, SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(101L, 1L, 1L)));
        appendGroup(sealed, List.of(frame(1L, 2)), 1L, 2L);
        Path active = root.resolve(SigningManifestCodec.activeName(102L));
        Files.write(active, SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(102L, 2L, 2L)));
        writeManifest(root, new SigningManifestCodec.Manifest(2L, 1L,
                Optional.of(new SigningManifestCodec.Checkpoint(100L, 1L, 0L,
                        Files.size(checkpoint), commitment(checkpoint),
                        checkpoint.getFileName().toString())),
                List.of(new SigningManifestCodec.Segment(101L, 1L, 1L,
                        Files.size(sealed), commitment(sealed),
                        sealed.getFileName().toString())), activeDescriptor(102L, 2L, 2L)));

        CollectingSink sink = new CollectingSink();
        try (SigningLedgerRecovery.Handle handle = SigningLedgerRecovery.recover(root,
                configuration(), sink)) {
            assertEquals(List.of(0L, 1L), sink.sequences);
            assertEquals(List.of(new SigningCheckpointCodec.Header(
                    100L, 1L, 0L, 1, dataOffset)), sink.boundaries);
            assertEquals(1, handle.statistics().checkpointEntries());
            assertEquals(1L, handle.statistics().sealedFrames());
            assertEquals(3, handle.generationSnapshot().registered());
            assertEquals(3L, handle.generationSnapshot().recoveryTemporaryReferences());
            handle.releaseTemporaryOwnership();
            assertEquals(0L, handle.generationSnapshot().recoveryTemporaryReferences());
            assertEquals(0L, handle.generationSnapshot().snapshotPins());
        }
    }

    @Test
    void noCheckpointPublishesNoCheckpointBoundary() throws Exception {
        Path root = createRoot("no-checkpoint-boundary");
        activeOnly(root, 7L, 0L, 0L);
        CollectingSink sink = new CollectingSink();

        try (SigningLedgerRecovery.Handle ignored = SigningLedgerRecovery.recover(root,
                configuration(), sink)) {
            assertTrue(sink.boundaries.isEmpty());
            assertTrue(sink.published.get());
        }
    }

    @Test
    void recoveredStateCheckpointBoundaryFailsClosedForMissingDuplicateAndConflict()
            throws Exception {
        SigningCheckpointCodec.Header header = new SigningCheckpointCodec.Header(
                20L, 7L, 11L, 0, SigningCheckpointCodec.HEADER_BYTES);
        SigningManifestCodec.Manifest manifest = manifestWithCheckpoint(header);

        SigningLedgerRecovery.RecoverySink.Session missing = recoveredSession(manifest);
        assertThrows(IOException.class, missing::prepare);
        missing.close();

        SigningLedgerRecovery.RecoverySink.Session accepted = recoveredSession(manifest);
        accepted.acceptCheckpointBoundary(header);
        assertThrows(IOException.class, () -> accepted.acceptCheckpointBoundary(header));
        try (SigningLedgerRecovery.RecoverySink.Prepared prepared = accepted.prepare()) {
            prepared.publish();
        }
        accepted.close();

        SigningLedgerRecovery.RecoverySink.Session conflict = recoveredSession(manifest);
        SigningCheckpointCodec.Header different = new SigningCheckpointCodec.Header(
                20L, 8L, 11L, 0, SigningCheckpointCodec.HEADER_BYTES);
        assertThrows(IOException.class, () -> conflict.acceptCheckpointBoundary(different));
        conflict.close();

        SigningLedgerRecovery.RecoverySink.Session prematureWal = recoveredSession(manifest);
        assertThrows(IOException.class,
                () -> prematureWal.acceptWalGroup(List.of(), header.revision()));
        prematureWal.close();
    }

    private static SigningLedgerRecovery.RecoverySink.Session recoveredSession(
            SigningManifestCodec.Manifest manifest) throws IOException {
        SigningLedgerRecoveredState.RecoveryFold fold =
                new SigningLedgerRecoveredState.RecoveryFold(Path.of("."),
                        new zeroecho.pki.spi.store.MetadataStoreId(
                                "0123456789abcdef0123456789abcdef"));
        return fold.begin(manifest);
    }

    private static SigningManifestCodec.Manifest manifestWithCheckpoint(
            SigningCheckpointCodec.Header header) {
        byte[] commitment = new byte[SigningFormatSupport.SHA_256_BYTES];
        SigningManifestCodec.Checkpoint checkpoint = new SigningManifestCodec.Checkpoint(
                header.generationIdentity(), header.revision(), header.committedSequence(),
                1L, commitment, SigningManifestCodec.checkpointName(
                        header.revision(), header.committedSequence()));
        return new SigningManifestCodec.Manifest(header.revision(), header.committedSequence(),
                Optional.of(checkpoint), List.of(), activeDescriptor(
                        21L, header.committedSequence() + 1L, header.revision()));
    }

    @Test
    void checkpointRecoveryUsesMetadataSemanticOrderAcrossLengthPrefixes() throws Exception {
        Path root = createRoot("semantic-checkpoint-order");
        String firstKey = new MetadataKey("a", "aa").canonical();
        String secondKey = new MetadataKey("a", "z").canonical();
        byte[] firstFrame = SigningWalFrameCodec.encode(frame(0L, 1));
        byte[] secondFrame = SigningWalFrameCodec.encode(frame(1L, 2));
        long dataOffset = SigningCheckpointCodec.HEADER_BYTES
                + SigningCheckpointCodec.encodedIndexBytes(firstKey)
                + SigningCheckpointCodec.encodedIndexBytes(secondKey);
        SigningCheckpointCodec.EntryDescriptor first = new SigningCheckpointCodec.EntryDescriptor(
                firstKey, SigningWalFrameCodec.RecordType.MUTATION, dataOffset,
                firstFrame.length, 1L, 0L);
        SigningCheckpointCodec.EntryDescriptor second = new SigningCheckpointCodec.EntryDescriptor(
                secondKey, SigningWalFrameCodec.RecordType.MUTATION,
                dataOffset + firstFrame.length, secondFrame.length, 2L, 1L);
        Path checkpoint = root.resolve(SigningManifestCodec.checkpointName(2L, 1L));
        writeCheckpoint(checkpoint, new SigningCheckpointCodec.Header(
                100L, 2L, 1L, 2, dataOffset),
                new SigningCheckpointCodec.EntryDescriptor[] { first, second },
                new byte[][] { firstFrame, secondFrame });
        Path active = root.resolve(SigningManifestCodec.activeName(102L));
        Files.write(active, SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(102L, 2L, 2L)));
        writeManifest(root, new SigningManifestCodec.Manifest(2L, 1L,
                Optional.of(new SigningManifestCodec.Checkpoint(100L, 2L, 1L,
                        Files.size(checkpoint), commitment(checkpoint),
                        checkpoint.getFileName().toString())), List.of(),
                activeDescriptor(102L, 2L, 2L)));

        CollectingSink sink = new CollectingSink();
        try (SigningLedgerRecovery.Handle ignored = SigningLedgerRecovery.recover(root,
                configuration(), sink)) {
            assertEquals(List.of(firstKey, secondKey), sink.keys);
        }
    }

    @Test
    @RequiresSymlinkCreation
    void unsupportedRootEntryAndReferencedSymlinkFailClosed() throws Exception {
        Path root = createRoot("root-validation");
        SigningManifestCodec.Manifest manifest = activeOnly(root, 7L, 0L, 0L);
        Files.write(root.resolve("unknown"), new byte[] { 1 });
        assertCode(SigningLedgerRecovery.Code.ORPHAN_UNSUPPORTED,
                () -> SigningLedgerRecovery.recover(root, configuration(), new CollectingSink()));
        Files.delete(root.resolve("unknown"));
        Path external = temporaryDirectory.resolve("external");
        Files.write(external, new byte[] { 1 });
        try {
            Files.delete(root.resolve(manifest.activeWal().name()));
            Files.createSymbolicLink(root.resolve(manifest.activeWal().name()), external);
            assertCode(SigningLedgerRecovery.Code.REFERENCED_INVALID,
                    () -> SigningLedgerRecovery.recover(root, configuration(), new CollectingSink()));
        } catch (UnsupportedOperationException | java.nio.file.FileSystemException unsupported) {
            // The filesystem forbids symbolic links, or the OS requires a privilege
            // not held by this process (Windows without SeCreateSymbolicLinkPrivilege
            // or Developer Mode). The symlink leg cannot be exercised here.
            assertTrue(Files.exists(external));
        }
    }

    @Test
    void manifestBoundaryRejectsPreCheckpointSegments() throws Exception {
        byte[] commitment = new byte[SigningFormatSupport.SHA_256_BYTES];
        SigningManifestCodec.Checkpoint checkpoint = new SigningManifestCodec.Checkpoint(
                1L, 5L, 9L, 1L, commitment,
                SigningManifestCodec.checkpointName(5L, 9L));
        assertThrows(IllegalArgumentException.class, () -> SigningManifestCodec.encode(
                new SigningManifestCodec.Manifest(6L, 10L, Optional.of(checkpoint),
                        List.of(new SigningManifestCodec.Segment(2L, 0L, 11L,
                                1L, commitment, SigningManifestCodec.segmentName(0L, 10L))),
                        activeDescriptor(3L, 11L, 6L))));
    }

    private IntegrityFixture integrityFixture(Path root, IntegrityImage image) throws Exception {
        String checkpointKey = new MetadataKey("secret-namespace", "secret-key").canonical();
        byte[] checkpointFrame = SigningWalFrameCodec.encode(frame(0L, 1));
        long checkpointDataOffset = SigningCheckpointCodec.HEADER_BYTES
                + SigningCheckpointCodec.encodedIndexBytes(checkpointKey);
        Path checkpoint = root.resolve(SigningManifestCodec.checkpointName(1L, 0L));
        writeCheckpoint(checkpoint, new SigningCheckpointCodec.Header(
                100L, 1L, 0L, 1, checkpointDataOffset),
                new SigningCheckpointCodec.EntryDescriptor(checkpointKey,
                        SigningWalFrameCodec.RecordType.MUTATION, checkpointDataOffset,
                        checkpointFrame.length, 1L, 0L), checkpointFrame);

        long sealedBaseline = image == IntegrityImage.TOPOLOGY_CONTINUITY ? 0L : 1L;
        Path sealed = root.resolve(SigningManifestCodec.segmentName(1L, 3L));
        Files.write(sealed, SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(101L, 1L, sealedBaseline)));
        long firstCommittedRevision = image == IntegrityImage.REVISION_CONTINUITY ? 4L : 3L;
        appendGroup(sealed, List.of(frame(1L, 2), frame(2L, 3)),
                sealedBaseline, firstCommittedRevision);
        long manifestRevision = image == IntegrityImage.REVISION_CONTINUITY ? 5L : 4L;
        appendFollowingGroup(sealed, List.of(frame(3L, 4)), 1L,
                firstCommittedRevision, manifestRevision);

        Path active = root.resolve(SigningManifestCodec.activeName(102L));
        Files.write(active, SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(102L, 4L, manifestRevision)));
        appendGroup(active, List.of(frame(4L, 5)), manifestRevision, manifestRevision + 1L);
        SigningManifestCodec.Manifest manifest = new SigningManifestCodec.Manifest(manifestRevision, 3L,
                Optional.of(new SigningManifestCodec.Checkpoint(100L, 1L, 0L,
                        Files.size(checkpoint), commitment(checkpoint), checkpoint.getFileName().toString())),
                List.of(new SigningManifestCodec.Segment(101L, 1L, 3L,
                        Files.size(sealed), commitment(sealed), sealed.getFileName().toString())),
                activeDescriptor(102L, 4L, manifestRevision));
        writeManifest(root, manifest);
        Files.write(root.resolve(".manifest.zem-00000000-0000-0000-0000-000000000012.tmp"),
                new byte[] { 99 });
        return new IntegrityFixture(root, manifest, checkpoint, checkpointDataOffset, sealed, active,
                Files.readAllBytes(active), checkpointKey);
    }

    private static Map<String, byte[]> inventory(Path root) throws IOException {
        Map<String, byte[]> inventory = new TreeMap<>();
        try (java.util.stream.Stream<Path> paths = Files.list(root)) {
            for (Path path : paths.sorted().toList()) {
                inventory.put(path.getFileName().toString(), Files.readAllBytes(path));
            }
        }
        return inventory;
    }

    private static void assertInventoryEquals(Map<String, byte[]> expected,
            Map<String, byte[]> actual) {
        assertEquals(expected.keySet(), actual.keySet());
        for (String name : expected.keySet()) {
            assertArrayEquals(expected.get(name), actual.get(name), name);
        }
    }

    private static void assertRedacted(SigningLedgerRecovery.RecoveryException failure,
            IntegrityFixture fixture) throws IOException {
        String diagnostic = failure.getMessage();
        assertFalse(diagnostic.contains(fixture.root().toString()));
        assertFalse(diagnostic.contains(fixture.checkpointKey()));
        assertFalse(diagnostic.contains(fixture.manifest().activeWal().name()));
        assertFalse(diagnostic.contains(frame(0L, 1).transactionId().toString()));
        assertFalse(diagnostic.contains(java.util.HexFormat.of().formatHex(commitment(fixture.checkpoint()))));
        assertFalse(diagnostic.contains("secret-namespace"));
        assertFalse(diagnostic.contains("secret-key"));
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }

    private static void flipByte(Path path, long offset, boolean rewriteFrameChecksum) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        int exactOffset = Math.toIntExact(offset);
        bytes[exactOffset] ^= 1;
        if (rewriteFrameChecksum) {
            rewriteFrameChecksum(bytes, SigningWalContainerCodec.HEADER_BYTES);
        }
        Files.write(path, bytes, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private static void rewriteFrameChecksum(byte[] bytes, int frameOffset) {
        ByteBuffer view = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        int frameLength = view.getInt(frameOffset + 8);
        CRC32C checksum = new CRC32C();
        checksum.update(bytes, frameOffset, frameLength - SigningWalFrameCodec.CHECKSUM_BYTES);
        view.putInt(frameOffset + frameLength - SigningWalFrameCodec.CHECKSUM_BYTES,
                (int) checksum.getValue());
    }

    private static void corruptRollingCommitment(Path active) throws IOException {
        byte[] bytes = Files.readAllBytes(active);
        int frameOffset = SigningWalContainerCodec.HEADER_BYTES;
        int frameLength = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).getInt(frameOffset + 8);
        int markerOffset = frameOffset + frameLength;
        int previousCommitmentOffset = markerOffset + SigningWalFrameCodec.HEADER_BYTES + 40;
        bytes[previousCommitmentOffset] ^= 1;
        rewriteFrameChecksum(bytes, markerOffset);
        Files.write(active, bytes, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private static void reorderFirstSealedFrames(Path sealed) throws IOException {
        byte[] bytes = Files.readAllBytes(sealed);
        int firstOffset = SigningWalContainerCodec.HEADER_BYTES;
        int firstLength = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).getInt(firstOffset + 8);
        int secondOffset = firstOffset + firstLength;
        int secondLength = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).getInt(secondOffset + 8);
        if (firstLength != secondLength) {
            throw new IllegalStateException("test frames must have equal encoded lengths");
        }
        byte[] first = java.util.Arrays.copyOfRange(bytes, firstOffset, secondOffset);
        System.arraycopy(bytes, secondOffset, bytes, firstOffset, secondLength);
        System.arraycopy(first, 0, bytes, secondOffset, firstLength);
        Files.write(sealed, bytes, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private static void reorderSealedGroups(Path sealed) throws IOException {
        byte[] bytes = Files.readAllBytes(sealed);
        int headerLength = SigningWalContainerCodec.HEADER_BYTES;
        int frameLength = SigningWalFrameCodec.encodedLength(frame(1L, 2));
        int firstGroupLength = 2 * frameLength + SigningWalFrameCodec.BATCH_MARKER_BYTES;
        int secondGroupOffset = headerLength + firstGroupLength;
        byte[] reordered = bytes.clone();
        int secondGroupLength = bytes.length - secondGroupOffset;
        System.arraycopy(bytes, secondGroupOffset, reordered, headerLength, secondGroupLength);
        System.arraycopy(bytes, headerLength, reordered, headerLength + secondGroupLength, firstGroupLength);
        Files.write(sealed, reordered, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private static void replaceCheckpointCommitment(IntegrityFixture fixture) throws IOException {
        SigningManifestCodec.Checkpoint checkpoint = fixture.manifest().checkpoint().orElseThrow();
        byte[] corrupt = checkpoint.commitment();
        corrupt[0] ^= 1;
        SigningManifestCodec.Checkpoint replacement = new SigningManifestCodec.Checkpoint(
                checkpoint.generationIdentity(), checkpoint.revision(), checkpoint.coveredSequence(),
                checkpoint.length(), corrupt, checkpoint.name());
        SigningManifestCodec.Manifest manifest = fixture.manifest();
        writeManifest(fixture.root(), new SigningManifestCodec.Manifest(manifest.committedRevision(),
                manifest.committedSequence(), Optional.of(replacement), manifest.sealedSegments(),
                manifest.activeWal()));
    }

    private static void replaceSealedCommitment(IntegrityFixture fixture) throws IOException {
        SigningManifestCodec.Segment segment = fixture.manifest().sealedSegments().getFirst();
        byte[] corrupt = segment.commitment();
        corrupt[0] ^= 1;
        SigningManifestCodec.Segment replacement = new SigningManifestCodec.Segment(
                segment.generationIdentity(), segment.firstSequence(), segment.sequenceCount(),
                segment.length(), corrupt, segment.name());
        SigningManifestCodec.Manifest manifest = fixture.manifest();
        writeManifest(fixture.root(), new SigningManifestCodec.Manifest(manifest.committedRevision(),
                manifest.committedSequence(), manifest.checkpoint(), List.of(replacement),
                manifest.activeWal()));
    }

    private record IntegrityFixture(Path root, SigningManifestCodec.Manifest manifest,
            Path checkpoint, long checkpointDataOffset, Path sealed, Path active,
            byte[] committedActive, String checkpointKey) {
        private IntegrityFixture {
            committedActive = committedActive.clone();
        }

        @Override public byte[] committedActive() { return committedActive.clone(); }
    }

    private enum IntegrityImage {
        ACTIVE_CRC32C(SigningLedgerRecovery.Code.RECOVERY_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                flipByte(fixture.active(), SigningWalContainerCodec.HEADER_BYTES
                        + SigningWalFrameCodec.HEADER_BYTES, false);
            }
        },
        ACTIVE_GROUP_DIGEST(SigningLedgerRecovery.Code.RECOVERY_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                flipByte(fixture.active(), SigningWalContainerCodec.HEADER_BYTES
                        + SigningWalFrameCodec.HEADER_BYTES, true);
            }
        },
        ACTIVE_ROLLING_COMMITMENT(SigningLedgerRecovery.Code.RECOVERY_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                corruptRollingCommitment(fixture.active());
            }
        },
        CHECKPOINT_FRAME_CRC32C(SigningLedgerRecovery.Code.RECOVERY_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                flipByte(fixture.checkpoint(), fixture.checkpointDataOffset()
                        + SigningWalFrameCodec.HEADER_BYTES, false);
            }
        },
        CHECKPOINT_SHA256(SigningLedgerRecovery.Code.REFERENCED_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                replaceCheckpointCommitment(fixture);
            }
        },
        SEALED_SHA256(SigningLedgerRecovery.Code.REFERENCED_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                replaceSealedCommitment(fixture);
            }
        },
        MANIFEST_COMMITMENT(SigningLedgerRecovery.Code.RECOVERY_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                byte[] manifest = Files.readAllBytes(fixture.root().resolve(SigningLedgerRecovery.MANIFEST_FILE));
                manifest[manifest.length - 1] ^= 1;
                Files.write(fixture.root().resolve(SigningLedgerRecovery.MANIFEST_FILE), manifest,
                        StandardOpenOption.TRUNCATE_EXISTING);
            }
        },
        SEALED_TRUNCATION(SigningLedgerRecovery.Code.REFERENCED_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                byte[] sealed = Files.readAllBytes(fixture.sealed());
                Files.write(fixture.sealed(), java.util.Arrays.copyOf(sealed, sealed.length - 1),
                        StandardOpenOption.TRUNCATE_EXISTING);
            }
        },
        INCOMPLETE_ACTIVE_SUFFIX(null) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                byte[] next = SigningWalFrameCodec.encode(frame(5L, 6));
                Files.write(fixture.active(), java.util.Arrays.copyOf(next, 7), StandardOpenOption.APPEND);
            }
        },
        FRAME_REORDER(SigningLedgerRecovery.Code.RECOVERY_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                reorderFirstSealedFrames(fixture.sealed());
            }
        },
        GROUP_REORDER(SigningLedgerRecovery.Code.RECOVERY_INVALID) {
            @Override void mutate(IntegrityFixture fixture) throws IOException {
                reorderSealedGroups(fixture.sealed());
            }
        },
        REVISION_CONTINUITY(SigningLedgerRecovery.Code.REPLAY_CONTINUITY_INVALID),
        TOPOLOGY_CONTINUITY(SigningLedgerRecovery.Code.REFERENCED_INVALID);

        private final SigningLedgerRecovery.Code code;

        IntegrityImage(SigningLedgerRecovery.Code code) {
            this.code = code;
        }

        void mutate(IntegrityFixture fixture) throws IOException {
            // The fixture constructor creates a validly encoded but discontinuous image.
        }

        private SigningLedgerRecovery.Code code() {
            return code;
        }
    }

    private Path createRoot(String name) throws Exception {
        Path root = Files.createDirectory(temporaryDirectory.resolve(name));
        SigningLedgerRecovery.initializeFormat(root);
        return root;
    }

    private SigningManifestCodec.Manifest activeOnly(Path root, long identity,
            long firstSequence, long revision) throws Exception {
        SigningManifestCodec.ActiveWal descriptor = activeDescriptor(identity,
                firstSequence, revision);
        Files.write(root.resolve(descriptor.name()), SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(identity, firstSequence, revision)));
        SigningManifestCodec.Manifest manifest = new SigningManifestCodec.Manifest(revision,
                firstSequence == 0L ? 0L : firstSequence - 1L,
                Optional.empty(), List.of(), descriptor);
        writeManifest(root, manifest);
        return manifest;
    }

    private static SigningManifestCodec.ActiveWal activeDescriptor(long identity,
            long firstSequence, long revision) {
        byte[] header = SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(identity, firstSequence, revision));
        return new SigningManifestCodec.ActiveWal(identity, firstSequence, revision,
                header.length, SigningFormatSupport.sha256().digest(header),
                SigningManifestCodec.activeName(identity));
    }

    private static void writeManifest(Path root, SigningManifestCodec.Manifest manifest)
            throws IOException {
        Files.write(root.resolve(SigningLedgerRecovery.MANIFEST_FILE),
                SigningManifestCodec.encode(manifest));
    }

    private static void writeCheckpoint(Path path, SigningCheckpointCodec.Header header,
            SigningCheckpointCodec.EntryDescriptor entry, byte[] encoded) throws IOException {
        writeCheckpoint(path, header, new SigningCheckpointCodec.EntryDescriptor[] { entry },
                new byte[][] { encoded });
    }

    private static void writeCheckpoint(Path path, SigningCheckpointCodec.Header header,
            SigningCheckpointCodec.EntryDescriptor[] entries, byte[][] frames) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            SigningCheckpointCodec.Writer writer = SigningCheckpointCodec.writer(channel, header);
            for (SigningCheckpointCodec.EntryDescriptor entry : entries) {
                writer.writeIndex(entry);
            }
            writer.beginData();
            for (int index = 0; index < entries.length; index++) {
                writer.writeFrame(entries[index], frames[index]);
            }
            writer.finish();
        }
    }

    private static void appendGroup(Path path, List<SigningWalFrameCodec.Frame> frames,
            long baseline, long revision) throws IOException {
        byte[] previous;
        try (FileChannel input = FileChannel.open(path, StandardOpenOption.READ)) {
            previous = SigningFileCommitment.sha256(input);
        }
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.APPEND)) {
            SigningWalFrameCodec.writeCommittedBatch(channel, frames, baseline, revision, previous);
        }
    }

    private static void appendFollowingGroup(Path path, List<SigningWalFrameCodec.Frame> frames,
            long expectedFirstSequence, long baseline, long revision) throws IOException {
        byte[] previous;
        try (FileChannel input = FileChannel.open(path, StandardOpenOption.READ)) {
            previous = SigningWalFrameCodec.scanGroups(input, expectedFirstSequence, false,
                    (committedFrames, marker) -> { }).rollingCommitment();
        }
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.APPEND)) {
            SigningWalFrameCodec.writeCommittedBatch(channel, frames, baseline, revision, previous);
        }
    }

    private static SigningWalFrameCodec.Frame frame(long sequence, int value) {
        return new SigningWalFrameCodec.Frame(SigningWalFrameCodec.RecordType.MUTATION,
                new UUID(1L, sequence + 1L), sequence, new byte[] { (byte) value });
    }

    private static byte[] commitment(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            return SigningFileCommitment.sha256(channel);
        }
    }

    private static SigningLedgerRecovery.Configuration configuration() {
        return new SigningLedgerRecovery.Configuration(64, 64L * 1024L * 1024L,
                10_000, new SigningActiveWal.Configuration(8, 8, 0L,
                        8L * SigningWalFrameCodec.MAX_PAYLOAD_BYTES,
                        SigningActiveWal.MAXIMUM_BATCH_BYTES));
    }

    private static void assertCode(SigningLedgerRecovery.Code expected,
            ThrowingOperation operation) {
        SigningLedgerRecovery.RecoveryException failure = assertThrows(
                SigningLedgerRecovery.RecoveryException.class, operation::run);
        assertEquals(expected, failure.code());
    }

    @FunctionalInterface
    private interface ThrowingOperation {
        void run() throws Exception;
    }

    private static final class CollectingSink implements SigningLedgerRecovery.RecoverySink {
        private final List<Long> sequences = new ArrayList<>();
        private final List<String> keys = new ArrayList<>();
        private final List<SigningCheckpointCodec.Header> boundaries = new ArrayList<>();
        private final AtomicBoolean published = new AtomicBoolean();

        @Override
        public Session begin(SigningManifestCodec.Manifest manifest) {
            return new Session() {
                @Override
                public void acceptCheckpoint(SigningCheckpointCodec.Header header,
                        SigningCheckpointCodec.EntryDescriptor entry,
                        SigningWalFrameCodec.Frame frame) {
                    keys.add(entry.key());
                    sequences.add(entry.sequence());
                }

                @Override
                public void acceptCheckpointBoundary(SigningCheckpointCodec.Header header) {
                    boundaries.add(header);
                }

                @Override
                public void acceptWalGroup(List<SigningWalFrameCodec.ScannedFrame> frames,
                        long committedRevision) {
                    frames.forEach(frame -> sequences.add(frame.frame().sequence()));
                }

                @Override
                public Prepared prepare() {
                    return new Prepared() {
                        @Override public void publish() { published.set(true); }
                        @Override public void close() { }
                    };
                }

                @Override public void close() { }
            };
        }
    }
}
