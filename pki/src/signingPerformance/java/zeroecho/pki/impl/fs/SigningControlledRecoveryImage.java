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
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Benchmark-only builder and validator for a production-recoverable controlled image. */
@SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.CommentRequired",
        "PMD.CyclomaticComplexity" })
final class SigningControlledRecoveryImage {
    static final String DESCRIPTOR_SCHEMA = "zeroecho-signing-controlled-recovery-image-v1";
    static final String DESCRIPTOR_FILE = "CONTROLLED_RECOVERY_IMAGE";
    /* Eight canonical ASCII lines with bounded numeric, boolean, and SHA-256 fields. */
    static final int MAXIMUM_DESCRIPTOR_BYTES = descriptorMaximumBytes();
    private static final String GENERIC_NAMESPACE = "io.zeroecho.pki.benchmark-retained";
    private static final MetadataKey REPLACED_KEY =
            new MetadataKey(GENERIC_NAMESPACE, "g0000000");
    private static final long MAXIMUM_INDEX_BYTES =
            FsPkiStoreOptions.DEFAULT_RESIDENT_INDEX_BUDGET_BYTES;

    private SigningControlledRecoveryImage() {
    }

    static Descriptor prepare(Path workRoot, long retainedPopulation, long activePopulation,
            int sealedSegments, long suffixFrames, Instant createdAt) throws IOException {
        prepareFreshRoot(workRoot);
        long genericRecords;
        try {
            genericRecords = Math.subtractExact(retainedPopulation,
                    Math.addExact(Math.multiplyExact(2L, activePopulation), 1L));
        } catch (ArithmeticException failure) {
            throw new ImageException("CONFIGURATION_INVALID", failure);
        }
        if (genericRecords <= 0L) {
            throw new ImageException("CONFIGURATION_INVALID");
        }
        Path storeRoot = workRoot.resolve("store");
        SigningPopulationFixture.populate(storeRoot, FsPkiStoreOptions.defaults(), createdAt,
                genericRecords, activePopulation);
        Path metadataRoot = new FsPaths(storeRoot).transactionalMetadataRoot();
        shape(metadataRoot, retainedPopulation, sealedSegments, suffixFrames);
        cleanupDeferredArtifacts(metadataRoot);
        SigningManifestCodec.Manifest manifest = readManifest(metadataRoot);
        Descriptor descriptor = Descriptor.create(retainedPopulation, activePopulation,
                sealedSegments, suffixFrames, manifestFingerprint(manifest));
        byte[] encoded = descriptor.encode();
        SigningFilePublisher.publishImmutable(workRoot.resolve(DESCRIPTOR_FILE),
                channel -> SigningFormatSupport.writeFully(channel, ByteBuffer.wrap(encoded)));
        return descriptor;
    }

    static Descriptor validate(Path workRoot, long retainedPopulation, long activePopulation,
            int sealedSegments, long suffixFrames) throws IOException {
        if (!Files.isDirectory(workRoot, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(workRoot)) {
            throw new ImageException("IMAGE_UNAVAILABLE_OR_INVALID");
        }
        Descriptor descriptor = Descriptor.decode(readBounded(
                workRoot.resolve(DESCRIPTOR_FILE), MAXIMUM_DESCRIPTOR_BYTES,
                "DESCRIPTOR_INVALID"));
        if (descriptor.retainedPopulation() != retainedPopulation
                || descriptor.activePopulation() != activePopulation
                || descriptor.sealedSegments() != sealedSegments
                || descriptor.suffixFrames() != suffixFrames || descriptor.synthetic()) {
            throw new ImageException("DESCRIPTOR_INVALID");
        }
        SigningManifestCodec.Manifest manifest = readManifest(metadataRoot(workRoot));
        if (!descriptor.manifestFingerprint().equals(manifestFingerprint(manifest))) {
            throw new ImageException("DESCRIPTOR_INVALID");
        }
        return descriptor;
    }

    static Path metadataRoot(Path workRoot) {
        return new FsPaths(workRoot.resolve("store")).transactionalMetadataRoot();
    }

    static SigningManifestCodec.Manifest readManifest(Path metadataRoot) throws IOException {
        try {
            return SigningManifestCodec.decode(readBounded(
                    metadataRoot.resolve(SigningLedgerRecovery.MANIFEST_FILE),
                    SigningManifestCodec.MAX_ENCODED_BYTES, "IMAGE_UNAVAILABLE_OR_INVALID"));
        } catch (ImageException failure) {
            throw failure;
        } catch (IOException failure) {
            throw new ImageException("IMAGE_UNAVAILABLE_OR_INVALID", failure);
        }
    }

    private static void shape(Path metadataRoot, long expectedCurrent, int sealedSegments,
            long suffixFrames) throws IOException {
        MetadataStoreId storeId = storeId(metadataRoot);
        SigningLedgerRecoveredState.RecoveryFold fold =
                new SigningLedgerRecoveredState.RecoveryFold(metadataRoot, storeId);
        SigningLedgerRecovery.Handle handle = SigningLedgerRecovery.recover(metadataRoot,
                recoveryConfiguration(), fold);
        SigningGenerationRegistry generations = handle.registry();
        SigningIndexCapacityBudget capacity = new SigningIndexCapacityBudget(MAXIMUM_INDEX_BYTES);
        SigningIndexCapacityBudget transientCapacity = new SigningIndexCapacityBudget(MAXIMUM_INDEX_BYTES);
        SigningMvccIndex index = new SigningMvccIndex(new SigningMvccIndex.Configuration(
                SigningMvccIndex.FOUR_GIB_MAXIMUM_KEYS, 1024, 10_000_000L, 0L),
                generations, capacity, transientCapacity);
        SigningLedgerMaintenance maintenance = null;
        try {
            SigningLedgerRecoveredState.State state = fold.state();
            index.recover(state.revision(), state.sequence(), state.records());
            handle.releaseTemporaryOwnership();
            SigningMvccIndex.RecoveredRecord replaced = state.records().stream()
                    .filter(value -> value.key().equals(REPLACED_KEY)).findFirst()
                    .orElseThrow(() -> new ImageException("IMAGE_UNAVAILABLE_OR_INVALID"));
            SigningActiveWal.Configuration activeConfiguration =
                    SigningActiveWal.Configuration.defaults();
            maintenance = new SigningLedgerMaintenance(metadataRoot, handle.manifest(),
                    handle.activeWal(), activeConfiguration, generations, index,
                    SigningLedgerRecoveredState.catalog(handle.manifest()),
                    new SigningLedgerMaintenance.Configuration(256L * 1024L * 1024L, 64),
                    stage -> { });
            long revision = appendReplace(maintenance.activeWal(), index,
                    replaced.revision(), 0L);
            long identity = nextIdentity(handle.manifest());
            long checkpointIdentity = identity++;
            long postCheckpointActive = identity++;
            SigningLedgerMaintenance.Compaction compaction = maintenance.compact(
                    checkpointIdentity, postCheckpointActive);
            if (compaction.liveRecords() != expectedCurrent) {
                throw new ImageException("EVIDENCE_MISMATCH");
            }
            long base = suffixFrames / sealedSegments;
            long remainder = suffixFrames % sealedSegments;
            long ordinal = 1L;
            for (int segment = 0; segment < sealedSegments; segment++) {
                long frames = base + (segment < remainder ? 1L : 0L);
                for (long frame = 0L; frame < frames; frame++) {
                    revision = appendReplace(maintenance.activeWal(), index, revision, ordinal++);
                }
                maintenance.rotate(identity++);
            }
            verifyShape(maintenance.manifest(), expectedCurrent, sealedSegments, suffixFrames);
        } finally {
            IOException failure = null;
            if (maintenance != null) {
                try {
                    maintenance.close();
                } catch (IOException closeFailure) {
                    failure = closeFailure;
                }
            }
            index.close();
            try {
                handle.close();
            } catch (IOException closeFailure) {
                if (failure == null) {
                    failure = closeFailure;
                } else {
                    failure.addSuppressed(closeFailure);
                }
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    private static void cleanupDeferredArtifacts(Path metadataRoot) throws IOException {
        SigningLedgerRecoveredState.RecoveryFold fold =
                new SigningLedgerRecoveredState.RecoveryFold(
                        metadataRoot, storeId(metadataRoot));
        try (SigningLedgerRecovery.Handle handle = SigningLedgerRecovery.recover(metadataRoot,
                recoveryConfiguration(), fold)) {
            SigningLedgerMaintenance.cleanupDeferredArtifacts(metadataRoot, handle.manifest(),
                    handle.cleanupPlan());
        }
    }

    private static long appendReplace(SigningActiveWal active, SigningMvccIndex index,
            long expectedRevision, long ordinal) throws IOException {
        SigningTransactionPayloadCodec.Mutation mutation =
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.REPLACE, REPLACED_KEY,
                        expectedRevision, new byte[] { 1 });
        List<SigningTransactionPayloadCodec.Mutation> mutations = List.of(mutation);
        byte[] payload = SigningTransactionPayloadCodec.directCommit(mutations, -1L);
        SigningActiveWal.CommitResult committed;
        try {
            committed = active.submit(SigningWalFrameCodec.RecordType.COMMIT,
                    new UUID(0x5245434f56455259L, ordinal + 1L), payload).await();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IOException("controlled recovery image preparation was interrupted", failure);
        } catch (ExecutionException failure) {
            throw new IOException("controlled recovery image WAL commit failed", failure.getCause());
        }
        SigningMvccIndex.RecordPointer pointer = new SigningMvccIndex.RecordPointer(
                committed.generationIdentity(), committed.offset(), committed.frameLength(),
                committed.sequence(), committed.revision(), SigningWalFrameCodec.RecordType.COMMIT);
        index.apply(committed.revision(), committed.sequence(),
                List.of(SigningMvccIndex.Mutation.upsert(REPLACED_KEY, pointer)));
        return committed.revision();
    }

    private static void verifyShape(SigningManifestCodec.Manifest manifest, long expectedCurrent,
            int sealedSegments, long suffixFrames) throws IOException {
        long actualFrames = 0L;
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            actualFrames = Math.addExact(actualFrames, segment.sequenceCount());
        }
        if (manifest.checkpoint().isEmpty()
                || manifest.sealedSegments().size() != sealedSegments
                || actualFrames != suffixFrames
                || manifest.activeWal().length() != SigningWalContainerCodec.HEADER_BYTES) {
            throw new ImageException("EVIDENCE_MISMATCH");
        }
        if (expectedCurrent <= 0L) {
            throw new ImageException("EVIDENCE_MISMATCH");
        }
    }

    private static long nextIdentity(SigningManifestCodec.Manifest manifest) {
        long maximum = manifest.activeWal().identity();
        if (manifest.checkpoint().isPresent()) {
            maximum = Math.max(maximum,
                    manifest.checkpoint().orElseThrow().generationIdentity());
        }
        for (SigningManifestCodec.Segment segment : manifest.sealedSegments()) {
            maximum = Math.max(maximum, segment.generationIdentity());
        }
        return Math.incrementExact(maximum);
    }

    private static MetadataStoreId storeId(Path metadataRoot) throws IOException {
        return new MetadataStoreId(Files.readString(
                metadataRoot.getParent().resolve("SIGNING_NAMESPACE")).trim());
    }

    private static SigningLedgerRecovery.Configuration recoveryConfiguration() {
        return new SigningLedgerRecovery.Configuration(16_384,
                SigningManifestCodec.MAX_FILE_BYTES, SigningCheckpointCodec.MAX_ENTRIES,
                SigningActiveWal.Configuration.defaults());
    }

    private static String manifestFingerprint(SigningManifestCodec.Manifest manifest) {
        return HexFormat.of().formatHex(SigningFormatSupport.sha256().digest(
                SigningManifestCodec.encode(manifest)));
    }

    private static byte[] readBounded(Path path, int maximumBytes, String reasonCode)
            throws IOException {
        try (SeekableByteChannel channel = Files.newByteChannel(path, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS)) {
            long size = channel.size();
            if (size <= 0L || size > maximumBytes) {
                throw new ImageException(reasonCode);
            }
            ByteBuffer buffer = ByteBuffer.allocate(Math.toIntExact(size));
            SigningFormatSupport.readFully(channel, buffer, "controlled recovery image is truncated");
            return buffer.array();
        } catch (ImageException failure) {
            throw failure;
        } catch (IOException failure) {
            throw new ImageException(reasonCode, failure);
        }
    }

    private static int descriptorMaximumBytes() {
        int total = lineBytes("schema", DESCRIPTOR_SCHEMA.length());
        total = Math.addExact(total, lineBytes("retainedPopulation", 7));
        total = Math.addExact(total, lineBytes("activePopulation", 7));
        total = Math.addExact(total, lineBytes("sealedSegments", 4));
        total = Math.addExact(total, lineBytes("suffixFrames", 7));
        total = Math.addExact(total, lineBytes("synthetic", 5));
        total = Math.addExact(total, lineBytes("manifestFingerprint", 64));
        return Math.addExact(total, lineBytes("descriptorFingerprint", 64));
    }

    private static int lineBytes(String name, int valueBytes) {
        return Math.addExact(Math.addExact(name.length(), valueBytes), 2);
    }

    private static void prepareFreshRoot(Path workRoot) throws IOException {
        if (Files.exists(workRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new ImageException("WORK_ROOT_NOT_FRESH");
        }
        Path parent = workRoot.getParent();
        if (parent == null) {
            throw new ImageException("CONFIGURATION_INVALID");
        }
        Files.createDirectories(parent);
        try {
            Files.createDirectory(workRoot);
        } catch (FileAlreadyExistsException failure) {
            throw new ImageException("WORK_ROOT_NOT_FRESH", failure);
        }
    }

    record Descriptor(long retainedPopulation, long activePopulation, int sealedSegments,
            long suffixFrames, boolean synthetic, String manifestFingerprint,
            String descriptorFingerprint) {
        private static Descriptor create(long retainedPopulation, long activePopulation,
                int sealedSegments, long suffixFrames, String manifestFingerprint) {
            String canonical = canonical(retainedPopulation, activePopulation, sealedSegments,
                    suffixFrames, false, manifestFingerprint);
            return new Descriptor(retainedPopulation, activePopulation, sealedSegments,
                    suffixFrames, false, manifestFingerprint, sha256(canonical));
        }

        private byte[] encode() {
            String canonical = canonical(retainedPopulation, activePopulation, sealedSegments,
                    suffixFrames, synthetic, manifestFingerprint);
            return (canonical + "descriptorFingerprint=" + descriptorFingerprint + '\n')
                    .getBytes(StandardCharsets.US_ASCII);
        }

        private static Descriptor decode(byte[] encoded) throws IOException {
            String[] lines = new String(encoded, StandardCharsets.US_ASCII).split("\\n", -1);
            if (lines.length != 9 || !lines[8].isEmpty()) {
                throw new ImageException("DESCRIPTOR_INVALID");
            }
            try {
                long retained = valueLong(lines[1], "retainedPopulation");
                long active = valueLong(lines[2], "activePopulation");
                int segments = Math.toIntExact(valueLong(lines[3], "sealedSegments"));
                long frames = valueLong(lines[4], "suffixFrames");
                boolean synthetic = value(lines[5], "synthetic").equals("true");
                String manifest = value(lines[6], "manifestFingerprint");
                String fingerprint = value(lines[7], "descriptorFingerprint");
                if (!lines[0].equals("schema=" + DESCRIPTOR_SCHEMA)
                        || !(value(lines[5], "synthetic").equals("true")
                                || value(lines[5], "synthetic").equals("false"))
                        || manifest.length() != 64 || fingerprint.length() != 64) {
                    throw new ImageException("DESCRIPTOR_INVALID");
                }
                Descriptor descriptor = new Descriptor(retained, active, segments, frames,
                        synthetic, manifest, fingerprint);
                String canonical = canonical(retained, active, segments, frames,
                        synthetic, manifest);
                if (!fingerprint.equals(sha256(canonical))) {
                    throw new ImageException("DESCRIPTOR_INVALID");
                }
                return descriptor;
            } catch (DescriptorFieldException | NumberFormatException
                    | ArithmeticException failure) {
                throw new ImageException("DESCRIPTOR_INVALID", failure);
            }
        }

        private static String canonical(long retained, long active, int segments, long frames,
                boolean synthetic, String manifest) {
            return "schema=" + DESCRIPTOR_SCHEMA + '\n'
                    + "retainedPopulation=" + retained + '\n'
                    + "activePopulation=" + active + '\n'
                    + "sealedSegments=" + segments + '\n'
                    + "suffixFrames=" + frames + '\n'
                    + "synthetic=" + synthetic + '\n'
                    + "manifestFingerprint=" + manifest + '\n';
        }

        private static long valueLong(String line, String name) {
            return Long.parseLong(value(line, name));
        }

        private static String value(String line, String name) {
            String prefix = name + '=';
            if (!line.startsWith(prefix) || line.length() == prefix.length()) {
                throw new DescriptorFieldException();
            }
            return line.substring(prefix.length());
        }

        private static String sha256(String canonical) {
            return HexFormat.of().formatHex(SigningFormatSupport.sha256().digest(
                    canonical.getBytes(StandardCharsets.US_ASCII)));
        }
    }

    private static final class DescriptorFieldException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        private DescriptorFieldException() {
            super("controlled recovery descriptor field is absent");
        }
    }

    static final class ImageException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String reasonCode;

        ImageException(String reasonCode) {
            super("controlled signing recovery image failed: code=" + reasonCode);
            this.reasonCode = reasonCode;
        }

        ImageException(String reasonCode, Throwable cause) {
            super("controlled signing recovery image failed: code=" + reasonCode, cause);
            this.reasonCode = reasonCode;
        }

        String reasonCode() {
            return reasonCode;
        }
    }
}
