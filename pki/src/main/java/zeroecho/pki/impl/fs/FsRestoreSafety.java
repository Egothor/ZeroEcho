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
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.ArrayList;
import zeroecho.pki.api.backup.BackupLimits;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Conservative, read-only authority comparison; never recovers or repairs the baseline. */
final class FsRestoreSafety {
    private static final String INVALID_BASELINE = "RESTORE_BASELINE_INVALID";

    private FsRestoreSafety() { }

    /* default */ record Projection(String namespace, long revision, long watermark, String logical, String files) { }

    /* default */ static void requireCompatible(Path baseline, Path candidate, BackupLimits limits) throws IOException {
        Projection previous = project(baseline, limits);
        Projection replacement = project(candidate, limits);
        if (!previous.namespace().equals(replacement.namespace())
                || replacement.revision() < previous.revision() || replacement.watermark() < previous.watermark()
                || !previous.logical().equals(replacement.logical()) || !previous.files().equals(replacement.files())) {
            throw new IOException("RESTORE_SAFETY_AUTHORITY_MISMATCH");
        }
    }

    // Each call owns one recovery graph, capped by the existing checkpoint cardinality limit.
    /* default */ static Projection project(Path root, BackupLimits limits) throws IOException {
        if (Files.size(root.resolve("VERSION")) != FilesystemPkiStore.CURRENT_STORE_VERSION.length()
                || Files.size(root.resolve("SIGNING_NAMESPACE")) != 32) {
            throw new IOException(INVALID_BASELINE);
        }
        if (!FilesystemPkiStore.CURRENT_STORE_VERSION.equals(new String(FsRestoreCoordinator.boundedRead(root.resolve("VERSION"),
                FilesystemPkiStore.CURRENT_STORE_VERSION.length()), StandardCharsets.US_ASCII))) {
            throw new IOException(INVALID_BASELINE);
        }
        String namespace = new String(FsRestoreCoordinator.boundedRead(root.resolve("SIGNING_NAMESPACE"), 32), StandardCharsets.US_ASCII);
        if (!namespace.matches("[a-f0-9]{32}")) { throw new IOException(INVALID_BASELINE); }
        Path metadata = root.resolve("metadata");
        SigningLedgerRecoveredState.RecoveryFold fold = new SigningLedgerRecoveredState.RecoveryFold(metadata,
                new MetadataStoreId(namespace), SigningLedgerRecovery.Configuration.defaults().maximumCheckpointEntries());
        try (SigningLedgerRecovery.PreparedOpen prepared = SigningLedgerRecovery.prepare(metadata,
                SigningLedgerRecovery.Configuration.defaults(), fold)) {
            SigningLedgerRecoveredState.State state = fold.preparedState();
            SigningArtifactCatalog catalog = SigningLedgerRecoveredState.catalog(prepared.view().manifest());
            return new Projection(namespace, state.revision(), state.watermark(),
                    ledgerDigest(metadata, catalog, state), fileDigest(root, limits));
        }
    }

    private static String ledgerDigest(Path metadata, SigningArtifactCatalog catalog,
            SigningLedgerRecoveredState.State state) throws IOException {
        MessageDigest digest = FsBackupFiles.digest();
        for (SigningMvccIndex.RecoveredRecord record : state.records()) {
            if (record.key().equals(SigningLedgerRecoveredState.WATERMARK_KEY)) { continue; }
            add(digest, record.key().canonical());
            add(digest, Long.toString(record.revision()));
            SigningWalFrameCodec.Frame frame = read(metadata, catalog, record.pointer());
            if (SigningLedgerRecoveredState.OUTCOME_NAMESPACE.equals(record.key().namespace())) {
                MetadataCommitResult result = state.outcomes().get(frame.transactionId());
                if (result == null) { throw new IOException(INVALID_BASELINE); }
                add(digest, result.outcome().name());
                add(digest, result.committedRevision().toString());
                add(digest, result.failureCategory().toString());
            } else {
                SigningTransactionPayloadCodec.Payload payload = SigningTransactionPayloadCodec.decode(frame.payload());
                byte[] value = null;
                for (SigningTransactionPayloadCodec.Mutation mutation : payload.mutations()) {
                    if (mutation.key().equals(record.key())) { value = mutation.contentInternal(); }
                }
                if (value == null) { throw new IOException(INVALID_BASELINE); }
                digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
                digest.update(value);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String fileDigest(Path root, BackupLimits limits) throws IOException {
        MessageDigest files = FsBackupFiles.digest();
        FsBackupFiles.Budget budget = new FsBackupFiles.Budget(limits);
        addFile(files, root, root.resolve("revocations/transitions.log"), budget);
        Path workflows = root.resolve("workflows");
        if (Files.exists(workflows)) {
            try (java.util.stream.Stream<Path> entries = Files.walk(workflows, 5)) {
                List<Path> ordered = new ArrayList<>();
                java.util.Iterator<Path> iterator = entries.iterator();
                int count = 0;
                while (iterator.hasNext()) {
                    Path file = iterator.next();
                    if (++count > limits.entryCount()) { throw new IOException("RESTORE_WORKFLOW_LIMIT"); }
                    String relative = root.relativize(file).toString().replace(java.io.File.separatorChar, '/');
                    if (relative.getBytes(StandardCharsets.UTF_8).length > limits.pathBytes()) {
                        throw new IOException("RESTORE_WORKFLOW_LIMIT");
                    }
                    if (Files.isRegularFile(file)) {
                        FsBackupFiles.validatePath(relative, limits);
                        ordered.add(file);
                    } else if (!Files.isDirectory(file) || workflows.relativize(file).getNameCount() >= 5) {
                        throw new IOException("RESTORE_WORKFLOW_INVALID");
                    }
                }
                ordered.sort(Path::compareTo);
                for (Path file : ordered) {
                    addFile(files, root, file, budget);
                }
            }
        }
        return HexFormat.of().formatHex(files.digest());
    }


    private static SigningWalFrameCodec.Frame read(Path root, SigningArtifactCatalog catalog,
            SigningMvccIndex.RecordPointer pointer) throws IOException {
        byte[] encoded = new byte[pointer.frameLength()];
        try (FileChannel channel = FileChannel.open(root.resolve(catalog.readable(pointer.generationId()).name()), StandardOpenOption.READ)) {
            channel.position(pointer.frameOffset());
            SigningFormatSupport.readFully(channel, ByteBuffer.wrap(encoded), INVALID_BASELINE);
        }
        SigningWalFrameCodec.Frame frame = SigningWalFrameCodec.decode(encoded);
        if (frame.sequence() != pointer.sequence() || frame.recordType() != pointer.recordType()) {
            throw new IOException(INVALID_BASELINE);
        }
        return frame;
    }

    private static void addFile(MessageDigest digest, Path root, Path file, FsBackupFiles.Budget budget) throws IOException {
        add(digest, root.relativize(file).toString().replace(java.io.File.separatorChar, '/'));
        long length = Files.size(file);
        budget.add(length);
        add(digest, Long.toString(length));
        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[FsBackupFiles.BUFFER_BYTES];
            long remaining = length;
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count == 0 || count > remaining) { throw new IOException(INVALID_BASELINE); }
                digest.update(buffer, 0, count);
                remaining -= count;
            }
            if (remaining != 0) { throw new IOException(INVALID_BASELINE); }
        }
    }

    private static void add(MessageDigest digest, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        digest.update(bytes);
    }
}
