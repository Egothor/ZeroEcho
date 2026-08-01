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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;

/** Coordinates the credential-record/content-owner write-once handoff. */
@SuppressWarnings("PMD.CyclomaticComplexity")
final class CredentialContentTransaction {

    private static final int MAGIC = 0x5A454348;
    private static final int VERSION = 1;
    private static final int MAX_TEXT_BYTES = 4 * 1024;
    private static final int BUFFER_BYTES = 16 * 1024;
    private static final int MAX_INTENT_BYTES = 64 * 1024;
    private static final int LOCK_COUNT = 64;
    private static final String INTENT_SUFFIX = ".intent";
    private static final String PRIVATE_SUFFIX = ".credential.pending";
    private static final byte[] INTENT_KEY_DOMAIN =
            "zeroecho:pki:credential-handoff-intent:v1".getBytes(StandardCharsets.US_ASCII);

    private final FsPaths paths;
    private final FilesystemStagedContentStore stagedContent;
    private final Path intentRoot;
    private final ReentrantLock[] locks;

    /* default */ CredentialContentTransaction(FsPaths paths, FilesystemStagedContentStore stagedContent) {
        this.paths = Objects.requireNonNull(paths, "paths");
        this.stagedContent = Objects.requireNonNull(stagedContent, "stagedContent");
        this.intentRoot = paths.root().resolve("credential-handoffs");
        this.locks = new ReentrantLock[LOCK_COUNT];
        for (int index = 0; index < locks.length; index++) {
            locks[index] = new ReentrantLock();
        }
    }

    /* default */ void put(Credential credential) {
        Objects.requireNonNull(credential, "credential");
        PkiId credentialId = credential.credentialId();
        ReentrantLock lock = lock(credentialId);
        lock.lock();
        try {
            putLocked(credential);
        } finally {
            lock.unlock();
        }
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ExceptionAsFlowControl" })
    private void putLocked(Credential credential) {
        PkiId credentialId = credential.credentialId();
        Path target = paths.credentialPath(credentialId);
        Path privateRecord = privateRecordPath(credentialId);
        Path intentPath = intentPath(credentialId);
        DurableContentOwner owner = DurableContentOwner.credentialRecord(credentialId);
        boolean intentWritten = false;
        boolean ownerAdded = false;
        boolean published = false;
        try {
            requirePersistedReference(credential.content());
            validateIntegrity(credential.content());
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw duplicate(credentialId, null);
            }
            if (Files.exists(intentPath, LinkOption.NOFOLLOW_LINKS)
                    || Files.exists(privateRecord, LinkOption.NOFOLLOW_LINKS)) {
                throw new IllegalStateException("Credential content handoff is already pending");
            }
            Set<DurableContentOwner> owners = stagedContent.contentOwners(credential.content());
            if (owners.contains(owner)) {
                throw new IllegalStateException("Credential content owner exists without a credential record");
            }
            Intent prepared = Intent.from(credential, State.PREPARED);
            intentWritten = true;
            DurableMetadataFiles.create(intentPath, MAX_INTENT_BYTES, output -> writeIntent(output, prepared));
            ownerAdded = stagedContent.retainContent(credential.content(), owner);
            if (!ownerAdded) {
                throw new IllegalStateException("Credential content owner was not newly retained");
            }
            FsOperations.writeNewAtomicStrict(privateRecord, FsCodec.encode(FsCodec.CREDENTIAL, credential));
            publish(privateRecord, target);
            published = true;
            DurableMetadataFiles.replace(intentPath, MAX_INTENT_BYTES,
                    output -> writeIntent(output, prepared.withState(State.COMMITTED)));
            cleanup(privateRecord, intentPath);
        } catch (FileAlreadyExistsException failure) {
            rollbackBeforePublication(credential.content(), owner, privateRecord, intentPath, intentWritten,
                    ownerAdded, failure);
            throw duplicate(credentialId, failure);
        } catch (PublishedException failure) {
            throw new IllegalStateException("Credential publication durability is unconfirmed", failure);
        } catch (IOException failure) {
            if (!published) {
                rollbackBeforePublication(credential.content(), owner, privateRecord, intentPath, intentWritten,
                        ownerAdded, failure);
            }
            throw new IllegalStateException("Credential content handoff failed", failure);
        } catch (RuntimeException failure) {
            if (!published) {
                rollbackBeforePublication(credential.content(), owner, privateRecord, intentPath, intentWritten,
                        ownerAdded, failure);
            }
            throw failure;
        }
    }

    /* default */ Credential validateLoaded(PkiId expectedId, Credential credential) throws IOException {
        Objects.requireNonNull(expectedId, "expectedId");
        Objects.requireNonNull(credential, "credential");
        if (!expectedId.equals(credential.credentialId())) {
            throw new IOException("Credential record identifier mismatch");
        }
        requirePersistedReference(credential.content());
        DurableContentOwner owner = DurableContentOwner.credentialRecord(expectedId);
        if (!stagedContent.contentOwners(credential.content()).contains(owner)) {
            throw new IOException("Credential content owner is missing");
        }
        validateIntegrity(credential.content());
        return credential;
    }

    /* default */ void recover() throws IOException {
        recoverIntents();
        cleanupOrphanedPrivateRecords();
        validatePublishedRecords();
    }

    private void recoverIntents() throws IOException {
        if (!Files.isDirectory(intentRoot, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        List<Path> intents = DurableMetadataFiles.list(intentRoot, INTENT_SUFFIX);
        for (Path intentPath : intents) {
            recoverIntent(intentPath);
        }
    }

    private void recoverIntent(Path intentPath) throws IOException {
        if (!isRegularFile(intentPath)) {
            throw new IOException("Credential handoff intent is not a regular file");
        }
        Intent intent = DurableMetadataFiles.read(intentPath, MAX_INTENT_BYTES,
                CredentialContentTransaction::readIntent);
        if (!intentPath(intent.credentialId()).equals(intentPath)) {
            throw new IOException("Credential handoff intent filename mismatch");
        }
        Path target = paths.credentialPath(intent.credentialId());
        Path privateRecord = privateRecordPath(intent.credentialId());
        if (isRegularFile(target)) {
            Credential credential = FsCodec.decode(FsCodec.CREDENTIAL, FsOperations.readAll(target), stagedContent);
            requireIntentMatch(intent, credential);
            validateLoaded(intent.credentialId(), credential);
            cleanup(privateRecord, intentPath);
            return;
        }
        releasePreparedOwner(intent);
        cleanup(privateRecord, intentPath);
    }

    private void releasePreparedOwner(Intent intent) throws IOException {
        Path metadata = paths.stagedContentRoot().resolve(intent.contentId() + ".meta");
        if (!isRegularFile(metadata)) {
            return;
        }
        DurableContentReference reference = intent.restore(stagedContent);
        DurableContentOwner owner = intent.owner();
        if (stagedContent.contentOwners(reference).contains(owner)) {
            stagedContent.releaseContent(reference, owner);
        }
    }

    private void cleanupOrphanedPrivateRecords() throws IOException {
        Path root = paths.root().resolve("credentials").resolve("by-id");
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (Stream<Path> stream = Files.list(root)) {
            java.util.Iterator<Path> iterator = stream
                    .filter(path -> path.getFileName().toString().endsWith(PRIVATE_SUFFIX)).iterator();
            while (iterator.hasNext()) {
                Files.deleteIfExists(iterator.next());
            }
        }
    }

    private void validatePublishedRecords() throws IOException {
        Path root = paths.root().resolve("credentials").resolve("by-id");
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        List<Path> records;
        try (Stream<Path> stream = Files.list(root)) {
            records = stream.filter(path -> path.getFileName().toString().endsWith(".bin"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString())).toList();
        }
        for (Path record : records) {
            if (!isRegularFile(record)) {
                throw new IOException("Credential record is not a regular file");
            }
            Credential credential = FsCodec.decode(FsCodec.CREDENTIAL, FsOperations.readAll(record), stagedContent);
            if (!paths.credentialPath(credential.credentialId()).equals(record)) {
                throw new IOException("Credential record filename mismatch");
            }
            validateLoaded(credential.credentialId(), credential);
        }
    }

    private void validateIntegrity(DurableContentReference reference) throws IOException {
        try (RepeatableContent content = stagedContent.openContent(reference);
                InputStream input = content.openStream()) {
            byte[] buffer = new byte[BUFFER_BYTES];
            try {
                long readLength = 0L;
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    readLength = Math.addExact(readLength, read);
                }
                if (readLength != reference.length()) {
                    throw new IOException("Credential content length changed while reading");
                }
            } finally {
                Arrays.fill(buffer, (byte) 0);
            }
        }
    }

    private void requirePersistedReference(DurableContentReference reference) {
        Objects.requireNonNull(reference, "credential.content");
        if (!stagedContent.contentStoreId().equals(reference.storeId())) {
            throw new IllegalArgumentException("Credential content belongs to another store");
        }
        if (reference.lifecycle() != DurableContentReference.Lifecycle.PERSISTED) {
            throw new IllegalArgumentException("Credential content must use the PERSISTED lifecycle");
        }
    }

    private static void requireIntentMatch(Intent intent, Credential credential) throws IOException {
        if (!intent.credentialId().equals(credential.credentialId())
                || !intent.matches(credential.content())
                || !intent.owner().equals(DurableContentOwner.credentialRecord(credential.credentialId()))) {
            throw new IOException("Credential handoff intent does not match the published record");
        }
    }

    private void rollbackBeforePublication(DurableContentReference reference, DurableContentOwner owner,
            Path privateRecord, Path intentPath, boolean intentWritten, boolean ownerAdded, Throwable failure) {
        try {
            if (intentWritten) {
                Files.deleteIfExists(privateRecord);
            }
            if (ownerAdded) {
                stagedContent.releaseContent(reference, owner);
            }
            if (intentWritten) {
                DurableMetadataFiles.delete(intentPath);
            }
        } catch (IOException rollbackFailure) {
            failure.addSuppressed(rollbackFailure);
        }
    }

    private static void cleanup(Path privateRecord, Path intentPath) throws IOException {
        Files.deleteIfExists(privateRecord);
        DurableMetadataFiles.delete(intentPath);
    }

    private Path intentPath(PkiId credentialId) {
        return intentRoot.resolve(intentFileName(credentialId));
    }

    /* default */ static String intentFileName(PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        MessageDigest digest = sha256();
        byte[] identifier = credentialId.value().getBytes(StandardCharsets.UTF_8);
        updateLength(digest, INTENT_KEY_DOMAIN.length);
        digest.update(INTENT_KEY_DOMAIN);
        updateLength(digest, identifier.length);
        digest.update(identifier);
        return HexFormat.of().formatHex(digest.digest()) + INTENT_SUFFIX;
    }

    private Path privateRecordPath(PkiId credentialId) {
        return paths.credentialPath(credentialId).resolveSibling(
                paths.credentialPath(credentialId).getFileName().toString() + PRIVATE_SUFFIX);
    }

    private ReentrantLock lock(PkiId credentialId) {
        return locks[Math.floorMod(credentialId.hashCode(), locks.length)];
    }

    // The directory-force cause is replaced by a path-free publication-state marker.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static void publish(Path source, Path target) throws IOException {
        boolean moved = false;
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
            moved = true;
            try (FileChannel directory = FileChannel.open(target.getParent(), StandardOpenOption.READ)) {
                directory.force(true);
            } catch (IOException failure) {
                throw new PublishedException();
            }
        } catch (AtomicMoveNotSupportedException failure) {
            throw new IOException("Atomic credential publication is unavailable", failure);
        } finally {
            if (!moved) {
                Files.deleteIfExists(source);
            }
        }
    }

    private static IllegalStateException duplicate(PkiId credentialId, Throwable cause) {
        String message = "CREDENTIAL is write-once; already exists: " + FsUtil.safeId(credentialId);
        return cause == null ? new IllegalStateException(message) : new IllegalStateException(message, cause);
    }

    private static boolean isRegularFile(Path path) {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path);
    }

    /* default */ static byte[] encode(Intent intent) throws IOException {
        Objects.requireNonNull(intent, "intent");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            writeIntent(output, intent);
        }
        return bytes.toByteArray();
    }

    /* default */ static Intent decode(byte[] encoded) throws IOException {
        Objects.requireNonNull(encoded, "encoded");
        ByteArrayInputStream bytes = new ByteArrayInputStream(encoded);
        try (DataInputStream input = new DataInputStream(bytes)) {
            Intent intent = readIntent(input);
            if (bytes.available() != 0) {
                throw new IOException("Trailing credential handoff intent data");
            }
            return intent;
        }
    }

    private static void writeIntent(DataOutputStream output, Intent intent) throws IOException {
        output.writeInt(MAGIC);
        output.writeByte(VERSION);
        output.writeByte(intent.state().code);
        writeText(output, intent.credentialId().value());
        writeText(output, intent.owner().category().name());
        writeText(output, intent.owner().identifier());
        writeText(output, intent.storeId());
        writeText(output, intent.contentId());
        writeText(output, intent.encoding().name());
        output.writeLong(intent.length());
        writeText(output, intent.sha256());
        writeText(output, intent.lifecycle().name());
    }

    private static Intent readIntent(DataInputStream input) throws IOException {
        try {
            if (input.readInt() != MAGIC || input.readUnsignedByte() != VERSION) {
                throw new IOException("Unsupported credential handoff intent");
            }
            State state = State.fromCode(input.readUnsignedByte());
            DurableContentOwner.Category category;
            Encoding encoding;
            DurableContentReference.Lifecycle lifecycle;
            try {
                PkiId credentialId = new PkiId(readText(input));
                category = DurableContentOwner.Category.valueOf(readText(input));
                DurableContentOwner owner = new DurableContentOwner(category, readText(input));
                String storeId = readText(input);
                String contentId = readText(input);
                encoding = Encoding.valueOf(readText(input));
                long length = input.readLong();
                String sha256 = readText(input);
                lifecycle = DurableContentReference.Lifecycle.valueOf(readText(input));
                return new Intent(state, credentialId, owner, storeId, contentId, encoding, length, sha256,
                        lifecycle);
            } catch (IllegalArgumentException failure) {
                throw new IOException("Malformed credential handoff intent", failure);
            }
        } catch (EOFException failure) {
            throw new IOException("Truncated credential handoff intent", failure);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }

    private static void updateLength(MessageDigest digest, int length) {
        digest.update((byte) (length >>> 24));
        digest.update((byte) (length >>> 16));
        digest.update((byte) (length >>> 8));
        digest.update((byte) length);
    }

    private static void writeText(DataOutputStream output, String value) throws IOException {
        byte[] encoded = Objects.requireNonNull(value, "value").getBytes(StandardCharsets.UTF_8);
        if (encoded.length > MAX_TEXT_BYTES) {
            throw new IOException("Credential handoff intent text is too long");
        }
        output.writeShort(encoded.length);
        output.write(encoded);
    }

    private static String readText(DataInputStream input) throws IOException {
        int length = input.readUnsignedShort();
        if (length > MAX_TEXT_BYTES) {
            throw new IOException("Credential handoff intent text is too long");
        }
        byte[] encoded = input.readNBytes(length);
        if (encoded.length != length) {
            throw new EOFException("Credential handoff intent text is truncated");
        }
        String value = new String(encoded, StandardCharsets.UTF_8);
        if (!Arrays.equals(encoded, value.getBytes(StandardCharsets.UTF_8))) {
            throw new IOException("Credential handoff intent text is not canonical UTF-8");
        }
        return value;
    }

    /** Closed persisted handoff states. */
    /* default */ enum State {
        PREPARED(1),
        COMMITTED(2);

        private final int code;

        State(int code) {
            this.code = code;
        }

        private static State fromCode(int code) throws IOException {
            for (State state : values()) {
                if (state.code == code) {
                    return state;
                }
            }
            throw new IOException("Unknown credential handoff state");
        }
    }

    /** Strict path-free and payload-free persisted handoff description. */
    /* default */ record Intent(State state, PkiId credentialId, DurableContentOwner owner, String storeId, String contentId,
            Encoding encoding, long length, String sha256, DurableContentReference.Lifecycle lifecycle) {

        Intent {
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(credentialId, "credentialId");
            Objects.requireNonNull(owner, "owner");
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(contentId, "contentId");
            Objects.requireNonNull(encoding, "encoding");
            Objects.requireNonNull(sha256, "sha256");
            Objects.requireNonNull(lifecycle, "lifecycle");
            if (!owner.equals(DurableContentOwner.credentialRecord(credentialId))
                    || lifecycle != DurableContentReference.Lifecycle.PERSISTED || length < 0L
                    || !storeId.matches("[0-9a-f]{32}")
                    || !contentId.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
                    || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Credential handoff intent is inconsistent");
            }
        }

        /* default */ static Intent from(Credential credential, State state) {
            DurableContentReference reference = credential.content();
            return new Intent(state, credential.credentialId(),
                    DurableContentOwner.credentialRecord(credential.credentialId()), reference.storeId(),
                    reference.contentId(), reference.encoding(), reference.length(), reference.sha256(),
                    reference.lifecycle());
        }

        /* default */ Intent withState(State next) {
            return new Intent(next, credentialId, owner, storeId, contentId, encoding, length, sha256, lifecycle);
        }

        /* default */ boolean matches(DurableContentReference reference) {
            return storeId.equals(reference.storeId()) && contentId.equals(reference.contentId())
                    && encoding == reference.encoding() && length == reference.length()
                    && sha256.equals(reference.sha256()) && lifecycle == reference.lifecycle();
        }

        /* default */ DurableContentReference restore(FilesystemStagedContentStore store) throws IOException {
            return store.restoreReference(storeId, contentId, encoding, length, sha256, lifecycle);
        }
    }

    /** Marks a completed namespace move with unconfirmed directory durability. */
    private static final class PublishedException extends IOException {
        private static final long serialVersionUID = -8788329245365479704L;

        private PublishedException() {
            super("Credential record is published but directory durability is unconfirmed");
        }
    }
}
