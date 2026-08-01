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

import java.io.FilterOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.charset.StandardCharsets;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.HexFormat;
import java.util.Objects;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.spi.store.TemporaryUniqueIndex;

/**
 * Filesystem-backed staged-content store with atomic completion and streaming
 * integrity verification.
 *
 * <p>
 * Partial files are never exposed through a durable reference. Aggregate lengths
 * use {@code long}; content is never buffered in aggregate memory. Callers own
 * lifecycle release. The implementation creates restrictive files when POSIX
 * permissions are available.
 * </p>
 */
public final class FilesystemStagedContentStore implements StagedContentStore {

    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> OWNER_DIRECTORY = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final int BUFFER_BYTES = 16 * 1024;
    private static final int METADATA_VERSION = 1;
    private static final int OWNER_METADATA_VERSION = 2;
    private static final int MAX_OWNER_RECORD_BYTES = 1024 * 1024;
    private static final int MAX_OWNER_COUNT = 2048;
    private static final int OWNER_LOCK_COUNT = 64;
    private static final long MINIMUM_CONTENT_LENGTH = 0L;

    private final Path root;
    private final String storeId;
    private final ReentrantLock[] ownerLocks;

    /**
     * Creates a staged-content store.
     *
     * @param root    private storage directory
     * @param storeId stable runtime/store identifier
     * @throws IOException              if the directory cannot be created
     * @throws IllegalArgumentException if {@code storeId} is blank
     */
    public FilesystemStagedContentStore(Path root, String storeId) throws IOException {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.storeId = requireStoreIdentifier(storeId);
        this.ownerLocks = new ReentrantLock[OWNER_LOCK_COUNT];
        for (int index = 0; index < ownerLocks.length; index++) {
            ownerLocks[index] = new ReentrantLock();
        }
        Files.createDirectories(this.root);
        if (Files.isSymbolicLink(this.root) || !Files.isDirectory(this.root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Staged-content root must be a real directory");
        }
        cleanupAbandonedTemporaryState();
    }

    @Override
    public String contentStoreId() {
        return storeId;
    }

    @Override
    public ContentSink beginContent(Encoding encoding, DurableContentReference.Lifecycle lifecycle) throws IOException {
        Objects.requireNonNull(encoding, "encoding");
        Objects.requireNonNull(lifecycle, "lifecycle");
        String contentId = UUID.randomUUID().toString();
        Path incomplete = root.resolve(contentId + ".incomplete");
        Path complete = root.resolve(contentId + ".content");
        Files.createFile(incomplete);
        restrict(incomplete);
        return new FileSink(contentId, incomplete, complete, encoding, lifecycle);
    }

    @Override
    public RepeatableContent openContent(DurableContentReference reference) throws IOException {
        DurableContentReference exact = requireOwned(reference);
        DurableContentReference persisted = readMetadata(exact.contentId());
        if (!persisted.equals(exact)) {
            throw new IOException("Staged content metadata mismatch: code=CONTENT_INTEGRITY_FAILED");
        }
        Path path = completePath(exact);
        if (!isRegularFile(path)) {
            throw new IOException("Staged content missing: code=STAGED_CONTENT_MISSING");
        }
        long actualLength = Files.size(path);
        if (actualLength != exact.length()) {
            throw new IOException("Staged content integrity failed: code=CONTENT_INTEGRITY_FAILED");
        }
        return new FileContent(path, exact);
    }

    @Override
    public DurableContentReference restoreReference(String persistedStoreId, String contentId, Encoding encoding,
            long length, String sha256, DurableContentReference.Lifecycle lifecycle) throws IOException {
        if (!storeId.equals(requireStoreIdentifier(persistedStoreId))) {
            throw new IllegalArgumentException("Staged content belongs to another store");
        }
        requireContentIdentifier(contentId);
        StoreReference supplied = new StoreReference(storeId, contentId, encoding, length, sha256, lifecycle);
        DurableContentReference persisted = readMetadata(contentId);
        if (!persisted.equals(supplied)) {
            throw new IOException("Staged content metadata mismatch: code=CONTENT_INTEGRITY_FAILED");
        }
        return persisted;
    }

    @Override
    public boolean retainContent(DurableContentReference reference, DurableContentOwner owner) throws IOException {
        DurableContentReference exact = requireOwned(reference);
        Objects.requireNonNull(owner, "owner");
        ReentrantLock lock = ownerLock(exact.contentId());
        lock.lock();
        try {
            requireExactMetadata(exact);
            Set<DurableContentOwner> owners = readOwners(exact.contentId());
            if (!owners.add(owner)) {
                return false;
            }
            writeOwners(exact.contentId(), owners);
            return true;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean releaseContent(DurableContentReference reference, DurableContentOwner owner) throws IOException {
        DurableContentReference exact = requireOwned(reference);
        Objects.requireNonNull(owner, "owner");
        ReentrantLock lock = ownerLock(exact.contentId());
        lock.lock();
        try {
            if (!isRegularFile(metadataPath(exact.contentId()))) {
                return false;
            }
            requireExactMetadata(exact);
            Set<DurableContentOwner> owners = readOwners(exact.contentId());
            if (!owners.remove(owner)) {
                return false;
            }
            writeOwners(exact.contentId(), owners);
            if (owners.isEmpty()) {
                retireFiles(exact);
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public Set<DurableContentOwner> contentOwners(DurableContentReference reference) throws IOException {
        DurableContentReference exact = requireOwned(reference);
        ReentrantLock lock = ownerLock(exact.contentId());
        lock.lock();
        try {
            requireExactMetadata(exact);
            return Set.copyOf(readOwners(exact.contentId()));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void retireUnownedContent(DurableContentReference reference) throws IOException {
        DurableContentReference exact = requireOwned(reference);
        ReentrantLock lock = ownerLock(exact.contentId());
        lock.lock();
        try {
            requireExactMetadata(exact);
            if (!readOwners(exact.contentId()).isEmpty()) {
                throw new IOException("Staged content remains durably owned");
            }
            retireFiles(exact);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void recoverContent(TemporaryUniqueIndex retained, TemporaryUniqueIndex retainedOwners) throws IOException {
        StoreIo.recoverContent(this, retained, retainedOwners);
    }

    @Override
    public TemporaryUniqueIndex beginUniqueIndex() throws IOException {
        Path directory = root.resolve(UUID.randomUUID() + ".unique-index");
        Files.createDirectory(directory);
        restrictDirectory(directory);
        return FilesystemTemporaryUniqueIndex.general(directory);
    }

    /* default */ TemporaryUniqueIndex beginOwnerIndex() throws IOException {
        Path directory = root.resolve(UUID.randomUUID() + ".unique-index");
        Files.createDirectory(directory);
        restrictDirectory(directory);
        return FilesystemTemporaryUniqueIndex.owners(directory);
    }

    /* default */ static String ownerIndexKey(DurableContentOwner owner) {
        Objects.requireNonNull(owner, "owner");
        return FilesystemTemporaryUniqueIndex.ownerKey(owner);
    }

    private void cleanupAbandonedTemporaryState() throws IOException {
        StoreIo.cleanupAbandonedTemporaryState(this);
    }

    private void cleanupOrphanedCompletedFiles() throws IOException {
        StoreIo.cleanupOrphanedCompletedFiles(this);
    }

    private void cleanupOrphanedOwnerFiles() throws IOException {
        StoreIo.cleanupOrphanedOwnerFiles(this);
    }

    private DurableContentReference requireOwned(DurableContentReference reference) {
        return StoreIo.requireOwned(this, reference);
    }

    private Path completePath(DurableContentReference reference) {
        return resolveOwned(reference.contentId() + ".content");
    }

    private Path metadataPath(String contentId) {
        requireContentIdentifier(contentId);
        return resolveOwned(contentId + ".meta");
    }

    private DurableContentReference readMetadata(String contentId) throws IOException {
        return StoreIo.readMetadata(this, contentId);
    }

    private void requireExactMetadata(DurableContentReference exact) throws IOException {
        StoreIo.requireExactMetadata(this, exact);
    }

    private Set<DurableContentOwner> readOwners(String contentId) throws IOException {
        return StoreIo.readOwners(this, contentId);
    }

    private void writeOwners(String contentId, Set<DurableContentOwner> owners) throws IOException {
        StoreIo.writeOwners(this, contentId, owners);
    }

    private void retireFiles(DurableContentReference reference) throws IOException {
        Files.deleteIfExists(metadataPath(reference.contentId()));
        Files.deleteIfExists(completePath(reference));
        DurableMetadataFiles.delete(ownerPath(reference.contentId()));
    }

    private Path ownerPath(String contentId) {
        requireContentIdentifier(contentId);
        return resolveOwned(contentId + ".owners");
    }

    private ReentrantLock ownerLock(String contentId) {
        requireContentIdentifier(contentId);
        return ownerLocks[Math.floorMod(contentId.hashCode(), ownerLocks.length)];
    }

    private void writeMetadata(DurableContentReference reference) throws IOException {
        StoreIo.writeMetadata(this, reference);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private static void restrict(Path path) throws IOException {
        if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        }
    }

    private static void restrictDirectory(Path path) throws IOException {
        if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(path, OWNER_DIRECTORY);
        }
    }

    /** Atomic file-backed sink with explicit terminal lifecycle. */
    private final class FileSink implements ContentSink {
        private final String contentId;
        private final Path incomplete;
        private final Path complete;
        private final Encoding encoding;
        private final DurableContentReference.Lifecycle lifecycle;
        private final AtomicBoolean terminal;
        private final ReentrantLock lock;
        private CountingOutputStream output;

        private FileSink(String contentId, Path incomplete, Path complete, Encoding encoding,
                DurableContentReference.Lifecycle lifecycle) {
            this.contentId = contentId;
            this.incomplete = incomplete;
            this.complete = complete;
            this.encoding = encoding;
            this.lifecycle = lifecycle;
            this.terminal = new AtomicBoolean();
            this.lock = new ReentrantLock();
        }

        @Override
        public OutputStream outputStream() throws IOException {
            lock.lock();
            try {
                requireOpen();
                if (output == null) {
                    output = openCountingOutput(incomplete);
                }
                return output;
            } finally {
                lock.unlock();
            }
        }

        @Override
        public long length() {
            lock.lock();
            try {
                return output == null ? 0L : output.length();
            } finally {
                lock.unlock();
            }
        }

        @Override
        public DurableContentReference complete() throws IOException {
            lock.lock();
            try {
                requireOpen();
                if (output == null) {
                    output = openCountingOutput(incomplete);
                }
                output.close();
                try (FileChannel channel = FileChannel.open(incomplete, StandardOpenOption.READ)) {
                    channel.force(true);
                }
                try {
                    Files.move(incomplete, complete, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException ex) {
                    Files.move(incomplete, complete);
                }
                DurableContentReference reference = new StoreReference(storeId, contentId, encoding,
                        output.length(), output.digestHex(), lifecycle);
                try {
                    writeMetadata(reference);
                    terminal.set(true);
                    return reference;
                } catch (IOException failure) {
                    terminal.set(true);
                    Files.deleteIfExists(complete);
                    Files.deleteIfExists(resolveOwned(contentId + ".meta.incomplete"));
                    Files.deleteIfExists(metadataPath(contentId));
                    throw failure;
                }
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void abort() throws IOException {
            lock.lock();
            try {
                if (terminal.compareAndSet(false, true)) {
                    if (output != null) {
                        output.close();
                    }
                    Files.deleteIfExists(incomplete);
                }
            } finally {
                lock.unlock();
            }
        }

        @Override
        public void close() throws IOException {
            lock.lock();
            try {
                if (!terminal.get()) {
                    terminal.set(true);
                    if (output != null) {
                        output.close();
                    }
                    Files.deleteIfExists(incomplete);
                }
            } finally {
                lock.unlock();
            }
        }

        private void requireOpen() {
            if (terminal.get()) {
                throw new IllegalStateException("Content sink is no longer open");
            }
        }
    }

    private static CountingOutputStream openCountingOutput(Path path) throws IOException {
        return new CountingOutputStream(Files.newOutputStream(path, StandardOpenOption.WRITE), sha256());
    }

    /** Overflow-checked streaming digest and length adapter. */
    private static final class CountingOutputStream extends FilterOutputStream {
        private final DigestOutputStream digestOutput;
        private long length;

        private CountingOutputStream(OutputStream output, MessageDigest digest) {
            super(new DigestOutputStream(output, digest));
            this.digestOutput = (DigestOutputStream) out;
        }

        @Override
        public void write(int value) throws IOException {
            out.write(value);
            length = Math.addExact(length, 1L);
        }

        @Override
        public void write(byte[] bytes, int offset, int count) throws IOException {
            Objects.checkFromIndexSize(offset, count, bytes.length);
            long next = Math.addExact(length, count);
            out.write(bytes, offset, count);
            length = next;
        }

        private long length() {
            return length;
        }

        private String digestHex() {
            return HexFormat.of().formatHex(digestOutput.getMessageDigest().digest());
        }
    }

    /** Repeatable immutable view over one completed staged file. */
    private static final class FileContent implements RepeatableContent {
        private final Path path;
        private final DurableContentReference reference;

        private FileContent(Path path, DurableContentReference reference) {
            this.path = path;
            this.reference = reference;
        }

        @Override
        public InputStream openStream() throws IOException {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile() || attributes.size() != reference.length()) {
                throw new IOException("Staged content integrity failed: code=CONTENT_INTEGRITY_FAILED");
            }
            return new VerifiedChannelInputStream(path, reference);
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(reference.length());
        }

        @Override
        public String contentId() {
            return "sha256:" + reference.sha256();
        }

        @Override
        public void close() {
            // The durable store owns the underlying file lifecycle.
        }
    }

    private static void requireDigest(FileChannel channel, DurableContentReference reference) throws IOException {
        MessageDigest digest = sha256();
        ByteBuffer buffer = ByteBuffer.allocate(BUFFER_BYTES);
        long length = 0L;
        while (channel.read(buffer) >= 0) {
            buffer.flip();
            int count = buffer.remaining();
            if (count != 0) {
                digest.update(buffer);
                length = Math.addExact(length, count);
            }
            buffer.clear();
        }
        String actual = HexFormat.of().formatHex(digest.digest());
        if (length != reference.length() || !MessageDigest.isEqual(actual.getBytes(StandardCharsets.US_ASCII),
                reference.sha256().getBytes(StandardCharsets.US_ASCII))) {
            throw new IOException("Staged content integrity failed: code=CONTENT_INTEGRITY_FAILED");
        }
    }

    /** Read stream retaining the verified file identity through its open descriptor. */
    private static final class VerifiedChannelInputStream extends InputStream {
        private final FileChannel channel;
        private final InputStream delegate;

        private VerifiedChannelInputStream(Path path, DurableContentReference reference) throws IOException {
            super();
            channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
            boolean initialized = false;
            try {
                requireDigest(channel, reference);
                channel.position(0L);
                delegate = Channels.newInputStream(channel);
                initialized = true;
            } finally {
                if (!initialized) {
                    closeFailedChannel(channel);
                }
            }
        }

        @Override
        public int read() throws IOException {
            return delegate.read();
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            return delegate.read(bytes, offset, length);
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }

        private static void closeFailedChannel(FileChannel failedChannel) throws IOException {
            try (FileChannel ignored = failedChannel) {
                // Transfer to try-with-resources solely for failed construction cleanup.
            }
        }
    }

    private Path resolveOwned(String fileName) {
        Path resolved = root.resolve(fileName).normalize();
        if (!root.equals(resolved.getParent())) {
            throw new IllegalArgumentException("Staged content identifier escapes its store");
        }
        return resolved;
    }

    private static boolean isRegularFile(Path path) {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path);
    }

    private static String requireStoreIdentifier(String value) {
        String exact = Objects.requireNonNull(value, "storeId");
        if (!exact.matches("[0-9a-f]{32}")) {
            throw new IllegalArgumentException("Staged content store identifier is not canonical");
        }
        return exact;
    }

    private static void requireContentIdentifier(String contentId) {
        requireCanonicalUuid(contentId, true);
    }

    /** Store-branded immutable reference; arbitrary interface implementations are rejected. */
    /** Mechanical home for filesystem metadata branches kept outside the store coordinator. */
    private static final class StoreIo {
        private static void recoverContent(FilesystemStagedContentStore store, TemporaryUniqueIndex retained,
                TemporaryUniqueIndex retainedOwners) throws IOException {
            Objects.requireNonNull(retained, "retained");
            Objects.requireNonNull(retainedOwners, "retainedOwners");
            retained.validateNamespace();
            retainedOwners.validateNamespace();
            try (java.util.stream.Stream<Path> paths = Files.list(store.root)) {
                java.util.Iterator<Path> iterator = paths
                        .filter(path -> path.getFileName().toString().endsWith(".meta")).iterator();
                while (iterator.hasNext()) {
                    Path metadata = iterator.next();
                    String name = metadata.getFileName().toString();
                    String contentId = name.substring(0, name.length() - ".meta".length());
                    recoverContent(store, retained, retainedOwners, contentId);
                }
            }
            store.cleanupOrphanedCompletedFiles();
            store.cleanupOrphanedOwnerFiles();
        }

        private static void recoverContent(FilesystemStagedContentStore store, TemporaryUniqueIndex retained,
                TemporaryUniqueIndex retainedOwners, String contentId) throws IOException {
            ReentrantLock lock = store.ownerLock(contentId);
            lock.lock();
            try {
                DurableContentReference reference = store.readMetadata(contentId);
                Set<DurableContentOwner> owners = store.readOwners(contentId);
                owners.removeIf(owner -> !containsOwner(retainedOwners, owner));
                if (!owners.isEmpty()) {
                    store.writeOwners(contentId, owners);
                }
                boolean referenced = retained.contains(contentId.getBytes(StandardCharsets.US_ASCII));
                boolean keep = reference.lifecycle() != DurableContentReference.Lifecycle.TEMPORARY
                        && (referenced || !owners.isEmpty());
                if (!keep || !isRegularFile(store.completePath(reference))) {
                    store.retireFiles(reference);
                }
            } finally {
                lock.unlock();
            }
        }

        private static void cleanupAbandonedTemporaryState(FilesystemStagedContentStore store) throws IOException {
            try (java.util.stream.Stream<Path> paths = Files.list(store.root)) {
                java.util.Iterator<Path> iterator = paths.iterator();
                while (iterator.hasNext()) {
                    Path path = iterator.next();
                    String name = path.getFileName().toString();
                    if (name.endsWith(".incomplete")) {
                        Files.deleteIfExists(path);
                    } else if (name.endsWith(".unique-index")
                            && Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        deleteIndex(path);
                    }
                }
            }
        }

        private static void cleanupOrphanedCompletedFiles(FilesystemStagedContentStore store) throws IOException {
            try (java.util.stream.Stream<Path> paths = Files.list(store.root)) {
                java.util.Iterator<Path> iterator = paths
                        .filter(path -> path.getFileName().toString().endsWith(".content")).iterator();
                while (iterator.hasNext()) {
                    Path content = iterator.next();
                    String name = content.getFileName().toString();
                    String contentId = name.substring(0, name.length() - ".content".length());
                    if (!isRegularFile(store.metadataPath(contentId))) {
                        Files.deleteIfExists(content);
                    }
                }
            }
        }

        private static void cleanupOrphanedOwnerFiles(FilesystemStagedContentStore store) throws IOException {
            try (java.util.stream.Stream<Path> paths = Files.list(store.root)) {
                java.util.Iterator<Path> iterator = paths
                        .filter(path -> path.getFileName().toString().endsWith(".owners")).iterator();
                while (iterator.hasNext()) {
                    Path owners = iterator.next();
                    String name = owners.getFileName().toString();
                    String contentId = name.substring(0, name.length() - ".owners".length());
                    if (!isRegularFile(store.metadataPath(contentId))) {
                        DurableMetadataFiles.delete(owners);
                    }
                }
            }
        }

        private static void deleteIndex(Path directory) throws IOException {
            try (java.util.stream.Stream<Path> paths = Files.list(directory)) {
                java.util.Iterator<Path> iterator = paths.iterator();
                while (iterator.hasNext()) {
                    Files.deleteIfExists(iterator.next());
                }
            }
            Files.deleteIfExists(directory);
        }

        private static DurableContentReference requireOwned(FilesystemStagedContentStore store,
                DurableContentReference reference) {
            DurableContentReference exact = Objects.requireNonNull(reference, "reference");
            if (!store.storeId.equals(exact.storeId())) {
                throw new IllegalArgumentException("Staged content belongs to another store");
            }
            if (!(exact instanceof StoreReference)) {
                throw new IllegalArgumentException("Staged content reference was not issued by this store");
            }
            return exact;
        }

        private static DurableContentReference readMetadata(FilesystemStagedContentStore store, String contentId)
                throws IOException {
            Path metadata = store.metadataPath(contentId);
            if (!isRegularFile(metadata)) {
                throw new IOException("Staged content metadata missing: code=STAGED_CONTENT_INCOMPLETE");
            }
            try (DataInputStream input = new DataInputStream(Channels.newInputStream(
                    FileChannel.open(metadata, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)))) {
                int version = input.readUnsignedByte();
                if (version != METADATA_VERSION) {
                    throw new IOException("Unsupported staged content metadata");
                }
                Encoding encoding = Encoding.valueOf(input.readUTF());
                DurableContentReference.Lifecycle lifecycle = DurableContentReference.Lifecycle.valueOf(
                        input.readUTF());
                long length = input.readLong();
                String digest = input.readUTF();
                if (input.read() >= 0) {
                    throw new IOException("Trailing staged content metadata");
                }
                return new StoreReference(store.storeId, contentId, encoding, length, digest, lifecycle);
            } catch (IllegalArgumentException exception) {
                throw new IOException("Malformed staged content metadata", exception);
            }
        }

        private static void requireExactMetadata(FilesystemStagedContentStore store,
                DurableContentReference exact) throws IOException {
            DurableContentReference persisted = store.readMetadata(exact.contentId());
            if (!persisted.equals(exact)) {
                throw new IOException("Staged content metadata mismatch: code=CONTENT_INTEGRITY_FAILED");
            }
            if (!isRegularFile(store.completePath(exact))
                    || Files.size(store.completePath(exact)) != exact.length()) {
                throw new IOException("Staged content integrity failed: code=CONTENT_INTEGRITY_FAILED");
            }
        }

        private static Set<DurableContentOwner> readOwners(FilesystemStagedContentStore store, String contentId)
                throws IOException {
            Path ownersPath = store.ownerPath(contentId);
            try {
                return DurableMetadataFiles.read(ownersPath, MAX_OWNER_RECORD_BYTES,
                        input -> decodeOwners(input, contentId));
            } catch (java.nio.file.NoSuchFileException missing) {
                return new LinkedHashSet<>();
            } catch (IllegalArgumentException exception) {
                throw new IOException("Malformed staged content owner metadata", exception);
            }
        }

        private static Set<DurableContentOwner> decodeOwners(DataInputStream input, String contentId)
                throws IOException {
            Set<DurableContentOwner> owners = new LinkedHashSet<>();
            if (input.readUnsignedByte() != OWNER_METADATA_VERSION) {
                throw new IOException("Unsupported staged content owner metadata");
            }
            if (!contentId.equals(input.readUTF())) {
                throw new IOException("Staged content owner metadata identity mismatch");
            }
            int count = input.readInt();
            if (count < 0 || count > MAX_OWNER_COUNT) {
                throw new IOException("Invalid staged content owner count");
            }
            for (int index = 0; index < count; index++) {
                DurableContentOwner owner = parseOwner(input.readUTF());
                if (!owners.add(owner)) {
                    throw new IOException("Duplicate staged content owner");
                }
            }
            return owners;
        }

        private static void writeOwners(FilesystemStagedContentStore store, String contentId,
                Set<DurableContentOwner> owners) throws IOException {
            if (owners.size() > MAX_OWNER_COUNT) {
                throw new IOException("Staged content owner count exceeds metadata capability");
            }
            Path complete = store.ownerPath(contentId);
            java.util.List<String> encoded = owners.stream().map(DurableContentOwner::canonicalForm).sorted()
                    .toList();
            DurableMetadataFiles.replace(complete, MAX_OWNER_RECORD_BYTES, output -> {
                output.writeByte(OWNER_METADATA_VERSION);
                output.writeUTF(contentId);
                output.writeInt(encoded.size());
                for (String value : encoded) {
                    output.writeUTF(value);
                }
            });
        }

        private static DurableContentOwner parseOwner(String encoded) {
            int separator = encoded.indexOf(':');
            if (separator <= 0 || separator == encoded.length() - 1) {
                throw new IllegalArgumentException("Malformed durable content owner");
            }
            DurableContentOwner.Category category = DurableContentOwner.Category.valueOf(
                    encoded.substring(0, separator));
            return new DurableContentOwner(category, encoded.substring(separator + 1));
        }

        private static boolean containsOwner(TemporaryUniqueIndex retainedOwners, DurableContentOwner owner) {
            try {
                return retainedOwners.contains(owner.canonicalForm().getBytes(StandardCharsets.UTF_8));
            } catch (IOException exception) {
                throw new java.io.UncheckedIOException(exception);
            }
        }

        private static void writeMetadata(FilesystemStagedContentStore store, DurableContentReference reference)
                throws IOException {
            Path incomplete = store.resolveOwned(reference.contentId() + ".meta.incomplete");
            Path complete = store.metadataPath(reference.contentId());
            Files.createFile(incomplete);
            restrict(incomplete);
            try (DataOutputStream output = new DataOutputStream(Files.newOutputStream(incomplete))) {
                output.writeByte(METADATA_VERSION);
                output.writeUTF(reference.encoding().name());
                output.writeUTF(reference.lifecycle().name());
                output.writeLong(reference.length());
                output.writeUTF(reference.sha256());
            }
            try (FileChannel channel = FileChannel.open(incomplete, StandardOpenOption.READ)) {
                channel.force(true);
            }
            try {
                Files.move(incomplete, complete, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException exception) {
                Files.move(incomplete, complete);
            }
        }
    }

    private record StoreReference(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference {
        private StoreReference {
            requireStoreIdentifier(storeId);
            requireContentIdentifier(contentId);
            Objects.requireNonNull(encoding, "encoding");
            Objects.requireNonNull(lifecycle, "lifecycle");
            if (length < MINIMUM_CONTENT_LENGTH) {
                throw new IllegalArgumentException("Content length must not be negative");
            }
            String exactDigest = Objects.requireNonNull(sha256, "sha256");
            if (!exactDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Content integrity value must be canonical SHA-256");
            }
        }
    }

    private static void requireCanonicalUuid(String value, boolean requireRandomVersion) {
        UUID parsed;
        try {
            parsed = UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Staged content identifier is not canonical UUID text", exception);
        }
        if (!parsed.toString().equals(value) || parsed.variant() != 2 || requireRandomVersion && parsed.version() != 4) {
            throw new IllegalArgumentException("Staged content identifier is not store-issued");
        }
    }

}
