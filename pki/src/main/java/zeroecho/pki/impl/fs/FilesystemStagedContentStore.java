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

import java.io.FilterOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UTFDataFormatException;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
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
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.ConfusingTernary",
        "PMD.AvoidCatchingGenericException", "PMD.UnusedPrivateMethod" })
public final class FilesystemStagedContentStore implements StagedContentStore { // NOPMD TooManyMethods - One cohesive gateway, realm ownership boundary, or durable store SPI implementation.
    private static final String OWNERS_SUFFIX = ".owners";


    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> OWNER_DIRECTORY = EnumSet.of(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
    private static final int METADATA_VERSION = 1;
    private static final int OWNER_METADATA_VERSION = 2;
    private static final int MAX_OWNER_RECORD_BYTES = 1024 * 1024;
    private static final int MAX_OWNER_COUNT = 2048;
    private static final int OWNER_LOCK_COUNT = 64;
    private static final long MINIMUM_CONTENT_LENGTH = 0L;
    private static final ThreadLocal<SealFaultInjector> SEAL_FAULTS = new ThreadLocal<>();
    private static final ThreadLocal<MetadataReadFaultInjector> METADATA_READ_FAULTS =
            new ThreadLocal<>();
    private static final ThreadLocal<MetadataAttributeReadFaultInjector>
            METADATA_ATTRIBUTE_READ_FAULTS = new ThreadLocal<>(); // NOPMD - LongVariable: descriptive byte-unit/projection name preserves its established contract.

    private final Path root;
    private final String storeId;
    private final ReentrantLock[] ownerLocks;
    private final ConcurrentMap<String, Integer> transactionalReservations;
    private final AtomicReference<TransactionalOwnership> transactionalOwnership;
    private final ContentReadObserver contentReadObserver;
    private final Semaphore openSinks;
    private final StoreMutationBarrier mutationBarrier;

    /**
     * Creates a staged-content store.
     *
     * @param root    private storage directory
     * @param storeId stable runtime/store identifier
     * @throws IOException              if the directory cannot be created
     * @throws IllegalArgumentException if {@code storeId} is blank
     */
    public FilesystemStagedContentStore(Path root, String storeId) throws IOException {
        this(root, storeId, Integer.MAX_VALUE, null);
    }

    /* default */ FilesystemStagedContentStore(Path root, String storeId, ContentReadObserver observer)
            throws IOException {
        this(root, storeId, Integer.MAX_VALUE, observer);
    }

    /* default */ FilesystemStagedContentStore(Path root, String storeId, int maximumOpenSinks,
            ContentReadObserver observer) throws IOException {
        this(root, storeId, maximumOpenSinks, observer, true);
    }

    /* default */ FilesystemStagedContentStore(Path root, String storeId, int maximumOpenSinks,
            ContentReadObserver observer, boolean cleanupTemporaryState) throws IOException {
        this(root, storeId, maximumOpenSinks, observer, cleanupTemporaryState, new StoreMutationBarrier());
    }

    /* default */ FilesystemStagedContentStore(Path root, String storeId, int maximumOpenSinks,
            ContentReadObserver observer, boolean cleanupTemporaryState, StoreMutationBarrier mutationBarrier)
            throws IOException {
        this.mutationBarrier = Objects.requireNonNull(mutationBarrier, "mutationBarrier");
        if (maximumOpenSinks <= 0) {
            throw new IllegalArgumentException("maximumOpenSinks must be positive");
        }
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.storeId = requireStoreIdentifier(storeId);
        this.contentReadObserver = observer;
        this.ownerLocks = new ReentrantLock[OWNER_LOCK_COUNT];
        this.transactionalReservations = new ConcurrentHashMap<>();
        this.transactionalOwnership = new AtomicReference<>(reference -> Set.of());
        this.openSinks = new Semaphore(maximumOpenSinks);
        for (int index = 0; index < ownerLocks.length; index++) {
            ownerLocks[index] = new ReentrantLock();
        }
        if (cleanupTemporaryState) {
            Files.createDirectories(this.root);
        }
        if (Files.isSymbolicLink(this.root) || !Files.isDirectory(this.root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Staged-content root must be a real directory");
        }
        if (cleanupTemporaryState) {
            cleanupAbandonedTemporaryState();
        }
    }

    /** Opens a resolver whose construction and supported operation are read-only. */
    /* default */ static StagedContentStore readOnlyResolver(Path root, String storeId)
            throws IOException {
        return new ReadOnlyResolver(new FilesystemStagedContentStore(
                root, storeId, Integer.MAX_VALUE, null, false));
    }

    /** Runs restart cleanup only after signing metadata passes semantic validation. */
    /* default */ void cleanupValidatedTemporaryState() throws IOException {
        cleanupAbandonedTemporaryState();
    }

    @Override
    public String contentStoreId() {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            return storeId;
        }
    }

    /* package */ static void validateExistingLayout(Path root) throws IOException {
        Objects.requireNonNull(root, "root");
        long entries = 0L;
        try (java.util.stream.Stream<Path> paths = Files.list(root)) {
            java.util.Iterator<Path> iterator = paths.iterator();
            while (iterator.hasNext()) {
                Path path = iterator.next();
                if (++entries > 1_000_000L || Files.isSymbolicLink(path)) {
                    throw new MalformedLayoutException();
                }
                String name = path.getFileName().toString();
                boolean uniqueIndex = name.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.unique-index");
                boolean contentFile = name.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.(content|meta|owners|incomplete)");
                boolean metadataTemporary = name.matches("\\.metadata-[0-9a-f-]{36}\\.tmp");
                if (uniqueIndex) {
                    if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        throw new MalformedLayoutException();
                    }
                    try (java.util.stream.Stream<Path> nested = Files.walk(path)) {
                        if (nested.anyMatch(Files::isSymbolicLink)) {
                            throw new MalformedLayoutException();
                        }
                    }
                } else if (!contentFile && !metadataTemporary
                        || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                    throw new MalformedLayoutException();
                } else if ((name.endsWith(".meta") && Files.size(path) > 4096L)
                        || (name.endsWith(OWNERS_SUFFIX) && Files.size(path) > MAX_OWNER_RECORD_BYTES)) {
                    throw new MalformedLayoutException();
                }
                if (name.endsWith(OWNERS_SUFFIX)) {
                    String contentId = name.substring(0, name.length() - OWNERS_SUFFIX.length());
                    DurableMetadataFiles.read(path, MAX_OWNER_RECORD_BYTES, input -> StoreIo.decodeOwners(input, contentId));
                }
            }
        }
    }

    /** Cause-free marker distinguishing invalid layout from operational I/O. */
    /* default */ static final class MalformedLayoutException extends IOException {
        private static final long serialVersionUID = 1L;

        private MalformedLayoutException() {
            super("Staged-content format unsupported");
        }
    }

    /** Cause-free marker for malformed staged-content metadata or reference binding. */
    /* default */ static final class MalformedStagedContentException extends IOException {
        private static final long serialVersionUID = 1L;
    }

    /* default */ static void installSealFault(SealFaultInjector injector) {
        SEAL_FAULTS.set(Objects.requireNonNull(injector, "injector"));
    }

    /* default */ static void clearSealFault() {
        SEAL_FAULTS.remove();
    }

    /* default */ static void installMetadataReadFault(MetadataReadFaultInjector fault) {
        METADATA_READ_FAULTS.set(Objects.requireNonNull(fault, "fault"));
    }

    /* default */ static void clearMetadataReadFault() {
        METADATA_READ_FAULTS.remove();
    }

    /* default */ static void installMetadataAttributeReadFault(
            MetadataAttributeReadFaultInjector fault) {
        METADATA_ATTRIBUTE_READ_FAULTS.set(Objects.requireNonNull(fault, "fault"));
    }

    /* default */ static void clearMetadataAttributeReadFault() {
        METADATA_ATTRIBUTE_READ_FAULTS.remove();
    }

    private static void tripSealFault(SealFaultPoint point) throws IOException {
        SealFaultInjector injector = SEAL_FAULTS.get();
        if (injector != null) {
            injector.fail(point);
        }
    }

    /** Resolves staged content without exposing mutation of the backing store. */
    private static final class ReadOnlyResolver implements StagedContentStore {
        private final FilesystemStagedContentStore delegate;

        private ReadOnlyResolver(FilesystemStagedContentStore delegate) {
            this.delegate = delegate;
        }

        @Override public String contentStoreId() { return delegate.contentStoreId(); }

        @Override
        public DurableContentReference restoreReference(String storeId, String contentId,
                Encoding encoding, long length, String sha256,
                DurableContentReference.Lifecycle lifecycle) throws IOException {
            return delegate.restoreReference(storeId, contentId, encoding, length, sha256,
                    lifecycle);
        }

        @Override public ContentSink beginContent(Encoding encoding,
                DurableContentReference.Lifecycle lifecycle) {
            throw readOnly();
        }

        @Override public RepeatableContent openContent(DurableContentReference reference) throws IOException {
            // Recovery validates live proof bytes before activating metadata or reclaiming content.
            return delegate.openContent(reference);
        }

        @Override public boolean retainContent(DurableContentReference reference,
                DurableContentOwner owner) {
            throw readOnly();
        }

        @Override public boolean releaseContent(DurableContentReference reference,
                DurableContentOwner owner) {
            throw readOnly();
        }

        @Override public Set<DurableContentOwner> contentOwners(
                DurableContentReference reference) {
            throw readOnly();
        }

        @Override public void retireUnownedContent(DurableContentReference reference) {
            throw readOnly();
        }

        @Override public void recoverContent(TemporaryUniqueIndex retained,
                TemporaryUniqueIndex retainedOwners) {
            throw readOnly();
        }

        @Override public TemporaryUniqueIndex beginUniqueIndex() {
            throw readOnly();
        }

        private static UnsupportedOperationException readOnly() {
            return new UnsupportedOperationException("staged-content resolver is read-only");
        }
    }

    @Override
    public ContentSink beginContent(Encoding encoding, DurableContentReference.Lifecycle lifecycle) throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            Objects.requireNonNull(encoding, "encoding");
            Objects.requireNonNull(lifecycle, "lifecycle");
            if (!openSinks.tryAcquire()) {
                throw new IOException("Staged-content preparation is busy: code=STAGED_CONTENT_PREPARATION_BUSY");
            }
            String contentId = UUID.randomUUID().toString();
            Path incomplete = root.resolve(contentId + ".incomplete");
            Path complete = root.resolve(contentId + ".content");
            try {
                createOwnerOnlyFile(incomplete);
                return new FileSink(contentId, incomplete, complete, encoding, lifecycle);
            } catch (IOException | RuntimeException failure) {
                openSinks.release();
                throw failure;
            }
        }
    }

    @Override
    public RepeatableContent openContent(DurableContentReference reference) throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
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
            return new FileContent(path, exact, contentReadObserver);
        }
    }

    @Override
    public DurableContentReference restoreReference(String persistedStoreId, String contentId, Encoding encoding,
            long length, String sha256, DurableContentReference.Lifecycle lifecycle) throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            if (!storeId.equals(requireStoreIdentifier(persistedStoreId))) {
                throw new IllegalArgumentException("Staged content belongs to another store");
            }
            requireContentIdentifier(contentId);
            StoreReference supplied = new StoreReference(storeId, contentId, encoding, length, sha256, lifecycle);
            DurableContentReference persisted = readMetadata(contentId);
            if (!persisted.equals(supplied)) {
                throw new MalformedStagedContentException();
            }
            return persisted;
        }
    }

    @Override
    public boolean retainContent(DurableContentReference reference, DurableContentOwner owner) throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            DurableContentReference exact = requireOwned(reference);
            Objects.requireNonNull(owner, "owner");
            TransactionalOwnershipIo.requireSidecarOwner(owner);
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
    }

    @Override
    public boolean releaseContent(DurableContentReference reference, DurableContentOwner owner) throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            DurableContentReference exact = requireOwned(reference);
            Objects.requireNonNull(owner, "owner");
            TransactionalOwnershipIo.requireSidecarOwner(owner);
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
                TransactionalOwnershipIo.retireIfUnowned(this, exact, owners);
                return true;
            } finally {
                lock.unlock();
            }
        }
    }

    @Override
    public Set<DurableContentOwner> contentOwners(DurableContentReference reference) throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            DurableContentReference exact = requireOwned(reference);
            ReentrantLock lock = ownerLock(exact.contentId());
            lock.lock();
            try {
                requireExactMetadata(exact);
                Set<DurableContentOwner> owners = readOwners(exact.contentId());
                owners.addAll(transactionalOwnership.get().findOwners(exact));
                return Set.copyOf(owners);
            } finally {
                lock.unlock();
            }
        }
    }

    @Override
    public void retireUnownedContent(DurableContentReference reference) throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            DurableContentReference exact = requireOwned(reference);
            ReentrantLock lock = ownerLock(exact.contentId());
            lock.lock();
            try {
                requireExactMetadata(exact);
                TransactionalOwnershipIo.requireUnowned(this, exact);
                retireFiles(exact);
            } finally {
                lock.unlock();
            }
        }
    }

    @Override
    public void recoverContent(TemporaryUniqueIndex retained, TemporaryUniqueIndex retainedOwners) throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            try (TemporaryUniqueIndex transactionalOwners = beginUniqueIndex()) {
                StoreIo.recoverContent(this, retained, retainedOwners, transactionalOwners);
            }
        }
    }

    /** Recovery input separating transactional authority from general references and sidecars. */
    /* package */ void recoverContent(TemporaryUniqueIndex retained, TemporaryUniqueIndex retainedOwners,
            TemporaryUniqueIndex transactionalOwners) throws IOException {
        StoreIo.recoverContent(this, retained, retainedOwners, transactionalOwners);
    }

    @Override
    public TemporaryUniqueIndex beginUniqueIndex() throws IOException {
        StoreMutationBarrier.Lease admission = mutationBarrier.enter();
        try (admission) {
            Path directory = root.resolve(UUID.randomUUID() + ".unique-index");
            Files.createDirectory(directory);
            restrictDirectory(directory);
            return FilesystemTemporaryUniqueIndex.general(directory);
        }
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

    /** Called only while the owning store's exclusive backup barrier is held. */
    /* default */ void copyBackupContent(Path target, FsBackupFiles.Budget budget, TemporaryUniqueIndex selected,
            TemporaryUniqueIndex requiredPayload)
            throws IOException {
        Files.createDirectories(target);
        try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(root, "*.meta")) {
            for (Path metadata : entries) {
                String name = metadata.getFileName().toString();
                String contentId = name.substring(0, name.length() - ".meta".length());
                DurableContentReference reference = readMetadata(contentId);
                if (!selected.contains(reference.contentId().getBytes(StandardCharsets.US_ASCII))) { continue; }
                FsBackupFiles.copy(metadata, target.resolve(name), budget);
                if (requiredPayload.contains(reference.contentId().getBytes(StandardCharsets.US_ASCII))) {
                    Path payload = completePath(reference);
                    FsBackupFiles.copy(payload, target.resolve(payload.getFileName()), budget);
                }
                Path owners = ownerPath(contentId);
                if (Files.exists(owners, LinkOption.NOFOLLOW_LINKS)) {
                    FsBackupFiles.copy(owners, target.resolve(owners.getFileName()), budget);
                }
            }
        }
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
        TransactionalOwnershipIo.requireSidecarOwners(owners);
        StoreIo.writeOwners(this, contentId, owners);
    }

    /* package */ void retireSigningContent(DurableContentReference reference) throws IOException {
        DurableContentReference exact = requireOwned(reference);
        ReentrantLock lock = ownerLock(exact.contentId());
        lock.lock();
        try {
            requireExactMetadata(exact);
            Files.deleteIfExists(completePath(exact));
            SigningFormatSupport.forceDirectory(root);
        } finally {
            lock.unlock();
        }
    }

    /* package */ void purgeSigningContent(DurableContentReference reference) throws IOException {
        DurableContentReference exact = requireOwned(reference);
        ReentrantLock lock = ownerLock(exact.contentId());
        lock.lock();
        try {
            retireFiles(exact);
            SigningFormatSupport.forceDirectory(root);
        } finally {
            lock.unlock();
        }
    }

    /* package */ void bindTransactionalOwnership(TransactionalOwnership ownership) {
        transactionalOwnership.set(Objects.requireNonNull(ownership, "ownership"));
    }

    /* package */ TransactionalReservation reserveTransactionalPublication(DurableContentReference reference)
            throws IOException {
        return TransactionalOwnershipIo.reserveTransactionalPublication(this, reference);
    }

    /** Internal callback to signing and status transactional owner authority. */
    /* default */
    @FunctionalInterface
    interface TransactionalOwnership {
        /** Finds every exact transactional owner for a durable content reference. */
        Set<DurableContentOwner> findOwners(DurableContentReference reference) throws IOException;

        /** Tests exact transactional ownership without materializing owner identities. */
        default boolean hasOwner(DurableContentReference reference) throws IOException {
            return !findOwners(reference).isEmpty();
        }
    }

    /** Short-lived reference-counted reservation spanning validation and commit. */
    /* package */ final class TransactionalReservation implements AutoCloseable {
        private final String contentId;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicBoolean recoveryRequired = new AtomicBoolean();

        private TransactionalReservation(String contentId) {
            this.contentId = contentId;
        }

        /* package */ void preserveUntilRecovery() {
            recoveryRequired.set(true);
        }

        @Override
        public void close() {
            if (!recoveryRequired.get() && closed.compareAndSet(false, true)) {
                ReentrantLock lock = ownerLock(contentId);
                lock.lock();
                try {
                    transactionalReservations.computeIfPresent(contentId,
                            (ignored, count) -> count == 1 ? null : count - 1);
                } finally {
                    lock.unlock();
                }
            }
        }
    }

    private void retireFiles(DurableContentReference reference) throws IOException {
        Files.deleteIfExists(metadataPath(reference.contentId()));
        Files.deleteIfExists(completePath(reference));
        DurableMetadataFiles.delete(ownerPath(reference.contentId()));
    }

    private Path ownerPath(String contentId) {
        requireContentIdentifier(contentId);
        return resolveOwned(contentId + OWNERS_SUFFIX);
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

    private static void createOwnerOnlyFile(Path path) throws IOException {
        if (Files.getFileStore(path.getParent()).supportsFileAttributeView("posix")) {
            Files.createFile(path, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        } else {
            Files.createFile(path);
            restrict(path);
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
            StoreMutationBarrier.Lease admission = mutationBarrier.enter();
            try (admission) {
                lock.lock();
                try {
                    requireOpen();
                    if (output == null) {
                        output = openCountingOutput(incomplete);
                    }
                    output.close();
                    try (FileChannel channel = FileChannel.open(incomplete, StandardOpenOption.READ,
                            LinkOption.NOFOLLOW_LINKS)) {
                        tripSealFault(SealFaultPoint.PAYLOAD_FORCE);
                        channel.force(true);
                    }
                    tripSealFault(SealFaultPoint.PAYLOAD_ATOMIC_MOVE);
                    Files.move(incomplete, complete, StandardCopyOption.ATOMIC_MOVE);
                    tripSealFault(SealFaultPoint.PAYLOAD_DIRECTORY_FORCE);
                    SigningFormatSupport.forceDirectory(root);
                    DurableContentReference reference = new StoreReference(storeId, contentId, encoding,
                            output.length(), output.digestHex(), lifecycle);
                    try {
                        writeMetadata(reference);
                        markTerminal();
                        return reference;
                    } catch (IOException failure) {
                        markTerminal();
                        Files.deleteIfExists(complete);
                        Files.deleteIfExists(resolveOwned(contentId + ".meta.incomplete"));
                        Files.deleteIfExists(metadataPath(contentId));
                        throw failure;
                    }
                } finally {
                    lock.unlock();
                }
            }
        }

        @Override
        public void abort() throws IOException {
            lock.lock();
            try {
                if (terminal.compareAndSet(false, true)) {
                    openSinks.release();
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
                    markTerminal();
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

        private void markTerminal() {
            if (terminal.compareAndSet(false, true)) {
                openSinks.release();
            }
        }
    }

    private static CountingOutputStream openCountingOutput(Path path) throws IOException {
        return new CountingOutputStream(Files.newOutputStream(path, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS), sha256());
    }

    /** Durable payload publication boundaries used by deterministic fault tests. */
    /* default */ enum SealFaultPoint {
        PAYLOAD_FORCE,
        PAYLOAD_ATOMIC_MOVE,
        PAYLOAD_DIRECTORY_FORCE
    }

    /** Test seam for failing one durable payload publication boundary. */
    /* default */ @FunctionalInterface
    interface SealFaultInjector {
        /** Fails the selected publication boundary. */
        void fail(SealFaultPoint point) throws IOException;
    }

    /** Test seam for operational staged-metadata reads during recovery validation. */
    /* default */ @FunctionalInterface
    interface MetadataReadFaultInjector {
        /** Runs before the selected metadata access and may inject an I/O failure. */
        void beforeRead(Path metadata) throws IOException;
    }

    /** Test seam for operational staged-metadata attribute reads during recovery. */
    /* default */ @FunctionalInterface
    interface MetadataAttributeReadFaultInjector {
        /** Runs before the selected metadata access and may inject an I/O failure. */
        void beforeRead(Path metadata) throws IOException;
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
        private final ContentReadObserver observer;

        private FileContent(Path path, DurableContentReference reference, ContentReadObserver observer) {
            this.path = path;
            this.reference = reference;
            this.observer = observer;
        }

        @Override
        public InputStream openStream() throws IOException {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile() || attributes.size() != reference.length()) {
                throw new IOException("Staged content integrity failed: code=CONTENT_INTEGRITY_FAILED");
            }
            return new VerifiedChannelInputStream(path, reference, observer);
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

    /** Read stream validating the retained file identity during caller consumption. */
    @SuppressWarnings("PMD.AvoidMessageDigestField")
    private static final class VerifiedChannelInputStream extends InputStream {
        private final FileChannel channel;
        private final InputStream delegate;
        private final DurableContentReference reference;
        private final ContentReadObserver observer;
        private final MessageDigest digest = sha256();
        private long length;
        private boolean verified;

        private VerifiedChannelInputStream(Path path, DurableContentReference reference, ContentReadObserver observer)
                throws IOException {
            super();
            this.reference = reference;
            this.observer = observer;
            channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
            boolean initialized = false;
            try {
                delegate = Channels.newInputStream(channel);
                if (observer != null) {
                    observer.opened();
                }
                initialized = true;
            } finally {
                if (!initialized) {
                    closeFailedChannel(channel);
                }
            }
        }

        @Override
        public int read() throws IOException {
            int value = delegate.read();
            if (value < 0) {
                verifyAtEnd();
            } else {
                digest.update((byte) value);
                length = Math.addExact(length, 1L);
                observeRead(1);
                rejectExcessLength();
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            int count = delegate.read(bytes, offset, length);
            if (count < 0) {
                verifyAtEnd();
            } else if (count > 0) {
                digest.update(bytes, offset, count);
                this.length = Math.addExact(this.length, count);
                observeRead(count);
                rejectExcessLength();
            }
            return count;
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }

        private static void closeFailedChannel(FileChannel failedChannel) throws IOException {
            if (failedChannel != null) {
                failedChannel.close();
            }
        }

        private void rejectExcessLength() throws IOException {
            if (length > reference.length()) {
                throw integrityFailure();
            }
        }

        private void observeRead(int count) {
            if (observer != null) {
                observer.read(count);
            }
        }

        private void verifyAtEnd() throws IOException {
            if (verified) {
                return;
            }
            verified = true;
            byte[] actual = digest.digest();
            byte[] expected = HexFormat.of().parseHex(reference.sha256());
            try {
                if (length != reference.length() || !MessageDigest.isEqual(actual, expected)) {
                    throw integrityFailure();
                }
            } finally {
                java.util.Arrays.fill(actual, (byte) 0);
                java.util.Arrays.fill(expected, (byte) 0);
            }
        }

        private static IOException integrityFailure() {
            return new IOException("Staged content integrity failed: code=CONTENT_INTEGRITY_FAILED");
        }
    }

    /** Package-local instrumentation seam for proving production stream I/O shape. */
    /* default */ interface ContentReadObserver {
        /** Records one successful payload-channel open. */
        void opened();

        /** Records payload bytes returned to the consumer. */
        void read(int count);
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

    /** Mechanical home for filesystem metadata branches kept outside the store coordinator. */
    private static final class StoreIo {
        private static void recoverContent(FilesystemStagedContentStore store, TemporaryUniqueIndex retained,
                TemporaryUniqueIndex retainedOwners, TemporaryUniqueIndex transactionalOwners) throws IOException {
            Objects.requireNonNull(retained, "retained");
            Objects.requireNonNull(retainedOwners, "retainedOwners");
            Objects.requireNonNull(transactionalOwners, "transactionalOwners");
            retained.validateNamespace();
            retainedOwners.validateNamespace();
            transactionalOwners.validateNamespace();
            try (java.util.stream.Stream<Path> paths = Files.list(store.root)) {
                java.util.Iterator<Path> iterator = paths
                        .filter(path -> path.getFileName().toString().endsWith(".meta")).iterator();
                while (iterator.hasNext()) {
                    Path metadata = iterator.next();
                    String name = metadata.getFileName().toString();
                    String contentId = name.substring(0, name.length() - ".meta".length());
                    recoverContent(store, retained, retainedOwners, transactionalOwners, contentId);
                }
            }
            store.cleanupOrphanedCompletedFiles();
            store.cleanupOrphanedOwnerFiles();
        }

        private static void recoverContent(FilesystemStagedContentStore store, TemporaryUniqueIndex retained,
                TemporaryUniqueIndex retainedOwners, TemporaryUniqueIndex transactionalOwners, String contentId)
                throws IOException {
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
                boolean transactionallyOwned = transactionalOwners.contains(
                        contentId.getBytes(StandardCharsets.US_ASCII));
                boolean keep = reference.lifecycle() != DurableContentReference.Lifecycle.TEMPORARY
                        && (referenced || transactionallyOwned || !owners.isEmpty());
                boolean payloadPresent = isRegularFile(store.completePath(reference));
                if (!keep) {
                    store.retireFiles(reference);
                } else if (transactionallyOwned && !payloadPresent) {
                    throw new IOException("Accepted staged content is missing");
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
                    } else if (name.matches("\\.metadata-[0-9a-f-]{36}\\.tmp")) {
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
                        .filter(path -> path.getFileName().toString().endsWith(OWNERS_SUFFIX)).iterator();
                while (iterator.hasNext()) {
                    Path owners = iterator.next();
                    String name = owners.getFileName().toString();
                    String contentId = name.substring(0, name.length() - OWNERS_SUFFIX.length());
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

        // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
        @SuppressWarnings({ "PMD.PreserveStackTrace" })
        private static DurableContentReference readMetadata(FilesystemStagedContentStore store, String contentId)
                throws IOException {
            Path metadata = store.metadataPath(contentId);
            MetadataAttributeReadFaultInjector attributeFault =
                    METADATA_ATTRIBUTE_READ_FAULTS.get();
            if (attributeFault != null) {
                attributeFault.beforeRead(metadata);
            }
            BasicFileAttributes attributes;
            try {
                attributes = Files.readAttributes(metadata, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
            } catch (NoSuchFileException missing) {
                throw new MalformedStagedContentException();
            }
            if (!attributes.isRegularFile()) {
                throw new MalformedStagedContentException();
            }
            try (FileChannel channel = FileChannel.open(metadata, StandardOpenOption.READ,
                    LinkOption.NOFOLLOW_LINKS);
                    DataInputStream input = new DataInputStream(Channels.newInputStream(channel))) {
                MetadataReadFaultInjector fault = METADATA_READ_FAULTS.get();
                if (fault != null) {
                    fault.beforeRead(metadata);
                }
                int version = input.readUnsignedByte();
                if (version != METADATA_VERSION) {
                    throw new MalformedStagedContentException();
                }
                Encoding encoding = Encoding.valueOf(input.readUTF());
                DurableContentReference.Lifecycle lifecycle = DurableContentReference.Lifecycle.valueOf(
                        input.readUTF());
                long length = input.readLong();
                String digest = input.readUTF();
                if (input.read() >= 0) {
                    throw new MalformedStagedContentException();
                }
                return new StoreReference(store.storeId, contentId, encoding, length, digest, lifecycle);
            } catch (EOFException | UTFDataFormatException | IllegalArgumentException malformed) {
                throw new MalformedStagedContentException();
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
            } catch (NoSuchFileException missing) {
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
                if (owner.category() == DurableContentOwner.Category.CREDENTIAL_RECORD) {
                    throw new MalformedLayoutException();
                }
                if (TransactionalOwnershipIo.isTransactionalOwner(owner)) {
                    continue;
                }
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
            Path complete = store.metadataPath(reference.contentId());
            DurableMetadataFiles.create(complete, 4096L, output -> {
                output.writeByte(METADATA_VERSION);
                output.writeUTF(reference.encoding().name());
                output.writeUTF(reference.lifecycle().name());
                output.writeLong(reference.length());
                output.writeUTF(reference.sha256());
            });
        }
    }

    /** Isolates transactional staged-content ownership lifecycle decisions. */
    private static final class TransactionalOwnershipIo {
        private static void requireSidecarOwners(Set<DurableContentOwner> owners) {
            for (DurableContentOwner owner : owners) {
                requireSidecarOwner(owner);
            }
        }

        private static void requireSidecarOwner(DurableContentOwner owner) {
            if (isTransactionalOwner(owner)) {
                throw new IllegalArgumentException(
                        "Transactional ownership is authoritative metadata");
            }
        }

        private static boolean isTransactionalOwner(DurableContentOwner owner) {
            return owner.category() == DurableContentOwner.Category.SIGNING_OPERATION
                    || owner.category() == DurableContentOwner.Category.STATUS_OBJECT_RECORD
                    || owner.category() == DurableContentOwner.Category.CREDENTIAL_RECORD;
        }

        private static TransactionalReservation reserveTransactionalPublication(FilesystemStagedContentStore store,
                DurableContentReference reference) throws IOException {
            DurableContentReference exact = store.requireOwned(reference);
            ReentrantLock lock = store.ownerLock(exact.contentId());
            lock.lock();
            try {
                store.requireExactMetadata(exact);
                store.transactionalReservations.merge(exact.contentId(), 1, Math::addExact);
                return store.new TransactionalReservation(exact.contentId());
            } catch (ArithmeticException exception) {
                throw new IOException("Transactional content reservation limit exceeded", exception);
            } finally {
                lock.unlock();
            }
        }

        private static boolean hasTransactionalAuthority(FilesystemStagedContentStore store,
                DurableContentReference reference) throws IOException {
            return store.transactionalReservations.containsKey(reference.contentId())
                    || store.transactionalOwnership.get().hasOwner(reference);
        }

        private static void retireIfUnowned(FilesystemStagedContentStore store,
                DurableContentReference reference, Set<DurableContentOwner> owners) throws IOException {
            if (owners.isEmpty() && !hasTransactionalAuthority(store, reference)) {
                store.retireFiles(reference);
            }
        }

        private static void requireUnowned(FilesystemStagedContentStore store,
                DurableContentReference reference) throws IOException {
            if (!store.readOwners(reference.contentId()).isEmpty()
                    || hasTransactionalAuthority(store, reference)) {
                throw new IOException("Staged content remains durably owned");
            }
        }

        private static void retireTransactionalContent(FilesystemStagedContentStore store,
                DurableContentReference reference) throws IOException {
            DurableContentReference exact = store.requireOwned(reference);
            ReentrantLock lock = store.ownerLock(exact.contentId());
            lock.lock();
            try {
                store.requireExactMetadata(exact);
                if (store.readOwners(exact.contentId()).isEmpty()
                        && !hasTransactionalAuthority(store, exact)) {
                    store.retireFiles(exact);
                }
            } finally {
                lock.unlock();
            }
        }
    }

    /** Store-branded immutable reference; arbitrary interface implementations are rejected. */
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
