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

import java.util.Iterator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;

/**
 * Coordinates the credential-record/content-owner write-once handoff.
 */
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
    private static final ThreadLocal<DirectoryForceObserver> DIRECTORY_FORCE_OBSERVER = new ThreadLocal<>();
    private static final ThreadLocal<Consumer<ReentrantLock>> BEFORE_LOCK_OBSERVER = new ThreadLocal<>();
    private static final byte[] INTENT_KEY_DOMAIN =
            "zeroecho:pki:credential-handoff-intent:v1".getBytes(StandardCharsets.US_ASCII);

    private final FsPaths paths;
    private final FilesystemStagedContentStore stagedContent;
    private final Path intentRoot;
    private final ReentrantLock[] locks;

    /**
     * Creates the write-once handoff coordinator with striped credential locks.
     *
     * @param paths credential record layout
     * @param stagedContent content store whose ownership accompanies each credential
     * @throws NullPointerException if either dependency is null
     */
    /* default */ CredentialContentTransaction(FsPaths paths, FilesystemStagedContentStore stagedContent) {
        this.paths = Objects.requireNonNull(paths, "paths");
        this.stagedContent = Objects.requireNonNull(stagedContent, "stagedContent");
        this.intentRoot = paths.root().resolve("credential-handoffs");
        this.locks = new ReentrantLock[LOCK_COUNT];
        for (int index = 0; index < locks.length; index++) {
            locks[index] = new ReentrantLock();
        }
    }

    /**
     * Publishes a new credential record together with its durable content ownership under its credential lock.
     *
     * @param credential credential with persisted content belonging to this store
     * @throws NullPointerException if credential is null
     * @throws IllegalArgumentException if content belongs to another store or is not persisted
     * @throws IllegalStateException if the credential already exists, a handoff is pending, ownership is
     *     inconsistent, or publication fails; an unconfirmed publication requires recovery
     */
    /* default */ void put(Credential credential) {
        Objects.requireNonNull(credential, "credential");
        PkiId credentialId = credential.credentialId();
        ReentrantLock lock = lock(credentialId);
        observeBeforeLock(lock);
        lock.lock();
        try {
            putLocked(credential);
        } finally {
            lock.unlock();
        }
    }

    // The handoff marker unwraps its original IOException and installs the store fence before releasing the lock.
    /**
     * Publishes X.509 content or verifies an exact completed replay while holding the credential handoff lock.
     * The usability callback runs after acquiring the lock; unconfirmed publication invokes the recovery
     * callback before unlocking.
     *
     * @param credential X.509 credential with persisted store-owned content
     * @param requireStoreUsable callback rejecting a fenced or otherwise unusable store
     * @param recoveryRequired maps an unconfirmed or pending handoff to the store recovery exception
     * @throws NullPointerException if a parameter is null
     * @throws IllegalArgumentException if the format is not X.509 or content is not persisted in this store
     * @throws IllegalStateException if verification, publication or exact replay validation fails
     * @throws PkiException if the recovery callback fences an incomplete handoff
     */
    @SuppressWarnings({ "PMD.ExceptionAsFlowControl", "PMD.PreserveStackTrace" })
    /* default */ void putOrVerifyExactX509(Credential credential, Runnable requireStoreUsable,
            Function<IOException, PkiException> recoveryRequired) {
        Objects.requireNonNull(credential, "credential");
        Objects.requireNonNull(requireStoreUsable, "requireStoreUsable");
        Objects.requireNonNull(recoveryRequired, "recoveryRequired");
        if (!BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
            throw new IllegalArgumentException("Exact credential replay requires X.509 content");
        }
        ReentrantLock lock = lock(credential.credentialId());
        observeBeforeLock(lock);
        lock.lock();
        try {
            // A queued caller must observe any fence raised by the preceding
            // publisher before it can acknowledge the visible target.
            requireStoreUsable.run();
            if (Files.exists(intentPath(credential.credentialId()), LinkOption.NOFOLLOW_LINKS)
                    || Files.exists(privateRecordPath(credential.credentialId()), LinkOption.NOFOLLOW_LINKS)) {
                throw recoveryRequired.apply(new IOException("Credential content handoff requires recovery"));
            }
            Path target = paths.credentialPath(credential.credentialId());
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                if (!isRegularFile(target)) { throw new IOException("Credential record is not a regular file"); }
                requirePersistedReference(credential.content());
                validateIntegrity(credential.content());
                Credential actual = FsCodec.decode(FsCodec.CREDENTIAL, FsOperations.readAll(target), stagedContent);
                validateLoaded(credential.credentialId(), actual);
                requireExactReplay(actual, credential);
            } else {
                putLocked(credential);
            }
        } catch (HandoffUnconfirmedException failure) {
            // The shared store fence is installed while the handoff lock is
            // still held, including failures after intent cleanup has begun.
            throw recoveryRequired.apply(failure.failure);
        } catch (IOException failure) {
            throw new IllegalStateException("Credential replay verification failed", failure);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Requires equal credential metadata, canonical attributes and content integrity coordinates.
     *
     * @param actual already published credential
     * @param expected replay requested by the caller
     * @throws NullPointerException if either credential is null
     * @throws IllegalStateException if any compared coordinate differs
     */
    /* default */ static void requireExactReplay(Credential actual, Credential expected) {
        Credential metadata = new Credential(actual.credentialId(), actual.formatId(), actual.issuerRef(),
                actual.subjectRef(), actual.validity(), actual.serialOrUniqueId(), actual.publicKeyId(),
                actual.profileBinding(), actual.status(), expected.content(), expected.attributes());
        if (!metadata.equals(expected) || actual.content().length() != expected.content().length()
                || actual.content().encoding() != expected.content().encoding()
                || !actual.content().sha256().equals(expected.content().sha256())
                || !DomainAttributeEncoding.encode(actual.attributes()).equals(DomainAttributeEncoding.encode(expected.attributes()))) {
            throw new IllegalStateException("Persisted credential differs from its replay");
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
            throw new HandoffUnconfirmedException(failure);
        } catch (IOException failure) {
            if (published) { throw new HandoffUnconfirmedException(failure); }
            rollbackBeforePublication(credential.content(), owner, privateRecord, intentPath, intentWritten,
                    ownerAdded, failure);
            throw new IllegalStateException("Credential content handoff failed", failure);
        } catch (RuntimeException failure) {
            if (!published) {
                rollbackBeforePublication(credential.content(), owner, privateRecord, intentPath, intentWritten,
                        ownerAdded, failure);
            }
            throw failure;
        }
    }

    /**
     * Validates a loaded record identity, persisted content ownership and readable payload length.
     *
     * @param expectedId identifier selected by the record path
     * @param credential decoded credential
     * @return the same credential after validation
     * @throws NullPointerException if either argument is null
     * @throws IllegalArgumentException if the content belongs to another store or is not persisted
     * @throws IOException if identity, ownership or content integrity fails validation
     */
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

    /**
     * Visits each validated published credential once during startup recovery.
     */
    @FunctionalInterface
    public interface PublishedCredentialVisitor {
        /**
         * Visits one credential after its durable content and ownership have been validated.
         *
         * @param credential validated published credential
         * @throws IOException if the visitor cannot process the credential
         */
        void accept(Credential credential) throws IOException;
    }

    /**
     * Recovers handoff intents, removes orphaned private records and visits each validated published credential.
     *
     * @param publishedVisitor callback invoked after record and content validation
     * @throws NullPointerException if publishedVisitor is null
     * @throws IOException if recovery, record validation or the visitor fails
     */
    /* default */ void recover(PublishedCredentialVisitor publishedVisitor) throws IOException {
        Objects.requireNonNull(publishedVisitor, "publishedVisitor");
        recoverIntents();
        cleanupOrphanedPrivateRecords();
        validatePublishedRecords(publishedVisitor);
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
            forceCredentialDirectory(target.getParent());
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
            Iterator<Path> iterator = stream
                    .filter(path -> path.getFileName().toString().endsWith(PRIVATE_SUFFIX)).iterator();
            while (iterator.hasNext()) {
                Files.deleteIfExists(iterator.next());
            }
        }
    }

    private void validatePublishedRecords(PublishedCredentialVisitor publishedVisitor) throws IOException {
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
            publishedVisitor.accept(credential);
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

    /**
     * Derives a path-safe, domain-separated SHA-256 handoff filename from the exact credential identifier.
     *
     * @param credentialId identifier to bind into the digest
     * @return lowercase digest followed by the intent suffix
     * @throws NullPointerException if credentialId is null
     */
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
            try {
                forceCredentialDirectory(target.getParent());
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

    // Calling-thread fault/ordering seams for the credential publication boundary.
    /**
     * Calling-thread observer of directory durability boundaries.
     */
    /* default */
    @FunctionalInterface
    interface DirectoryForceObserver {
        /**
         * Runs immediately before forcing the credential directory to durable storage.
         *
         * @param directory directory whose publication durability is being established
         * @throws IOException to inject a directory-force failure
         */
        void beforeForce(Path directory) throws IOException;
    }
    /**
     * Installs the calling-thread observer for directory durability boundaries.
     *
     * @param observer replacement instrumentation callback
     * @throws NullPointerException if observer is null
     */
    /* default */ static void installDirectoryForceObserver(DirectoryForceObserver observer) {
        DIRECTORY_FORCE_OBSERVER.set(Objects.requireNonNull(observer, "observer"));
    }
    /**
     * Removes the calling-thread directory-force observer, restoring uninstrumented operation.
     */
    /* default */ static void clearDirectoryForceObserver() { DIRECTORY_FORCE_OBSERVER.remove(); }
    /**
     * Installs the calling-thread observer invoked before acquiring a credential handoff lock.
     *
     * @param observer replacement instrumentation callback
     * @throws NullPointerException if observer is null
     */
    /* default */ static void installBeforeLockObserver(Consumer<ReentrantLock> observer) {
        BEFORE_LOCK_OBSERVER.set(Objects.requireNonNull(observer, "observer"));
    }
    /**
     * Removes the calling-thread pre-lock observer, restoring uninstrumented operation.
     */
    /* default */ static void clearBeforeLockObserver() { BEFORE_LOCK_OBSERVER.remove(); }

    private static void observeBeforeLock(ReentrantLock lock) {
        Consumer<ReentrantLock> observer = BEFORE_LOCK_OBSERVER.get();
        if (observer != null) { observer.accept(lock); }
    }

    private static void forceCredentialDirectory(Path directory) throws IOException {
        DirectoryForceObserver observer = DIRECTORY_FORCE_OBSERVER.get();
        if (observer != null) { observer.beforeForce(directory); }
        PlatformFs.forceDirectory(directory);
    }

    private static IllegalStateException duplicate(PkiId credentialId, Throwable cause) {
        String message = "CREDENTIAL is write-once; already exists: " + FsUtil.safeId(credentialId);
        return cause == null ? new IllegalStateException(message) : new IllegalStateException(message, cause);
    }

    private static boolean isRegularFile(Path path) {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path);
    }

    /**
     * Encodes one bounded, versioned credential handoff intent.
     *
     * @param intent validated handoff state
     * @return newly allocated complete intent bytes
     * @throws NullPointerException if intent is null
     * @throws IOException if an intent field exceeds the wire bounds or encoding fails
     */
    /* default */ static byte[] encode(Intent intent) throws IOException {
        Objects.requireNonNull(intent, "intent");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            writeIntent(output, intent);
        }
        return bytes.toByteArray();
    }

    /**
     * Decodes exactly one versioned handoff intent and rejects trailing bytes.
     *
     * @param encoded complete intent bytes
     * @return validated recovered handoff state
     * @throws NullPointerException if encoded is null
     * @throws IOException if framing, fields, version or trailing data are invalid
     */
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

    /**
     * Closed persisted handoff states.
     */
    /* default */ enum State {
        /**
         * The transaction has prepared owned content but has not committed it.
         */
        PREPARED(1),
        /**
         * The transaction has a retained committed terminal outcome.
         */
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

    /**
     * Strict path-free and payload-free persisted handoff description.
     * @param state closed lifecycle state
     * @param credentialId exact credential identity
     * @param owner durable content owner receiving the handoff
     * @param storeId exact authoritative metadata store identity
     * @param contentId opaque durable content identity
     * @param encoding exact content representation encoding
     * @param length exact encoded content length in bytes
     * @param sha256 canonical lowercase SHA-256 hexadecimal content commitment
     * @param lifecycle durable content lifecycle classification
     */
    /* default */ record Intent(State state, PkiId credentialId, DurableContentOwner owner, String storeId, String contentId,
            Encoding encoding, long length, String sha256, DurableContentReference.Lifecycle lifecycle) {

        /**
         * Creates the strict path-free and payload-free persisted handoff description.
         *
         * @param state closed lifecycle state
         * @param credentialId exact credential identity
         * @param owner durable content owner receiving the handoff
         * @param storeId exact authoritative metadata store identity
         * @param contentId opaque durable content identity
         * @param encoding exact content representation encoding
         * @param length exact encoded content length in bytes
         * @param sha256 canonical lowercase SHA-256 hexadecimal content commitment
         * @param lifecycle durable content lifecycle classification
         * @throws NullPointerException if {@code state} is null; or if {@code credentialId} is null;
         * or if {@code owner} is null; or if {@code storeId} is null; or if {@code contentId} is
         * null; or if {@code encoding} is null; or if {@code sha256} is null; or if {@code
         * lifecycle} is null
         * @throws IllegalArgumentException if {@code
         * (!owner.equals(DurableContentOwner.credentialRecord(credentialId)) || lifecycle !=
         * DurableContentReference.Lifecycle.PERSISTED || length < 0L ||
         * !storeId.matches("[0-9a-f]{32}") ||
         * !contentId.matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
         * || !sha256.matches("[0-9a-f]{64}"))}
         */
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

        /**
         * Captures the credential identity, content coordinates and record ownership in a handoff intent.
         *
         * @param credential source credential with persisted content
         * @param state initial handoff phase
         * @return validated intent for that credential and phase
         * @throws NullPointerException if credential or state is null
         * @throws IllegalArgumentException if the content coordinates violate the intent format
         */
        /* default */ static Intent from(Credential credential, State state) {
            DurableContentReference reference = credential.content();
            return new Intent(state, credential.credentialId(),
                    DurableContentOwner.credentialRecord(credential.credentialId()), reference.storeId(),
                    reference.contentId(), reference.encoding(), reference.length(), reference.sha256(),
                    reference.lifecycle());
        }

        /**
         * Copies this intent with another handoff phase and identical ownership coordinates.
         *
         * @param next replacement phase
         * @return new intent retaining all credential and content coordinates
         * @throws NullPointerException if next is null
         */
        /* default */ Intent withState(State next) {
            return new Intent(next, credentialId, owner, storeId, contentId, encoding, length, sha256, lifecycle);
        }

        /**
         * Compares every stored content coordinate with a supplied durable reference.
         *
         * @param reference candidate content reference
         * @return true if store, identifier, encoding, length, digest and lifecycle match
         * @throws NullPointerException if reference is null
         */
        /* default */ boolean matches(DurableContentReference reference) {
            return storeId.equals(reference.storeId()) && contentId.equals(reference.contentId())
                    && encoding == reference.encoding() && length == reference.length()
                    && sha256.equals(reference.sha256()) && lifecycle == reference.lifecycle();
        }

        /**
         * Restores the exact content reference through the owning filesystem store.
         *
         * @param store store that must own the persisted coordinates
         * @return restored store-branded reference
         * @throws NullPointerException if store is null
         * @throws IllegalArgumentException if the coordinates belong to another store
         * @throws IOException if persisted content metadata fails validation
         */
        /* default */ DurableContentReference restore(FilesystemStagedContentStore store) throws IOException {
            return store.restoreReference(storeId, contentId, encoding, length, sha256, lifecycle);
        }
    }

    /**
     * Preserves the recovery requirement until the owning store installs its fence.
     */
    private static final class HandoffUnconfirmedException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final IOException failure;

        private HandoffUnconfirmedException(IOException failure) {
            super("Credential publication durability is unconfirmed", failure);
            this.failure = failure;
        }
    }

    /**
     * Marks a completed namespace move with unconfirmed directory durability.
     */
    private static final class PublishedException extends IOException {
        private static final long serialVersionUID = -8788329245365479704L;

        private PublishedException() {
            super("Credential record is published but directory durability is unconfirmed");
        }
    }
}
