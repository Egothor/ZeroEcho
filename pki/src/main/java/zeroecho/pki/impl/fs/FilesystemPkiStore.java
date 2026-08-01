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

import java.io.Closeable;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.impl.ProfileLifecycleFailure;
import zeroecho.pki.impl.ProfileLifecycleFailure.Code;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.TemporaryUniqueIndex;
import zeroecho.pki.spi.store.RevocationSnapshot;

/**
 * Filesystem-based reference implementation of {@link PkiStore}.
 *
 * <h2>Consistency and Atomicity Guarantees</h2>
 *
 * <p>
 * This store provides the following guarantees:
 * </p>
 *
 * <ul>
 * <li><strong>Atomic object replacement:</strong> writes of {@code current.bin}
 * are done via a write-to-temp + atomic move (best-effort {@code ATOMIC_MOVE},
 * with a documented fallback when not supported).</li>
 *
 * <li><strong>Write-once enforcement:</strong> objects stored under write-once
 * namespaces (credentials, requests, status objects, policy traces,
 * publications) are never overwritten. A second write to the same identifier
 * fails with {@link IllegalStateException}. This is intentional to surface
 * anomalous behavior for audit and incident analysis.
 *
 * <li><strong>Audit history for mutable entities:</strong> CA records and
 * profiles append history before updating {@code current.bin}. Revocation state
 * is instead one atomically replaced, internally ordered journal per
 * credential.</li>
 *
 * <li><strong>Deterministic behavior:</strong> filenames, ordering, and cleanup
 * semantics are deterministic. Cleanup occurs only during writes
 * ({@link FsHistoryPolicy.CleanupStrategy#ON_WRITE}).</li>
 *
 * <li><strong>Single-writer process lock:</strong> an exclusive file lock is
 * held for the lifetime of the instance. Multiple processes can be prevented
 * from concurrently modifying the same root.</li>
 * </ul>
 *
 * <h2>Security Notes</h2>
 *
 * <p>
 * This reference implementation stores domain objects through a closed,
 * current-version schema. It does not implement encryption at rest. It also
 * must not persist private key material; higher layers must respect the SPI
 * security requirements. Earlier pre-release formats are rejected rather than
 * migrated.
 * </p>
 *
 * <p>
 * Logging (JUL) never includes raw serialized bytes or sensitive payloads. Logs
 * are limited to object type, safe IDs, and file operation outcomes.
 * </p>
 */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity", "PMD.TooManyMethods" })
public final class FilesystemPkiStore implements PkiStore, Closeable {

    private static final Logger LOG = Logger.getLogger(FilesystemPkiStore.class.getName());

    /* package */ static final String CURRENT_STORE_VERSION = "v3";
    private static final String SIGN_RECORD_NAMESPACE = "io.zeroecho.pki.signing-record";
    private static final String SIGN_OWNER_NAMESPACE = "io.zeroecho.pki.signing-owner";
    private static final String STATUS_RECORD_NAMESPACE = "io.zeroecho.pki.status-object-record";
    private static final String STATUS_OWNER_NAMESPACE = "io.zeroecho.pki.status-object-owner";
    private static final int CURRENT_SIGN_RECORD_VERSION = 2;
    private static final int SIGN_OWNER_VALUE_VERSION = 1;
    private static final int STATUS_OWNER_VALUE_VERSION = 1;
    private static final int METADATA_TRANSFER_BUFFER_BYTES = 16 * 1024;
    private static final ThreadLocal<StatusCommitFaultPoint> STATUS_COMMIT_FAULT = new ThreadLocal<>();
    private static final String SIGN_FINGERPRINT_PREFIX = "signfp:v1:";
    private static final int SIGN_FINGERPRINT_HEX_LENGTH = 64;
    private static final long INITIAL_FENCE = 0L;
    private static final String STORE_OWNERSHIP_UNAVAILABLE = "Filesystem store ownership unavailable: code=STORE_ALREADY_OPEN";

    private final FsPkiStoreOptions options;
    private final FsPaths paths;
    private final AtomicLong historySeq;
    private final Clock clock;
    private final String signingNamespace;
    private final AtomicLong signingTimeWatermark;
    private final ReentrantLock signingTimeLock;
    private final ConcurrentMap<PkiId, SignLockEntry> signLocks;
    private final ConcurrentMap<PkiId, RevocationLockEntry> revocationLocks;
    private final ConcurrentMap<String, ProfileLockEntry> profileLocks;
    private final AtomicBoolean durabilityUncertain;
    private final FilesystemStagedContentStore stagedContent;
    private final CredentialContentTransaction credentialContentTransactions;
    private final PosixTransactionalMetadataStore metadataStore;

    private final StoreOwnership ownership;

    /**
     * Opens or creates a filesystem PKI store rooted at {@code root}.
     *
     * @param root    store root directory
     * @param options implementation options
     * @throws IllegalArgumentException if inputs are null
     * @throws IllegalStateException    if the store cannot be opened or locked
     */
    public FilesystemPkiStore(final Path root, final FsPkiStoreOptions options) {
        this(root, options, Clock.systemUTC());
    }

    /**
     * Opens or creates a filesystem store with an explicit authoritative clock.
     *
     * @param root    store root directory
     * @param options store options
     * @param clock   authoritative signing workflow clock
     * @throws IllegalArgumentException if an argument is {@code null}
     * @throws IllegalStateException    if the store cannot be opened or is already
     *                                  owned by another store instance or process
     */
    // StoreOwnership transfers to this store on success and remains open until
    // close();
    // try-with-resources here would release process ownership at constructor
    // return.
    @SuppressWarnings("PMD.CloseResource")
    public FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock) {
        this.options = Objects.requireNonNull(options, "options");
        Objects.requireNonNull(root, "root");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.signLocks = new ConcurrentHashMap<>();
        this.revocationLocks = new ConcurrentHashMap<>();
        this.profileLocks = new ConcurrentHashMap<>();
        this.durabilityUncertain = new AtomicBoolean();
        this.signingTimeLock = new ReentrantLock();
        this.paths = new FsPaths(root);

        StoreOwnership acquiredOwnership;
        try {
            FsOperations.ensureDir(root);
            FsOperations.ensureDir(this.paths.lockFile().getParent());
            acquiredOwnership = StoreOwnership.acquire(this.paths.lockFile());
        } catch (IOException e) {
            throw new IllegalStateException("failed to open filesystem store at " + root, e);
        }

        boolean ownershipTransferred = false;
        PosixTransactionalMetadataStore openedMetadata = null;
        try {
            ensureVersionFile();
            this.signingNamespace = ensureSigningNamespace();
            this.stagedContent = new FilesystemStagedContentStore(this.paths.stagedContentRoot(),
                    this.signingNamespace);
            FsOperations.ensureDir(this.paths.transactionalMetadataLog().getParent());
            openedMetadata = openMetadataStore();
            this.metadataStore = openedMetadata;
            this.stagedContent.bindTransactionalOwnership(this::findTransactionalOwners);
            this.credentialContentTransactions = new CredentialContentTransaction(this.paths, this.stagedContent);
            this.signingTimeWatermark = new AtomicLong(loadSigningTimeWatermark());
            this.historySeq = new AtomicLong(0L);
            recoverStagedContent();

            LOG.log(Level.INFO, "running in {0}", root);
            this.ownership = acquiredOwnership;
            ownershipTransferred = true;
        } catch (IOException e) {
            throw new IllegalStateException("failed to open filesystem store at " + root, e);
        } finally {
            if (!ownershipTransferred) {
                if (openedMetadata != null) {
                    try {
                        closeMetadataAfterFailedOpen(openedMetadata);
                    } catch (IOException closeFailure) {
                        LOG.log(Level.WARNING, "Metadata-store cleanup failed during initialization");
                    }
                }
                acquiredOwnership.closeSilently();
            }
        }
    }

    private static void closeMetadataAfterFailedOpen(PosixTransactionalMetadataStore openedMetadata)
            throws IOException {
        openedMetadata.close();
    }

    private PosixTransactionalMetadataStore openMetadataStore() throws IOException {
        Path log = paths.transactionalMetadataLog();
        PosixTransactionalMetadataStore opened = Files.exists(log)
                ? PosixTransactionalMetadataStore.open(log)
                : PosixTransactionalMetadataStore.create(log, new MetadataStoreId(signingNamespace));
        if (!opened.id().equals(new MetadataStoreId(signingNamespace))) {
            try {
                opened.close();
            } catch (IOException closeFailure) {
                throw new IOException("Metadata store authority mismatch", closeFailure);
            }
            throw new IOException("Metadata store authority mismatch");
        }
        return opened;
    }

    private Set<DurableContentOwner> findSigningOwner(DurableContentReference reference) throws IOException {
        Set<DurableContentOwner> owners = new HashSet<>();
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(SIGN_OWNER_NAMESPACE),
                        CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                MetadataSnapshot.Record owner = next.orElseThrow();
                try (owner) {
                    Optional<DurableContentOwner> matched = matchingSigningOwner(owner, reference);
                    matched.ifPresent(owners::add);
                }
            }
            return Set.copyOf(owners);
        }
    }

    private Set<DurableContentOwner> findTransactionalOwners(DurableContentReference reference) throws IOException {
        Set<DurableContentOwner> owners = new HashSet<>(findSigningOwner(reference));
        for (StoredStatus stored : listStoredStatuses()) {
            if (reference.equals(stored.status().content())) {
                owners.add(new DurableContentOwner(DurableContentOwner.Category.STATUS_OBJECT_RECORD,
                        stored.status().statusObjectId().value()));
            }
        }
        return Set.copyOf(owners);
    }

    private Optional<DurableContentOwner> matchingSigningOwner(MetadataSnapshot.Record owner,
            DurableContentReference reference)
            throws IOException {
        PkiId submissionId = new PkiId(owner.key().key());
        if (reference.equals(decodeSigningOwner(owner, submissionId))) {
            return Optional.of(DurableContentOwner.signingOperation(submissionId));
        }
        return Optional.empty();
    }

    @Override
    public StagedContentStore stagedContent() {
        return stagedContent;
    }

    private void recoverStagedContent() throws IOException {
        credentialContentTransactions.recover();
        List<StoredStatus> statuses = listStoredStatuses();
        try (TemporaryUniqueIndex retained = stagedContent.beginUniqueIndex();
                TemporaryUniqueIndex retainedOwners = stagedContent.beginOwnerIndex();
                TemporaryUniqueIndex transactionalOwners = stagedContent.beginUniqueIndex()) {
            try {
                addPersistedCredentialReferences(retained, retainedOwners);
                addTransactionalStatusOwnership(transactionalOwners, statuses);
                addPendingSigningReferences(retained);
                stagedContent.recoverContent(retained, retainedOwners, transactionalOwners);
            } catch (IllegalStateException | PkiException malformedDurableState) {
                // Recovery cannot prove abandonment while durable metadata is
                // corrupt. Preserve content so the normal owning subsystem can
                // report the authoritative corruption without destructive loss.
                LOG.log(Level.WARNING, "Staged-content reclamation skipped: code=DURABLE_METADATA_INVALID");
            }
        }
    }

    private void addPersistedCredentialReferences(TemporaryUniqueIndex retained, TemporaryUniqueIndex retainedOwners)
            throws IOException {
        Path root = paths.root().resolve("credentials").resolve("by-id");
        if (!Files.isDirectory(root)) {
            return;
        }
        try (Stream<Path> pathsStream = Files.list(root)) {
            java.util.Iterator<Path> iterator = pathsStream
                    .filter(path -> Files.isRegularFile(path) && path.getFileName().toString().endsWith(".bin"))
                    .iterator();
            while (iterator.hasNext()) {
                Credential credential = FsCodec.decode(FsCodec.CREDENTIAL, FsOperations.readAll(iterator.next()),
                        stagedContent);
                addRetained(retained, credential.content());
                DurableContentOwner owner = DurableContentOwner.credentialRecord(credential.credentialId());
                retainedOwners.add(owner.canonicalForm().getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    private static void addTransactionalStatusOwnership(TemporaryUniqueIndex transactionalOwners,
            List<StoredStatus> statuses)
            throws IOException {
        for (StoredStatus stored : statuses) {
            addRetained(transactionalOwners, stored.status().content());
        }
    }

    private void addPendingSigningReferences(TemporaryUniqueIndex retained) throws IOException {
        for (StoredSign stored : listStoredSigns()) {
            if (stored.record().state() != SignWorkflowStore.State.RETIRED) {
                addRetained(retained, stored.reference().orElseThrow());
            }
        }
    }

    private static void addRetained(TemporaryUniqueIndex retained, DurableContentReference reference)
            throws IOException {
        retained.add(reference.contentId().getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Exports a snapshot of this store as of time {@code at} into
     * {@code targetRoot}.
     *
     * <p>
     * This method is an implementation-only feature. It does not modify the current
     * store; it clones a new store layout and reconstructs {@code current.bin} for
     * history-tracked entities. Standalone credential authority is reconstructed by
     * streaming validated live-source credential content into new target-owned
     * references before publishing selected ID-only CA records. The signing namespace,
     * monotonic signing-time watermark, and authoritative signing workflow records
     * are safety metadata:
     * their current export-time values are copied regardless of {@code at}, because
     * historical reconstruction could permit identifier reuse or lose a terminal
     * result.
     * </p>
     *
     * @param targetRoot new store root to create/populate
     * @param at         snapshot time (inclusive, "latest &lt;= at")
     * @throws IllegalArgumentException if inputs are null
     * @throws IllegalStateException    if export fails
     */
    public void exportSnapshot(final Path targetRoot, final Instant at) {
        requireStoreUsable();
        Objects.requireNonNull(targetRoot, "targetRoot");
        Objects.requireNonNull(at, "at");
        new FsSnapshotExporter(this.options).exportSnapshot(this, targetRoot, at);
    }

    /* default */ Path snapshotRoot() {
        return paths.root();
    }

    /* default */ Set<String> snapshotNonCredentialContentIds() {
        requireStoreUsable();
        Set<String> contentIds = new HashSet<>();
        for (StoredSign stored : listStoredSigns()) {
            stored.reference().map(DurableContentReference::contentId).ifPresent(contentIds::add);
        }
        return Set.copyOf(contentIds);
    }

    /* default */ List<StatusObject> snapshotStatusObjects() {
        requireStoreUsable();
        return listStoredStatuses().stream().map(StoredStatus::status).toList();
    }

    @Override
    public void putCa(final CaRecord record) {
        requireStoreUsable();
        Objects.requireNonNull(record, "record");
        validateCaCredentialReferences(record);
        PkiId caId = record.caId();
        Path current = this.paths.caCurrent(caId);

        writeWithHistory(this.paths.caHistoryDir(caId), current, FsCodec.encode(FsCodec.CA_RECORD, record),
                this.options.caHistoryPolicy(), "CA", FsUtil.safeId(caId));
    }

    @Override
    public Optional<CaRecord> getCa(final PkiId caId) {
        requireStoreUsable();
        Objects.requireNonNull(caId, "caId");
        Path p = this.paths.caCurrent(caId);
        return readOptional(p, FsCodec.CA_RECORD).map(this::validateCaCredentialReferences);
    }

    @Override
    public List<CaRecord> listCas() {
        requireStoreUsable();
        Path casRoot = this.paths.root().resolve("cas").resolve("by-id");
        return listCurrentRecords(casRoot, FsCodec.CA_RECORD).stream().map(this::validateCaCredentialReferences)
                .toList();
    }

    @Override
    public void putCredential(final Credential credential) {
        requireStoreUsable();
        Objects.requireNonNull(credential, "credential");
        credentialContentTransactions.put(credential);
    }

    @Override
    public Optional<Credential> getCredential(final PkiId credentialId) {
        requireStoreUsable();
        Objects.requireNonNull(credentialId, "credentialId");
        Path path = this.paths.credentialPath(credentialId);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        try {
            Credential credential = FsCodec.decode(FsCodec.CREDENTIAL, FsOperations.readAll(path), stagedContent);
            return Optional.of(credentialContentTransactions.validateLoaded(credentialId, credential));
        } catch (IOException failure) {
            throw new IllegalStateException("Credential read failed", failure);
        }
    }

    private CaRecord validateCaCredentialReferences(CaRecord record) {
        for (PkiId credentialId : record.credentialIds()) {
            if (getCredential(credentialId).isEmpty()) {
                throw new IllegalStateException("CA credential reference is missing");
            }
        }
        return record;
    }

    @Override
    public void putRequest(final ParsedCertificationRequest request) {
        requireStoreUsable();
        Objects.requireNonNull(request, "request");
        PkiId id = request.requestId();
        writeOnce(this.paths.requestPath(id), FsCodec.encode(FsCodec.PARSED_REQUEST, request), "REQUEST",
                FsUtil.safeId(id));
    }

    @Override
    public Optional<ParsedCertificationRequest> getRequest(final PkiId requestId) {
        requireStoreUsable();
        Objects.requireNonNull(requestId, "requestId");
        return readOptional(this.paths.requestPath(requestId), FsCodec.PARSED_REQUEST);
    }

    @Override
    // Store failures are intentionally replaced by one stable redacted boundary.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    public RevocationJournal transitionRevocation(final RevocationCommand command, final Instant transitionTime) {
        requireStoreUsable();
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(transitionTime, "transitionTime");
        PkiId credentialId = command.credentialId();
        RevocationLockEntry lock = acquireRevocationLock(credentialId);
        try {
            Optional<Credential> credential;
            try {
                credential = getCredential(credentialId);
            } catch (RuntimeException failure) {
                throw corruptRevocationState();
            }
            if (credential.isEmpty()) {
                throw new PkiException("Revocation target unavailable: code=REVOCATION_CREDENTIAL_NOT_FOUND");
            }
            Optional<RevocationJournal> current;
            try {
                current = readRevocationJournal(credentialId);
            } catch (RuntimeException failure) {
                throw corruptRevocationState();
            }
            RevocationJournal updated = appendRevocation(current, credentialId, command, transitionTime);
            try {
                FsOperations.writeAtomicStrict(paths.revocationJournal(credentialId),
                        FsCodec.encode(FsCodec.REVOCATION_JOURNAL, updated));
            } catch (FsOperations.DurabilityUncertainException failure) {
                durabilityUncertain.set(true);
                throw new PkiException("Revocation durability unconfirmed: code=REVOCATION_DURABILITY_UNCONFIRMED");
            } catch (IOException ex) {
                throw new PkiException("Revocation persistence failed: code=REVOCATION_PERSIST_FAILED");
            }
            return updated;
        } finally {
            releaseRevocationLock(credentialId, lock);
        }
    }

    @Override
    public Optional<RevocationJournal> getRevocationJournal(final PkiId credentialId) {
        requireStoreUsable();
        Objects.requireNonNull(credentialId, "credentialId");
        return readRevocationJournal(credentialId);
    }

    @Override
    // Snapshot failures are intentionally replaced by one stable redacted boundary.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public RevocationSnapshot openRevocationSnapshot() {
        requireStoreUsable();
        Path root = this.paths.root().resolve("revocations").resolve("by-credential");
        String snapshotId = UUID.randomUUID().toString();
        Path snapshotRoot = paths.revocationSnapshotRoot().resolve(snapshotId);
        long count = 0L;
        try {
            Files.createDirectories(snapshotRoot);
            if (Files.isDirectory(root)) {
                try (Stream<Path> journals = Files.walk(root)) {
                    java.util.Iterator<Path> iterator = journals
                            .filter(path -> Files.isRegularFile(path)
                                    && "journal.bin".equals(path.getFileName().toString()))
                            .iterator();
                    while (iterator.hasNext()) {
                        Files.copy(iterator.next(), snapshotRoot.resolve(Long.toUnsignedString(count) + ".bin"));
                        count = Math.addExact(count, 1L);
                    }
                }
            }
            return new FilesystemRevocationSnapshot(snapshotId, snapshotRoot, count);
        } catch (IOException ex) {
            throw corruptRevocationState();
        }
    }

    @Override
    public void putStatusObject(final StatusObject object) {
        requireStoreUsable();
        Objects.requireNonNull(object, "object");
        byte[] encoded = validateStatusObject(object);
        DurableContentReference reference = object.content();
        try (FilesystemStagedContentStore.TransactionalReservation reservation =
                stagedContent.reserveTransactionalPublication(reference)) {
            validateStatusContent(reference);
            MetadataCommitResult result = createStatusMetadata(object, encoded);
            if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                return;
            }
            if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
                reservation.preserveUntilRecovery();
                durabilityUncertain.set(true);
                throw new PkiException("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
            }
            throw new IllegalStateException("Status object already exists");
        } catch (IOException exception) {
            throw new IllegalStateException("Status object content is invalid", exception);
        }
    }

    @Override
    public Optional<StatusObject> getStatusObject(final PkiId statusObjectId) {
        requireStoreUsable();
        Objects.requireNonNull(statusObjectId, "statusObjectId");
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> record = snapshot.get(statusRecordKey(statusObjectId));
            if (record.isEmpty()) {
                Optional<MetadataSnapshot.Record> owner = snapshot.get(statusOwnerKey(statusObjectId));
                if (owner.isPresent()) {
                    try (MetadataSnapshot.Record ignored = owner.orElseThrow()) {
                        throw new IllegalStateException("Status owner exists without its record");
                    }
                }
                return Optional.empty();
            }
            return Optional.of(decodeStoredStatus(snapshot, record.orElseThrow()).status());
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to read authoritative status object", exception);
        }
    }

    @Override
    public List<StatusObject> listStatusObjects(final PkiId issuerCaId) {
        requireStoreUsable();
        Objects.requireNonNull(issuerCaId, "issuerCaId");

        List<StatusObject> out = new ArrayList<>();
        for (StoredStatus stored : listStoredStatuses()) {
            StatusObject o = stored.status();
            if (issuerCaId.equals(o.issuerCaId())) {
                out.add(o);
            }
        }
        return out;
    }

    @Override
    public void putPublicationRecord(final PublicationRecord record) {
        requireStoreUsable();
        Objects.requireNonNull(record, "record");
        PkiId id = record.publicationId();
        writeOnce(this.paths.publicationPath(id), FsCodec.encode(FsCodec.PUBLICATION, record), "PUBLICATION",
                FsUtil.safeId(id));
    }

    @Override
    public List<PublicationRecord> listPublicationRecords() {
        requireStoreUsable();
        Path byId = this.paths.root().resolve("publications").resolve("by-id");
        return listBinaryFiles(byId, FsCodec.PUBLICATION);
    }

    @Override
    // Persistence causes may contain filesystem data and are intentionally
    // redacted.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public ImportedCertificateProfileVersion importProfileVersion(final ImportedCertificateProfileVersion version) {
        requireStoreUsable();
        Objects.requireNonNull(version, "version");
        String profileId = version.reference().profileId();
        ProfileLockEntry lock = acquireProfileLock(profileId);
        try {
            ValidatedImportedProfile.validate(version, profileId, version.reference().profileVersion());
            Path target = paths.profileVersion(profileId, version.reference().profileVersion());
            if (Files.exists(target)) {
                ImportedCertificateProfileVersion existing = decodeProfileVersion(target, profileId,
                        version.reference().profileVersion());
                if (!existing.reference().equals(version.reference())) {
                    throw new ProfileLifecycleFailure(Code.PROFILE_VERSION_CONFLICT);
                }
                return existing;
            }
            requireConsistentProfileKind(version);
            try {
                FsOperations.writeNewAtomicStrict(target, FsCodec.encode(FsCodec.PROFILE_VERSION, version));
                return version;
            } catch (FileAlreadyExistsException conflict) {
                ImportedCertificateProfileVersion existing = decodeProfileVersion(target, profileId,
                        version.reference().profileVersion());
                if (!existing.reference().equals(version.reference())) {
                    throw new ProfileLifecycleFailure(Code.PROFILE_VERSION_CONFLICT);
                }
                return existing;
            } catch (FsOperations.DurabilityUncertainException failure) {
                durabilityUncertain.set(true);
                throw new ProfileLifecycleFailure(Code.PROFILE_DURABILITY_UNCONFIRMED);
            } catch (IOException failure) {
                throw new ProfileLifecycleFailure(Code.PROFILE_IMPORT_FAILED);
            }
        } finally {
            releaseProfileLock(profileId, lock);
        }
    }

    private void requireConsistentProfileKind(ImportedCertificateProfileVersion candidate) {
        for (ImportedCertificateProfileVersion existing : listProfileVersions(candidate.reference().profileId())) {
            if (existing.definition().certificateType() != candidate.definition().certificateType()) {
                throw new ProfileLifecycleFailure(Code.PROFILE_KIND_CONFLICT);
            }
        }
    }

    @Override
    public Optional<ImportedCertificateProfileVersion> getProfileVersion(final String profileId,
            final long profileVersion) {
        requireStoreUsable();
        requireProfileIdentity(profileId, profileVersion);
        Path path = paths.profileVersion(profileId, profileVersion);
        return Files.exists(path) ? Optional.of(decodeProfileVersion(path, profileId, profileVersion))
                : Optional.empty();
    }

    @Override
    // Filesystem failures are normalized to the stable store failure code.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public List<ImportedCertificateProfileVersion> listProfileVersions(final String profileId) {
        requireStoreUsable();
        requireProfileIdentity(profileId, 1L);
        Path directory = paths.profileVersionsDir(profileId);
        if (!Files.isDirectory(directory)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(directory)) {
            List<ImportedCertificateProfileVersion> versions = new ArrayList<>();
            for (Path file : files.filter(Files::isRegularFile)
                    .sorted(Comparator.comparingLong(FilesystemPkiStore::profileVersionFromPath)).toList()) {
                long version = profileVersionFromPath(file);
                versions.add(decodeProfileVersion(file, profileId, version));
            }
            return List.copyOf(versions);
        } catch (IOException | SecurityException failure) {
            throw new ProfileLifecycleFailure(Code.PROFILE_STORE_FAILURE);
        }
    }

    @Override
    // Persistence causes may contain filesystem data and are intentionally
    // redacted.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public CertificateProfileRef activateProfile(final String profileId, final long profileVersion) {
        requireStoreUsable();
        requireProfileIdentity(profileId, profileVersion);
        ProfileLockEntry lock = acquireProfileLock(profileId);
        try {
            ImportedCertificateProfileVersion version = getProfileVersion(profileId, profileVersion)
                    .orElseThrow(() -> new ProfileLifecycleFailure(Code.PROFILE_VERSION_NOT_FOUND));
            CertificateProfileRef reference = version.reference();
            Optional<CertificateProfileRef> current = readActiveProfileRef(profileId);
            if (current.filter(reference::equals).isPresent()) {
                return reference;
            }
            try {
                FsOperations.writeAtomicStrict(paths.profileActive(profileId),
                        FsCodec.encode(FsCodec.ACTIVE_PROFILE_REF, reference));
                return reference;
            } catch (FsOperations.DurabilityUncertainException failure) {
                durabilityUncertain.set(true);
                throw new ProfileLifecycleFailure(Code.PROFILE_DURABILITY_UNCONFIRMED);
            } catch (IOException failure) {
                throw new ProfileLifecycleFailure(Code.PROFILE_ACTIVATION_FAILED);
            }
        } finally {
            releaseProfileLock(profileId, lock);
        }
    }

    @Override
    public Optional<CertificateProfileRef> getActiveProfileRef(final String profileId) {
        requireStoreUsable();
        requireProfileIdentity(profileId, 1L);
        return readValidatedActiveProfile(profileId).map(validated -> validated.version().reference());
    }

    @Override
    public ActiveCertificateProfile requireActiveProfile(final String profileId) {
        requireStoreUsable();
        requireProfileIdentity(profileId, 1L);
        ValidatedImportedProfile validated = readValidatedActiveProfile(profileId)
                .orElseThrow(() -> new ProfileLifecycleFailure(Code.PROFILE_NOT_ACTIVE));
        ImportedCertificateProfileVersion version = validated.version();
        return new ActiveCertificateProfile(version.reference(), version.definition());
    }

    @Override
    public void putPolicyTrace(final PolicyTrace trace) {
        requireStoreUsable();
        Objects.requireNonNull(trace, "trace");
        PkiId id = trace.decisionId();
        writeOnce(this.paths.policyTracePath(id), FsCodec.encode(FsCodec.POLICY_TRACE, trace), "POLICY_TRACE",
                FsUtil.safeId(id));
    }

    @Override
    public Optional<PolicyTrace> getPolicyTrace(final PkiId decisionId) {
        requireStoreUsable();
        Objects.requireNonNull(decisionId, "decisionId");
        return readOptional(this.paths.policyTracePath(decisionId), FsCodec.POLICY_TRACE);
    }

    // -------------------------------------------------------------------------
    // Workflow continuation state (orchestration)
    // -------------------------------------------------------------------------

    @Override
    public void putWorkflowState(final WorkflowStateRecord record) {
        requireStoreUsable();
        Objects.requireNonNull(record, "record");

        PkiId opId = record.opId();
        Path current = this.paths.workflowCurrent(opId);

        // Never log payload; writeWithHistory logs only type + safe identifiers.
        writeWithHistory(this.paths.workflowHistoryDir(opId), current, FsCodec.encode(FsCodec.WORKFLOW_STATE, record),
                this.options.workflowHistoryPolicy(), "WORKFLOW", FsUtil.safeId(opId));
    }

    @Override
    public Optional<WorkflowStateRecord> getWorkflowState(final PkiId opId) {
        requireStoreUsable();
        Objects.requireNonNull(opId, "opId");
        return readOptional(this.paths.workflowCurrent(opId), FsCodec.WORKFLOW_STATE);
    }

    @Override
    public void deleteWorkflowState(final PkiId opId) {
        requireStoreUsable();
        Objects.requireNonNull(opId, "opId");
        Path current = this.paths.workflowCurrent(opId);

        try {
            Files.deleteIfExists(current);
        } catch (IOException e) {
            throw new IllegalStateException("failed to delete workflow state opId=" + FsUtil.safeId(opId), e);
        }
    }

    @Override
    public List<WorkflowStateRecord> listWorkflowStates() {
        requireStoreUsable();
        // List by operation directory (workflows/by-op/<opId>/current.bin)
        return listCurrentRecords(this.paths.workflowRoot(), FsCodec.WORKFLOW_STATE);
    }

    @Override
    public Instant signingNow() {
        requireStoreUsable();
        signingTimeLock.lock();
        try {
            long monotonic = Math.max(signingTimeWatermark.get(), clock.instant().toEpochMilli());
            persistSigningTimeWatermark(monotonic);
            signingTimeWatermark.set(monotonic);
            return Instant.ofEpochMilli(monotonic);
        } finally {
            signingTimeLock.unlock();
        }
    }

    @Override
    public String signingNamespace() {
        requireStoreUsable();
        return signingNamespace;
    }

    @Override
    public Duration signingHorizon() {
        requireStoreUsable();
        return options.signingOperationHorizon();
    }

    @Override
    public Duration signingPermittedSkew() {
        requireStoreUsable();
        return options.signingIdPermittedSkew();
    }

    @Override
    public SignWorkflowStore.CreateResult createSignIntent(SignWorkflowStore.Record intent) {
        requireStoreUsable();
        Objects.requireNonNull(intent, "intent");
        SignLockEntry lock = acquireSignLock(intent.submissionId());
        try {
            SigningSubmissionId parsed = SigningSubmissionId.parse(intent.submissionId());
            if (!intent.namespace().startsWith(signingNamespace + ".")) {
                throw new IllegalArgumentException("Signing intent belongs to a different store namespace");
            }
            parsed.validate(intent.namespace(), signingNow(), options.signingOperationHorizon(),
                    options.signingIdPermittedSkew());
            if (!parsed.createdAt().equals(intent.createdAt()) || intent.deadline().isBefore(intent.createdAt())
                    || intent.deadline().isAfter(parsed.createdAt().plus(options.signingOperationHorizon()))) {
                throw new IllegalArgumentException("Signing intent timestamps do not match its stable identifier");
            }
            if (intent.state() != SignWorkflowStore.State.INTENT || intent.revision() != 0L || intent.fence() != 0L
                    || intent.leaseUntil().isPresent() || intent.result().isPresent()) {
                throw new IllegalArgumentException("New signing intent has invalid initial state");
            }
            Optional<SignWorkflowStore.Record> existing = readSignRecord(intent.submissionId());
            if (existing.isPresent()) {
                return existing.get().fingerprint().equals(intent.fingerprint())
                        ? SignWorkflowStore.CreateResult.ATTACHED
                        : SignWorkflowStore.CreateResult.CONFLICT;
            }
            PkiSigningBus.SignContinuation continuation = PkiSigningBus.SignContinuation.decode(intent.request(),
                    stagedContent);
            DurableContentReference reference = continuation.content();
            MetadataCommitResult result;
            try (FilesystemStagedContentStore.TransactionalReservation ignoredReservation =
                            stagedContent.reserveTransactionalPublication(reference);
                    RepeatableContent ignoredContent = stagedContent.openContent(reference)) {
                stagedContent.restoreReference(reference.storeId(), reference.contentId(), reference.encoding(),
                        reference.length(), reference.sha256(), reference.lifecycle());
                result = createSignMetadata(intent, reference);
            } catch (IOException exception) {
                retireFailedSigningPublication(reference);
                throw new PkiException("Signing staged content is invalid: code=CONTENT_INTEGRITY_FAILED", exception);
            } catch (PkiException | IllegalArgumentException | IllegalStateException exception) {
                if (!durabilityUncertain.get()) {
                    retireFailedSigningPublication(reference);
                }
                throw exception;
            }
            if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                return SignWorkflowStore.CreateResult.CREATED;
            }
            retireFailedSigningPublication(reference);
            return SignWorkflowStore.CreateResult.CONFLICT;
        } finally {
            releaseSignLock(intent.submissionId(), lock);
        }
    }

    private void retireFailedSigningPublication(DurableContentReference reference) {
        try {
            stagedContent.retireUnownedContent(reference);
        } catch (IOException cleanupFailure) {
            LOG.log(Level.WARNING, "Failed signing publication cleanup was incomplete");
        }
    }

    @Override
    public Optional<SignWorkflowStore.Record> getSignRecord(PkiId submissionId) {
        requireStoreUsable();
        Objects.requireNonNull(submissionId, "submissionId");
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            return readSignRecord(submissionId);
        } finally {
            releaseSignLock(submissionId, lock);
        }
    }

    @Override
    public List<SignWorkflowStore.Record> listSignRecords() {
        requireStoreUsable();
        return listStoredSigns().stream().map(StoredSign::record).toList();
    }

    private List<StoredSign> listStoredSigns() {
        List<StoredSign> storedSigns = new ArrayList<>();
        Set<String> recordIdentities = new HashSet<>();
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(SIGN_RECORD_NAMESPACE),
                    CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    StoredSign stored = decodeStoredSign(snapshot, next.orElseThrow());
                    storedSigns.add(stored);
                    recordIdentities.add(stored.record().submissionId().value());
                }
            }
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(SIGN_OWNER_NAMESPACE),
                    CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    if (!recordIdentities.contains(next.orElseThrow().key().key())) {
                        throw new IllegalStateException("Signing owner exists without its record");
                    }
                }
            }
            return List.copyOf(storedSigns);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to list authoritative signing records", ex);
        }
    }

    private List<StoredStatus> listStoredStatuses() {
        List<StoredStatus> statuses = new ArrayList<>();
        Set<String> recordIdentities = new HashSet<>();
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(STATUS_RECORD_NAMESPACE),
                    CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    StoredStatus stored = decodeStoredStatus(snapshot, next.orElseThrow());
                    statuses.add(stored);
                    recordIdentities.add(stored.status().statusObjectId().value());
                }
            }
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(STATUS_OWNER_NAMESPACE),
                    CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record owner = next.orElseThrow()) {
                        if (!recordIdentities.contains(owner.key().key())) {
                            throw new IllegalStateException("Status owner exists without its record");
                        }
                    }
                }
            }
            return List.copyOf(statuses);
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to list authoritative status objects", exception);
        }
    }

    private StoredStatus decodeStoredStatus(MetadataSnapshot snapshot, MetadataSnapshot.Record storedRecord)
            throws IOException {
        try (storedRecord) {
            StatusObject status = FsCodec.decode(FsCodec.STATUS_OBJECT, readMetadataValue(storedRecord),
                    stagedContent);
            PkiId statusId = status.statusObjectId();
            if (!statusRecordKey(statusId).equals(storedRecord.key())) {
                throw new IOException("Status record metadata key mismatch");
            }
            validateStatusObject(status);
            Optional<MetadataSnapshot.Record> storedOwner = snapshot.get(statusOwnerKey(statusId));
            try (MetadataSnapshot.Record owner = storedOwner.orElseThrow(
                    () -> new IOException("Status record owner edge is missing"))) {
                DurableContentReference reference = decodeStatusOwner(owner, statusId);
                if (!reference.equals(status.content())) {
                    throw new IOException("Status record owner reference mismatch");
                }
                validateStatusContent(reference);
                return new StoredStatus(status, storedRecord.recordRevision(), owner.recordRevision());
            }
        }
    }

    private byte[] validateStatusObject(StatusObject object) {
        DurableContentReference reference = object.content();
        if (!stagedContent.contentStoreId().equals(reference.storeId())
                || reference.lifecycle() != DurableContentReference.Lifecycle.PERSISTED) {
            throw new IllegalArgumentException("Status content reference is not persistent store authority");
        }
        byte[] encoded = FsCodec.encode(FsCodec.STATUS_OBJECT, object);
        StatusObject canonical = FsCodec.decode(FsCodec.STATUS_OBJECT, encoded, stagedContent);
        if (!object.statusObjectId().equals(canonical.statusObjectId())
                || !Arrays.equals(encoded, FsCodec.encode(FsCodec.STATUS_OBJECT, canonical))) {
            throw new IllegalArgumentException("Status object is not canonical");
        }
        return encoded;
    }

    private void validateStatusContent(DurableContentReference reference) throws IOException {
        stagedContent.restoreReference(reference.storeId(), reference.contentId(), reference.encoding(),
                reference.length(), reference.sha256(), reference.lifecycle());
        try (RepeatableContent content = stagedContent.openContent(reference);
                InputStream input = content.openStream()) {
            byte[] buffer = new byte[METADATA_TRANSFER_BUFFER_BYTES];
            while (true) {
                int count = input.read(buffer);
                if (count < 0) {
                    return;
                }
                if (count == 0) {
                    throw new IOException("Status content validation made no progress");
                }
            }
        }
    }

    private MetadataCommitResult createStatusMetadata(StatusObject status, byte[] encoded) throws IOException {
        PkiId statusId = status.statusObjectId();
        try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
            transaction.create(statusRecordKey(statusId), byteContent(encoded), CancellationSignal.NONE);
            transaction.create(statusOwnerKey(statusId),
                    byteContent(encodeStatusOwner(statusId, status.content())), CancellationSignal.NONE);
            if (STATUS_COMMIT_FAULT.get() == StatusCommitFaultPoint.BEFORE_COMMIT) {
                throw new IOException("Injected status commit failure");
            }
            MetadataCommitResult result = transaction.commit();
            if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED
                    && STATUS_COMMIT_FAULT.get() == StatusCommitFaultPoint.AFTER_COMMIT_AS_UNKNOWN) {
                return new MetadataCommitResult(result.transactionId(), MetadataCommitResult.Outcome.UNKNOWN,
                        OptionalLong.empty(), Optional.empty());
            }
            return result;
        }
    }

    /* package */ static void installStatusCommitFault(StatusCommitFaultPoint point) {
        STATUS_COMMIT_FAULT.set(Objects.requireNonNull(point, "point"));
    }

    /* package */ static void clearStatusCommitFault() {
        STATUS_COMMIT_FAULT.remove();
    }

    /** Test-only status-publication boundary; never part of production API. */
    /* default */
    enum StatusCommitFaultPoint {
        /** Fails after admission but before the metadata commit attempt. */
        BEFORE_COMMIT,
        /** Reports uncertainty only after a real durable commit. */
        AFTER_COMMIT_AS_UNKNOWN
    }

    @Override
    public Optional<SignWorkflowStore.Record> tryClaimSign(PkiId submissionId, long expectedRevision, Duration lease) {
        requireStoreUsable();
        requirePositive(lease, "lease");
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.get();
            SignWorkflowStore.Record current = stored.record();
            Instant now = signingNow();
            boolean claimable = current.state() == SignWorkflowStore.State.INTENT;
            boolean leaseAvailable = current.leaseUntil().isEmpty() || !current.leaseUntil().get().isAfter(now);
            if (current.revision() != expectedRevision || !claimable || !leaseAvailable) {
                return Optional.empty();
            }
            SignWorkflowStore.Record claimed = copySignRecord(current, current.state(), current.revision() + 1L,
                    current.fence() + 1L, Optional.of(now.plus(lease)), current.detailCode(), current.result(),
                    current.providerUpdatedAt());
            return replaceSignMetadata(stored, claimed, false) ? Optional.of(claimed) : Optional.empty();
        } finally {
            releaseSignLock(submissionId, lock);
        }
    }

    @Override
    public Optional<SignWorkflowStore.Record> renewSignClaim(PkiId submissionId, long expectedRevision, long fence,
            Duration lease) {
        requireStoreUsable();
        requirePositive(lease, "lease");
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.get();
            SignWorkflowStore.Record current = stored.record();
            if (current.revision() != expectedRevision || current.fence() != fence || current.leaseUntil().isEmpty()) {
                return Optional.empty();
            }
            SignWorkflowStore.Record renewed = copySignRecord(current, current.state(), current.revision() + 1L, fence,
                    Optional.of(signingNow().plus(lease)), current.detailCode(), current.result(),
                    current.providerUpdatedAt());
            return replaceSignMetadata(stored, renewed, false) ? Optional.of(renewed) : Optional.empty();
        } finally {
            releaseSignLock(submissionId, lock);
        }
    }

    @Override
    public Optional<SignWorkflowStore.Record> transitionSign(PkiId submissionId, long expectedRevision, long fence,
            SignWorkflowStore.State target, Optional<String> detailCode, Optional<EncodedObject> result,
            Optional<Instant> providerUpdatedAt) {
        requireStoreUsable();
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(detailCode, "detailCode");
        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(providerUpdatedAt, "providerUpdatedAt");
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.get();
            SignWorkflowStore.Record current = stored.record();
            if (current.revision() != expectedRevision || current.fence() != fence
                    || !validSignTransition(current.state(), target)) {
                return Optional.empty();
            }
            if (target == SignWorkflowStore.State.SUCCEEDED && result.isEmpty()
                    || target != SignWorkflowStore.State.SUCCEEDED && result.isPresent()) {
                throw new IllegalArgumentException("Signing result does not match target state");
            }
            if (target == SignWorkflowStore.State.SUCCEEDED
                    && (providerUpdatedAt.isEmpty() || !providerUpdatedAt.get().isBefore(current.deadline()))) {
                throw new IllegalArgumentException("Successful signing completion timestamp is not trustworthy");
            }
            SignWorkflowStore.Record transitioned = copySignRecord(current, target, current.revision() + 1L, fence,
                    Optional.empty(), detailCode, result, providerUpdatedAt);
            return replaceSignMetadata(stored, transitioned, false) ? Optional.of(transitioned) : Optional.empty();
        } finally {
            releaseSignLock(submissionId, lock);
        }
    }

    @Override
    public Optional<SignWorkflowStore.Record> retireSign(PkiId submissionId, long expectedRevision, long fence) {
        requireStoreUsable();
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.get();
            SignWorkflowStore.Record current = stored.record();
            if (current.revision() != expectedRevision || current.fence() != fence
                    || !isRetirableSignState(current.state())) {
                return Optional.empty();
            }
            PkiSigningBus.SignContinuation continuation = PkiSigningBus.SignContinuation.decode(current.request(),
                    stagedContent);
            EncodedObject retiredRequest = continuation.withoutLiveContent().encode();
            SignWorkflowStore.Record retired = new SignWorkflowStore.Record(current.submissionId(),
                    current.namespace(), current.fingerprint(), current.owner(), current.createdAt(),
                    current.deadline(), retiredRequest, SignWorkflowStore.State.RETIRED, current.revision() + 1L,
                    fence, Optional.empty(), Optional.of("RETIRED"), current.result(), current.providerUpdatedAt());
            if (!replaceSignMetadata(stored, retired, true)) {
                return Optional.empty();
            }
            stored.reference().ifPresent(reference -> {
                try {
                    if (reference.lifecycle() == DurableContentReference.Lifecycle.OPERATION) {
                        stagedContent.retireSigningContent(reference);
                    }
                } catch (IOException exception) {
                    LOG.log(Level.WARNING, "Signing content retirement cleanup failed");
                }
            });
            return Optional.of(retired);
        } finally {
            releaseSignLock(submissionId, lock);
        }
    }

    @Override
    public int purgeExpiredSignRecords() {
        requireStoreUsable();
        int purged = 0;
        for (SignWorkflowStore.Record record : listSignRecords()) {
            if (record.state() == SignWorkflowStore.State.RETIRED
                    && !record.createdAt().plus(options.signingOperationHorizon()).isAfter(signingNow())) {
                SignLockEntry lock = acquireSignLock(record.submissionId());
                try {
                    Optional<StoredSign> current = readStoredSign(record.submissionId());
                    if (current.isPresent() && current.get().record().state() == SignWorkflowStore.State.RETIRED
                            && !current.get().record().createdAt().plus(options.signingOperationHorizon())
                                    .isAfter(signingNow())
                            && deleteSignMetadata(current.get())) {
                        purged++;
                    }
                } finally {
                    releaseSignLock(record.submissionId(), lock);
                }
            }
        }
        return purged;
    }

    @Override
    public void close() throws IOException {
        IOException failure = null;
        try {
            metadataStore.close();
        } catch (IOException exception) {
            failure = exception;
        }
        try {
            ownership.close();
        } catch (IOException exception) {
            if (failure == null) {
                failure = exception;
            } else {
                failure.addSuppressed(exception);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    private void requireStoreUsable() {
        if (durabilityUncertain.get()) {
            throw new PkiException("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
        }
    }

    private SignLockEntry acquireSignLock(PkiId submissionId) {
        SignLockEntry entry = signLocks.compute(submissionId, (ignored, current) -> {
            SignLockEntry selected = current == null ? new SignLockEntry() : current;
            selected.references.incrementAndGet();
            return selected;
        });
        entry.lock.lock();
        return entry;
    }

    private void releaseSignLock(PkiId submissionId, SignLockEntry entry) {
        entry.lock.unlock();
        signLocks.computeIfPresent(submissionId, (ignored, current) -> {
            if (current != entry) { // NOPMD - identity protects a replacement lock entry
                return current;
            }
            return current.references.decrementAndGet() == 0 ? null : current;
        });
    }

    private RevocationLockEntry acquireRevocationLock(PkiId credentialId) {
        RevocationLockEntry entry = revocationLocks.compute(credentialId, (ignored, current) -> {
            RevocationLockEntry selected = current == null ? new RevocationLockEntry() : current;
            selected.references.incrementAndGet();
            return selected;
        });
        entry.lock.lock();
        return entry;
    }

    private void releaseRevocationLock(PkiId credentialId, RevocationLockEntry entry) {
        entry.lock.unlock();
        revocationLocks.computeIfPresent(credentialId, (ignored, current) -> {
            if (current != entry) { // NOPMD - identity protects a replacement lock entry
                return current;
            }
            return current.references.decrementAndGet() == 0 ? null : current;
        });
    }

    private ProfileLockEntry acquireProfileLock(String profileId) {
        ProfileLockEntry entry = profileLocks.compute(profileId, (ignored, current) -> {
            ProfileLockEntry selected = current == null ? new ProfileLockEntry() : current;
            selected.references.incrementAndGet();
            return selected;
        });
        entry.lock.lock();
        return entry;
    }

    private void releaseProfileLock(String profileId, ProfileLockEntry entry) {
        entry.lock.unlock();
        profileLocks.computeIfPresent(profileId, (ignored, current) -> {
            if (current != entry) { // NOPMD - identity protects a replacement lock entry
                return current;
            }
            return current.references.decrementAndGet() == 0 ? null : current;
        });
    }

    /*
     * Strict decoding may throw several runtime parsing failures. They are
     * deliberately collapsed without causes at this hostile persistence boundary.
     */
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private Optional<CertificateProfileRef> readActiveProfileRef(String profileId) {
        Path path = paths.profileActive(profileId);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        try {
            CertificateProfileRef reference = FsCodec.decode(FsCodec.ACTIVE_PROFILE_REF, FsOperations.readAll(path));
            if (!profileId.equals(reference.profileId())) {
                throw new ProfileLifecycleFailure(Code.PROFILE_ACTIVE_POINTER_CORRUPT);
            }
            return Optional.of(reference);
        } catch (ProfileLifecycleFailure failure) {
            throw failure;
        } catch (IOException failure) {
            throw new ProfileLifecycleFailure(Code.PROFILE_STORE_FAILURE);
        } catch (RuntimeException failure) {
            throw new ProfileLifecycleFailure(Code.PROFILE_ACTIVE_POINTER_CORRUPT);
        }
    }

    private Optional<ValidatedImportedProfile> readValidatedActiveProfile(String profileId) {
        ProfileLockEntry lock = acquireProfileLock(profileId);
        try {
            Optional<CertificateProfileRef> pointer = readActiveProfileRef(profileId);
            if (pointer.isEmpty()) {
                return Optional.empty();
            }
            CertificateProfileRef reference = pointer.orElseThrow();
            Path path = paths.profileVersion(profileId, reference.profileVersion());
            if (!Files.isRegularFile(path)) {
                throw new ProfileLifecycleFailure(Code.PROFILE_ACTIVE_POINTER_CORRUPT);
            }
            ValidatedImportedProfile validated = decodeValidatedProfileVersion(path, profileId,
                    reference.profileVersion());
            if (!reference.equals(validated.version().reference())) {
                throw new ProfileLifecycleFailure(Code.PROFILE_HASH_MISMATCH);
            }
            return Optional.of(validated);
        } finally {
            releaseProfileLock(profileId, lock);
        }
    }

    private static ImportedCertificateProfileVersion decodeProfileVersion(Path path, String profileId,
            long profileVersion) {
        return decodeValidatedProfileVersion(path, profileId, profileVersion).version();
    }

    /*
     * Strict codec and policy constructors expose multiple runtime failure types;
     * all are intentionally normalized without their input-bearing causes.
     */
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private static ValidatedImportedProfile decodeValidatedProfileVersion(Path path, String profileId,
            long profileVersion) {
        try {
            return ValidatedImportedProfile.decode(FsOperations.readAll(path), profileId, profileVersion);
        } catch (ProfileLifecycleFailure failure) {
            throw failure;
        } catch (IOException failure) {
            throw new ProfileLifecycleFailure(Code.PROFILE_STORE_FAILURE);
        } catch (RuntimeException failure) {
            throw new ProfileLifecycleFailure(Code.PROFILE_VERSION_CORRUPT);
        }
    }

    // Numeric path details are intentionally excluded from the public failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static long profileVersionFromPath(Path path) {
        String name = path.getFileName().toString();
        if (!name.endsWith(".bin")) {
            throw new ProfileLifecycleFailure(Code.PROFILE_VERSION_CORRUPT);
        }
        long value;
        try {
            value = Long.parseLong(name.substring(0, name.length() - 4));
        } catch (NumberFormatException failure) {
            throw new ProfileLifecycleFailure(Code.PROFILE_VERSION_CORRUPT);
        }
        if (value <= 0) {
            throw new ProfileLifecycleFailure(Code.PROFILE_VERSION_CORRUPT);
        }
        return value;
    }

    private static void requireProfileIdentity(String profileId, long profileVersion) {
        if (profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException("profileId must not be null/blank");
        }
        if (profileVersion <= 0) {
            throw new IllegalArgumentException("profileVersion must be positive");
        }
    }

    private Optional<RevocationJournal> readRevocationJournal(PkiId credentialId) {
        Path path = paths.revocationJournal(credentialId);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        RevocationJournal journal = decodeRevocationJournal(path);
        validateRevocationJournal(credentialId, journal);
        return Optional.of(journal);
    }

    /** Stable file-backed revocation snapshot isolated from later store writes. */
    private static final class FilesystemRevocationSnapshot implements RevocationSnapshot {
        private final String snapshotId;
        private final Path root;
        private final long count;
        private final AtomicBoolean closed;

        private FilesystemRevocationSnapshot(String snapshotId, Path root, long count) {
            this.snapshotId = snapshotId;
            this.root = root;
            this.count = count;
            this.closed = new AtomicBoolean();
        }

        @Override
        public String snapshotId() {
            return snapshotId;
        }

        @Override
        public OptionalLong count() {
            return OptionalLong.of(count);
        }

        @Override
        public Cursor openCursor() {
            if (closed.get()) {
                throw new IllegalStateException("Revocation snapshot is closed");
            }
            return new FilesystemRevocationCursor(root, count);
        }

        @Override
        public void close() throws IOException {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            if (Files.isDirectory(root)) {
                try (Stream<Path> files = Files.list(root)) {
                    java.util.Iterator<Path> iterator = files.iterator();
                    while (iterator.hasNext()) {
                        Files.deleteIfExists(iterator.next());
                    }
                }
                Files.deleteIfExists(root);
            }
        }
    }

    /** Sequential bounded-memory cursor over one immutable snapshot directory. */
    private static final class FilesystemRevocationCursor implements RevocationSnapshot.Cursor {
        private final Path root;
        private final long count;
        private long nextOrdinal;
        private RevocationJournal current;
        private boolean closed;

        private FilesystemRevocationCursor(Path root, long count) {
            this.root = root;
            this.count = count;
        }

        @Override
        public boolean next() throws IOException {
            if (closed) {
                throw new IllegalStateException("Revocation cursor is closed");
            }
            if (nextOrdinal >= count) {
                current = null;
                return false;
            }
            current = decodeRevocationJournal(root.resolve(Long.toUnsignedString(nextOrdinal) + ".bin"));
            nextOrdinal = Math.addExact(nextOrdinal, 1L);
            return true;
        }

        @Override
        public RevocationJournal current() {
            if (current == null) {
                throw new IllegalStateException("Revocation cursor is not positioned");
            }
            return current;
        }

        @Override
        public long ordinal() {
            if (current == null) {
                throw new IllegalStateException("Revocation cursor is not positioned");
            }
            return nextOrdinal - 1L;
        }

        @Override
        public void close() {
            current = null;
            closed = true;
        }
    }

    // Codec and filesystem failures are external persisted-state boundaries; raw
    // causes are deliberately removed from the stable corruption exception.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private static RevocationJournal decodeRevocationJournal(Path path) {
        try {
            return FsCodec.decode(FsCodec.REVOCATION_JOURNAL, FsOperations.readAll(path));
        } catch (IOException | RuntimeException ex) {
            throw corruptRevocationState();
        }
    }

    // Revision overflow is persisted-state corruption and is mapped to the stable,
    // redacted state-corruption boundary.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static RevocationJournal appendRevocation(Optional<RevocationJournal> current, PkiId credentialId,
            RevocationCommand command, Instant transitionTime) {
        if (current.isPresent() && transitionTime.isBefore(current.get().latest().time())) {
            throw new PkiException("Revocation transition conflict: code=REVOCATION_TRANSITION_CONFLICT");
        }
        RevocationState previous = current.map(RevocationJournal::latest).map(RevocationTransition::state).orElse(null);
        RevocationState next = nextRevocationState(previous, command);
        long revision = current.map(RevocationJournal::latest).map(RevocationTransition::revision).map(value -> {
            try {
                return Math.addExact(value, 1L);
            } catch (ArithmeticException ex) {
                throw corruptRevocationState();
            }
        }).orElse(1L);
        List<RevocationTransition> transitions = new ArrayList<>(
                current.map(RevocationJournal::transitions).orElseGet(List::of));
        Optional<RevocationReason> permanentReason = command instanceof RevocationCommand.RevokePermanently revoke
                ? Optional.of(revoke.reason())
                : Optional.empty();
        transitions
                .add(new RevocationTransition(revision, next, transitionTime, permanentReason, command.attributes()));
        RevocationJournal journal = new RevocationJournal(credentialId, transitions);
        validateRevocationJournal(credentialId, journal);
        return journal;
    }

    private static RevocationState nextRevocationState(RevocationState previous, RevocationCommand command) {
        if (previous == RevocationState.PERMANENTLY_REVOKED) {
            throw new PkiException("Revocation is terminal: code=REVOCATION_TERMINAL");
        }
        boolean hold = command instanceof RevocationCommand.Hold;
        boolean unhold = command instanceof RevocationCommand.Unhold;
        if (previous == null) {
            return unhold ? throwIllegalTransition()
                    : hold ? RevocationState.HELD : RevocationState.PERMANENTLY_REVOKED;
        }
        return switch (previous) {
            case CLEAR ->
                unhold ? throwIllegalTransition() : hold ? RevocationState.HELD : RevocationState.PERMANENTLY_REVOKED;
            case HELD ->
                hold ? throwIllegalTransition() : unhold ? RevocationState.CLEAR : RevocationState.PERMANENTLY_REVOKED;
            case PERMANENTLY_REVOKED -> throw new PkiException("Revocation is terminal: code=REVOCATION_TERMINAL");
        };
    }

    private static void validateRevocationJournal(PkiId expectedId, RevocationJournal journal) {
        if (!expectedId.equals(journal.credentialId())) {
            throw corruptRevocationState();
        }
    }

    private static RevocationState throwIllegalTransition() {
        throw illegalRevocationTransition();
    }

    private static PkiException illegalRevocationTransition() {
        return new PkiException("Revocation transition rejected: code=REVOCATION_TRANSITION_ILLEGAL");
    }

    private static PkiException corruptRevocationState() {
        return new PkiException("Revocation state invalid: code=REVOCATION_STATE_CORRUPT");
    }

    private Optional<SignWorkflowStore.Record> readSignRecord(PkiId submissionId) {
        return readStoredSign(submissionId).map(StoredSign::record);
    }

    private Optional<StoredSign> readStoredSign(PkiId submissionId) {
        MetadataKey recordKey = signingRecordKey(submissionId);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> storedRecord = snapshot.get(recordKey);
            if (storedRecord.isEmpty()) {
                if (snapshot.get(signingOwnerKey(submissionId)).isPresent()) {
                    throw new IllegalStateException("Signing owner exists without its record");
                }
                return Optional.empty();
            }
            return Optional.of(decodeStoredSign(snapshot, storedRecord.orElseThrow()));
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to read authoritative signing record", ex);
        }
    }

    private StoredSign decodeStoredSign(MetadataSnapshot snapshot, MetadataSnapshot.Record storedRecord)
            throws IOException {
        SignWorkflowStore.Record record = decodeSignRecord(storedRecord);
        PkiId submissionId = record.submissionId();
        if (!signingRecordKey(submissionId).equals(storedRecord.key())) {
            throw new IllegalStateException("Signing record metadata key mismatch");
        }
        validateSignRecord(submissionId, record);
        Optional<MetadataSnapshot.Record> storedOwner = snapshot.get(signingOwnerKey(submissionId));
        if (record.state() == SignWorkflowStore.State.RETIRED) {
            if (storedOwner.isPresent()) {
                throw new IllegalStateException("Retired signing record retains an owner edge");
            }
            return new StoredSign(record, storedRecord.recordRevision(), OptionalLong.empty(), Optional.empty());
        }
        try (MetadataSnapshot.Record owner = storedOwner.orElseThrow(
                () -> new IllegalStateException("Signing record owner edge is missing"))) {
            DurableContentReference reference = decodeSigningOwner(owner, submissionId);
            PkiSigningBus.SignContinuation continuation = PkiSigningBus.SignContinuation.decode(
                    record.request(), stagedContent);
            if (!reference.equals(continuation.content())) {
                throw new IllegalStateException("Signing record owner reference mismatch");
            }
            return new StoredSign(record, storedRecord.recordRevision(), OptionalLong.of(owner.recordRevision()),
                    Optional.of(reference));
        }
    }

    private SignWorkflowStore.Record decodeSignRecord(MetadataSnapshot.Record stored) throws IOException {
        return FsCodec.decode(FsCodec.SIGN_WORKFLOW_RECORD, readMetadataValue(stored), stagedContent);
    }

    // Parsing and canonicalization failures can carry persisted request material;
    // validation deliberately replaces every such cause with a safe corruption
    // code.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private void validateSignRecord(PkiId requestedId, SignWorkflowStore.Record record) {
        Objects.requireNonNull(requestedId, "requestedId");
        Objects.requireNonNull(record, "record");

        SigningSubmissionId parsed;
        PkiSigningBus.SignContinuation continuation;
        Instant horizonEnd;
        Instant futureLimit;
        try {
            parsed = SigningSubmissionId.parse(record.submissionId());
            continuation = PkiSigningBus.SignContinuation.decode(record.request(), stagedContent);
            horizonEnd = record.createdAt().plus(options.signingOperationHorizon());
            futureLimit = signingNow().plus(options.signingIdPermittedSkew());
        } catch (RuntimeException ex) {
            throw invalidSignRecord(record, "IDENTITY_OR_REQUEST_INVALID");
        }

        requireValidSignRecord(requestedId.equals(record.submissionId()), record, "SUBMISSION_ID_MISMATCH");
        requireValidSignRecord(record.namespace().startsWith(signingNamespace + "."), record,
                "STORE_NAMESPACE_MISMATCH");
        requireValidSignRecord(parsed.namespace().equals(record.namespace()), record, "ID_NAMESPACE_MISMATCH");
        requireValidSignRecord(parsed.createdAt().equals(record.createdAt()), record, "ID_TIMESTAMP_MISMATCH");
        requireValidSignRecord(!record.createdAt().isAfter(futureLimit), record, "CREATION_TIME_FUTURE");
        requireValidSignRecord(record.deadline().isAfter(record.createdAt()) && !record.deadline().isAfter(horizonEnd),
                record, "DEADLINE_INVALID");
        requireValidSignRecord(continuation.isBoundTo(record.submissionId(), record.owner()), record,
                "CONTINUATION_IDENTITY_MISMATCH");
        requireValidSignRecord(record.state() == SignWorkflowStore.State.RETIRED != continuation.hasLiveContent(),
                record, "CONTINUATION_LIFECYCLE_MISMATCH");

        byte[] storedRequest = record.request().bytes();
        byte[] canonicalRequest = null;
        String expectedFingerprint;
        try {
            canonicalRequest = continuation.encode().bytes();
            expectedFingerprint = continuation.semanticFingerprint(record.namespace(), record.deadline());
        } catch (RuntimeException ex) {
            Arrays.fill(storedRequest, (byte) 0);
            if (canonicalRequest != null) {
                Arrays.fill(canonicalRequest, (byte) 0);
            }
            throw invalidSignRecord(record, "FINGERPRINT_RECOMPUTE_FAILED");
        }
        try {
            requireValidSignRecord(MessageDigest.isEqual(storedRequest, canonicalRequest), record,
                    "CONTINUATION_NONCANONICAL");
            requireValidSignRecord(hasCanonicalFingerprintShape(record.fingerprint()), record,
                    "FINGERPRINT_FORMAT_INVALID");
            requireValidSignRecord(constantTimeAsciiEquals(record.fingerprint(), expectedFingerprint), record,
                    "FINGERPRINT_MISMATCH");
        } finally {
            Arrays.fill(storedRequest, (byte) 0);
            Arrays.fill(canonicalRequest, (byte) 0);
        }

        requireValidSignRecord(record.revision() >= record.fence(), record, "REVISION_FENCE_ORDER_INVALID");
        requireValidSignRecord(record.detailCode().isEmpty() || !record.detailCode().get().isBlank(), record,
                "DETAIL_CODE_INVALID");
        if (record.leaseUntil().isPresent()) {
            Instant leaseUntil = record.leaseUntil().get();
            requireValidSignRecord(leaseUntil.isAfter(record.createdAt()) && !leaseUntil.isAfter(horizonEnd), record,
                    "LEASE_TIME_INVALID");
        }
        if (record.result().isPresent()) {
            requireValidSignRecord(record.result().get().bytes().length <= FsCodec.MAX_COMPONENT_BYTES, record,
                    "RESULT_SIZE_INVALID");
        }

        validateSignRecordState(record);
    }

    private MetadataCommitResult createSignMetadata(SignWorkflowStore.Record record,
            DurableContentReference reference) {
        validateSignRecord(record.submissionId(), record);
        try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
            transaction.create(signingRecordKey(record.submissionId()),
                    byteContent(FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, record)), CancellationSignal.NONE);
            transaction.create(signingOwnerKey(record.submissionId()),
                    byteContent(encodeSigningOwner(record.submissionId(), reference)), CancellationSignal.NONE);
            return requireKnownOutcome(transaction.commit());
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to persist signing authority", ex);
        }
    }

    private boolean replaceSignMetadata(StoredSign current, SignWorkflowStore.Record replacement,
            boolean removeOwner) {
        validateSignRecord(replacement.submissionId(), replacement);
        try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
            transaction.replace(signingRecordKey(replacement.submissionId()), current.recordRevision(),
                    byteContent(FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, replacement)), CancellationSignal.NONE);
            if (removeOwner) {
                transaction.delete(signingOwnerKey(replacement.submissionId()),
                        current.ownerRevision().orElseThrow());
            }
            return requireKnownOutcome(transaction.commit()).outcome() == MetadataCommitResult.Outcome.COMMITTED;
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to replace signing authority", ex);
        }
    }

    private boolean deleteSignMetadata(StoredSign current) {
        try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
            transaction.delete(signingRecordKey(current.record().submissionId()), current.recordRevision());
            return requireKnownOutcome(transaction.commit()).outcome() == MetadataCommitResult.Outcome.COMMITTED;
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to retire signing authority", ex);
        }
    }

    private MetadataCommitResult requireKnownOutcome(MetadataCommitResult result) {
        if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
            durabilityUncertain.set(true);
            throw new PkiException("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
        }
        return result;
    }

    private static SignWorkflowStore.Record copySignRecord(SignWorkflowStore.Record current,
            SignWorkflowStore.State state, long revision, long fence, Optional<Instant> leaseUntil,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt) {
        return new SignWorkflowStore.Record(current.submissionId(), current.namespace(), current.fingerprint(),
                current.owner(), current.createdAt(), current.deadline(), current.request(), state, revision, fence,
                leaseUntil, detailCode, result, providerUpdatedAt);
    }

    private static MetadataKey signingRecordKey(PkiId submissionId) {
        SigningSubmissionId parsed = SigningSubmissionId.parse(submissionId);
        return new MetadataKey(SIGN_RECORD_NAMESPACE, parsed.id().value());
    }

    private static MetadataKey signingOwnerKey(PkiId submissionId) {
        SigningSubmissionId parsed = SigningSubmissionId.parse(submissionId);
        return new MetadataKey(SIGN_OWNER_NAMESPACE, parsed.id().value());
    }

    private static MetadataKey statusRecordKey(PkiId statusObjectId) {
        return new MetadataKey(STATUS_RECORD_NAMESPACE, statusObjectId.value());
    }

    private static MetadataKey statusOwnerKey(PkiId statusObjectId) {
        return new MetadataKey(STATUS_OWNER_NAMESPACE, statusObjectId.value());
    }

    private static RepeatableContent byteContent(byte[] value) {
        return new ByteValueContent(value);
    }

    private static byte[] readMetadataValue(MetadataSnapshot.Record record) throws IOException {
        long length = record.length().orElseThrow();
        if (length < 0L || length > FsCodec.MAX_COMPONENT_BYTES) {
            throw new IOException("Metadata value length is invalid");
        }
        byte[] result = new byte[Math.toIntExact(length)];
        try (InputStream input = record.openStream()) {
            int offset = 0;
            while (offset < result.length) {
                int count = input.read(result, offset, result.length - offset);
                if (count <= 0) {
                    throw new IOException("Metadata value is truncated");
                }
                offset += count;
            }
            if (input.read() >= 0) {
                throw new IOException("Metadata value has trailing data");
            }
        }
        return result;
    }

    private static byte[] encodeSigningOwner(PkiId submissionId, DurableContentReference reference) {
        return encodeTransactionalOwner(SIGN_OWNER_VALUE_VERSION, DurableContentOwner.Category.SIGNING_OPERATION,
                submissionId, reference);
    }

    private static byte[] encodeStatusOwner(PkiId statusObjectId, DurableContentReference reference) {
        new DurableContentOwner(DurableContentOwner.Category.STATUS_OBJECT_RECORD, statusObjectId.value());
        return encodeTransactionalOwner(STATUS_OWNER_VALUE_VERSION,
                DurableContentOwner.Category.STATUS_OBJECT_RECORD, statusObjectId, reference);
    }

    private static byte[] encodeTransactionalOwner(int version, DurableContentOwner.Category category,
            PkiId ownerId, DurableContentReference reference) {
        byte[][] fields = {
                category.name().getBytes(StandardCharsets.US_ASCII),
                ownerId.value().getBytes(StandardCharsets.UTF_8),
                reference.storeId().getBytes(StandardCharsets.UTF_8),
                reference.contentId().getBytes(StandardCharsets.UTF_8),
                reference.encoding().name().getBytes(StandardCharsets.US_ASCII),
                reference.sha256().getBytes(StandardCharsets.US_ASCII),
                reference.lifecycle().name().getBytes(StandardCharsets.US_ASCII)
        };
        int size = Integer.BYTES + Long.BYTES;
        for (byte[] field : fields) {
            size = Math.addExact(size, Math.addExact(Integer.BYTES, field.length));
        }
        ByteBuffer output = ByteBuffer.allocate(size);
        output.putInt(version);
        for (byte[] field : fields) {
            output.putInt(field.length).put(field);
        }
        output.putLong(reference.length());
        return output.array();
    }

    private DurableContentReference decodeSigningOwner(MetadataSnapshot.Record owner, PkiId expectedId)
            throws IOException {
        return decodeTransactionalOwner(owner, expectedId, SIGN_OWNER_VALUE_VERSION,
                DurableContentOwner.Category.SIGNING_OPERATION, signingOwnerKey(expectedId), "signing");
    }

    private DurableContentReference decodeStatusOwner(MetadataSnapshot.Record owner, PkiId expectedId)
            throws IOException {
        return decodeTransactionalOwner(owner, expectedId, STATUS_OWNER_VALUE_VERSION,
                DurableContentOwner.Category.STATUS_OBJECT_RECORD, statusOwnerKey(expectedId), "status");
    }

    private DurableContentReference decodeTransactionalOwner(MetadataSnapshot.Record owner, PkiId expectedId,
            int expectedVersion, DurableContentOwner.Category expectedCategory, MetadataKey expectedKey,
            String authority) throws IOException {
        ByteBuffer input = ByteBuffer.wrap(readMetadataValue(owner));
        try {
            if (input.getInt() != expectedVersion) {
                throw new IOException("Unsupported " + authority + " owner metadata");
            }
            DurableContentOwner.Category category = DurableContentOwner.Category.valueOf(readOwnerField(input));
            String ownerId = readOwnerField(input);
            String storeId = readOwnerField(input);
            String contentId = readOwnerField(input);
            zeroecho.pki.api.Encoding encoding = zeroecho.pki.api.Encoding.valueOf(readOwnerField(input));
            String digest = readOwnerField(input);
            DurableContentReference.Lifecycle lifecycle = DurableContentReference.Lifecycle.valueOf(
                    readOwnerField(input));
            long length = input.getLong();
            if (input.hasRemaining() || category != expectedCategory
                    || !ownerId.equals(expectedId.value())) {
                throw new IOException("Transactional owner metadata identity mismatch");
            }
            new DurableContentOwner(category, ownerId);
            DurableContentReference restored = stagedContent.restoreReference(storeId, contentId, encoding,
                    length, digest, lifecycle);
            if (!expectedKey.equals(owner.key())) {
                throw new IOException("Transactional owner metadata key mismatch");
            }
            return restored;
        } catch (IllegalArgumentException | java.nio.BufferUnderflowException exception) {
            throw new IOException("Malformed transactional owner metadata", exception);
        }
    }

    private static String readOwnerField(ByteBuffer input) throws IOException {
        int length = input.getInt();
        if (length <= 0 || length > MetadataKey.MAXIMUM_KEY_UTF8_BYTES || input.remaining() < length) {
            throw new IOException("Malformed signing owner metadata field");
        }
        byte[] value = new byte[length];
        input.get(value);
        String decoded = new String(value, StandardCharsets.UTF_8);
        if (!Arrays.equals(value, decoded.getBytes(StandardCharsets.UTF_8))) {
            throw new IOException("Malformed signing owner metadata UTF-8");
        }
        return decoded;
    }

    private record StoredSign(SignWorkflowStore.Record record, long recordRevision,
            OptionalLong ownerRevision, Optional<DurableContentReference> reference) {
    }

    private record StoredStatus(StatusObject status, long recordRevision, long ownerRevision) {
    }

    /** Store-owned bounded finite control metadata used only for synchronous admission. */
    private static final class ByteValueContent implements RepeatableContent {
        private final byte[] value;

        private ByteValueContent(byte[] value) {
            this.value = Objects.requireNonNull(value, "value").clone();
        }

        @Override
        public InputStream openStream() {
            return new ByteArrayInputStream(value);
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(value.length);
        }

        @Override
        public String contentId() {
            return "signing-control-metadata";
        }

        @Override
        public void close() {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static boolean validSignTransition(SignWorkflowStore.State source, SignWorkflowStore.State target) {
        if (source == SignWorkflowStore.State.INTENT) {
            return target == SignWorkflowStore.State.DISPATCHED || target == SignWorkflowStore.State.FAILED
                    || target == SignWorkflowStore.State.CANCELLING || target == SignWorkflowStore.State.EXPIRED;
        }
        if (source == SignWorkflowStore.State.DISPATCHED) {
            return target == SignWorkflowStore.State.SUCCEEDED || target == SignWorkflowStore.State.FAILED
                    || target == SignWorkflowStore.State.CANCELLING || target == SignWorkflowStore.State.EXPIRED;
        }
        if (source == SignWorkflowStore.State.CANCELLING) {
            return target == SignWorkflowStore.State.CANCELLING || target == SignWorkflowStore.State.SUCCEEDED
                    || target == SignWorkflowStore.State.FAILED || target == SignWorkflowStore.State.CANCELLED
                    || target == SignWorkflowStore.State.EXPIRED;
        }
        return false;
    }

    private static boolean isRetirableSignState(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.SUCCEEDED || state == SignWorkflowStore.State.FAILED
                || state == SignWorkflowStore.State.CANCELLED || state == SignWorkflowStore.State.EXPIRED;
    }

    private static void validateSignRecordState(SignWorkflowStore.Record record) {
        switch (record.state()) {
            case INTENT -> {
                requireValidSignRecord(record.result().isEmpty() && record.providerUpdatedAt().isEmpty(), record,
                        "INTENT_TERMINAL_DATA_PRESENT");
                requireDetailCode(record, "INTENT");
                if (record.fence() == INITIAL_FENCE) {
                    requireValidSignRecord(record.revision() == 0L && record.leaseUntil().isEmpty(), record,
                            "INTENT_INITIAL_CLAIM_INVALID");
                } else {
                    requireValidSignRecord(record.revision() >= record.fence() && record.leaseUntil().isPresent(),
                            record, "INTENT_CLAIM_INVALID");
                }
            }
            case DISPATCHED -> {
                requireValidSignRecord(record.fence() > 0L && record.revision() > record.fence(), record,
                        "DISPATCH_REVISION_INVALID");
                requireValidSignRecord(record.leaseUntil().isEmpty() && record.result().isEmpty()
                        && record.providerUpdatedAt().isEmpty(), record, "DISPATCH_TERMINAL_DATA_PRESENT");
                requireDetailCode(record, "DISPATCHED");
            }
            case CANCELLING -> {
                requireValidSignRecord(record.revision() > record.fence(), record, "CANCELLING_REVISION_INVALID");
                requireValidSignRecord(record.leaseUntil().isEmpty() && record.result().isEmpty()
                        && record.providerUpdatedAt().isEmpty(), record, "CANCELLING_TERMINAL_DATA_PRESENT");
                requireValidSignRecord(record.detailCode()
                        .filter(code -> "CANCEL_REQUESTED".equals(code) || "CANCEL_SUBMITTED".equals(code)).isPresent(),
                        record, "DETAIL_CODE_INVALID");
            }
            case SUCCEEDED -> {
                requireValidSignRecord(record.fence() > 0L && record.revision() - record.fence() >= 2L, record,
                        "SUCCESS_REVISION_INVALID");
                requireValidSignRecord(record.leaseUntil().isEmpty() && record.result().isPresent()
                        && record.providerUpdatedAt().isPresent(), record, "SUCCESS_EVIDENCE_MISSING");
                requireValidSignRecord(record.providerUpdatedAt().get().isBefore(record.deadline()), record,
                        "PROVIDER_TIME_INVALID");
                requireValidSignRecord(!hasContradictorySuccessCode(record.detailCode()), record,
                        "SUCCESS_DETAIL_CONTRADICTORY");
            }
            case FAILED -> {
                requireValidSignRecord(record.fence() > 0L && record.revision() > record.fence(), record,
                        "FAILURE_REVISION_INVALID");
                requireValidSignRecord(record.leaseUntil().isEmpty() && record.result().isEmpty(), record,
                        "FAILURE_RESULT_OR_LEASE_PRESENT");
                requireValidSignRecord(!hasLifecycleCode(record.detailCode(), "SIGNED"), record,
                        "FAILURE_DETAIL_CONTRADICTORY");
            }
            case CANCELLED -> {
                requireValidSignRecord(record.revision() - record.fence() >= 2L, record, "CANCELLED_REVISION_INVALID");
                requireValidSignRecord(record.leaseUntil().isEmpty() && record.result().isEmpty(), record,
                        "CANCELLED_RESULT_OR_LEASE_PRESENT");
                requireValidSignRecord(!hasLifecycleCode(record.detailCode(), "SIGNED"), record,
                        "CANCELLED_DETAIL_CONTRADICTORY");
            }
            case EXPIRED -> {
                requireValidSignRecord(record.revision() > record.fence(), record, "EXPIRED_REVISION_INVALID");
                requireValidSignRecord(record.leaseUntil().isEmpty() && record.result().isEmpty(), record,
                        "EXPIRED_RESULT_OR_LEASE_PRESENT");
                requireValidSignRecord(!hasLifecycleCode(record.detailCode(), "SIGNED"), record,
                        "EXPIRED_DETAIL_CONTRADICTORY");
            }
            case RETIRED -> {
                requireValidSignRecord(record.leaseUntil().isEmpty(), record, "RETIRED_LEASE_PRESENT");
                requireDetailCode(record, "RETIRED");
                if (record.result().isPresent()) {
                    requireValidSignRecord(
                            record.fence() > 0L && record.revision() - record.fence() >= 3L
                                    && record.providerUpdatedAt().isPresent()
                                    && record.providerUpdatedAt().get().isBefore(record.deadline()),
                            record, "PROVIDER_TIME_INVALID");
                } else {
                    requireValidSignRecord(record.revision() - record.fence() >= 2L, record,
                            "RETIRED_TERMINAL_REVISION_INVALID");
                }
            }
        }
    }

    private static boolean hasCanonicalFingerprintShape(String fingerprint) {
        if (fingerprint.length() != SIGN_FINGERPRINT_PREFIX.length() + SIGN_FINGERPRINT_HEX_LENGTH
                || !fingerprint.startsWith(SIGN_FINGERPRINT_PREFIX)) {
            return false;
        }
        for (int index = SIGN_FINGERPRINT_PREFIX.length(); index < fingerprint.length(); index++) {
            char value = fingerprint.charAt(index);
            if (!(value >= '0' && value <= '9' || value >= 'a' && value <= 'f')) {
                return false;
            }
        }
        return true;
    }

    private static boolean constantTimeAsciiEquals(String left, String right) {
        byte[] leftBytes = left.getBytes(StandardCharsets.US_ASCII);
        byte[] rightBytes = right.getBytes(StandardCharsets.US_ASCII);
        try {
            return MessageDigest.isEqual(leftBytes, rightBytes);
        } finally {
            Arrays.fill(leftBytes, (byte) 0);
            Arrays.fill(rightBytes, (byte) 0);
        }
    }

    private static boolean hasContradictorySuccessCode(Optional<String> detailCode) {
        return hasLifecycleCode(detailCode, "INTENT") || hasLifecycleCode(detailCode, "DISPATCHED")
                || hasLifecycleCode(detailCode, "CANCEL_REQUESTED") || hasLifecycleCode(detailCode, "CANCELLED")
                || hasLifecycleCode(detailCode, "EXPIRED") || hasLifecycleCode(detailCode, "RETIRED")
                || hasLifecycleCode(detailCode, "REQUEST_INTEGRITY_FAILURE")
                || hasLifecycleCode(detailCode, "PROVIDER_ID_MISMATCH")
                || hasLifecycleCode(detailCode, "PROVIDER_SUBMISSION_FAILED")
                || hasLifecycleCode(detailCode, "PROVIDER_RESULT_MISSING")
                || hasLifecycleCode(detailCode, "LATE_PROVIDER_SUCCESS");
    }

    private static boolean hasLifecycleCode(Optional<String> detailCode, String code) {
        return detailCode.filter(code::equals).isPresent();
    }

    private static void requireDetailCode(SignWorkflowStore.Record record, String required) {
        requireValidSignRecord(record.detailCode().filter(required::equals).isPresent(), record,
                "STATE_DETAIL_CODE_INVALID");
    }

    private static void requireValidSignRecord(boolean condition, SignWorkflowStore.Record record, String code) {
        if (!condition) {
            throw invalidSignRecord(record, code);
        }
    }

    private static IllegalStateException invalidSignRecord(SignWorkflowStore.Record record, String code) {
        return new IllegalStateException("Signing record corruption: type=sign-workflow version="
                + CURRENT_SIGN_RECORD_VERSION + " state=" + record.state() + " code=" + code);
    }

    private static void requirePositive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }

    /**
     * Reference-counted lock entry removed when no mutation uses it.
     */
    private static final class SignLockEntry {
        private final ReentrantLock lock = new ReentrantLock();
        private final AtomicInteger references = new AtomicInteger();
    }

    /**
     * Reference-counted per-credential revocation transition lock.
     */
    private static final class RevocationLockEntry {
        private final ReentrantLock lock = new ReentrantLock();
        private final AtomicInteger references = new AtomicInteger();
    }

    /** Reference-counted per-profile import and activation lock. */
    private static final class ProfileLockEntry {
        private final ReentrantLock lock = new ReentrantLock();
        private final AtomicInteger references = new AtomicInteger();
    }

    /**
     * Owns the operating-system resources that exclude a second store process.
     *
     * <p>
     * Ownership begins when {@link #acquire(Path)} returns and ends when
     * {@link #close()} releases the lock and closes its channel. The resources
     * intentionally remain open for the complete lifetime of their enclosing
     * {@link FilesystemPkiStore}.
     * </p>
     */
    private static final class StoreOwnership implements AutoCloseable {
        private final FileChannel channel;
        private final FileLock lock;
        private final ReentrantLock closeLock = new ReentrantLock();
        private boolean closed;

        private StoreOwnership(FileChannel channel, FileLock lock) {
            this.channel = channel;
            this.lock = lock;
        }

        // Raw lock exceptions are deliberately replaced by the stable redacted
        // contention code.
        @SuppressWarnings("PMD.PreserveStackTrace")
        private static StoreOwnership acquire(Path lockFile) throws IOException {
            FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            FileLock lock = null;
            try {
                try {
                    lock = channel.tryLock();
                } catch (OverlappingFileLockException contention) {
                    throw new IllegalStateException(STORE_OWNERSHIP_UNAVAILABLE);
                }
                if (lock == null) {
                    throw new IllegalStateException(STORE_OWNERSHIP_UNAVAILABLE);
                }
                return new StoreOwnership(channel, lock);
            } finally {
                if (lock == null) {
                    closePartial(channel);
                }
            }
        }

        private static void closePartial(FileChannel channel) {
            try {
                channel.close();
            } catch (IOException ignored) {
                // Contention remains authoritative and contains no operating-system detail.
            }
        }

        private void closeSilently() {
            try {
                close();
            } catch (IOException ignored) {
                // Constructor failure remains authoritative and safely redacted.
            }
        }

        @Override
        public void close() throws IOException {
            closeLock.lock();
            try {
                if (closed) {
                    return;
                }
                boolean releaseFailed = false;
                boolean closeFailed = false;
                try {
                    if (lock.isValid()) {
                        lock.release();
                    }
                } catch (IOException failure) {
                    releaseFailed = true;
                }
                try {
                    channel.close();
                } catch (IOException failure) {
                    closeFailed = true;
                }
                closed = true;
                if (releaseFailed || closeFailed) {
                    throw new IOException(
                            "Filesystem store ownership release failed: " + "code=STORE_OWNERSHIP_RELEASE_FAILED");
                }
            } finally {
                closeLock.unlock();
            }
        }
    }

    private String ensureSigningNamespace() throws IOException {
        Path file = paths.signingNamespaceFile();
        if (Files.exists(file)) {
            String value = Files.readString(file, StandardCharsets.US_ASCII).trim();
            if (!value.matches("[a-f0-9]{32}")) {
                throw new IllegalStateException("Invalid persisted signing namespace");
            }
            return value;
        }
        byte[] random = new byte[16];
        new SecureRandom().nextBytes(random);
        String value = HexFormat.of().formatHex(random);
        FsOperations.writeAtomic(file, value.getBytes(StandardCharsets.US_ASCII));
        return value;
    }

    private long loadSigningTimeWatermark() throws IOException {
        Path file = paths.signingTimeWatermarkFile();
        long observed = clock.instant().toEpochMilli();
        if (!Files.exists(file)) {
            writeDurableSigningTimeWatermark(file, observed);
            return observed;
        }
        try {
            return Math.max(observed, Long.parseLong(Files.readString(file, StandardCharsets.US_ASCII).trim()));
        } catch (NumberFormatException ex) {
            throw new IllegalStateException("Invalid persisted signing time watermark", ex);
        }
    }

    private void persistSigningTimeWatermark(long epochMilli) {
        try {
            writeDurableSigningTimeWatermark(paths.signingTimeWatermarkFile(), epochMilli);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to persist signing time watermark", ex);
        }
    }

    private static void writeDurableSigningTimeWatermark(Path target, long epochMilli) throws IOException {
        Path parent = target.getParent();
        FsOperations.ensureDir(parent);
        Path temporary = Files.createTempFile(parent, ".signing-time-watermark-", ".tmp");
        try {
            ByteBuffer bytes = ByteBuffer.wrap(Long.toString(epochMilli).getBytes(StandardCharsets.US_ASCII));
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                while (bytes.hasRemaining()) {
                    channel.write(bytes);
                }
                channel.force(true);
            }
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
            try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
                directory.force(true);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void ensureVersionFile() throws IOException {
        Path vf = this.paths.versionFile();
        if (!Files.exists(vf)) {
            FsOperations.writeAtomic(vf, CURRENT_STORE_VERSION.getBytes());
            return;
        }
        String ver = Files.readString(vf).trim();
        if (!CURRENT_STORE_VERSION.equals(ver)) {
            throw new IllegalStateException("unsupported store version: " + ver);
        }
    }

    private <T> Optional<T> readOptional(final Path path, final FsCodec.Schema<T> schema) {
        try {
            if (!Files.exists(path)) {
                return Optional.empty();
            }
            byte[] data = FsOperations.readAll(path);
            return Optional.of(FsCodec.decode(schema, data, stagedContent));
        } catch (IOException e) {
            throw new IllegalStateException("read failed: " + path, e);
        }
    }

    private <T> List<T> listBinaryFiles(final Path byIdDir, final FsCodec.Schema<T> schema) {
        if (!Files.isDirectory(byIdDir)) {
            return List.of();
        }
        try {
            return Files.list(byIdDir).filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString())).map(p -> {
                        try {
                            return FsCodec.decode(schema, FsOperations.readAll(p), stagedContent);
                        } catch (IOException e) {
                            throw new IllegalStateException("read failed: " + p, e);
                        }
                    }).toList();
        } catch (IOException e) {
            throw new IllegalStateException("list failed: " + byIdDir, e);
        }
    }

    private <T> List<T> listCurrentRecords(final Path byIdDir, final FsCodec.Schema<T> schema) {
        if (!Files.isDirectory(byIdDir)) {
            return List.of();
        }
        try {
            List<Path> entityDirs = Files.list(byIdDir).filter(Files::isDirectory)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString())).toList();

            List<T> out = new ArrayList<>();
            for (Path entityDir : entityDirs) {
                Path current = entityDir.resolve(FsPaths.CURRENT_FILE);
                if (Files.exists(current)) {
                    out.add(FsCodec.decode(schema, FsOperations.readAll(current), stagedContent));
                }
            }
            return out;
        } catch (IOException e) {
            throw new IllegalStateException("list current records failed: " + byIdDir, e);
        }
    }

    private static void writeOnce(final Path target, final byte[] data, final String kind, final String safeId) {
        try {
            FsOperations.ensureDir(target.getParent());
            if (Files.exists(target)) {
                throw new IllegalStateException(kind + " is write-once; already exists: " + safeId);
            }
            FsOperations.writeNew(target, data);
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "{0} stored (write-once): {1}", new Object[] { kind, safeId });
            }
        } catch (FileAlreadyExistsException e) {
            throw new IllegalStateException(kind + " is write-once; already exists: " + safeId, e);
        } catch (IOException e) {
            throw new IllegalStateException("write-once store failed: " + kind + " " + safeId, e);
        }
    }

    private void writeWithHistory(final Path historyDir, final Path currentFile, final byte[] data,
            final FsHistoryPolicy policy, final String kind, final String safeId) {

        try {
            FsOperations.ensureDir(currentFile.getParent());

            if (policy.enabled()) {
                FsOperations.ensureDir(historyDir);
                Path entry = historyDir.resolve(historyFileName(Instant.now(), this.historySeq.incrementAndGet()));
                FsOperations.writeAtomic(entry, data);

                if (policy.cleanupStrategy() == FsHistoryPolicy.CleanupStrategy.ON_WRITE) {
                    cleanupHistory(historyDir, policy.retentionWindow());
                }
            }

            FsOperations.writeAtomic(currentFile, data);
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "{0} stored/updated: {1}", new Object[] { kind, safeId });
            }

        } catch (IOException e) {
            throw new IllegalStateException("store failed: " + kind + " " + safeId, e);
        }
    }

    private static String historyFileName(final Instant now, final long seq) {
        long tsMicros = now.getEpochSecond() * 1_000_000L + (now.getNano() / 1_000);
        return tsMicros + "-" + seq + ".bin";
    }

    private static void cleanupHistory(final Path historyDir, final Optional<Duration> retentionWindow) {
        if (retentionWindow.isEmpty()) {
            return;
        }
        Duration window = retentionWindow.get();
        Instant cutoff = Instant.now().minus(window);

        try {
            Files.list(historyDir).filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString())).forEach(p -> {
                        String name = p.getFileName().toString();
                        int dash = name.indexOf('-');
                        if (dash <= 0) {
                            return;
                        }
                        String tsPart = name.substring(0, dash);
                        try {
                            long tsMicros = Long.parseLong(tsPart);
                            Instant entryTime = Instant.ofEpochSecond(tsMicros / 1_000_000L,
                                    (tsMicros % 1_000_000L) * 1_000L); // NOPMD
                            if (entryTime.isBefore(cutoff)) {
                                Files.deleteIfExists(p);
                            }
                        } catch (NumberFormatException | IOException ignored) {
                            // deterministic best-effort; never fail a write due to cleanup
                        }
                    });
        } catch (IOException ignored) {
            // deterministic best-effort
        }
    }
}
