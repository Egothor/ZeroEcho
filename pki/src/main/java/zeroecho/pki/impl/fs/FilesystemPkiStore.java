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
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
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
import zeroecho.pki.impl.ProfileLifecycleFailure;
import zeroecho.pki.impl.ProfileLifecycleFailure.Code;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

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

    /* package */ static final String CURRENT_STORE_VERSION = "v2";
    private static final int SIGN_RECORD_MAGIC = 0x5A455352;
    private static final int CURRENT_SIGN_RECORD_VERSION = 2;
    private static final int SIGN_RECORD_HEADER_BYTES = Integer.BYTES * 2;
    private static final String SIGN_FINGERPRINT_PREFIX = "signfp:v1:";
    private static final int SIGN_FINGERPRINT_HEX_LENGTH = 64;
    private static final long INITIAL_FENCE = 0L;
    private static final String STORE_OWNERSHIP_UNAVAILABLE =
            "Filesystem store ownership unavailable: code=STORE_ALREADY_OPEN";

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
     * @param root store root directory
     * @param options store options
     * @param clock authoritative signing workflow clock
     * @throws IllegalArgumentException if an argument is {@code null}
     * @throws IllegalStateException if the store cannot be opened or is already
     *                               owned by another store instance or process
     */
    // StoreOwnership transfers to this store on success and remains open until close();
    // try-with-resources here would release process ownership at constructor return.
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
        try {
            ensureVersionFile();
            this.signingNamespace = ensureSigningNamespace();
            this.signingTimeWatermark = new AtomicLong(loadSigningTimeWatermark());
            this.historySeq = new AtomicLong(0L);

            LOG.log(Level.INFO, "running in {0}", root);
            this.ownership = acquiredOwnership;
            ownershipTransferred = true;
        } catch (IOException e) {
            throw new IllegalStateException("failed to open filesystem store at " + root, e);
        } finally {
            if (!ownershipTransferred) {
                acquiredOwnership.closeSilently();
            }
        }
    }

    /**
     * Exports a snapshot of this store as of time {@code at} into
     * {@code targetRoot}.
     *
     * <p>
     * This method is an implementation-only feature. It does not modify the current
     * store; it clones a new store layout and reconstructs {@code current.bin} for
     * history-tracked entities. The signing namespace, monotonic signing-time
     * watermark, and authoritative signing workflow records are safety metadata:
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
        new FsSnapshotExporter(this.options).exportSnapshot(this.paths.root(), targetRoot, at);
    }

    @Override
    public void putCa(final CaRecord record) {
        requireStoreUsable();
        Objects.requireNonNull(record, "record");
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
        return readOptional(p, FsCodec.CA_RECORD);
    }

    @Override
    public List<CaRecord> listCas() {
        requireStoreUsable();
        Path casRoot = this.paths.root().resolve("cas").resolve("by-id");
        return listCurrentRecords(casRoot, FsCodec.CA_RECORD);
    }

    @Override
    public void putCredential(final Credential credential) {
        requireStoreUsable();
        Objects.requireNonNull(credential, "credential");
        PkiId id = credential.credentialId();
        Path p = this.paths.credentialPath(id);
        writeOnce(p, FsCodec.encode(FsCodec.CREDENTIAL, credential), "CREDENTIAL", FsUtil.safeId(id));
    }

    @Override
    public Optional<Credential> getCredential(final PkiId credentialId) {
        requireStoreUsable();
        Objects.requireNonNull(credentialId, "credentialId");
        return readOptional(this.paths.credentialPath(credentialId), FsCodec.CREDENTIAL);
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
                throw new PkiException(
                        "Revocation durability unconfirmed: code=REVOCATION_DURABILITY_UNCONFIRMED");
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
    // Listing failures are intentionally replaced by one stable redacted boundary.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public List<RevocationJournal> listRevocationJournals() {
        requireStoreUsable();
        Path root = this.paths.root().resolve("revocations").resolve("by-credential");
        if (!Files.isDirectory(root)) {
            return List.of();
        }
        try (Stream<Path> directories = Files.list(root)) {
            List<RevocationJournal> journals = new ArrayList<>();
            for (Path entityDir : directories.filter(Files::isDirectory)
                    .sorted(Comparator.comparing(path -> path.getFileName().toString())).toList()) {
                Path journalPath = entityDir.resolve("journal.bin");
                if (Files.exists(journalPath)) {
                    RevocationJournal journal = decodeRevocationJournal(journalPath);
                    if (!entityDir.getFileName().toString().equals(FsUtil.safeId(journal.credentialId()))) {
                        throw corruptRevocationState();
                    }
                    journals.add(journal);
                }
            }
            return List.copyOf(journals);
        } catch (IOException ex) {
            throw corruptRevocationState();
        }
    }

    @Override
    public void putStatusObject(final StatusObject object) {
        requireStoreUsable();
        Objects.requireNonNull(object, "object");
        PkiId id = object.statusObjectId();
        writeOnce(this.paths.statusObjectPath(id), FsCodec.encode(FsCodec.STATUS_OBJECT, object), "STATUS_OBJECT",
                FsUtil.safeId(id));
    }

    @Override
    public Optional<StatusObject> getStatusObject(final PkiId statusObjectId) {
        requireStoreUsable();
        Objects.requireNonNull(statusObjectId, "statusObjectId");
        return readOptional(this.paths.statusObjectPath(statusObjectId), FsCodec.STATUS_OBJECT);
    }

    @Override
    public List<StatusObject> listStatusObjects(final PkiId issuerCaId) {
        requireStoreUsable();
        Objects.requireNonNull(issuerCaId, "issuerCaId");

        // Deterministic but coarse: scan all and filter by issuer id.
        // This is acceptable for a reference implementation; indexes can be added
        // later.
        Path byId = this.paths.root().resolve("status").resolve("by-id");
        List<StatusObject> all = listBinaryFiles(byId, FsCodec.STATUS_OBJECT);
        List<StatusObject> out = new ArrayList<>();
        for (StatusObject o : all) {
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
    // Persistence causes may contain filesystem data and are intentionally redacted.
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
        for (ImportedCertificateProfileVersion existing :
                listProfileVersions(candidate.reference().profileId())) {
            if (existing.definition().certificateType()
                    != candidate.definition().certificateType()) {
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
    // Persistence causes may contain filesystem data and are intentionally redacted.
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
            writeSignRecord(intent);
            return SignWorkflowStore.CreateResult.CREATED;
        } finally {
            releaseSignLock(intent.submissionId(), lock);
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
        Path root = paths.signWorkflowRoot();
        if (!Files.isDirectory(root)) {
            return List.of();
        }
        try (Stream<Path> directories = Files.list(root)) {
            return directories.filter(Files::isDirectory)
                    .map(directory -> directory.resolve(FsPaths.CURRENT_FILE))
                    .filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(Path::toString))
                    .map(this::readSignRecordFile)
                    .peek(record -> validateSignRecord(record.submissionId(), record))
                    .toList();
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to list authoritative signing records", ex);
        }
    }

    @Override
    public Optional<SignWorkflowStore.Record> tryClaimSign(PkiId submissionId, long expectedRevision,
            Duration lease) {
        requireStoreUsable();
        requirePositive(lease, "lease");
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<SignWorkflowStore.Record> optional = readSignRecord(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            SignWorkflowStore.Record current = optional.get();
            Instant now = signingNow();
            boolean claimable = current.state() == SignWorkflowStore.State.INTENT;
            boolean leaseAvailable = current.leaseUntil().isEmpty() || !current.leaseUntil().get().isAfter(now);
            if (current.revision() != expectedRevision || !claimable || !leaseAvailable) {
                return Optional.empty();
            }
            SignWorkflowStore.Record claimed = copySignRecord(current, current.state(), current.revision() + 1L,
                    current.fence() + 1L, Optional.of(now.plus(lease)), current.detailCode(), current.result(),
                    current.providerUpdatedAt());
            writeSignRecord(claimed);
            return Optional.of(claimed);
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
            Optional<SignWorkflowStore.Record> optional = readSignRecord(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            SignWorkflowStore.Record current = optional.get();
            if (current.revision() != expectedRevision || current.fence() != fence || current.leaseUntil().isEmpty()) {
                return Optional.empty();
            }
            SignWorkflowStore.Record renewed = copySignRecord(current, current.state(), current.revision() + 1L,
                    fence, Optional.of(signingNow().plus(lease)), current.detailCode(), current.result(),
                    current.providerUpdatedAt());
            writeSignRecord(renewed);
            return Optional.of(renewed);
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
            Optional<SignWorkflowStore.Record> optional = readSignRecord(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            SignWorkflowStore.Record current = optional.get();
            if (current.revision() != expectedRevision || current.fence() != fence
                    || !validSignTransition(current.state(), target)) {
                return Optional.empty();
            }
            if (target == SignWorkflowStore.State.SUCCEEDED && result.isEmpty()
                    || target != SignWorkflowStore.State.SUCCEEDED && result.isPresent()) {
                throw new IllegalArgumentException("Signing result does not match target state");
            }
            if (target == SignWorkflowStore.State.SUCCEEDED
                    && (providerUpdatedAt.isEmpty()
                            || !providerUpdatedAt.get().isBefore(current.deadline()))) {
                throw new IllegalArgumentException("Successful signing completion timestamp is not trustworthy");
            }
            SignWorkflowStore.Record transitioned = copySignRecord(current, target, current.revision() + 1L, fence,
                    Optional.empty(), detailCode, result, providerUpdatedAt);
            writeSignRecord(transitioned);
            return Optional.of(transitioned);
        } finally {
            releaseSignLock(submissionId, lock);
        }
    }

    @Override
    public Optional<SignWorkflowStore.Record> retireSign(PkiId submissionId, long expectedRevision, long fence) {
        requireStoreUsable();
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<SignWorkflowStore.Record> optional = readSignRecord(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            SignWorkflowStore.Record current = optional.get();
            if (current.revision() != expectedRevision || current.fence() != fence
                    || !isRetirableSignState(current.state())) {
                return Optional.empty();
            }
            SignWorkflowStore.Record retired = copySignRecord(current, SignWorkflowStore.State.RETIRED,
                    current.revision() + 1L, fence, Optional.empty(), Optional.of("RETIRED"), current.result(),
                    current.providerUpdatedAt());
            writeSignRecord(retired);
            return Optional.of(retired);
        } finally {
            releaseSignLock(submissionId, lock);
        }
    }

    @Override
    public int purgeExpiredSignRecords() {
        requireStoreUsable();
        Path root = paths.signWorkflowRoot();
        if (!Files.isDirectory(root)) {
            return 0;
        }
        int purged = 0;
        for (SignWorkflowStore.Record record : listSignRecords()) {
            if (record.state() == SignWorkflowStore.State.RETIRED
                    && !record.createdAt().plus(options.signingOperationHorizon()).isAfter(signingNow())) {
                SignLockEntry lock = acquireSignLock(record.submissionId());
                try {
                    Optional<SignWorkflowStore.Record> current = readSignRecord(record.submissionId());
                    if (current.isPresent() && current.get().state() == SignWorkflowStore.State.RETIRED
                            && !current.get().createdAt().plus(options.signingOperationHorizon())
                                    .isAfter(signingNow())
                            && Files.deleteIfExists(paths.signWorkflowPath(record.submissionId()))) {
                        purged++;
                    }
                } catch (IOException ex) {
                    throw new IllegalStateException("failed to purge signing workflow", ex);
                } finally {
                    releaseSignLock(record.submissionId(), lock);
                }
            }
        }
        return purged;
    }

    @Override
    public void close() throws IOException {
        this.ownership.close();
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
            CertificateProfileRef reference = FsCodec.decode(FsCodec.ACTIVE_PROFILE_REF,
                    FsOperations.readAll(path));
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
            ValidatedImportedProfile validated =
                    decodeValidatedProfileVersion(path, profileId, reference.profileVersion());
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
        RevocationState previous = current.map(RevocationJournal::latest).map(RevocationTransition::state)
                .orElse(null);
        RevocationState next = nextRevocationState(previous, command);
        long revision = current.map(RevocationJournal::latest).map(RevocationTransition::revision)
                .map(value -> {
                    try {
                        return Math.addExact(value, 1L);
                    } catch (ArithmeticException ex) {
                        throw corruptRevocationState();
                    }
                }).orElse(1L);
        List<RevocationTransition> transitions = new ArrayList<>(
                current.map(RevocationJournal::transitions).orElseGet(List::of));
        Optional<RevocationReason> permanentReason = command instanceof RevocationCommand.RevokePermanently revoke
                ? Optional.of(revoke.reason()) : Optional.empty();
        transitions.add(new RevocationTransition(revision, next, transitionTime,
                permanentReason, command.attributes()));
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
            case CLEAR -> unhold ? throwIllegalTransition()
                    : hold ? RevocationState.HELD : RevocationState.PERMANENTLY_REVOKED;
            case HELD -> hold ? throwIllegalTransition()
                    : unhold ? RevocationState.CLEAR : RevocationState.PERMANENTLY_REVOKED;
            case PERMANENTLY_REVOKED -> throw new PkiException(
                    "Revocation is terminal: code=REVOCATION_TERMINAL");
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
        Path path = paths.signWorkflowPath(submissionId);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        SignWorkflowStore.Record record = readSignRecordFile(path);
        validateSignRecord(submissionId, record);
        return Optional.of(record);
    }

    private SignWorkflowStore.Record readSignRecordFile(Path path) {
        try {
            byte[] envelope = FsOperations.readAll(path);
            if (envelope.length < SIGN_RECORD_HEADER_BYTES) {
                throw new IllegalStateException("Invalid signing record envelope");
            }
            ByteBuffer input = ByteBuffer.wrap(envelope);
            if (input.getInt() != SIGN_RECORD_MAGIC) {
                throw new IllegalStateException("Invalid signing record envelope");
            }
            if (input.getInt() != CURRENT_SIGN_RECORD_VERSION) {
                throw new IllegalStateException("Unsupported signing record version");
            }
            byte[] payload = new byte[input.remaining()];
            input.get(payload);
            return FsCodec.decode(FsCodec.SIGN_WORKFLOW_RECORD, payload);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to read authoritative signing record", ex);
        }
    }

    // Parsing and canonicalization failures can carry persisted request material;
    // validation deliberately replaces every such cause with a safe corruption code.
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
            continuation = PkiSigningBus.SignContinuation.decode(record.request());
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
        requireValidSignRecord(record.deadline().isAfter(record.createdAt())
                && !record.deadline().isAfter(horizonEnd), record, "DEADLINE_INVALID");
        requireValidSignRecord(continuation.isBoundTo(record.submissionId(), record.owner()), record,
                "CONTINUATION_IDENTITY_MISMATCH");

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

    private void writeSignRecord(SignWorkflowStore.Record record) {
        validateSignRecord(record.submissionId(), record);
        try {
            byte[] payload = FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, record);
            ByteBuffer envelope = ByteBuffer.allocate(SIGN_RECORD_HEADER_BYTES + payload.length);
            envelope.putInt(SIGN_RECORD_MAGIC);
            envelope.putInt(CURRENT_SIGN_RECORD_VERSION);
            envelope.put(payload);
            FsOperations.writeAtomic(paths.signWorkflowPath(record.submissionId()), envelope.array());
        } catch (IOException ex) {
            throw new IllegalStateException("failed to persist signing workflow", ex);
        }
    }

    private static SignWorkflowStore.Record copySignRecord(SignWorkflowStore.Record current,
            SignWorkflowStore.State state, long revision, long fence, Optional<Instant> leaseUntil,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt) {
        return new SignWorkflowStore.Record(current.submissionId(), current.namespace(), current.fingerprint(),
                current.owner(), current.createdAt(), current.deadline(), current.request(), state, revision, fence,
                leaseUntil, detailCode, result, providerUpdatedAt);
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
            return target == SignWorkflowStore.State.CANCELLING
                    || target == SignWorkflowStore.State.SUCCEEDED || target == SignWorkflowStore.State.FAILED
                    || target == SignWorkflowStore.State.CANCELLED || target == SignWorkflowStore.State.EXPIRED;
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
                    requireValidSignRecord(record.revision() >= record.fence()
                            && record.leaseUntil().isPresent(), record, "INTENT_CLAIM_INVALID");
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
                requireValidSignRecord(record.detailCode().filter(code -> "CANCEL_REQUESTED".equals(code)
                        || "CANCEL_SUBMITTED".equals(code)).isPresent(), record, "DETAIL_CODE_INVALID");
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
                requireValidSignRecord(record.revision() - record.fence() >= 2L, record,
                        "CANCELLED_REVISION_INVALID");
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
                    requireValidSignRecord(record.fence() > 0L && record.revision() - record.fence() >= 3L
                            && record.providerUpdatedAt().isPresent()
                            && record.providerUpdatedAt().get().isBefore(record.deadline()), record,
                            "PROVIDER_TIME_INVALID");
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
        return hasLifecycleCode(detailCode, "INTENT")
                || hasLifecycleCode(detailCode, "DISPATCHED")
                || hasLifecycleCode(detailCode, "CANCEL_REQUESTED")
                || hasLifecycleCode(detailCode, "CANCELLED")
                || hasLifecycleCode(detailCode, "EXPIRED")
                || hasLifecycleCode(detailCode, "RETIRED")
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

        // Raw lock exceptions are deliberately replaced by the stable redacted contention code.
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
                    throw new IOException("Filesystem store ownership release failed: "
                            + "code=STORE_OWNERSHIP_RELEASE_FAILED");
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

    private static <T> Optional<T> readOptional(final Path path, final FsCodec.Schema<T> schema) {
        try {
            if (!Files.exists(path)) {
                return Optional.empty();
            }
            byte[] data = FsOperations.readAll(path);
            return Optional.of(FsCodec.decode(schema, data));
        } catch (IOException e) {
            throw new IllegalStateException("read failed: " + path, e);
        }
    }

    private static <T> List<T> listBinaryFiles(final Path byIdDir, final FsCodec.Schema<T> schema) {
        if (!Files.isDirectory(byIdDir)) {
            return List.of();
        }
        try {
            return Files.list(byIdDir).filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> p.getFileName().toString())).map(p -> {
                        try {
                            return FsCodec.decode(schema, FsOperations.readAll(p));
                        } catch (IOException e) {
                            throw new IllegalStateException("read failed: " + p, e);
                        }
                    }).toList();
        } catch (IOException e) {
            throw new IllegalStateException("list failed: " + byIdDir, e);
        }
    }

    private static <T> List<T> listCurrentRecords(final Path byIdDir, final FsCodec.Schema<T> schema) {
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
                    out.add(FsCodec.decode(schema, FsOperations.readAll(current)));
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
