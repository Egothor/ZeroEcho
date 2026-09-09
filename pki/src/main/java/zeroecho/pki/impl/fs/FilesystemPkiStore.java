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
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import java.security.cert.X509Certificate;

import zeroecho.pkix.Pkix;


import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallengeIssuance;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationReview;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewPage;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.publication.PublicationCursor;
import zeroecho.pki.api.publication.PublicationFailure;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.impl.ProfileLifecycleFailure;
import zeroecho.pki.impl.ProfileLifecycleFailure.Code;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.core.async.DomainContinuationValidation;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.StagedContentStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.TemporaryUniqueIndex;
import zeroecho.pki.spi.store.RevocationSnapshot;
import zeroecho.pki.spi.store.RevocationView;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.AuditEvidenceFeed;
import zeroecho.pki.spi.store.RevocationTransitionFeed;

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
 * profiles append history before updating {@code current.bin}. Revocation
 * transitions append to one authenticated global log; current indexes and
 * ordered checkpoints are derived and rebuildable.</li>
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
 * <p>Opening validates and repairs the derived confirmation-review index in
 * {@code O((L + P + C) log M)} time, where {@code L} is the lifecycle-record count,
 * {@code P} is the review-projection count, {@code C} is the challenge count,
 * and {@code M} is the transactional
 * metadata population. Auxiliary heap is bounded by {@code O(4096 + 32S)}, where
 * {@code S} is the maximum encoded lifecycle-record size; repair cohorts contain
 * at most 32 independent singleton mutations and never execute while their
 * planning snapshot is live.</p>
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
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity", "PMD.TooManyMethods",
        "PMD.ExcessivePublicCount", "PMD.UseTryWithResources", "PMD.ExceptionAsFlowControl",
        "PMD.PreserveStackTrace", "PMD.NcssCount", "PMD.AvoidDuplicateLiterals",
        "PMD.ControlStatementBraces", "PMD.CollapsibleIfStatements", "PMD.AvoidDeeplyNestedIfStmts",
        "PMD.AvoidLiteralsInIfCondition", "PMD.AvoidCatchingGenericException",
        "PMD.AvoidInstantiatingObjectsInLoops", "PMD.CloseResource", "PMD.CommentRequired" })
public final class FilesystemPkiStore implements PkiStore, AtomicLocalSigningLedgerParticipant, Closeable {

    private static final Logger LOG = Logger.getLogger(FilesystemPkiStore.class.getName());

    /* package */ static final String CURRENT_STORE_VERSION = "v12";
    private static final byte[] CURRENT_STORE_VERSION_BYTES =
            CURRENT_STORE_VERSION.getBytes(StandardCharsets.US_ASCII);
    private static final String SIGN_RECORD_NAMESPACE = "io.zeroecho.pki.signing-record";
    private static final String DOMAIN_CONT_NAMESPACE = "io.zeroecho.pki.domain-continuation";
    private static final String DOMAIN_CORRELATION_NAMESPACE = "io.zeroecho.pki.domain-correlation";
    private static final String STATUS_RECORD_NAMESPACE = "io.zeroecho.pki.status-object-record";
    private static final String STATUS_OWNER_NAMESPACE = "io.zeroecho.pki.status-object-owner";
    private static final String PUBLICATION_RECORD_NAMESPACE = "io.zeroecho.pki.publication-record";
    private static final String CREDENTIAL_SERIAL_NAMESPACE = "io.zeroecho.pki.credential-serial-index";
    /* default */ static final String ISSUANCE_EVIDENCE_NAMESPACE = "io.zeroecho.pki.issuance-evidence-log";
    /* default */ static final String STATUS_EVIDENCE_NAMESPACE = "io.zeroecho.pki.status-evidence-log";
    /* default */ static final String PUBLICATION_EVIDENCE_NS = "io.zeroecho.pki.publication-evidence-log";
    /* default */ static final String SIGNING_EVIDENCE_NAMESPACE = "io.zeroecho.pki.signing-evidence-log";
    private static final String CONFIRMATION_RECORD_NS = "io.zeroecho.pki.confirmation-record";
    private static final String CONFIRMATION_REVIEW_NS = "io.zeroecho.pki.confirmation-review";
    private static final String CONFIRMATION_CHALLENGE_NS =
            "io.zeroecho.pki.confirmation-challenge";
    private static final int CONFIRMATION_REPAIR_LIMIT = 31;
    private static final int MAX_LIST_REPAIRS = 10;
    private static final int MAX_LIST_REPAIR_DELETES = 30;
    private static final long CONFIRMATION_EPOCH_MAX = 253_402_300_799L;
    private static final int CURRENT_SIGN_RECORD_VERSION = 4;
    private static final int DOMAIN_CONTINUATION_VERSION = 2;
    private static final int SIGN_OWNER_VALUE_VERSION = 1;
    private static final int STATUS_OWNER_VALUE_VERSION = 1;
    private static final int METADATA_BUFFER_BYTES = 16 * 1024;
    private static final int MAX_METADATA_VALUE_BYTES = FsCodec.MAX_COMPONENT_BYTES + 64 * 1024;
    private static final ThreadLocal<StatusCommitFaultPoint> STATUS_COMMIT_FAULT = new ThreadLocal<>();
    private static final ThreadLocal<PublicationCommitFaultPoint> PUBLICATION_COMMIT_FAULT = new ThreadLocal<>();
    private static final ThreadLocal<Runnable> SIGN_ADMISSION_OBSERVER = new ThreadLocal<>();
    private static final String SIGN_FINGERPRINT_PREFIX = "signfp:v3:";
    private static final int SIGN_FINGERPRINT_HEX_LENGTH = 64;
    private static final long INITIAL_FENCE = 0L;
    private static final String STORE_OWNERSHIP_UNAVAILABLE = "Filesystem store ownership unavailable: code=STORE_ALREADY_OPEN";

    private final FsPkiStoreOptions options;
    private final FsPaths paths;
    private final AtomicLong historySeq;
    private final Clock clock;
    private final String signingNamespace;
    private final AtomicLong signingTimeWatermark;
    private final ConcurrentMap<PkiId, SignLockEntry> signLocks;
    private final ConcurrentMap<PkiId, AtomicBoolean> localSignCancellations;
    private final ConcurrentMap<PkiId, CredentialStateLockEntry> credentialStateLocks;
    private final ConcurrentMap<String, ProfileLockEntry> profileLocks;
    private final AtomicBoolean durabilityUncertain;
    private final AtomicBoolean closing;
    private final int maximumSigningWork;
    private final SigningActiveWal.Operations signingWalOperations;
    private final SigningActiveWal.Configuration signingWalConfiguration;
    private final FilesystemStagedContentStore stagedContent;
    private final CredentialContentTransaction credentialTransactions;
    private final SegmentedTransactionalMetadataStore metadataStore;
    private final MetadataEvidenceLog issuanceEvidenceLog;
    private final MetadataEvidenceLog statusEvidenceLog;
    private final MetadataEvidenceLog publicationEvidenceLog;
    // Non-null only when the operator opts into per-signing key-usage audit (FsPkiStoreOptions.signingEvidenceAudit).
    private final MetadataEvidenceLog signingEvidenceLog;
    private final FilesystemRevocationAuthority revocations;
    private final SigningContentRetirementFaultInjector signingRetirementFaults;
    private final ConfirmationRevocationCleanupFaultInjector confirmationCleanupFaults;

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
    public FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock) {
        this(root, options, clock, FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE);
    }

    /* package */ FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock,
            final FilesystemRevocationAuthority.IndexUpdateFaultInjector indexUpdateFaults) {
        this(root, options, clock, indexUpdateFaults, SigningContentRetirementFaultInjector.NONE,
                ConfirmationRevocationCleanupFaultInjector.NONE, false,
                SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, null);
    }

    /* package */ FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock,
            final FilesystemRevocationAuthority.IndexUpdateFaultInjector indexUpdateFaults,
            final SigningContentRetirementFaultInjector signingRetirementFaults) {
        this(root, options, clock, indexUpdateFaults, signingRetirementFaults,
                ConfirmationRevocationCleanupFaultInjector.NONE, false,
                SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, null);
    }

    /* package */ FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock,
            final ConfirmationRevocationCleanupFaultInjector confirmationCleanupFaults) {
        this(root, options, clock, FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE,
                SigningContentRetirementFaultInjector.NONE, confirmationCleanupFaults,
                false, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, null);
    }

    /* package */ FilesystemPkiStore(final Path root, final FsPkiStoreOptions options,
            final Clock clock, final int maximumSigningWork,
            final SigningActiveWal.Operations signingWalOperations) {
        this(root, options, clock, FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE,
                SigningContentRetirementFaultInjector.NONE,
                ConfirmationRevocationCleanupFaultInjector.NONE, false,
                maximumSigningWork, signingWalOperations);
    }

    /* package */ FilesystemPkiStore(final Path root, final FsPkiStoreOptions options,
            final Clock clock, final int maximumSigningWork,
            final SigningActiveWal.Operations signingWalOperations,
            final SigningActiveWal.Configuration signingWalConfiguration) {
        this(root, options, clock, FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE,
                SigningContentRetirementFaultInjector.NONE,
                ConfirmationRevocationCleanupFaultInjector.NONE, false,
                maximumSigningWork, signingWalOperations, signingWalConfiguration);
    }

    private FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock,
            final FilesystemRevocationAuthority.IndexUpdateFaultInjector indexUpdateFaults,
            final SigningContentRetirementFaultInjector signingRetirementFaults,
            final ConfirmationRevocationCleanupFaultInjector confirmationCleanupFaults,
            final boolean snapshotAssembly, final int maximumSigningWork,
            final SigningActiveWal.Operations signingWalOperations) {
        this(root, options, clock, indexUpdateFaults, signingRetirementFaults,
                confirmationCleanupFaults, snapshotAssembly, maximumSigningWork,
                signingWalOperations, SigningActiveWal.Configuration.defaults(
                        Objects.requireNonNull(options, "options").signingMaximumGroupSize()));
    }

    @SuppressWarnings("PMD.CloseResource")
    private FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock,
            final FilesystemRevocationAuthority.IndexUpdateFaultInjector indexUpdateFaults,
            final SigningContentRetirementFaultInjector signingRetirementFaults,
            final ConfirmationRevocationCleanupFaultInjector confirmationCleanupFaults,
            final boolean snapshotAssembly, final int maximumSigningWork,
            final SigningActiveWal.Operations signingWalOperations,
            final SigningActiveWal.Configuration signingWalConfiguration) {
        this.options = Objects.requireNonNull(options, "options");
        Objects.requireNonNull(root, "root");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.signLocks = new ConcurrentHashMap<>();
        this.localSignCancellations = new ConcurrentHashMap<>();
        this.credentialStateLocks = new ConcurrentHashMap<>();
        this.profileLocks = new ConcurrentHashMap<>();
        this.durabilityUncertain = new AtomicBoolean();
        this.closing = new AtomicBoolean();
        if (maximumSigningWork <= 0
                || maximumSigningWork > SigningDueWorkIndex.FOUR_GIB_ORDERED_LIMIT) {
            throw new IllegalArgumentException("maximumSigningWork is invalid");
        }
        this.maximumSigningWork = maximumSigningWork;
        this.signingWalOperations = signingWalOperations;
        this.signingWalConfiguration = Objects.requireNonNull(
                signingWalConfiguration, "signingWalConfiguration");
        this.signingRetirementFaults = Objects.requireNonNull(signingRetirementFaults,
                "signingRetirementFaults");
        this.confirmationCleanupFaults = Objects.requireNonNull(
                confirmationCleanupFaults, "confirmationCleanupFaults");
        this.paths = new FsPaths(root);

        StoreOwnership acquiredOwnership;
        try {
            preflightExistingRoot(root, snapshotAssembly,
                    recoveryConfiguration(signingWalConfiguration));
            FsOperations.ensureDir(root);
            PlatformFs.requireOwnerOnlyCapable(root);
            PlatformFs.ops().restrictToOwner(root);
            FsOperations.ensureDir(this.paths.lockFile().getParent());
            acquiredOwnership = StoreOwnership.acquire(this.paths.lockFile());
        } catch (IOException e) {
            throw new IllegalStateException("Filesystem store open failed: code=STORE_OPEN_FAILED", e);
        }

        boolean ownershipTransferred = false;
        SegmentedTransactionalMetadataStore openedMetadata = null;
        FilesystemRevocationAuthority openedRevocations = null;
        try {
            boolean newStore = !Files.exists(this.paths.versionFile());
            boolean initializeMetadata = newStore && !Files.exists(
                    this.paths.transactionalMetadataRoot().resolve(SigningLedgerRecovery.FORMAT_FILE));
            if (newStore && !snapshotAssembly) {
                rejectNonEmptyUnversionedStore();
            }
            ensureVersionFile();
            rejectObsoletePublicationLayout();
            this.signingNamespace = ensureSigningNamespace();
            this.stagedContent = new FilesystemStagedContentStore(this.paths.stagedContentRoot(),
                    this.signingNamespace);
            FsOperations.ensureDir(this.paths.transactionalMetadataRoot());
            openedMetadata = openMetadataStore(initializeMetadata);
            this.metadataStore = openedMetadata;
            this.issuanceEvidenceLog = new MetadataEvidenceLog(openedMetadata, ISSUANCE_EVIDENCE_NAMESPACE);
            this.statusEvidenceLog = new MetadataEvidenceLog(openedMetadata, STATUS_EVIDENCE_NAMESPACE);
            this.publicationEvidenceLog = new MetadataEvidenceLog(openedMetadata, PUBLICATION_EVIDENCE_NS);
            this.signingEvidenceLog = options.signingEvidenceAudit()
                    ? new MetadataEvidenceLog(openedMetadata, SIGNING_EVIDENCE_NAMESPACE) : null;
            this.stagedContent.bindTransactionalOwnership(
                    new FilesystemStagedContentStore.TransactionalOwnership() {
                        @Override
                        public Set<DurableContentOwner> findOwners(
                                DurableContentReference reference) throws IOException {
                            return findTransactionalOwners(reference);
                        }

                        @Override
                        public boolean hasOwner(DurableContentReference reference)
                                throws IOException {
                            return hasTransactionalOwner(reference);
                        }
                    });
            this.credentialTransactions = new CredentialContentTransaction(this.paths, this.stagedContent);
            this.signingTimeWatermark = new AtomicLong(openedMetadata.recoveredWatermark());
            this.historySeq = new AtomicLong(0L);
            if (!snapshotAssembly) {
                recoverStagedContent();
                reconcileSigningEvidence();
            }
            rebuildCredentialSerialIndex();
            recoverPublicationRecords();
            boolean snapshotRestore = requireSnapshotBoundary();
            openedRevocations = FilesystemRevocationAuthority.open(
                    this.paths, new MetadataStoreId(this.signingNamespace), credentialId -> {
                        if (getCredential(credentialId).isEmpty()) {
                            throw new IOException("Revocation credential authority is missing");
                        }
                    }, newStore, indexUpdateFaults);
            this.revocations = openedRevocations;
            rebuildCredentialConfirmationReviewIndex();
            removeRevokedCredentialConfirmationChallenges();
            validateCredentialConfirmationChallenges();
            if (snapshotRestore) {
                Files.delete(this.paths.revocationSnapshotBoundary());
                SigningFormatSupport.forceDirectory(this.paths.root());
            }

            LOG.log(Level.INFO, "Filesystem PKI store opened");
            this.ownership = acquiredOwnership;
            ownershipTransferred = true;
        } catch (IOException e) {
            throw new IllegalStateException("Filesystem store open failed: code=STORE_OPEN_FAILED", e);
        } finally {
            if (!ownershipTransferred) {
                if (openedRevocations != null) {
                    try {
                        openedRevocations.close();
                    } catch (IOException closeFailure) {
                        LOG.log(Level.WARNING, "Revocation-store cleanup failed during initialization");
                    }
                }
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

    private static void preflightExistingRoot(Path root, boolean snapshotAssembly,
            SigningLedgerRecovery.Configuration recoveryConfiguration)
            throws IOException {
        if (!Files.exists(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return;
        if (!Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(root)) {
            throw new IOException("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
        }
        Path version = root.resolve("VERSION");
        if (!Files.exists(version, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            try (Stream<Path> entries = Files.list(root)) {
                if (entries.findAny().isPresent() && !snapshotAssembly) {
                    throw new IOException(
                            "Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
                }
            }
            return;
        }
        requireCurrentStoreVersion(version);
        Path metadata = root.resolve("metadata");
        if (Files.exists(metadata, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            try {
                SigningLedgerRecovery.validateExistingLayout(
                        metadata, recoveryConfiguration);
            } catch (SigningLedgerRecovery.RecoveryException malformed) {
                throw new IOException(
                        "Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
            }
        } else if (!snapshotAssembly) {
            throw new IOException(
                    "Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
        }
    }

    private static SigningLedgerRecovery.Configuration recoveryConfiguration(
            SigningActiveWal.Configuration activeWalConfiguration) {
        SigningLedgerRecovery.Configuration defaults = SigningLedgerRecovery.Configuration.defaults();
        return new SigningLedgerRecovery.Configuration(defaults.maximumRootEntries(),
                defaults.maximumArtifactBytes(), defaults.maximumCheckpointEntries(),
                activeWalConfiguration);
    }

    /* package */ static FilesystemPkiStore openSnapshotAssembly(final Path root,
            final FsPkiStoreOptions options) {
        return new FilesystemPkiStore(root, options, Clock.systemUTC(),
                FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE,
                SigningContentRetirementFaultInjector.NONE,
                ConfirmationRevocationCleanupFaultInjector.NONE, true,
                SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, null);
    }

    private boolean requireSnapshotBoundary() throws IOException {
        Path marker = paths.revocationSnapshotBoundary();
        if (!Files.exists(marker, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        if (!Files.isRegularFile(marker, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Revocation snapshot boundary is invalid");
        }
        String encoded;
        try (FileChannel channel = FileChannel.open(marker, StandardOpenOption.READ,
                java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            long size = channel.size();
            if (size < 1L || size > 19L) {
                throw new IOException("Revocation snapshot boundary is invalid");
            }
            ByteBuffer buffer = ByteBuffer.allocate(19);
            while (buffer.position() < size) {
                int read = channel.read(buffer);
                if (read <= 0) {
                    throw new IOException("Revocation snapshot boundary is invalid");
                }
            }
            encoded = new String(buffer.array(), 0, (int) size, StandardCharsets.US_ASCII);
        }
        long expected;
        try {
            expected = Long.parseLong(encoded);
        } catch (NumberFormatException failure) {
            throw new IOException("Revocation snapshot boundary is invalid");
        }
        if (!Long.toString(expected).equals(encoded)
                || expected < RevocationTransitionFrameCodec.PREAMBLE_BYTES
                || !Files.isRegularFile(paths.revocationTransitionLog())
                || Files.size(paths.revocationTransitionLog()) != expected) {
            throw new IOException("Revocation snapshot authority boundary is invalid");
        }
        return true;
    }

    private static void closeMetadataAfterFailedOpen(SegmentedTransactionalMetadataStore openedMetadata)
            throws IOException {
        openedMetadata.close();
    }

    private SegmentedTransactionalMetadataStore openMetadataStore(boolean initialize) throws IOException {
        Path root = paths.transactionalMetadataRoot();
        SegmentedTransactionalMetadataStore opened = initialize
                ? SegmentedTransactionalMetadataStore.create(root,
                        new MetadataStoreId(signingNamespace), signingWalOperations, maximumSigningWork,
                        signingWalConfiguration, options.signingResidentIndexBudgetBytes(),
                        options.signingCompactionTransientBudgetBytes())
                : SegmentedTransactionalMetadataStore.open(root,
                        new MetadataStoreId(signingNamespace), maximumSigningWork,
                        signingWalConfiguration, options.signingResidentIndexBudgetBytes(),
                        options.signingCompactionTransientBudgetBytes());
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
        visitSigningOwners(reference, (submissionId, candidate) ->
                owners.add(DurableContentOwner.signingOperation(submissionId)));
        return Set.copyOf(owners);
    }

    private Set<DurableContentOwner> findTransactionalOwners(DurableContentReference reference) throws IOException {
        Set<DurableContentOwner> owners = new HashSet<>(findSigningOwner(reference));
        if (reference.lifecycle() != DurableContentReference.Lifecycle.PERSISTED) {
            return Set.copyOf(owners);
        }
        for (StoredStatus stored : listStoredStatuses()) {
            if (reference.equals(stored.status().content())) {
                owners.add(new DurableContentOwner(DurableContentOwner.Category.STATUS_OBJECT_RECORD,
                        stored.status().statusObjectId().value()));
            }
        }
        return Set.copyOf(owners);
    }

    private boolean hasTransactionalOwner(DurableContentReference reference) throws IOException {
        if (hasSigningOwner(reference)) return true;
        if (reference.lifecycle() != DurableContentReference.Lifecycle.PERSISTED) return false;
        for (StoredStatus stored : listStoredStatuses()) {
            if (reference.equals(stored.status().content())) return true;
        }
        return false;
    }

    private boolean hasSigningOwner(DurableContentReference reference) throws IOException {
        boolean[] found = { false };
        visitSigningOwners(reference, (submissionId, candidate) -> found[0] = true, true);
        return found[0];
    }

    @Override
    public StagedContentStore stagedContent() {
        return stagedContent;
    }

    private void recoverStagedContent() throws IOException {
        // Reconcile the crash window between a committed credential file and its issuance-evidence append:
        // the same O(N) published-record scan re-appends any missing entry (idempotent per credential).
        credentialTransactions.recover(this::recordIssuanceEvidence);
        List<StoredStatus> statuses = listStoredStatuses();
        // Reconcile the status-evidence crash window on the SAME enumeration used for staged-content
        // recovery, so startup adds no second full scan of status objects (idempotent per object).
        for (StoredStatus stored : statuses) {
            recordStatusEvidence(stored.status());
        }
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
        Optional<String> cursor = Optional.empty();
        while (true) {
            try (SegmentedTransactionalMetadataStore.SigningDuePage page =
                    metadataStore.pageSigningDue(Instant.MAX, cursor, Optional.empty(), 4096)) {
                MetadataSnapshot snapshot = page.snapshot();
                for (SegmentedTransactionalMetadataStore.SigningDueCandidate candidate
                        : page.candidates()) {
                    if (candidate.malformed()) {
                        throw new IllegalStateException("Projected signing record is malformed");
                    }
                    PkiId submissionId = new PkiId(candidate.operationId());
                    try {
                        try (MetadataSnapshot.Record record = snapshot.get(signingRecordKey(submissionId))
                                .orElseThrow(() -> new IllegalStateException(
                                        "Projected signing record metadata is missing"))) {
                            addRetained(retained, decodeStoredSign(snapshot, record)
                                    .reference().orElseThrow());
                        }
                    } catch (IOException malformed) {
                        throw new IllegalStateException("Projected signing record is malformed");
                    }
                }
                if (page.endReached()) return;
                if (page.candidates().isEmpty()) {
                    throw new IllegalStateException("Projected signing record page did not advance");
                }
                cursor = Optional.of(page.candidates().getLast().operationId());
            }
        }
    }

    private void visitSigningOwners(DurableContentReference reference,
            SigningOwnerVisitor visitor) throws IOException {
        visitSigningOwners(reference, visitor, false);
    }

    private void visitSigningOwners(DurableContentReference reference,
            SigningOwnerVisitor visitor, boolean stopAfterFirst) throws IOException {
        MetadataSnapshot.KeyRange range = SigningOwnerKey.contentRange(reference);
        try (SegmentedTransactionalMetadataStore.CurrentSelection selection = stopAfterFirst
                ? metadataStore.selectCurrentFirst(range)
                : metadataStore.selectCurrentRange(range)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = selection.next()).isPresent()) {
                try (MetadataSnapshot.Record owner = next.orElseThrow()) {
                    SigningOwnerKey.Parsed parsed;
                    try {
                        parsed = SigningOwnerKey.parse(owner.key());
                    } catch (IllegalArgumentException malformed) {
                        throw new IOException("Signing owner key is invalid", malformed);
                    }
                    DurableContentReference candidate = decodeSigningOwner(
                            owner, parsed.submissionId());
                    if (!reference.equals(candidate)
                            || !reference.contentId().equals(parsed.contentId())) {
                        throw new IOException("Signing owner reference mismatch");
                    }
                    visitor.visit(parsed.submissionId(), candidate);
                    if (stopAfterFirst) return;
                }
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
        try {
            metadataStore.advanceWatermark(signingNow().toEpochMilli());
        } catch (IOException failure) {
            durabilityUncertain.set(true);
            throw storeDurabilityUnconfirmed(
                    "Snapshot watermark durability failed: code=STORE_DURABILITY_UNCONFIRMED");
        }
        new FsSnapshotExporter(this.options).exportSnapshot(this, targetRoot, at);
    }

    /* default */ Path snapshotRoot() {
        return paths.root();
    }

    /* default */ SegmentedTransactionalMetadataStore metadataStore() {
        return metadataStore;
    }

    /* default */ FilesystemRevocationLog.RecoveryTarget copyRevocationPrefix(Path target)
            throws IOException {
        requireStoreUsable();
        return revocations.copyAuthoritativePrefix(target);
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

    /* default */ void copySnapshotMetadataTo(Path targetRoot) throws IOException {
        requireStoreUsable();
        Objects.requireNonNull(targetRoot, "targetRoot");
        Path metadataRoot = new FsPaths(targetRoot).transactionalMetadataRoot();
        FsOperations.ensureDir(metadataRoot);
        metadataStore.exportSnapshotTo(metadataRoot, Set.of(STATUS_RECORD_NAMESPACE,
                STATUS_OWNER_NAMESPACE, PUBLICATION_RECORD_NAMESPACE,
                CREDENTIAL_SERIAL_NAMESPACE));
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
    public List<CaRecord> listCasPage(Optional<PkiId> afterCaId, int limit) {
        requireStoreUsable();
        Objects.requireNonNull(afterCaId, "afterCaId");
        if (limit <= 0 || limit > 1_000) {
            throw new IllegalArgumentException("limit must be between 1 and 1000");
        }
        Path root = paths.root().resolve("cas").resolve("by-id");
        if (!Files.isDirectory(root)) {
            return List.of();
        }
        String after = afterCaId.map(PkiId::value).orElse("");
        List<CaRecord> selected = new ArrayList<>(limit);
        try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(root)) {
            for (Path entry : entries) {
                Path current = entry.resolve(FsPaths.CURRENT_FILE);
                if (!Files.isDirectory(entry) || !Files.isRegularFile(current)) {
                    continue;
                }
                CaRecord record = validateCaCredentialReferences(
                        FsCodec.decode(FsCodec.CA_RECORD, FsOperations.readAll(current), stagedContent));
                if (record.caId().value().compareTo(after) <= 0) {
                    continue;
                }
                int position = java.util.Collections.binarySearch(selected, record,
                        Comparator.comparing(value -> value.caId().value()));
                selected.add(position < 0 ? -position - 1 : position, record);
                if (selected.size() > limit) {
                    selected.remove(limit);
                }
            }
            return List.copyOf(selected);
        } catch (IOException exception) {
            throw new IllegalStateException("list CA page failed", exception);
        }
    }

    @Override
    public void putIssuerGeneration(IssuerGeneration generation) {
        requireStoreUsable();
        Objects.requireNonNull(generation, "generation");
        Credential credential = getCredential(generation.credentialId())
                .orElseThrow(() -> new IllegalStateException("Issuer credential reference is missing"));
        if (!credential.credentialId().equals(generation.credentialId())) {
            throw new IllegalStateException("Issuer credential identity mismatch");
        }
        writeOnce(paths.issuerGenerationPath(generation.issuerId()),
                FsCodec.encode(FsCodec.ISSUER_GENERATION, generation), "ISSUER_GENERATION",
                FsUtil.safeId(generation.issuerId()));
        x509Serial(credential).ifPresent(serial -> {
            requireSerialAvailable(generation.issuerId(), serial, generation.credentialId());
            ensureSerialIndex(generation.issuerId(), serial, generation.credentialId());
        });
    }

    @Override
    public Optional<IssuerGeneration> getIssuerGeneration(PkiId issuerId) {
        requireStoreUsable();
        Objects.requireNonNull(issuerId, "issuerId");
        return readOptional(paths.issuerGenerationPath(issuerId), FsCodec.ISSUER_GENERATION)
                .map(this::validateIssuerGeneration);
    }

    @Override
    public List<IssuerGeneration> listIssuerGenerations(PkiId authorityId) {
        requireStoreUsable();
        Objects.requireNonNull(authorityId, "authorityId");
        Path root = paths.root().resolve("issuer-generations").resolve("by-id");
        return listBinaryRecords(root, FsCodec.ISSUER_GENERATION).stream().map(this::validateIssuerGeneration)
                .filter(value -> authorityId.equals(value.authorityId())).toList();
    }

    @Override
    public void putIssuerChainPath(IssuerChainPath path) {
        requireStoreUsable();
        Objects.requireNonNull(path, "path");
        validateIssuerChainPath(path);
        writeOnce(paths.issuerChainPath(path.pathId()), FsCodec.encode(FsCodec.ISSUER_CHAIN_PATH, path),
                "ISSUER_CHAIN_PATH", FsUtil.safeId(path.pathId()));
    }

    @Override
    public Optional<IssuerChainPath> getIssuerChainPath(PkiId pathId) {
        requireStoreUsable();
        Objects.requireNonNull(pathId, "pathId");
        return readOptional(paths.issuerChainPath(pathId), FsCodec.ISSUER_CHAIN_PATH)
                .map(this::validateIssuerChainPath);
    }

    @Override
    public List<IssuerChainPath> listIssuerChainPaths(PkiId issuerId) {
        requireStoreUsable();
        Objects.requireNonNull(issuerId, "issuerId");
        Path root = paths.root().resolve("issuer-chain-paths").resolve("by-id");
        return listBinaryRecords(root, FsCodec.ISSUER_CHAIN_PATH).stream()
                .map(this::validateIssuerChainPath)
                .filter(value -> issuerId.equals(value.issuerId())).toList();
    }

    @Override
    public void putCredential(final Credential credential) {
        requireStoreUsable();
        Objects.requireNonNull(credential, "credential");
        Optional<BigInteger> serial = indexableSerial(credential);
        serial.ifPresent(value -> requireSerialAvailable(credential.issuerRef().issuerId(), value, credential));
        credentialTransactions.put(credential);
        serial.ifPresent(value -> ensureSerialIndex(credential.issuerRef().issuerId(), value,
                credential.credentialId()));
        recordIssuanceEvidence(credential);
    }

    // Appends one append-ordered issuance-evidence index entry for a committed end-entity credential, so the
    // audit projector can advance a durable cursor. Idempotent per credential (safe under crash-window retry
    // and startup reconciliation). The credential's co-committed attributes remain the evidence authority.
    // Best-effort: the credential is already durably committed by the time this runs, so an unconfirmed
    // evidence-log append must NOT fail the operation (that would orphan the committed credential for a
    // non-idempotent caller); startup reconciliation re-appends any missing entry from the committed record.
    private void recordIssuanceEvidence(Credential credential) {
        if (!(credential.profileBinding() instanceof EndEntityProfileBinding)) {
            return;
        }
        byte[] payload = zeroecho.pki.impl.core.async.DomainAttributeEncoding.encode(credential.attributes())
                .getBytes(StandardCharsets.UTF_8);
        try {
            issuanceEvidenceLog.append(credential.credentialId(), credential.validity().notBefore(), payload);
        } catch (IOException failure) {
            LOG.log(Level.WARNING, "Issuance evidence log append deferred to reconciliation: code=EVIDENCE_APPEND_UNCONFIRMED");
        }
    }

    // Appends one append-ordered status-generation-evidence entry for a committed status object. The evidence
    // is derived entirely from the status object (status generation has no external actor), so appending at
    // this single choke point covers synchronous, asynchronous (continuation), and snapshot-restore writes.
    // Idempotent per status object (safe under crash-window retry and startup reconciliation).
    private void recordStatusEvidence(StatusObject object) {
        zeroecho.pki.application.StatusGenerationEvidence evidence =
                zeroecho.pki.application.StatusGenerationEvidence.system(object.type().name(),
                        object.issuerCaId().value(), object.formatId().value(), object.thisUpdate().toString(),
                        object.nextUpdate().map(Instant::toString));
        byte[] payload = zeroecho.pki.impl.core.async.DomainAttributeEncoding.encode(evidence.attributes())
                .getBytes(StandardCharsets.UTF_8);
        try {
            statusEvidenceLog.append(object.statusObjectId(), object.thisUpdate(), payload);
        } catch (IOException failure) {
            // Best-effort: the status object is already committed; startup reconciliation re-appends.
            LOG.log(Level.WARNING, "Status evidence log append deferred to reconciliation: code=EVIDENCE_APPEND_UNCONFIRMED");
        }
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
            return Optional.of(credentialTransactions.validateLoaded(credentialId, credential));
        } catch (IOException failure) {
            throw new IllegalStateException("Credential read failed", failure);
        }
    }

    @Override
    public Optional<Credential> getCredentialByIssuerAndSerial(PkiId issuerId, BigInteger serial) {
        requireStoreUsable();
        Objects.requireNonNull(issuerId, "issuerId");
        requirePositiveSerial(serial);
        MetadataKey key = serialIndexKey(issuerId, serial);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> stored = snapshot.get(key);
            if (stored.isEmpty()) return Optional.empty();
            PkiId credentialId;
            try (MetadataSnapshot.Record record = stored.orElseThrow()) {
                credentialId = decodeSerialIndex(record, issuerId, serial);
            }
            Credential credential = getCredential(credentialId)
                    .orElseThrow(() -> new IllegalStateException("Credential serial index target is missing"));
            if (!credential.issuerRef().issuerId().equals(issuerId)
                    || !x509Serial(credential).filter(serial::equals).isPresent()) {
                throw new IllegalStateException("Credential serial index authority mismatch");
            }
            return Optional.of(credential);
        } catch (IOException failure) {
            throw new IllegalStateException("Credential serial index is invalid");
        }
    }

    private void rebuildCredentialSerialIndex() throws IOException {
        Path root = paths.root().resolve("credentials").resolve("by-id");
        if (!Files.isDirectory(root)) return;
        try (Stream<Path> records = Files.list(root)) {
            java.util.Iterator<Path> iterator = records
                    .filter(path -> path.getFileName().toString().endsWith(".bin"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString())).iterator();
            while (iterator.hasNext()) {
                Credential credential = FsCodec.decode(FsCodec.CREDENTIAL,
                        FsOperations.readAll(iterator.next()), stagedContent);
                Optional<BigInteger> serial = indexableSerial(credential);
                if (serial.isPresent()) {
                    requireSerialAvailable(credential.issuerRef().issuerId(), serial.orElseThrow(), credential);
                    ensureSerialIndex(credential.issuerRef().issuerId(), serial.orElseThrow(),
                            credential.credentialId());
                }
            }
        }
    }

    private void rebuildCredentialConfirmationReviewIndex() throws IOException {
        runConfirmationRepairPass(true);
        runConfirmationRepairPass(false);
    }

    private void runConfirmationRepairPass(boolean authoritativePass) throws IOException {
        Optional<MetadataKey> resumeInclusive = Optional.empty();
        while (true) {
            ConfirmationRepairBatch batch = authoritativePass
                    ? planConfirmationAuthorityRepairs(resumeInclusive)
                    : planConfirmationDerivedRepairs(resumeInclusive);
            commitConfirmationRepairs(batch.repairs());
            if (batch.endReached()) {
                return;
            }
            resumeInclusive = batch.lastExamined();
        }
    }

    private ConfirmationRepairBatch planConfirmationAuthorityRepairs(
            Optional<MetadataKey> resumeInclusive) throws IOException {
        List<ConfirmationIndexRepair> repairs = new ArrayList<>(CONFIRMATION_REPAIR_LIMIT);
        MetadataKey lastExamined = null;
        boolean endReached = false;
        Optional<String> lower = resumeInclusive.map(MetadataKey::key);
        MetadataSnapshot.KeyRange range = new MetadataSnapshot.KeyRange(
                CONFIRMATION_RECORD_NS, lower, Optional.empty());
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataCursor cursor = snapshot.scan(range, CancellationSignal.NONE)) {
            boolean skipResumeIfPresent = resumeInclusive.isPresent();
            while (repairs.size() < CONFIRMATION_REPAIR_LIMIT) {
                Optional<MetadataSnapshot.Record> candidate = cursor.next(CancellationSignal.NONE);
                if (candidate.isEmpty()) {
                    endReached = true;
                    break;
                }
                try (MetadataSnapshot.Record record = candidate.orElseThrow()) {
                    if (skipResumeIfPresent && record.key().equals(resumeInclusive.orElseThrow())) {
                        skipResumeIfPresent = false;
                        continue;
                    }
                    skipResumeIfPresent = false;
                    lastExamined = record.key();
                    CredentialConfirmationLifecycle lifecycle = decodeConfirmationRecord(record);
                    if (!record.key().equals(confirmationRecordKey(lifecycle.credentialId()))) {
                        throw new IOException("Credential confirmation authority key is inconsistent");
                    }
                    if (lifecycle.state() == CredentialConfirmationLifecycle.State.PENDING) {
                        Credential credential = getCredential(lifecycle.credentialId()).orElseThrow(() ->
                                new IOException("Credential confirmation target is unavailable"));
                        if (!hasRevocationHistory(lifecycle.credentialId())) {
                            CredentialConfirmationReview review = confirmationReview(lifecycle, credential);
                            planConfirmationReviewUpsert(snapshot, review, false).ifPresent(repairs::add);
                            planConfirmationReviewUpsert(snapshot, review, true).ifPresent(repairs::add);
                        }
                    }
                }
            }
        }
        return confirmationRepairBatch(repairs, lastExamined, endReached);
    }

    @SuppressWarnings("PMD.EmptyCatchBlock") // Malformed derived state is replaced from authority below.
    private static Optional<ConfirmationIndexRepair> planConfirmationReviewUpsert(
            MetadataSnapshot snapshot, CredentialConfirmationReview review,
            boolean profileScoped) throws IOException {
        MetadataKey key = confirmationReviewKey(review, profileScoped);
        byte[] encoded = CredentialConfirmationReviewCodec.encode(review);
        Optional<MetadataSnapshot.Record> existing = snapshot.get(key);
        if (existing.isEmpty()) {
            return Optional.of(ConfirmationIndexRepair.create(key, encoded));
        }
        try (MetadataSnapshot.Record record = existing.orElseThrow()) {
            try {
                if (decodeConfirmationReview(record).equals(review)) {
                    return Optional.empty();
                }
            } catch (IOException malformedDerivedState) {
                // The non-authoritative projection is replaced by the planned repair.
            }
            return Optional.of(ConfirmationIndexRepair.replace(key, record.recordRevision(), encoded));
        }
    }

    private ConfirmationRepairBatch planConfirmationDerivedRepairs(
            Optional<MetadataKey> resumeInclusive) throws IOException {
        List<ConfirmationIndexRepair> repairs = new ArrayList<>(CONFIRMATION_REPAIR_LIMIT);
        MetadataKey lastExamined = null;
        boolean endReached = false;
        Optional<String> lower = resumeInclusive.map(MetadataKey::key);
        MetadataSnapshot.KeyRange range = new MetadataSnapshot.KeyRange(
                CONFIRMATION_REVIEW_NS, lower, Optional.empty());
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataCursor cursor = snapshot.scan(range, CancellationSignal.NONE)) {
            boolean skipResumeIfPresent = resumeInclusive.isPresent();
            while (repairs.size() < CONFIRMATION_REPAIR_LIMIT) {
                Optional<MetadataSnapshot.Record> candidate = cursor.next(CancellationSignal.NONE);
                if (candidate.isEmpty()) {
                    endReached = true;
                    break;
                }
                try (MetadataSnapshot.Record record = candidate.orElseThrow()) {
                    if (skipResumeIfPresent && record.key().equals(resumeInclusive.orElseThrow())) {
                        skipResumeIfPresent = false;
                        continue;
                    }
                    skipResumeIfPresent = false;
                    lastExamined = record.key();
                    if (!isValidConfirmationReview(snapshot, record)) {
                        repairs.add(ConfirmationIndexRepair.delete(
                                record.key(), record.recordRevision()));
                    }
                }
            }
        }
        return confirmationRepairBatch(repairs, lastExamined, endReached);
    }

    private static ConfirmationRepairBatch confirmationRepairBatch(
            List<ConfirmationIndexRepair> repairs, MetadataKey lastExamined, boolean endReached) {
        if (!endReached && lastExamined == null) {
            throw new IllegalStateException("Confirmation repair scan made no progress");
        }
        return new ConfirmationRepairBatch(repairs, Optional.ofNullable(lastExamined), endReached);
    }

    private void commitConfirmationRepairs(List<ConfirmationIndexRepair> repairs) throws IOException {
        if (repairs.isEmpty()) {
            return;
        }
        List<List<SigningTransactionPayloadCodec.Mutation>> cohort =
                new ArrayList<>(repairs.size());
        for (ConfirmationIndexRepair repair : repairs) {
            SigningTransactionPayloadCodec.MutationKind kind = switch (repair.kind()) {
                case CREATE -> SigningTransactionPayloadCodec.MutationKind.CREATE;
                case REPLACE -> SigningTransactionPayloadCodec.MutationKind.REPLACE;
                case DELETE -> SigningTransactionPayloadCodec.MutationKind.DELETE;
            };
            byte[] content = repair.kind() == ConfirmationIndexRepairKind.DELETE
                    ? null : repair.content();
            cohort.add(List.of(new SigningTransactionPayloadCodec.Mutation(
                    kind, repair.key(), repair.expectedRevision(), content)));
        }
        for (MetadataCommitResult result : metadataStore.directCommitCohort(cohort)) {
            requireCommittedConfirmationRepairs(result);
        }
    }

    private void requireCommittedConfirmationRepairs(MetadataCommitResult result) throws IOException {
        switch (result.outcome()) {
            case COMMITTED -> {
                // Direct commits deliberately retain no acknowledgement outcome.
            }
            case NOT_COMMITTED ->
                throw new IOException("Credential confirmation review index rebuild conflicted");
            case UNKNOWN -> {
                durabilityUncertain.set(true);
                throw storeDurabilityUnconfirmed(
                        "Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
            }
        }
    }

    private boolean isValidConfirmationReview(MetadataSnapshot snapshot,
            MetadataSnapshot.Record reviewRecord) throws IOException {
        CredentialConfirmationReview review;
        try {
            review = decodeConfirmationReview(reviewRecord);
        } catch (IOException malformedDerivedState) {
            return false;
        }
        if (!isConfirmationReviewKey(reviewRecord.key(), review)) {
            return false;
        }
        Optional<MetadataSnapshot.Record> authoritative = snapshot.get(
                confirmationRecordKey(review.credentialId()));
        if (authoritative.isEmpty()) {
            return false;
        }
        try (MetadataSnapshot.Record record = authoritative.orElseThrow()) {
            CredentialConfirmationLifecycle lifecycle = decodeConfirmationRecord(record);
            if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
                return false;
            }
            Credential credential = getCredential(review.credentialId()).orElse(null);
            return credential != null && !hasRevocationHistory(review.credentialId())
                    && confirmationReview(lifecycle, credential).equals(review);
        }
    }

    private void requireSerialAvailable(PkiId issuerId, BigInteger serial, PkiId credentialId) {
        Credential candidate = getCredential(credentialId).orElse(null);
        requireSerialAvailable(issuerId, serial, candidate);
    }

    private void requireSerialAvailable(PkiId issuerId, BigInteger serial, Credential candidate) {
        Optional<Credential> existing = getCredentialByIssuerAndSerial(issuerId, serial);
        if (existing.isPresent() && (candidate == null
                || !existing.orElseThrow().credentialId().equals(candidate.credentialId()))) {
            if (candidate == null || !sameImmutableContent(existing.orElseThrow(), candidate)) {
                throw new IllegalStateException("Duplicate issuer-generation certificate serial");
            }
        }
    }

    private void ensureSerialIndex(PkiId issuerId, BigInteger serial, PkiId credentialId) {
        MetadataKey key = serialIndexKey(issuerId, serial);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> stored = snapshot.get(key);
            if (stored.isPresent()) {
                try (MetadataSnapshot.Record record = stored.orElseThrow()) {
                    PkiId indexedId = decodeSerialIndex(record, issuerId, serial);
                    if (!indexedId.equals(credentialId)) {
                        Credential indexed = getCredential(indexedId).orElseThrow(
                                () -> new IllegalStateException("Credential serial index target is missing"));
                        Credential candidate = getCredential(credentialId).orElseThrow(
                                () -> new IllegalStateException("Credential serial candidate is missing"));
                        if (!sameImmutableContent(indexed, candidate)) {
                            throw new IllegalStateException("Duplicate issuer-generation certificate serial");
                        }
                    }
                }
                return;
            }
        } catch (IOException failure) {
            throw new IllegalStateException("Credential serial index read failed");
        }
        try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
            transaction.create(key, byteContent(encodeSerialIndex(issuerId, serial, credentialId)),
                    CancellationSignal.NONE);
            MetadataCommitResult result = transaction.commit();
            if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                acknowledgeKnownOutcome(result);
                return;
            }
            if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
                durabilityUncertain.set(true);
                throw storeDurabilityUnconfirmed("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
            }
            acknowledgeKnownOutcome(result);
        } catch (IOException failure) {
            throw new IllegalStateException("Credential serial index persistence failed");
        }
        requireSerialAvailable(issuerId, serial, credentialId);
    }

    private static boolean sameImmutableContent(Credential left, Credential right) {
        return left.content().storeId().equals(right.content().storeId())
                && left.content().contentId().equals(right.content().contentId())
                && left.content().sha256().equals(right.content().sha256())
                && left.content().length() == right.content().length();
    }

    private static Optional<BigInteger> x509Serial(Credential credential) {
        if (!BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) return Optional.empty();
        try {
            BigInteger serial = new BigInteger(credential.serialOrUniqueId());
            if (serial.signum() <= 0 || serial.bitLength() > 160
                    || !serial.toString().equals(credential.serialOrUniqueId())) return Optional.empty();
            return Optional.of(serial);
        } catch (NumberFormatException failure) {
            return Optional.empty();
        }
    }

    private Optional<BigInteger> indexableSerial(Credential credential) {
        if (credential.issuerRef().issuerId().value().startsWith("issuer-unresolved:")
                || getIssuerGeneration(credential.issuerRef().issuerId()).isEmpty()) {
            return Optional.empty();
        }
        return x509Serial(credential);
    }

    private static void requirePositiveSerial(BigInteger serial) {
        Objects.requireNonNull(serial, "serial");
        if (serial.signum() <= 0 || serial.bitLength() > 160) {
            throw new IllegalArgumentException("X.509 serial must be a positive value of at most 20 octets");
        }
    }

    private static MetadataKey serialIndexKey(PkiId issuerId, BigInteger serial) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] issuer = issuerId.value().getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(issuer.length).array());
            digest.update(issuer);
            digest.update(serial.toByteArray());
            return new MetadataKey(CREDENTIAL_SERIAL_NAMESPACE,
                    HexFormat.of().formatHex(digest.digest()));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static byte[] encodeSerialIndex(PkiId issuerId, BigInteger serial, PkiId credentialId) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(256);
                DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(1);
            output.writeUTF(issuerId.value());
            output.writeUTF(serial.toString());
            output.writeUTF(credentialId.value());
            output.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("Credential serial index encoding failed", impossible);
        }
    }

    private static PkiId decodeSerialIndex(MetadataSnapshot.Record record, PkiId issuerId,
            BigInteger serial) throws IOException {
        byte[] encoded = readMetadataValue(record);
        if (encoded.length > 16_384) throw new IOException("Credential serial index exceeds its bound");
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readInt() != 1) throw new IOException("Credential serial index version is obsolete");
            PkiId storedIssuer = new PkiId(input.readUTF());
            String storedSerial = input.readUTF();
            PkiId credentialId = new PkiId(input.readUTF());
            if (input.read() != -1 || !storedIssuer.equals(issuerId)
                    || !serial.toString().equals(storedSerial)) {
                throw new IOException("Credential serial index authority mismatch");
            }
            return credentialId;
        } catch (IllegalArgumentException failure) {
            throw new IOException("Credential serial index is malformed", failure);
        }
    }

    @Override
    public Optional<Credential> getCredentialByIssuanceIntent(IssuanceIntent intent) {
        requireStoreUsable();
        Objects.requireNonNull(intent, "intent");
        Path root = paths.root().resolve("credentials").resolve("by-id");
        if (!Files.isDirectory(root)) {
            return Optional.empty();
        }
        Credential match = null;
        try (Stream<Path> records = Files.list(root)) {
            java.util.Iterator<Path> iterator = records
                    .filter(path -> path.getFileName().toString().endsWith(".bin"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString())).iterator();
            while (iterator.hasNext()) {
                Credential credential = FsCodec.decode(FsCodec.CREDENTIAL,
                        FsOperations.readAll(iterator.next()), stagedContent);
                Optional<AttributeValue> issuance = credential.attributes().get(IssuanceIntent.ID_ATTRIBUTE);
                if (issuance.orElse(null) instanceof AttributeValue.StringValue value
                        && intent.issuanceId().equals(value.value())) {
                    Optional<AttributeValue> commitment = credential.attributes()
                            .get(IssuanceIntent.COMMITMENT_ATTRIBUTE);
                    if (!(commitment.orElse(null) instanceof AttributeValue.StringValue command)
                            || !intent.commandCommitment().equals(command.value())) {
                        throw new IllegalStateException("Issuance identity was reused with different input");
                    }
                    if (match != null) {
                        throw new IllegalStateException("Duplicate issuance identity");
                    }
                    match = credentialTransactions.validateLoaded(credential.credentialId(), credential);
                }
            }
            return Optional.ofNullable(match);
        } catch (IOException failure) {
            throw new IllegalStateException("Issuance correlation read failed", failure);
        }
    }

    @Override
    public CredentialConfirmationLifecycle initializeCredentialConfirmation(
            final CredentialConfirmationInitialization initialization) {
        requireStoreUsable();
        CredentialConfirmationInitialization exact = Objects.requireNonNull(initialization, "initialization");
        PkiId credentialId = exact.credentialId();
        CredentialStateLockEntry lock = acquireCredentialStateLock(credentialId);
        try {
            Optional<StoredConfirmation> existing = readStoredConfirmation(credentialId);
            CredentialConfirmationLifecycle initial = CredentialConfirmationLifecycle.initialize(exact);
            if (existing.isPresent()) {
                CredentialConfirmationLifecycle committed = existing.orElseThrow().lifecycle();
                if (sameConfirmationInitialization(committed, exact)) {
                    return committed;
                }
                throw new IllegalArgumentException(
                        "Credential confirmation initialization conflicts with authoritative state");
            }
            requireConfirmationCredentialAvailable(credentialId);
            Credential credential = getCredential(credentialId).orElseThrow(() ->
                    new IllegalStateException("Credential confirmation target is unavailable"));
            CredentialConfirmationReview review = confirmationReview(initial, credential);
            byte[] encoded = CredentialConfirmationLifecycleCodec.encode(initial);
            byte[] encodedReview = CredentialConfirmationReviewCodec.encode(review);
            try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
                transaction.create(confirmationRecordKey(credentialId), byteContent(encoded),
                        CancellationSignal.NONE);
                if (initial.state() == CredentialConfirmationLifecycle.State.PENDING) {
                    transaction.create(confirmationReviewKey(review, false), byteContent(encodedReview),
                            CancellationSignal.NONE);
                    transaction.create(confirmationReviewKey(review, true), byteContent(encodedReview),
                            CancellationSignal.NONE);
                }
                MetadataCommitResult result = requireKnownOutcome(transaction.commit());
                if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                    throw new IllegalStateException("Credential confirmation initialization conflicted");
                }
                return initial;
            } catch (IOException failure) {
                throw confirmationPersistenceFailure(failure);
            }
        } finally {
            releaseCredentialStateLock(credentialId, lock);
        }
    }

    @Override
    public Optional<CredentialConfirmationLifecycle> getCredentialConfirmation(final PkiId credentialId) {
        requireStoreUsable();
        PkiId exact = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
        return readStoredConfirmation(exact).map(StoredConfirmation::lifecycle);
    }

    @Override
    public Optional<CredentialConfirmationChallenge> getCredentialConfirmationChallenge(
            final PkiId credentialId) {
        requireStoreUsable();
        PkiId exact = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
        Optional<StoredConfirmationChallenge> stored = readStoredConfirmationChallenge(exact);
        try {
            return hasRevocationHistory(exact) ? Optional.empty()
                    : stored.map(StoredConfirmationChallenge::challenge);
        } catch (IOException failure) {
            throw confirmationPersistenceFailure(failure);
        }
    }

    @Override
    public CredentialConfirmationChallenge issueCredentialConfirmationChallenge(
            final CredentialConfirmationChallengeIssuance issuance) {
        requireStoreUsable();
        CredentialConfirmationChallengeIssuance exact = Objects.requireNonNull(issuance, "issuance");
        PkiId credentialId = exact.credentialId();
        CredentialStateLockEntry lock = acquireCredentialStateLock(credentialId);
        try {
            Instant storeNow = Objects.requireNonNull(clock.instant(), "store clock instant");
            Instant issuedAt = requireConfirmationWholeSecond(storeNow);
            Instant expiresAt = confirmationChallengeExpiry(issuedAt, exact.timeToLive().getSeconds());
            CredentialConfirmationLifecycle lifecycle = readStoredConfirmation(credentialId)
                    .map(StoredConfirmation::lifecycle)
                    .orElseThrow(() -> new IllegalStateException(
                            "Credential confirmation lifecycle is not initialized"));
            requirePendingChallengeIssuanceBindings(exact, lifecycle);
            requireConfirmationCredentialAvailable(credentialId, storeNow);
            Optional<StoredConfirmationChallenge> existing = readStoredConfirmationChallenge(credentialId);
            if (existing.isPresent()) {
                StoredConfirmationChallenge committed = existing.orElseThrow();
                if (!sameChallengeLifecycleBindings(committed.challenge(), lifecycle)) {
                    throw new IllegalStateException(
                            "Credential confirmation challenge lifecycle is inconsistent");
                }
                if (!sameChallengeIssuanceBindings(committed.challenge(), exact)) {
                    throw new IllegalArgumentException(
                            "Credential confirmation challenge conflicts with authoritative state");
                }
                if (committed.challenge().isLiveAt(issuedAt)) {
                    return committed.challenge();
                }
                if (issuedAt.isBefore(committed.challenge().issuedAt())) {
                    throw new IllegalStateException(
                            "Credential confirmation store clock regressed before challenge issuance");
                }
                CredentialConfirmationChallenge replacement = createConfirmationChallenge(
                        exact, lifecycle, issuedAt, expiresAt);
                return persistConfirmationChallenge(replacement, Optional.of(committed));
            }
            CredentialConfirmationChallenge created = createConfirmationChallenge(
                    exact, lifecycle, issuedAt, expiresAt);
            return persistConfirmationChallenge(created, Optional.empty());
        } finally {
            releaseCredentialStateLock(credentialId, lock);
        }
    }

    @Override
    public CredentialConfirmationLifecycle completeCredentialConfirmation(
            final CredentialConfirmationProofCas proofCas) {
        requireStoreUsable();
        CredentialConfirmationProofCas exact = Objects.requireNonNull(proofCas, "proofCas");
        PkiId credentialId = exact.credentialId();
        CredentialStateLockEntry lock = acquireCredentialStateLock(credentialId);
        try {
            StoredConfirmation stored = readStoredConfirmation(credentialId)
                    .orElseThrow(() -> new IllegalStateException(
                            "Credential confirmation lifecycle is not initialized"));
            CredentialConfirmationLifecycle current = stored.lifecycle();
            if (current.state() == CredentialConfirmationLifecycle.State.CONFIRMED) {
                if (isExactTerminalConfirmationRetry(current, exact)) {
                    return current;
                }
                throw new IllegalArgumentException("Credential confirmation CAS conflicts with terminal state");
            }
            if (current.state() != CredentialConfirmationLifecycle.State.PENDING) {
                throw new IllegalStateException("Credential confirmation is not required");
            }
            if (current.revision() != exact.expectedLifecycleRevision()
                    || !current.recordCommitment().equals(exact.expectedLifecycleRecordCommitment())) {
                throw new IllegalArgumentException("Credential confirmation CAS expectation does not match");
            }
            StoredConfirmationChallenge storedChallenge = readStoredConfirmationChallenge(credentialId)
                    .orElseThrow(() -> new IllegalStateException(
                            "Credential confirmation challenge is not initialized"));
            CredentialConfirmationChallenge challenge = storedChallenge.challenge();
            if (!sameChallengeLifecycleBindings(challenge, current)) {
                throw new IllegalStateException(
                        "Credential confirmation challenge lifecycle is inconsistent");
            }
            if (!challenge.recordCommitment().equals(exact.expectedChallengeRecordCommitment())) {
                throw new IllegalArgumentException("Credential confirmation challenge CAS conflicts");
            }
            Credential credential = getCredential(credentialId).orElseThrow(() ->
                    new IllegalStateException("Credential confirmation target is unavailable"));
            CredentialConfirmationReview expectedReview = confirmationReview(current, credential);
            StoredConfirmationReview authorityReview = readStoredConfirmationReview(expectedReview, false)
                    .orElseThrow(() -> new IllegalStateException(
                            "Credential confirmation review projection is missing"));
            StoredConfirmationReview profileReview = readStoredConfirmationReview(expectedReview, true)
                    .orElseThrow(() -> new IllegalStateException(
                            "Credential confirmation profile review projection is missing"));
            if (!authorityReview.review().equals(expectedReview)
                    || !profileReview.review().equals(expectedReview)) {
                throw new IllegalStateException("Credential confirmation review projection is inconsistent");
            }
            Instant storeNow = Objects.requireNonNull(clock.instant(), "store clock instant");
            Instant storeNowWholeSecond = requireConfirmationWholeSecond(storeNow);
            if (storeNowWholeSecond.isBefore(challenge.issuedAt())) {
                throw new IllegalStateException(
                        "Credential confirmation store clock regressed before challenge issuance");
            }
            if (!challenge.isLiveAt(storeNowWholeSecond)) {
                throw new IllegalStateException("Credential confirmation challenge is expired");
            }
            requireConfirmationCredentialAvailable(credentialId, storeNow);
            CredentialConfirmationLifecycle replacement = current.deriveConfirmed(exact, storeNow);
            try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
                transaction.replace(confirmationRecordKey(credentialId), stored.recordRevision(),
                        byteContent(CredentialConfirmationLifecycleCodec.encode(replacement)),
                        CancellationSignal.NONE);
                transaction.delete(confirmationReviewKey(expectedReview, false),
                        authorityReview.recordRevision());
                transaction.delete(confirmationReviewKey(expectedReview, true),
                        profileReview.recordRevision());
                transaction.delete(confirmationChallengeKey(credentialId),
                        storedChallenge.recordRevision());
                MetadataCommitResult result = requireKnownOutcome(transaction.commit());
                if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                    throw new IllegalArgumentException("Credential confirmation CAS conflicted");
                }
                return replacement;
            } catch (IOException failure) {
                throw confirmationPersistenceFailure(failure);
            }
        } finally {
            releaseCredentialStateLock(credentialId, lock);
        }
    }

    @Override
    @SuppressWarnings("PMD.NPathComplexity")
    public CredentialConfirmationReviewPage pagePendingCredentialConfirmationReviews(
            final PkiId authorityId,
            final Optional<String> profileId,
            final Instant cutoffInclusive,
            final Optional<CredentialConfirmationReviewCursor> afterExclusive,
            final int limit) {
        requireStoreUsable();
        CredentialConfirmationReviewScope scope = confirmationReviewScope(authorityId, profileId);
        requireConfirmationReviewCutoff(cutoffInclusive);
        Objects.requireNonNull(afterExclusive, "afterExclusive");
        if (limit < 1 || limit > 4096) {
            throw new IllegalArgumentException("Confirmation review page limit must be from 1 through 4096");
        }
        CredentialConfirmationReviewCursorCodec.State resume = afterExclusive
                .map(CredentialConfirmationReviewCursorCodec::decode).orElse(null);
        byte[] scopeBinding = confirmationReviewScopeBinding(scope);
        List<ConfirmationIndexRepair> repairs = new ArrayList<>(
                MAX_LIST_REPAIR_DELETES);
        CredentialConfirmationReviewPage page;
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            if (resume != null && (!resume.storeId().equals(snapshot.storeId())
                    || !resume.cutoff().equals(cutoffInclusive)
                    || !MessageDigest.isEqual(resume.scopeBinding(), scopeBinding))) {
                throw new IllegalArgumentException(
                        "Confirmation review cursor belongs to another store, cutoff, or scope");
            }
            Optional<String> lower = resume == null ? Optional.empty()
                    : Optional.of(confirmationReviewKey(scope, resume.reviewAt(), resume.credentialId()).key());
            String prefix = confirmationReviewPrefix(scope);
            MetadataSnapshot.KeyRange scopedRange = MetadataSnapshot.KeyRange.prefix(
                    CONFIRMATION_REVIEW_NS, prefix);
            MetadataSnapshot.KeyRange range = new MetadataSnapshot.KeyRange(
                    CONFIRMATION_REVIEW_NS, lower.isPresent() ? lower : scopedRange.lowerInclusive(),
                    scopedRange.upperExclusive());
            List<CredentialConfirmationReview> reviews = new ArrayList<>(limit);
            Set<PkiId> revokedStaleCredentials = new HashSet<>(
                    MAX_LIST_REPAIRS);
            CredentialConfirmationReview lastExamined = null;
            boolean rangeEnd = false;
            int examined = 0;
            try (MetadataCursor cursor = snapshot.scan(range, CancellationSignal.NONE)) {
                boolean skipResume = resume != null;
                while (examined < limit
                        && revokedStaleCredentials.size()
                                < MAX_LIST_REPAIRS) {
                    Optional<MetadataSnapshot.Record> candidate = cursor.next(CancellationSignal.NONE);
                    if (candidate.isEmpty()) {
                        rangeEnd = true;
                        break;
                    }
                    try (MetadataSnapshot.Record record = candidate.orElseThrow()) {
                        if (skipResume && record.key().key().equals(lower.orElseThrow())) {
                            skipResume = false;
                            continue;
                        }
                        skipResume = false;
                        CredentialConfirmationReview review = decodeConfirmationReview(record);
                        if (!isConfirmationReviewKey(record.key(), review)) {
                            throw new IOException(
                                    "Credential confirmation review projection is inconsistent");
                        }
                        if (review.confirmationReviewAt().isAfter(cutoffInclusive)) {
                            rangeEnd = true;
                            break;
                        }
                        examined++;
                        lastExamined = review;
                        if (inspectConfirmationReview(snapshot, record.key(), review,
                                revokedStaleCredentials, repairs)) {
                            reviews.add(review);
                        }
                    }
                }
            }
            Optional<CredentialConfirmationReviewCursor> nextCursor = Optional.empty();
            if (!rangeEnd && lastExamined != null) {
                nextCursor = Optional.of(CredentialConfirmationReviewCursorCodec.encode(
                        snapshot.storeId(), scopeBinding, cutoffInclusive,
                        lastExamined.confirmationReviewAt(), lastExamined.credentialId()));
            }
            page = new CredentialConfirmationReviewPage(reviews, nextCursor);
        } catch (IOException failure) {
            throw confirmationPersistenceFailure(failure);
        }
        try {
            commitOpportunisticConfirmationRepairs(repairs);
            return page;
        } catch (IOException failure) {
            throw confirmationPersistenceFailure(failure);
        }
    }

    private static void requireConfirmationReviewCutoff(Instant cutoff) {
        Objects.requireNonNull(cutoff, "cutoffInclusive");
        if (cutoff.getEpochSecond() < 0L || cutoff.getEpochSecond() > 253_402_300_799L) {
            throw new IllegalArgumentException("Confirmation review cutoff is outside the supported UTC range");
        }
    }

    private static CredentialConfirmationLifecycle decodeConfirmationRecord(
            MetadataSnapshot.Record record) throws IOException {
        return CredentialConfirmationLifecycleCodec.decode(readMetadataValue(record));
    }

    private static CredentialConfirmationReview decodeConfirmationReview(
            MetadataSnapshot.Record record) throws IOException {
        return CredentialConfirmationReviewCodec.decode(readMetadataValue(record));
    }

    private boolean inspectConfirmationReview(MetadataSnapshot snapshot, MetadataKey reviewKey,
            CredentialConfirmationReview review, Set<PkiId> revokedStaleCredentials,
            List<ConfirmationIndexRepair> repairs) throws IOException {
        if (!isConfirmationReviewKey(reviewKey, review)) {
            throw new IOException("Credential confirmation review projection is inconsistent");
        }
        Optional<MetadataSnapshot.Record> authoritative = snapshot.get(
                confirmationRecordKey(review.credentialId()));
        if (authoritative.isEmpty()) {
            throw new IOException("Credential confirmation review authority is missing");
        }
        try (MetadataSnapshot.Record record = authoritative.orElseThrow()) {
            CredentialConfirmationLifecycle lifecycle = decodeConfirmationRecord(record);
            if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
                throw new IOException("Credential confirmation review authority is not pending");
            }
            Credential credential = getCredential(review.credentialId()).orElseThrow(() ->
                    new IOException("Credential confirmation review credential is missing"));
            if (!confirmationReview(lifecycle, credential).equals(review)) {
                throw new IOException("Credential confirmation review authority is inconsistent");
            }
            Optional<RevocationRecord> revocation = revocations.current(review.credentialId());
            if (revocation.isEmpty()) {
                return true;
            }
            if (revocation.orElseThrow().transition().state()
                    != RevocationState.PERMANENTLY_REVOKED) {
                return false;
            }
            if (revokedStaleCredentials.add(review.credentialId())) {
                planRevokedConfirmationDeletes(snapshot, review, repairs);
            }
            return false;
        }
    }

    private static void planRevokedConfirmationDeletes(MetadataSnapshot snapshot,
            CredentialConfirmationReview expected, List<ConfirmationIndexRepair> repairs)
            throws IOException {
        planExactReviewDelete(snapshot, expected, false).ifPresent(repairs::add);
        planExactReviewDelete(snapshot, expected, true).ifPresent(repairs::add);
        MetadataKey challengeKey = confirmationChallengeKey(expected.credentialId());
        Optional<MetadataSnapshot.Record> storedChallenge = snapshot.get(challengeKey);
        if (storedChallenge.isPresent()) {
            try (MetadataSnapshot.Record record = storedChallenge.orElseThrow()) {
                CredentialConfirmationChallenge challenge = CredentialConfirmationChallengeCodec.decode(
                        readMetadataValue(record));
                if (!record.key().equals(challengeKey)
                        || !challenge.credentialId().equals(expected.credentialId())) {
                    throw new IOException("Credential confirmation challenge projection is inconsistent");
                }
                repairs.add(ConfirmationIndexRepair.delete(record.key(), record.recordRevision()));
            }
        }
        if (repairs.size() > MAX_LIST_REPAIR_DELETES) {
            throw new IllegalStateException("Opportunistic confirmation repair exceeded its bound");
        }
    }

    private static Optional<ConfirmationIndexRepair> planExactReviewDelete(
            MetadataSnapshot snapshot, CredentialConfirmationReview expected,
            boolean profileScoped) throws IOException {
        MetadataKey key = confirmationReviewKey(expected, profileScoped);
        Optional<MetadataSnapshot.Record> stored = snapshot.get(key);
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        try (MetadataSnapshot.Record record = stored.orElseThrow()) {
            CredentialConfirmationReview actual = decodeConfirmationReview(record);
            if (!record.key().equals(key) || !actual.equals(expected)) {
                throw new IOException("Credential confirmation review projection is inconsistent");
            }
            return Optional.of(ConfirmationIndexRepair.delete(key, record.recordRevision()));
        }
    }

    private void commitOpportunisticConfirmationRepairs(
            List<ConfirmationIndexRepair> repairs) throws IOException {
        if (repairs.isEmpty()) {
            return;
        }
        List<List<SigningTransactionPayloadCodec.Mutation>> cohort = new ArrayList<>(repairs.size());
        for (ConfirmationIndexRepair repair : repairs) {
            cohort.add(List.of(new SigningTransactionPayloadCodec.Mutation(
                    SigningTransactionPayloadCodec.MutationKind.DELETE,
                    repair.key(), repair.expectedRevision(), null)));
        }
        for (MetadataCommitResult result : metadataStore.directCommitCohort(cohort)) {
            requireKnownOpportunisticConfirmationRepair(result);
        }
    }

    private void requireKnownOpportunisticConfirmationRepair(MetadataCommitResult result) {
        switch (result.outcome()) {
            case COMMITTED, NOT_COMMITTED -> {
                // A revision conflict is a benign concurrent repair or lifecycle transition.
            }
            case UNKNOWN -> {
                durabilityUncertain.set(true);
                throw storeDurabilityUnconfirmed(
                        "Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
            }
        }
    }

    private void removeRevokedCredentialConfirmationChallenges() throws IOException {
        Optional<MetadataKey> resumeInclusive = Optional.empty();
        while (true) {
            ConfirmationRepairBatch batch = planRevokedChallengeRepairs(resumeInclusive);
            commitConfirmationRepairs(batch.repairs());
            if (batch.endReached()) {
                return;
            }
            resumeInclusive = batch.lastExamined();
        }
    }

    private ConfirmationRepairBatch planRevokedChallengeRepairs(
            Optional<MetadataKey> resumeInclusive) throws IOException {
        List<ConfirmationIndexRepair> repairs = new ArrayList<>(CONFIRMATION_REPAIR_LIMIT);
        MetadataKey lastExamined = null;
        boolean endReached = false;
        Optional<String> lower = resumeInclusive.map(MetadataKey::key);
        MetadataSnapshot.KeyRange range = new MetadataSnapshot.KeyRange(
                CONFIRMATION_CHALLENGE_NS, lower, Optional.empty());
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataCursor cursor = snapshot.scan(range, CancellationSignal.NONE)) {
            boolean skipResumeIfPresent = resumeInclusive.isPresent();
            while (repairs.size() < CONFIRMATION_REPAIR_LIMIT) {
                Optional<MetadataSnapshot.Record> candidate = cursor.next(CancellationSignal.NONE);
                if (candidate.isEmpty()) {
                    endReached = true;
                    break;
                }
                try (MetadataSnapshot.Record record = candidate.orElseThrow()) {
                    if (skipResumeIfPresent && record.key().equals(resumeInclusive.orElseThrow())) {
                        skipResumeIfPresent = false;
                        continue;
                    }
                    skipResumeIfPresent = false;
                    lastExamined = record.key();
                    CredentialConfirmationChallenge challenge = CredentialConfirmationChallengeCodec.decode(
                            readMetadataValue(record));
                    if (!record.key().equals(confirmationChallengeKey(challenge.credentialId()))) {
                        throw new IOException("Credential confirmation challenge key is inconsistent");
                    }
                    if (hasRevocationHistory(challenge.credentialId())) {
                        repairs.add(ConfirmationIndexRepair.delete(
                                record.key(), record.recordRevision()));
                    }
                }
            }
        }
        return confirmationRepairBatch(repairs, lastExamined, endReached);
    }

    private void requireConfirmationCredentialAvailable(PkiId credentialId) {
        requireConfirmationCredentialAvailable(credentialId, clock.instant());
    }

    private void requireConfirmationCredentialAvailable(PkiId credentialId, Instant now) {
        Credential credential = getCredential(credentialId).orElseThrow(() ->
                new IllegalStateException("Credential confirmation target is unavailable"));
        if (credential.status() == CredentialStatus.EXPIRED
                || now.isAfter(credential.validity().notAfter())) {
            throw new IllegalStateException("Credential confirmation target is expired");
        }
        try {
            if (revocations.current(credentialId).isPresent()) {
                throw new IllegalStateException("Credential confirmation target has revocation history");
            }
        } catch (IOException failure) {
            throw confirmationPersistenceFailure(failure);
        }
    }

    private boolean hasRevocationHistory(PkiId credentialId) throws IOException {
        return revocations.current(credentialId).isPresent();
    }

    private Optional<StoredConfirmation> readStoredConfirmation(PkiId credentialId) {
        Optional<StoredConfirmation> stored = readStoredConfirmation(confirmationRecordKey(credentialId));
        if (stored.isPresent()
                && !stored.orElseThrow().lifecycle().credentialId().equals(credentialId)) {
            throw new IllegalStateException("Credential confirmation authority key is inconsistent");
        }
        return stored;
    }

    private Optional<StoredConfirmationChallenge> readStoredConfirmationChallenge(PkiId credentialId) {
        MetadataKey key = confirmationChallengeKey(credentialId);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> found = snapshot.get(key);
            if (found.isEmpty()) {
                return Optional.empty();
            }
            try (MetadataSnapshot.Record record = found.orElseThrow()) {
                CredentialConfirmationChallenge challenge = CredentialConfirmationChallengeCodec.decode(
                        readMetadataValue(record));
                if (!challenge.credentialId().equals(credentialId)) {
                    throw new IOException("Credential confirmation challenge key is inconsistent");
                }
                return Optional.of(new StoredConfirmationChallenge(challenge, record.recordRevision()));
            }
        } catch (IOException failure) {
            throw confirmationPersistenceFailure(failure);
        }
    }

    private CredentialConfirmationChallenge persistConfirmationChallenge(
            CredentialConfirmationChallenge challenge,
            Optional<StoredConfirmationChallenge> existing) {
        MetadataKey key = confirmationChallengeKey(challenge.credentialId());
        byte[] encoded = CredentialConfirmationChallengeCodec.encode(challenge);
        try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
            if (existing.isPresent()) {
                transaction.replace(key, existing.orElseThrow().recordRevision(), byteContent(encoded),
                        CancellationSignal.NONE);
            } else {
                transaction.create(key, byteContent(encoded), CancellationSignal.NONE);
            }
            MetadataCommitResult result = requireKnownOutcome(transaction.commit());
            if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                throw new IllegalStateException("Credential confirmation challenge issuance conflicted");
            }
            return challenge;
        } catch (IOException failure) {
            throw confirmationPersistenceFailure(failure);
        }
    }

    private void validateCredentialConfirmationChallenges() throws IOException {
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataCursor cursor = snapshot.scan(
                        MetadataSnapshot.KeyRange.all(CONFIRMATION_CHALLENGE_NS),
                        CancellationSignal.NONE)) {
            while (true) {
                Optional<MetadataSnapshot.Record> candidate = cursor.next(CancellationSignal.NONE);
                if (candidate.isEmpty()) {
                    return;
                }
                try (MetadataSnapshot.Record record = candidate.orElseThrow()) {
                    CredentialConfirmationChallenge challenge = CredentialConfirmationChallengeCodec.decode(
                            readMetadataValue(record));
                    if (!record.key().equals(confirmationChallengeKey(challenge.credentialId()))) {
                        throw new IOException("Credential confirmation challenge key is inconsistent");
                    }
                    Optional<MetadataSnapshot.Record> lifecycleRecord = snapshot.get(
                            confirmationRecordKey(challenge.credentialId()));
                    if (lifecycleRecord.isEmpty()) {
                        throw new IOException("Credential confirmation challenge lifecycle is missing");
                    }
                    try (MetadataSnapshot.Record authority = lifecycleRecord.orElseThrow()) {
                        CredentialConfirmationLifecycle lifecycle = decodeConfirmationRecord(authority);
                        if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING
                                || !sameChallengeLifecycleBindings(challenge, lifecycle)) {
                            throw new IOException(
                                    "Credential confirmation challenge lifecycle is inconsistent");
                        }
                    }
                }
            }
        }
    }

    private static void requirePendingChallengeIssuanceBindings(
            CredentialConfirmationChallengeIssuance issuance,
            CredentialConfirmationLifecycle lifecycle) {
        if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
            throw new IllegalStateException("Credential confirmation lifecycle is not pending");
        }
        if (!issuance.credentialId().equals(lifecycle.credentialId())
                || issuance.expectedLifecycleRevision() != lifecycle.revision()
                || !issuance.expectedLifecycleRecordCommitment().equals(lifecycle.recordCommitment())
                || !issuance.proofSuiteBinding().proofSuiteRef().equals(lifecycle.proofSuite())) {
            throw new IllegalArgumentException(
                    "Credential confirmation challenge issuance does not match the pending lifecycle");
        }
    }

    private static boolean sameChallengeLifecycleBindings(CredentialConfirmationChallenge challenge,
            CredentialConfirmationLifecycle lifecycle) {
        return challenge.credentialId().equals(lifecycle.credentialId())
                && challenge.expectedLifecycleRevision() == lifecycle.revision()
                && challenge.expectedLifecycleRecordCommitment().equals(lifecycle.recordCommitment())
                && challenge.initialDisclosurePolicy() == lifecycle.initialPolicy()
                && challenge.confirmationPolicyCommitment().equals(lifecycle.initialPolicyCommitment())
                && challenge.proofSuiteBinding().proofSuiteRef().equals(lifecycle.proofSuite());
    }

    private static boolean sameChallengeIssuanceBindings(CredentialConfirmationChallenge challenge,
            CredentialConfirmationChallengeIssuance issuance) {
        return challenge.realm().equals(issuance.realm())
                && challenge.serverAudience().equals(issuance.serverAudience())
                && challenge.credentialId().equals(issuance.credentialId())
                && challenge.expectedLifecycleRevision() == issuance.expectedLifecycleRevision()
                && challenge.expectedLifecycleRecordCommitment()
                        .equals(issuance.expectedLifecycleRecordCommitment())
                && challenge.proofSuiteBinding().equals(issuance.proofSuiteBinding());
    }

    private static CredentialConfirmationChallenge createConfirmationChallenge(
            CredentialConfirmationChallengeIssuance issuance,
            CredentialConfirmationLifecycle lifecycle, Instant issuedAt, Instant expiresAt) {
        byte[] rawChallenge = issuance.rawChallenge();
        try {
            return CredentialConfirmationChallenge.create(issuance.realm(), issuance.serverAudience(),
                    lifecycle, issuance.proofSuiteBinding(), rawChallenge, issuedAt, expiresAt);
        } finally {
            Arrays.fill(rawChallenge, (byte) 0);
        }
    }

    private static Instant requireConfirmationWholeSecond(Instant storeNow) {
        long epochSecond = storeNow.getEpochSecond();
        if (epochSecond < 0L || epochSecond > CONFIRMATION_EPOCH_MAX) {
            throw new IllegalStateException("Credential confirmation store clock is outside the supported range");
        }
        return Instant.ofEpochSecond(epochSecond);
    }

    private static Instant confirmationChallengeExpiry(Instant issuedAt, long timeToLiveSeconds) {
        long maximumIssuedAt = CONFIRMATION_EPOCH_MAX - timeToLiveSeconds;
        if (issuedAt.getEpochSecond() > maximumIssuedAt) {
            throw new IllegalStateException("Credential confirmation challenge expiry exceeds the supported range");
        }
        return issuedAt.plusSeconds(timeToLiveSeconds);
    }

    private Optional<StoredConfirmationReview> readStoredConfirmationReview(
            CredentialConfirmationReview review, boolean profileScoped) {
        MetadataKey key = confirmationReviewKey(review, profileScoped);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> found = snapshot.get(key);
            if (found.isEmpty()) {
                return Optional.empty();
            }
            try (MetadataSnapshot.Record record = found.orElseThrow()) {
                return Optional.of(new StoredConfirmationReview(
                        decodeConfirmationReview(record), record.recordRevision()));
            }
        } catch (IOException failure) {
            throw confirmationPersistenceFailure(failure);
        }
    }

    private Optional<StoredConfirmation> readStoredConfirmation(MetadataKey key) {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> found = snapshot.get(key);
            if (found.isEmpty()) {
                return Optional.empty();
            }
            try (MetadataSnapshot.Record record = found.orElseThrow()) {
                CredentialConfirmationLifecycle lifecycle = CredentialConfirmationLifecycleCodec.decode(
                        readMetadataValue(record));
                return Optional.of(new StoredConfirmation(lifecycle, record.recordRevision()));
            }
        } catch (IOException failure) {
            throw confirmationPersistenceFailure(failure);
        }
    }

    private static boolean sameConfirmationInitialization(CredentialConfirmationLifecycle lifecycle,
            CredentialConfirmationInitialization initialization) {
        return lifecycle.credentialId().equals(initialization.credentialId())
                && lifecycle.initialPolicy() == initialization.initialPolicy()
                && lifecycle.initialPolicyCommitment().equals(initialization.initialPolicyCommitment())
                && lifecycle.confirmationRequired() == initialization.confirmationRequired()
                && lifecycle.confirmationReviewAt().equals(initialization.confirmationReviewAt())
                && lifecycle.proofSuite().equals(initialization.proofSuite());
    }

    private static boolean isExactTerminalConfirmationRetry(CredentialConfirmationLifecycle lifecycle,
            CredentialConfirmationProofCas proofCas) {
        CredentialConfirmationInitialization initialization = new CredentialConfirmationInitialization(
                lifecycle.credentialId(), lifecycle.initialPolicy(), lifecycle.initialPolicyCommitment(),
                lifecycle.confirmationRequired(), lifecycle.confirmationReviewAt(), lifecycle.proofSuite());
        CredentialConfirmationLifecycle pending = CredentialConfirmationLifecycle.initialize(initialization);
        return lifecycle.credentialId().equals(proofCas.credentialId())
                && proofCas.expectedLifecycleRevision() == pending.revision()
                && proofCas.expectedLifecycleRecordCommitment().equals(pending.recordCommitment())
                && lifecycle.consumedChallengeRecordCommitment().orElseThrow()
                        .equals(proofCas.expectedChallengeRecordCommitment());
    }

    private static IllegalStateException confirmationPersistenceFailure(IOException failure) {
        return new IllegalStateException("Credential confirmation persistence failed", failure);
    }

    private static MetadataKey confirmationRecordKey(PkiId credentialId) {
        PkiId exact = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
        byte[] domain = "zeroecho:credential-confirmation-record-key:v1"
                .getBytes(StandardCharsets.US_ASCII);
        byte[] identity = exact.value().getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(domain.length).array());
            digest.update(domain);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(identity.length).array());
            digest.update(identity);
            return new MetadataKey(CONFIRMATION_RECORD_NS,
                    HexFormat.of().formatHex(digest.digest()));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static MetadataKey confirmationChallengeKey(PkiId credentialId) {
        PkiId exact = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
        byte[] domain = "zeroecho:credential-confirmation-challenge-key:v1"
                .getBytes(StandardCharsets.US_ASCII);
        byte[] identity = exact.value().getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(domain.length).array());
            digest.update(domain);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(identity.length).array());
            digest.update(identity);
            return new MetadataKey(CONFIRMATION_CHALLENGE_NS,
                    "v1-" + HexFormat.of().formatHex(digest.digest()));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static CredentialConfirmationReview confirmationReview(
            CredentialConfirmationLifecycle lifecycle, Credential credential) {
        if (!lifecycle.credentialId().equals(credential.credentialId())) {
            throw new IllegalStateException("Credential confirmation review identity is inconsistent");
        }
        return new CredentialConfirmationReview(lifecycle.credentialId(),
                credential.issuerRef().caId(), credentialProfileId(credential),
                lifecycle.confirmationReviewAt(), lifecycle.initialPolicy());
    }

    private static String credentialProfileId(Credential credential) {
        if (credential.profileBinding() instanceof EndEntityProfileBinding binding) {
            return binding.reference().profileId();
        }
        if (credential.profileBinding() instanceof CaProfileBinding binding) {
            return binding.reference().profileId();
        }
        throw new IllegalStateException("Credential confirmation profile binding is unsupported");
    }

    private static MetadataKey confirmationReviewKey(CredentialConfirmationReview review,
            boolean profileScoped) {
        return confirmationReviewKey(new CredentialConfirmationReviewScope(review.authorityId(),
                profileScoped ? Optional.of(review.profileId()) : Optional.empty()),
                review.confirmationReviewAt(), review.credentialId());
    }

    private static MetadataKey confirmationReviewKey(CredentialConfirmationReviewScope scope,
            Instant reviewAt, PkiId credentialId) {
        String key = confirmationReviewPrefix(scope)
                + HexFormat.of().toHexDigits(reviewAt.getEpochSecond())
                + HexFormat.of().toHexDigits(reviewAt.getNano()) + '-'
                + HexFormat.of().formatHex(credentialId.value()
                        .getBytes(StandardCharsets.UTF_8));
        return new MetadataKey(CONFIRMATION_REVIEW_NS, key);
    }

    private static boolean isConfirmationReviewKey(MetadataKey key,
            CredentialConfirmationReview review) {
        return key.equals(confirmationReviewKey(review, false))
                || key.equals(confirmationReviewKey(review, true));
    }

    private static CredentialConfirmationReviewScope confirmationReviewScope(PkiId authorityId,
            Optional<String> profileId) {
        Optional<String> exactProfile = Objects.requireNonNull(profileId, "profileId");
        CredentialConfirmationReview probe = new CredentialConfirmationReview(new PkiId("scope-probe"),
                authorityId, exactProfile.orElse("scope-probe"), Instant.EPOCH,
                ConfirmationDisclosurePolicy.AUTHENTICATED);
        return new CredentialConfirmationReviewScope(probe.authorityId(),
                exactProfile.map(value -> new CredentialConfirmationReview(new PkiId("scope-probe"),
                        probe.authorityId(), value, Instant.EPOCH,
                        ConfirmationDisclosurePolicy.AUTHENTICATED).profileId()));
    }

    private static String confirmationReviewPrefix(CredentialConfirmationReviewScope scope) {
        String authority = confirmationScopeDigest("authority", scope.authorityId().value());
        if (scope.profileId().isEmpty()) {
            return "a2-" + authority + '-';
        }
        return "p2-" + authority + '-'
                + confirmationScopeDigest("profile", scope.profileId().orElseThrow()) + '-';
    }

    private static byte[] confirmationReviewScopeBinding(CredentialConfirmationReviewScope scope) {
        return digestFramed("zeroecho:confirmation-review-query-scope:v2",
                scope.authorityId().value(), scope.profileId().orElse(""),
                Boolean.toString(scope.profileId().isPresent()));
    }

    private static String confirmationScopeDigest(String kind, String value) {
        return HexFormat.of().formatHex(digestFramed(
                "zeroecho:confirmation-review-index-scope:v2", kind, value));
    }

    private static byte[] digestFramed(String domain, String... values) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] domainBytes = domain.getBytes(StandardCharsets.US_ASCII);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(domainBytes.length).array());
            digest.update(domainBytes);
            for (String value : values) {
                byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(encoded.length).array());
                digest.update(encoded);
            }
            return digest.digest();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private CaRecord validateCaCredentialReferences(CaRecord record) {
        for (PkiId issuerId : record.issuerIds()) {
            IssuerGeneration generation = getIssuerGeneration(issuerId)
                    .orElseThrow(() -> new IllegalStateException("CA issuer-generation reference is missing"));
            if (!record.caId().equals(generation.authorityId())) {
                throw new IllegalStateException("CA issuer-generation authority mismatch");
            }
        }
        IssuerChainPath issuancePath = getIssuerChainPath(record.issuanceChainPathId())
                .orElseThrow(() -> new IllegalStateException("CA issuance chain path is missing"));
        if (!record.caId().equals(issuancePath.authorityId())
                || !record.currentIssuanceIssuerId().equals(issuancePath.issuerId())) {
            throw new IllegalStateException("CA issuance selection mismatch");
        }
        return record;
    }

    private IssuerGeneration validateIssuerGeneration(IssuerGeneration generation) {
        getCredential(generation.credentialId())
                .orElseThrow(() -> new IllegalStateException("Issuer credential reference is missing"));
        return generation;
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private IssuerChainPath validateIssuerChainPath(IssuerChainPath path) {
        IssuerGeneration generation = getIssuerGeneration(path.issuerId())
                .orElseThrow(() -> new IllegalStateException("Issuer generation is missing"));
        if (!path.authorityId().equals(generation.authorityId())
                || !path.orderedCredentialIds().get(0).equals(generation.credentialId())) {
            throw new IllegalStateException("Issuer chain path generation mismatch");
        }
        List<Credential> credentials = path.orderedCredentialIds().stream()
                .map(id -> getCredential(id).orElseThrow(
                        () -> new IllegalStateException("Issuer chain credential is missing"))).toList();
        long aggregate = 0L;
        for (Credential credential : credentials) {
            aggregate = Math.addExact(aggregate, credential.content().length());
            if (aggregate > 32L * 1024L * 1024L) {
                throw new IllegalStateException("Issuer chain exceeds the aggregate artifact limit");
            }
        }
        try {
            List<X509Certificate> holders = new ArrayList<>(credentials.size());
            for (Credential credential : credentials) {
                holders.add(certificateHolder(credential));
            }
            for (int index = 0; index + 1 < credentials.size(); index++) {
                Credential credential = credentials.get(index);
                Credential parent = credentials.get(index + 1);
                X509Certificate holder = holders.get(index);
                X509Certificate parentHolder = holders.get(index + 1);
                IssuerGeneration signingGeneration = getIssuerGeneration(credential.issuerRef().issuerId())
                        .orElseThrow(() -> new IllegalStateException("Issuer chain parent generation is missing"));
                boolean parentGeneration = listIssuerGenerations(credential.issuerRef().caId()).stream()
                        .anyMatch(candidate -> parent.credentialId().equals(candidate.credentialId()));
                if (!credential.issuerRef().caId().equals(signingGeneration.authorityId())
                        || !parentGeneration
                        || !holder.getIssuerX500Principal().equals(parentHolder.getSubjectX500Principal())
                        || !signatureValid(holder, parentHolder.getPublicKey())) {
                    throw new IllegalStateException("Issuer chain relationship is invalid");
                }
            }
            X509Certificate anchor = holders.get(holders.size() - 1);
            if (!anchor.getIssuerX500Principal().equals(anchor.getSubjectX500Principal())
                    || !signatureValid(anchor, anchor.getPublicKey())) {
                throw new IllegalStateException("Issuer chain trust anchor is invalid");
            }
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Issuer chain validation failed", exception);
        }
        return path;
    }

    private X509Certificate certificateHolder(Credential credential) throws IOException {
        long length = credential.content().length();
        if (length <= 0L || length > 1024L * 1024L || length > Integer.MAX_VALUE) {
            throw new IllegalStateException("Issuer certificate exceeds the artifact limit");
        }
        byte[] encoded = new byte[(int) length];
        try (RepeatableContent content = stagedContent.openContent(credential.content());
                InputStream input = content.openStream()) {
            int offset = 0;
            while (offset < encoded.length) {
                int count = input.read(encoded, offset, encoded.length - offset);
                if (count < 0) {
                    throw new IOException("Issuer certificate is truncated");
                }
                offset += count;
            }
            if (input.read() >= 0) {
                throw new IOException("Issuer certificate length changed");
            }
            X509Certificate holder;
            try {
                holder = Pkix.parseCertificate(encoded);
                if (!MessageDigest.isEqual(encoded, holder.getEncoded())) {
                    throw new IOException("Issuer certificate is not canonical DER");
                }
            } catch (IllegalArgumentException | java.security.cert.CertificateEncodingException failure) {
                throw new IOException("Issuer certificate is not canonical DER", failure);
            }
            return holder;
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static boolean signatureValid(X509Certificate certificate, java.security.PublicKey signerKey) {
        try {
            certificate.verify(signerKey);
            return true;
        } catch (java.security.GeneralSecurityException failure) {
            return false;
        }
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
    public RevocationRecord revokeOverduePendingCredentialConfirmation(
            final RevocationCommand.RevokePermanently command) {
        requireStoreUsable();
        RevocationCommand.RevokePermanently exact = Objects.requireNonNull(command, "command");
        if (exact.reason() != RevocationReason.UNSPECIFIED) {
            throw new IllegalArgumentException(
                    "Overdue pending confirmation revocation reason must be UNSPECIFIED");
        }
        PkiId credentialId = exact.credentialId();
        CredentialStateLockEntry lock = acquireCredentialStateLock(credentialId);
        try {
            Credential credential = getCredential(credentialId).orElseThrow(() ->
                    new PkiException(
                            "Revocation target unavailable: code=REVOCATION_CREDENTIAL_NOT_FOUND",
                            PkiFailureReason.REVOCATION_CREDENTIAL_NOT_FOUND));
            CredentialConfirmationLifecycle lifecycle = readStoredConfirmation(credentialId)
                    .map(StoredConfirmation::lifecycle)
                    .orElseThrow(FilesystemPkiStore::confirmationRevocationConflict);
            Optional<RevocationRecord> current;
            try {
                current = revocations.current(credentialId);
            } catch (IOException failure) {
                throw corruptRevocationState();
            }
            if (current.filter(record -> record.transition().state()
                    == RevocationState.PERMANENTLY_REVOKED).isPresent()) {
                RevocationRecord committed = current.orElseThrow();
                if (committed.transition().permanentReason().orElse(null) != RevocationReason.UNSPECIFIED
                        || !sameAttributes(committed.transition().attributes(), exact.attributes())) {
                    throw confirmationRevocationConflict();
                }
                finishPendingConfirmationRevocationCleanup(lifecycle, credential);
                return committed;
            }
            Instant transitionTime = Objects.requireNonNull(clock.instant(), "store clock instant");
            if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING
                    || lifecycle.initialPolicy() == ConfirmationDisclosurePolicy.PUBLIC
                    || !transitionTime.isAfter(lifecycle.confirmationReviewAt())) {
                throw confirmationRevocationConflict();
            }
            RevocationTransition transition = nextRevocationTransition(
                    current, exact, transitionTime);
            RevocationRecord committed;
            try {
                RevocationTransitionFrameCodec.CompleteRecord appended =
                        revocations.append(credentialId, transition);
                committed = new RevocationRecord(credentialId, appended.data().transition());
            } catch (FilesystemRevocationLog.OutcomeUnknownException uncertain) {
                throw new PkiException(
                        "Confirmation revocation requires recovery: code=CONFIRMATION_REVOCATION_RECOVERY_REQUIRED",
                        PkiFailureReason.CONFIRMATION_REVOCATION_RECOVERY_REQUIRED);
            } catch (IOException failure) {
                throw new PkiException(
                        "Revocation persistence failed: code=REVOCATION_PERSIST_FAILED",
                        PkiFailureReason.REVOCATION_PERSIST_FAILED);
            }
            finishPendingConfirmationRevocationCleanup(lifecycle, credential);
            return committed;
        } finally {
            releaseCredentialStateLock(credentialId, lock);
        }
    }

    private void finishPendingConfirmationRevocationCleanup(
            CredentialConfirmationLifecycle lifecycle, Credential credential) {
        try {
            confirmationCleanupFaults.beforeCleanup(lifecycle.credentialId());
            CredentialConfirmationReview review = confirmationReview(lifecycle, credential);
            Optional<StoredConfirmationReview> authorityReview = readStoredConfirmationReview(review, false);
            Optional<StoredConfirmationReview> profileReview = readStoredConfirmationReview(review, true);
            Optional<StoredConfirmationChallenge> challenge = readStoredConfirmationChallenge(
                    lifecycle.credentialId());
            if (authorityReview.isEmpty() && profileReview.isEmpty() && challenge.isEmpty()) {
                return;
            }
            try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
                authorityReview.ifPresent(stored -> transaction.delete(
                        confirmationReviewKey(review, false), stored.recordRevision()));
                profileReview.ifPresent(stored -> transaction.delete(
                        confirmationReviewKey(review, true), stored.recordRevision()));
                challenge.ifPresent(stored -> transaction.delete(
                        confirmationChallengeKey(lifecycle.credentialId()), stored.recordRevision()));
                MetadataCommitResult result = requireKnownOutcome(transaction.commit());
                if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                    throw new PkiException(
                            "Confirmation revocation requires recovery: code=CONFIRMATION_REVOCATION_RECOVERY_REQUIRED",
                        PkiFailureReason.CONFIRMATION_REVOCATION_RECOVERY_REQUIRED);
                }
            }
        } catch (IOException | RuntimeException failure) {
            if (failure instanceof PkiException pkiFailure
                    && pkiFailure.failureReason().orElse(null)
                            == PkiFailureReason.CONFIRMATION_REVOCATION_RECOVERY_REQUIRED) {
                throw pkiFailure;
            }
            throw new PkiException(
                    "Confirmation revocation requires recovery: code=CONFIRMATION_REVOCATION_RECOVERY_REQUIRED",
                        PkiFailureReason.CONFIRMATION_REVOCATION_RECOVERY_REQUIRED);
        }
    }

    private static PkiException confirmationRevocationConflict() {
        return new PkiException(
                "Pending confirmation is not revocable: code=CONFIRMATION_REVOCATION_CONFLICT",
                PkiFailureReason.CONFIRMATION_REVOCATION_CONFLICT);
    }

    private static boolean sameAttributes(AttributeSet left, AttributeSet right) {
        if (!left.ids().equals(right.ids())) {
            return false;
        }
        for (AttributeId id : left.ids()) {
            List<AttributeValue> leftValues = left.getAll(id);
            List<AttributeValue> rightValues = right.getAll(id);
            if (leftValues.size() != rightValues.size()) {
                return false;
            }
            for (int index = 0; index < leftValues.size(); index++) {
                if (!sameAttributeValue(leftValues.get(index), rightValues.get(index))) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean sameAttributeValue(AttributeValue left, AttributeValue right) {
        if (left instanceof AttributeValue.BytesValue leftBytes
                && right instanceof AttributeValue.BytesValue rightBytes) {
            return MessageDigest.isEqual(leftBytes.value(), rightBytes.value());
        }
        return left.equals(right);
    }

    @Override
    public Optional<ParsedCertificationRequest> getRequest(final PkiId requestId) {
        requireStoreUsable();
        Objects.requireNonNull(requestId, "requestId");
        return readOptional(this.paths.requestPath(requestId), FsCodec.PARSED_REQUEST);
    }

    @Override
    // Filesystem failures are normalized to the stable store failure code.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public List<ParsedCertificationRequest> searchRequests(
            final zeroecho.pki.api.request.RequestQuery query, final int maxResults) {
        requireStoreUsable();
        Objects.requireNonNull(query, "query");
        if (maxResults <= 0) {
            throw new IllegalArgumentException("maxResults must be positive");
        }
        Path byId = this.paths.requestsById();
        if (!Files.isDirectory(byId)) {
            return List.of();
        }
        // Lazily iterate the request namespace, stopping as soon as the result cap is reached, and
        // never materialising the full path set. The creation-time window is checked from the
        // immutable request file's stored-at instant before the file is read, so a time-scoped search
        // does not deserialise out-of-window requests. Results are unordered; the bound is maxResults.
        List<ParsedCertificationRequest> out = new ArrayList<>();
        try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(byId)) {
            for (Path file : entries) {
                if (out.size() >= maxResults) {
                    break;
                }
                if (!Files.isRegularFile(file) || !withinCreatedRange(file, query)) {
                    continue;
                }
                ParsedCertificationRequest request = FsCodec.decode(FsCodec.PARSED_REQUEST,
                        FsOperations.readAll(file), stagedContent);
                if (matchesRequestContent(request, query)) {
                    out.add(request);
                }
            }
            return List.copyOf(out);
        } catch (IOException | SecurityException failure) {
            throw new IllegalStateException("request search failed");
        }
    }

    // Immutable requests are written once, so the request file's last-modified time is its
    // authoritative stored-at instant for the query's creation-time range constraints.
    private static boolean withinCreatedRange(final Path file,
            final zeroecho.pki.api.request.RequestQuery query) throws IOException {
        if (query.createdAfter().isEmpty() && query.createdBefore().isEmpty()) {
            return true;
        }
        Instant storedAt = Files.getLastModifiedTime(file).toInstant();
        if (query.createdAfter().isPresent() && storedAt.isBefore(query.createdAfter().orElseThrow())) {
            return false;
        }
        return query.createdBefore().isEmpty() || storedAt.isBefore(query.createdBefore().orElseThrow());
    }

    private static boolean matchesRequestContent(final ParsedCertificationRequest request,
            final zeroecho.pki.api.request.RequestQuery query) {
        if (query.formatId().isPresent() && !query.formatId().orElseThrow().equals(request.formatId())) {
            return false;
        }
        if (query.subjectRef().isPresent() && !query.subjectRef().orElseThrow().equals(request.subjectRef())) {
            return false;
        }
        return query.profileId().isEmpty()
                || request.requestedProfileId().filter(query.profileId().orElseThrow()::equals).isPresent();
    }

    @Override
    // Store failures are intentionally replaced by one stable redacted boundary.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    public RevocationRecord transitionRevocation(final RevocationCommand command, final Instant transitionTime) {
        requireStoreUsable();
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(transitionTime, "transitionTime");
        PkiId credentialId = command.credentialId();
        CredentialStateLockEntry lock = acquireCredentialStateLock(credentialId);
        try {
            Optional<Credential> credential;
            try {
                credential = getCredential(credentialId);
            } catch (RuntimeException failure) {
                throw corruptRevocationState();
            }
            if (credential.isEmpty()) {
                throw new PkiException("Revocation target unavailable: code=REVOCATION_CREDENTIAL_NOT_FOUND",
                            PkiFailureReason.REVOCATION_CREDENTIAL_NOT_FOUND);
            }
            Optional<RevocationRecord> current;
            try {
                current = revocations.current(credentialId);
            } catch (RuntimeException | IOException failure) {
                throw corruptRevocationState();
            }
            RevocationTransition transition = nextRevocationTransition(
                    current, command, transitionTime);
            try {
                RevocationTransitionFrameCodec.CompleteRecord committed =
                        revocations.append(credentialId, transition);
                return new RevocationRecord(credentialId, committed.data().transition());
            } catch (FilesystemRevocationLog.OutcomeUnknownException uncertain) {
                throw new PkiException(
                        "Revocation append outcome requires recovery: code=REVOCATION_RECOVERY_REQUIRED",
                        PkiFailureReason.REVOCATION_RECOVERY_REQUIRED);
            } catch (IOException failure) {
                throw new PkiException("Revocation persistence failed: code=REVOCATION_PERSIST_FAILED",
                        PkiFailureReason.REVOCATION_PERSIST_FAILED);
            }
        } finally {
            releaseCredentialStateLock(credentialId, lock);
        }
    }

    @Override
    public Optional<RevocationRecord> getRevocation(final PkiId credentialId) {
        requireStoreUsable();
        Objects.requireNonNull(credentialId, "credentialId");
        try {
            return revocations.current(credentialId);
        } catch (IOException failure) {
            throw corruptRevocationState();
        }
    }

    @Override
    public RevocationHistory openRevocationHistory(final PkiId credentialId) {
        requireStoreUsable();
        Objects.requireNonNull(credentialId, "credentialId");
        try {
            return revocations.history(credentialId);
        } catch (IOException failure) {
            throw corruptRevocationState();
        }
    }

    @Override
    public RevocationTransitionFeed openRevocationTransitionFeed(
            final Optional<RevocationTransitionFeed.Position> afterExclusive) {
        requireStoreUsable();
        Objects.requireNonNull(afterExclusive, "afterExclusive");
        try {
            return revocations.feed(afterExclusive);
        } catch (IOException failure) {
            throw corruptRevocationState();
        }
    }

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public AuditEvidenceFeed openIssuanceEvidenceFeed(final long afterSequenceExclusive) {
        requireStoreUsable();
        try {
            return new EvidenceFeedAdapter(issuanceEvidenceLog.openReader(afterSequenceExclusive));
        } catch (IOException failure) {
            throw new IllegalStateException("Issuance evidence feed cannot be opened");
        }
    }

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public AuditEvidenceFeed openStatusEvidenceFeed(final long afterSequenceExclusive) {
        requireStoreUsable();
        try {
            return new EvidenceFeedAdapter(statusEvidenceLog.openReader(afterSequenceExclusive));
        } catch (IOException failure) {
            throw new IllegalStateException("Status evidence feed cannot be opened");
        }
    }

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public AuditEvidenceFeed openPublicationEvidenceFeed(final long afterSequenceExclusive) {
        requireStoreUsable();
        try {
            return new EvidenceFeedAdapter(publicationEvidenceLog.openReader(afterSequenceExclusive));
        } catch (IOException failure) {
            throw new IllegalStateException("Publication evidence feed cannot be opened");
        }
    }

    @Override
    public boolean supportsSigningEvidenceFeed() {
        return signingEvidenceLog != null;
    }

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public AuditEvidenceFeed openSigningEvidenceFeed(final long afterSequenceExclusive) {
        requireStoreUsable();
        if (signingEvidenceLog == null) {
            throw new UnsupportedOperationException("Signing evidence feed is not enabled for this store");
        }
        try {
            return new EvidenceFeedAdapter(signingEvidenceLog.openReader(afterSequenceExclusive));
        } catch (IOException failure) {
            throw new IllegalStateException("Signing evidence feed cannot be opened");
        }
    }


    private static final class EvidenceFeedAdapter implements AuditEvidenceFeed {
        private final MetadataEvidenceLog.Reader reader;

        private EvidenceFeedAdapter(MetadataEvidenceLog.Reader reader) {
            this.reader = reader;
        }

        @Override public long highWatermark() { return reader.highWatermark(); }

        @Override public boolean next(CancellationSignal cancellation) throws IOException {
            return reader.next(cancellation);
        }

        @Override public Entry current() {
            MetadataEvidenceLog.Entry entry = reader.current();
            return new Entry(entry.sequence(), entry.objectId(), entry.recordedAt(), entry.payload());
        }

        @Override public void close() { reader.close(); }
    }

    @Override
    // Snapshot failures are intentionally replaced by one stable redacted boundary.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public RevocationSnapshot openRevocationSnapshot() {
        requireStoreUsable();
        try {
            return revocations.snapshot();
        } catch (IOException failure) {
            throw corruptRevocationState();
        }
    }

    @Override
    public RevocationView openRevocationView() {
        requireStoreUsable();
        try {
            return revocations.view();
        } catch (IOException failure) {
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
                recordStatusEvidence(object);
                return;
            }
            if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
                reservation.preserveUntilRecovery();
                durabilityUncertain.set(true);
                throw storeDurabilityUnconfirmed("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
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
    public PublicationRecord createPublicationRecord(final PublicationRecord record) {
        requireStoreUsable();
        Objects.requireNonNull(record, "record");
        validatePublicationRecord(record);
        Optional<PublicationRecord> existing = getPublicationRecord(record.publicationId());
        if (existing.isPresent()) {
            if (publicationRecordsEqual(existing.orElseThrow(), record)) {
                return existing.orElseThrow();
            }
            throw new IllegalArgumentException("Publication identity conflicts with an existing operation");
        }
        try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
            transaction.create(publicationRecordKey(record.publicationId()),
                    byteContent(PublicationRecordCodec.encode(record)), CancellationSignal.NONE);
            PublicationCommitFaultPoint fault = takePublicationCommitFault();
            if (fault == PublicationCommitFaultPoint.CREATE_BEFORE_COMMIT) {
                throw new IOException("Injected publication create failure");
            }
            MetadataCommitResult result = transaction.commit();
            if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                acknowledgeKnownOutcome(result);
                return record;
            }
            if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
                throw publicationPersistenceUnknown();
            }
            acknowledgeKnownOutcome(result);
        } catch (IOException exception) {
            throw new IllegalStateException("Publication metadata persistence failed");
        }
        Optional<PublicationRecord> raced = getPublicationRecord(record.publicationId());
        if (raced.isPresent() && publicationRecordsEqual(raced.orElseThrow(), record)) {
            return raced.orElseThrow();
        }
        throw new IllegalArgumentException("Publication identity conflicts with an existing operation");
    }

    @Override
    public Optional<PublicationRecord> getPublicationRecord(final PkiId publicationId) {
        requireStoreUsable();
        Objects.requireNonNull(publicationId, "publicationId");
        MetadataKey key = publicationRecordKey(publicationId);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> stored = snapshot.get(key);
            if (stored.isEmpty()) {
                return Optional.empty();
            }
            try (MetadataSnapshot.Record record = stored.orElseThrow()) {
                return Optional.of(decodePublicationRecord(record, snapshot));
            }
        } catch (IOException exception) {
            throw new IllegalStateException("Publication metadata is invalid");
        }
    }

    @Override
    public boolean replacePublicationRecord(final PublicationRecord expected,
            final PublicationRecord replacement) {
        requireStoreUsable();
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(replacement, "replacement");
        validatePublicationReplacement(expected, replacement);
        MetadataKey key = publicationRecordKey(expected.publicationId());
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> stored = snapshot.get(key);
            if (stored.isEmpty()) {
                return false;
            }
            long revision;
            try (MetadataSnapshot.Record record = stored.orElseThrow()) {
                if (!publicationRecordsEqual(decodePublicationRecord(record, snapshot), expected)) {
                    return false;
                }
                revision = record.recordRevision();
            }
            boolean committed;
            try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
                transaction.replace(key, revision, byteContent(PublicationRecordCodec.encode(replacement)),
                        CancellationSignal.NONE);
                PublicationCommitFaultPoint fault = takePublicationCommitFault();
                if (fault == PublicationCommitFaultPoint.REPLACE_BEFORE_COMMIT) {
                    throw new IOException("Injected publication replacement failure");
                }
                MetadataCommitResult result = transaction.commit();
                if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED
                        && fault == PublicationCommitFaultPoint.REPLACE_COMMIT_AS_UNKNOWN) {
                    throw publicationPersistenceUnknown();
                }
                if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
                    throw publicationPersistenceUnknown();
                }
                acknowledgeKnownOutcome(result);
                committed = result.outcome() == MetadataCommitResult.Outcome.COMMITTED;
            }
            if (committed && isTerminalPublication(replacement.status())) {
                recordPublicationEvidence(replacement);
            }
            return committed;
        } catch (IOException exception) {
            throw new IllegalStateException("Publication metadata persistence failed");
        }
    }

    private static boolean isTerminalPublication(PublicationStatus status) {
        return status == PublicationStatus.SUCCEEDED
                || status == PublicationStatus.TERMINAL_FAILURE;
    }

    // Appends one append-ordered publication-evidence entry for a committed TERMINAL publication outcome, so
    // the audit projector can advance a durable cursor. Idempotent per publication (safe under crash-window
    // retry and startup reconciliation); a publication reaches at most one terminal outcome.
    private void recordPublicationEvidence(PublicationRecord record) {
        PublicationStatus status = record.status();
        zeroecho.pki.application.PublicationExecutionEvidence evidence =
                new zeroecho.pki.application.PublicationExecutionEvidence(record.sourceType().name(),
                        record.sourceId().value(), record.target().type().name(), record.target().targetId(),
                        record.attemptNumber(), record.evidence().map(Enum::name), record.failure().map(Enum::name),
                        status == PublicationStatus.SUCCEEDED
                                ? zeroecho.pki.application.PublicationExecutionEvidence.Outcome.SUCCEEDED
                                : zeroecho.pki.application.PublicationExecutionEvidence.Outcome.TERMINAL_FAILURE);
        byte[] payload = zeroecho.pki.impl.core.async.DomainAttributeEncoding.encode(evidence.attributes())
                .getBytes(StandardCharsets.UTF_8);
        try {
            publicationEvidenceLog.append(record.publicationId(), record.updatedAt(), payload);
        } catch (IOException failure) {
            // Best-effort: the terminal publication record is already committed; startup reconciliation re-appends.
            LOG.log(Level.WARNING, "Publication evidence log append deferred to reconciliation: code=EVIDENCE_APPEND_UNCONFIRMED");
        }
    }

    @Override
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    public PublicationCursor openPublicationRecords() {
        requireStoreUsable();
        MetadataSnapshot snapshot = null;
        try {
            snapshot = metadataStore.snapshot();
            MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(PUBLICATION_RECORD_NAMESPACE),
                    CancellationSignal.NONE);
            return new PublicationMetadataCursor(snapshot, cursor);
        } catch (IOException | RuntimeException failure) {
            if (snapshot != null) {
                snapshot.close();
            }
            throw new IllegalStateException("Publication metadata cursor cannot be opened");
        }
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
        return advanceSigningTime();
    }

    // Monotonic signing time shared by every signer. The watermark is an atomic maximum
    // and {@code observeWatermark} is itself monotonic (a commutative {@code Math.max}),
    // so concurrent signers already observe a non-decreasing signing time without any
    // additional mutual exclusion. Keeping this off a dedicated lock removes the single
    // point that otherwise serialized every signing request onto one thread at a time.
    private Instant advanceSigningTime() {
        long monotonic = signingTimeWatermark.accumulateAndGet(
                clock.instant().toEpochMilli(), Math::max);
        metadataStore.observeWatermark(monotonic);
        return Instant.ofEpochMilli(monotonic);
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
    public String localSigningNamespace(String providerId) {
        requireStoreUsable();
        Objects.requireNonNull(providerId, "providerId");
        if (providerId.isBlank()) {
            throw new IllegalArgumentException("providerId must not be blank");
        }
        return signingNamespace + "." + providerId;
    }

    @Override
    public AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptLocalSign(
            zeroecho.pki.spi.crypto.SignatureWorkflow.SignRequest request,
            zeroecho.pki.spi.crypto.SignatureWorkflow.ConfigurationCommitment configurationCommitment,
            SignWorkflowStore.Record intent, DurableContentReference reference) {
        Objects.requireNonNull(request, "request");
        try (SignWorkflowStore.SignAdmission admission =
                reserveSignAdmission(request.submissionId())) {
            return acceptLocalSign(admission, request, configurationCommitment, intent, reference);
        }
    }

    @Override
    public AtomicLocalSigningLedgerParticipant.AtomicAcceptance acceptLocalSign(
            SignWorkflowStore.SignAdmission admission,
            zeroecho.pki.spi.crypto.SignatureWorkflow.SignRequest request,
            zeroecho.pki.spi.crypto.SignatureWorkflow.ConfigurationCommitment configurationCommitment,
            SignWorkflowStore.Record intent, DurableContentReference reference) {
        requireStoreUsable();
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(configurationCommitment, "configurationCommitment");
        Objects.requireNonNull(intent, "intent");
        Objects.requireNonNull(reference, "reference");
        StoreSignAdmission ownedAdmission = claimAdmission(admission, request.submissionId());
        SignLockEntry lock = acquireSignLock(request.submissionId());
        try {
            Optional<StoredSign> optional = readStoredSign(request.submissionId());
            if (optional.isPresent()) {
                SignWorkflowStore.Record existing = optional.orElseThrow().record();
                requireMatchingLocalRequest(existing, request);
                if (!existing.configurationCommitment().matches(configurationCommitment)) {
                    throw new IllegalStateException("Local signing request conflicts: code=LOCAL_SIGN_CONFLICT");
                }
                return AtomicLocalSigningLedgerParticipant.AtomicAcceptance.attached();
            }
            if (!intent.submissionId().equals(request.submissionId())
                    || !constantTimeAsciiEquals(intent.fingerprint(), request.semanticFingerprint())
                    || !intent.configurationCommitment().matches(request.configurationCommitment())
                    || !intent.configurationCommitment().matches(configurationCommitment)
                    || intent.state() != SignWorkflowStore.State.INTENT) {
                throw new IllegalArgumentException("Local signing intent is inconsistent");
            }
            SignWorkflowStore.Record accepted = copySignRecord(intent, SignWorkflowStore.State.DISPATCHED,
                    2L, request.fencingToken(), Optional.empty(), Optional.of("DISPATCHED"),
                    Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
            validateSignRecord(accepted.submissionId(), accepted);
            try (FilesystemStagedContentStore.TransactionalReservation ignoredReservation =
                            stagedContent.reserveTransactionalPublication(reference)) {
                try (RepeatableContent ignoredContent = stagedContent.openContent(reference)) {
                    stagedContent.restoreReference(reference.storeId(), reference.contentId(), reference.encoding(),
                            reference.length(), reference.sha256(), reference.lifecycle());
                } catch (IOException contentFailure) {
                    throw new PkiException("Signing content unavailable: code=CONTENT_INTEGRITY_FAILED");
                }
                List<SigningTransactionPayloadCodec.Mutation> mutations = List.of(
                        new SigningTransactionPayloadCodec.Mutation(
                                SigningTransactionPayloadCodec.MutationKind.CREATE,
                                signingRecordKey(accepted.submissionId()), -1L,
                                FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, accepted)),
                        new SigningTransactionPayloadCodec.Mutation(
                                SigningTransactionPayloadCodec.MutationKind.CREATE,
                                SigningOwnerKey.exact(reference, accepted.submissionId()), -1L,
                                encodeSigningOwner(accepted.submissionId(), reference)));
                MetadataCommitResult result = metadataStore.directCommit(
                        mutations, ownedAdmission.transfer());
                if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                    retireFailedSigningPublication(reference);
                    return AtomicLocalSigningLedgerParticipant.AtomicAcceptance.attached();
                }
            } catch (MetadataStoreException failure) {
                throw translateSigningMetadataFailure(failure);
            } catch (IOException failure) {
                throw signingDurabilityFailure(failure);
            }
            AtomicBoolean cancellation = new AtomicBoolean();
            localSignCancellations.put(request.submissionId(), cancellation);
            LocalExecutionPermit permit = new LocalExecutionPermit(this, request.submissionId(),
                    request.semanticFingerprint(), configurationCommitment, request.fencingToken(),
                    cancellation::get);
            return AtomicLocalSigningLedgerParticipant.AtomicAcceptance.execute(permit);
        } finally {
            releaseSignLock(request.submissionId(), lock);
            ownedAdmission.close();
        }
    }

    @Override
    public boolean completeLocalSign(zeroecho.pki.spi.crypto.SignatureWorkflow.SignRequest request,
            zeroecho.pki.spi.crypto.SignatureWorkflow.OperationStatus terminal) {
        requireStoreUsable();
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(terminal, "terminal");
        if (!terminal.isTerminal()) {
            throw new IllegalArgumentException("Local signing completion must be terminal");
        }
        Optional<SignExpiry> expiry;
        boolean committed;
        SignLockEntry lock = acquireSignLock(request.submissionId());
        try {
            Optional<StoredSign> optional = readStoredSign(request.submissionId());
            if (optional.isEmpty()) {
                return false;
            }
            StoredSign stored = optional.orElseThrow();
            SignWorkflowStore.Record current = stored.record();
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                committed = false;
            } else {
                requireMatchingLocalRequest(current, request);
                if (current.state() != SignWorkflowStore.State.DISPATCHED
                        && current.state() != SignWorkflowStore.State.CANCELLING
                        || current.fence() != request.fencingToken()) {
                    return false;
                }
                SignWorkflowStore.State target = localTerminalState(terminal.state());
                Optional<EncodedObject> result = terminal.result()
                        .flatMap(zeroecho.pki.spi.crypto.SignatureWorkflow.OperationResult::signature);
                if (target != SignWorkflowStore.State.SUCCEEDED) {
                    result = Optional.empty();
                }
                if (target == SignWorkflowStore.State.SUCCEEDED && result.isEmpty()) {
                    target = SignWorkflowStore.State.FAILED;
                }
                if (target == SignWorkflowStore.State.EXPIRED) {
                    expiry = expireSign(stored);
                    committed = expiry.isPresent();
                } else {
                    Optional<String> detail = target == SignWorkflowStore.State.FAILED && result.isEmpty()
                            && terminal.state() == zeroecho.pki.spi.crypto.SignatureWorkflow.State.SUCCEEDED
                                    ? Optional.of("PROVIDER_RESULT_INVALID")
                                    : safeLocalDetail(target, terminal.detailCode());
                    SignWorkflowStore.Record completed = copySignRecord(current, target,
                            current.revision() + 1L, current.fence(), Optional.empty(), detail, result,
                            Optional.of(terminal.updatedAt()), 0, Optional.empty(), Optional.empty());
                    SignTransitionCommit terminalCommit = commitSignTransitionAtAdmission(stored, completed);
                    expiry = terminalCommit.expiry();
                    committed = terminalCommit.record().isPresent();
                    if (committed && expiry.isEmpty()) {
                        localSignCancellations.remove(request.submissionId());
                    }
                }
            }
        } finally {
            releaseSignLock(request.submissionId(), lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return committed;
    }

    @Override
    public zeroecho.pki.spi.crypto.SignatureWorkflow.OperationStatus localSignStatus(PkiId operationId) {
        requireStoreUsable();
        Objects.requireNonNull(operationId, "operationId");
        Optional<SignWorkflowStore.Record> optional = getSignRecord(operationId);
        if (optional.isEmpty()) {
            try {
                SigningSubmissionId parsed = SigningSubmissionId.parse(operationId);
                if (parsed.namespace().startsWith(signingNamespace + ".")
                        && !signingNow().isBefore(parsed.createdAt().plus(signingHorizon()))) {
                    return new zeroecho.pki.spi.crypto.SignatureWorkflow.OperationStatus(
                            zeroecho.pki.spi.crypto.SignatureWorkflow.State.EXPIRED, signingNow(),
                            Optional.of("EXPIRED"), Optional.empty());
                }
            } catch (IllegalArgumentException malformed) { // NOPMD - stable unknown status below
                // Unknown identifiers use the stable redacted status below.
            }
            return new zeroecho.pki.spi.crypto.SignatureWorkflow.OperationStatus(
                    zeroecho.pki.spi.crypto.SignatureWorkflow.State.FAILED, Instant.EPOCH,
                    Optional.of("UNKNOWN_OPERATION"), Optional.empty());
        }
        SignWorkflowStore.Record record = optional.orElseThrow();
        zeroecho.pki.spi.crypto.SignatureWorkflow.State state = switch (record.state()) {
            case INTENT -> zeroecho.pki.spi.crypto.SignatureWorkflow.State.PENDING;
            case DISPATCHED, CANCELLING -> zeroecho.pki.spi.crypto.SignatureWorkflow.State.RUNNING;
            case SUCCEEDED -> zeroecho.pki.spi.crypto.SignatureWorkflow.State.SUCCEEDED;
            case FAILED -> zeroecho.pki.spi.crypto.SignatureWorkflow.State.FAILED;
            case CANCELLED -> zeroecho.pki.spi.crypto.SignatureWorkflow.State.CANCELLED;
            case RETIRED -> record.result().isPresent()
                    ? zeroecho.pki.spi.crypto.SignatureWorkflow.State.SUCCEEDED
                    : zeroecho.pki.spi.crypto.SignatureWorkflow.State.CANCELLED;
            case EXPIRED -> zeroecho.pki.spi.crypto.SignatureWorkflow.State.EXPIRED;
        };
        Optional<zeroecho.pki.spi.crypto.SignatureWorkflow.OperationResult> result =
                state == zeroecho.pki.spi.crypto.SignatureWorkflow.State.SUCCEEDED
                        ? record.result().map(signature -> new zeroecho.pki.spi.crypto.SignatureWorkflow.OperationResult(
                                Optional.of(signature), Optional.empty())) : Optional.empty();
        Instant updatedAt = record.providerUpdatedAt().orElse(record.createdAt());
        return new zeroecho.pki.spi.crypto.SignatureWorkflow.OperationStatus(state, updatedAt,
                record.detailCode(), result);
    }

    @Override
    public CancellationSignal localCancellation(PkiId operationId) {
        requireStoreUsable();
        Objects.requireNonNull(operationId, "operationId");
        AtomicBoolean signal = localSignCancellations.computeIfAbsent(operationId, ignored -> new AtomicBoolean());
        return signal::get;
    }

    @Override
    public boolean cancelLocalSign(PkiId operationId, long fencingToken) {
        requireStoreUsable();
        Optional<SignExpiry> expiry;
        boolean cancelled;
        SignLockEntry lock = acquireSignLock(operationId);
        try {
            Optional<StoredSign> optional = readStoredSign(operationId);
            if (optional.isEmpty()) {
                return false;
            }
            StoredSign stored = optional.orElseThrow();
            SignWorkflowStore.Record current = stored.record();
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                cancelled = false;
            } else {
                if (current.state() == SignWorkflowStore.State.CANCELLED) {
                    return current.fence() == fencingToken;
                }
                if (current.state() == SignWorkflowStore.State.CANCELLING
                        && current.fence() == fencingToken) {
                    localSignCancellations.computeIfAbsent(operationId, ignored -> new AtomicBoolean()).set(true);
                    return true;
                }
                if (current.fence() != fencingToken
                        || current.state() != SignWorkflowStore.State.DISPATCHED) {
                    return false;
                }
                SignWorkflowStore.Record cancelling = copySignRecord(current, SignWorkflowStore.State.CANCELLING,
                        current.revision() + 1L, current.fence(), Optional.empty(), Optional.of("CANCEL_REQUESTED"),
                        Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
                if (!directReplaceSignMetadata(stored, cancelling)) return false;
                localSignCancellations.computeIfAbsent(operationId, ignored -> new AtomicBoolean()).set(true);
                cancelled = true;
            }
        } finally {
            releaseSignLock(operationId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return cancelled;
    }

    private void requireMatchingLocalRequest(SignWorkflowStore.Record record,
            zeroecho.pki.spi.crypto.SignatureWorkflow.SignRequest request) {
        if (!record.namespace().equals(request.namespace())
                || !record.configurationCommitment().matches(request.configurationCommitment())
                || !constantTimeAsciiEquals(record.fingerprint(), request.semanticFingerprint())) {
            throw new IllegalStateException("Local signing request conflicts: code=LOCAL_SIGN_CONFLICT");
        }
    }

    private static SignWorkflowStore.State localTerminalState(
            zeroecho.pki.spi.crypto.SignatureWorkflow.State state) {
        return switch (state) {
            case SUCCEEDED -> SignWorkflowStore.State.SUCCEEDED;
            case CANCELLED -> SignWorkflowStore.State.CANCELLED;
            case EXPIRED -> SignWorkflowStore.State.EXPIRED;
            case FAILED -> SignWorkflowStore.State.FAILED;
            case PENDING, RUNNING, WAITING_APPROVAL -> throw new IllegalArgumentException(
                    "Local signing completion must be terminal");
        };
    }

    private static Optional<String> safeLocalDetail(SignWorkflowStore.State target, Optional<String> supplied) {
        String fallback = switch (target) {
            case SUCCEEDED -> "SIGNED";
            case FAILED -> "PROVIDER_FAILURE";
            case CANCELLED -> "CANCELLED";
            case EXPIRED -> "EXPIRED";
            case INTENT, DISPATCHED, CANCELLING, RETIRED -> throw new IllegalArgumentException(
                    "Local terminal state is invalid");
        };
        return supplied.filter(code -> switch (code) {
            case "SIGNED", "CANCELLED", "EXPIRED", "CONTENT_INTEGRITY_FAILURE", "KEY_NOT_FOUND",
                    "INVALID_ALGORITHM_ID", "ALGORITHM_MISMATCH", "CRYPTO_FAILURE", "KEYRING_IO_ERROR",
                    "UNSUPPORTED_SIGNATURE_ENCODING", "PROVIDER_RESULT_INVALID" -> true;
            default -> false;
        }).or(() -> Optional.of(fallback));
    }

    @Override
    public long signingHeadroomEpoch() {
        requireStoreUsable();
        return metadataStore.headroomRestorationEpoch();
    }

    @Override
    public AtomicLocalSigningLedgerParticipant.HeadroomRegistration registerSigningHeadroomRestored(
            AtomicLocalSigningLedgerParticipant.HeadroomListener listener) {
        requireStoreUsable();
        AutoCloseable registration = metadataStore.registerHeadroomRestored(listener);
        return () -> {
            try {
                registration.close();
            } catch (Exception failure) {
                throw new IllegalStateException("Metadata headroom registration could not close", failure);
            }
        };
    }

    @Override
    public void recoverMatchedLocalSigning(String namespace,
            zeroecho.pki.spi.crypto.SignatureWorkflow.ConfigurationCommitment configurationCommitment) {
        requireStoreUsable();
        Objects.requireNonNull(namespace, "namespace");
        Objects.requireNonNull(configurationCommitment, "configurationCommitment");
        if (!namespace.startsWith(signingNamespace + ".")) {
            throw new IllegalArgumentException("Local signing namespace belongs to another store");
        }
        Optional<String> cursor = Optional.empty();
        Optional<String> highWatermark = Optional.empty();
        boolean firstPage = true;
        while (true) {
            SignWorkflowStore.Page page = pageSignRecords(cursor, highWatermark, 256,
                    CancellationSignal.NONE);
            if (firstPage) {
                highWatermark = page.highWatermark();
                firstPage = false;
            }
            if (page.failures() != 0) {
                throw new PkiException("Signing state invalid: code=CONTINUATION_INVALID");
            }
            for (SignWorkflowStore.Record candidate : page.records()) {
                if (!namespace.equals(candidate.namespace()) || !isActiveSignState(candidate.state())) {
                    continue;
                }
                recoverMatchedLocalSign(candidate.submissionId(), namespace, configurationCommitment);
            }
            if (page.endReached()) return;
            Optional<String> nextCursor = page.nextCursor();
            if (nextCursor.isEmpty() || nextCursor.equals(cursor)) {
                throw new PkiException("Signing state invalid: code=CONTINUATION_INVALID");
            }
            cursor = nextCursor;
        }
    }

    private void recoverMatchedLocalSign(PkiId submissionId, String namespace,
            zeroecho.pki.spi.crypto.SignatureWorkflow.ConfigurationCommitment configurationCommitment) {
        Optional<SignExpiry> expiry;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> stored = readStoredSign(submissionId);
            if (stored.isEmpty()) return;
            SignWorkflowStore.Record record = stored.orElseThrow().record();
            if (!namespace.equals(record.namespace()) || !isActiveSignState(record.state())) return;
            expiry = expireIfDeadlineReached(stored.orElseThrow());
            if (expiry.isEmpty() && record.configurationCommitment().matches(configurationCommitment)) {
                long recoveredFence = Math.max(1L, record.fence());
                long recoveredRevision = Math.max(record.revision() + 1L, recoveredFence + 1L);
                SignWorkflowStore.Record failed = copySignRecord(record, SignWorkflowStore.State.FAILED,
                        recoveredRevision, recoveredFence, Optional.empty(), Optional.of("RECOVERY_INCOMPLETE"),
                        Optional.empty(), Optional.of(signingNow()), 0, Optional.empty(), Optional.empty());
                SignTransitionCommit recoveryCommit =
                        commitSignTransitionAtAdmission(stored.orElseThrow(), failed);
                expiry = recoveryCommit.expiry();
                if (recoveryCommit.record().isEmpty()) {
                    throw new IllegalStateException(
                            "Local signing recovery conflicted: code=LOCAL_SIGN_RECOVERY_CONFLICT");
                }
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
    }

    private static boolean isActiveSignState(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.INTENT || state == SignWorkflowStore.State.DISPATCHED
                || state == SignWorkflowStore.State.CANCELLING;
    }

    @Override
    public SignWorkflowStore.CreateResult createSignIntent(SignWorkflowStore.Record intent) {
        Objects.requireNonNull(intent, "intent");
        try (SignWorkflowStore.SignAdmission admission =
                reserveSignAdmission(intent.submissionId())) {
            return createSignIntent(admission, intent);
        }
    }

    @Override
    public SignWorkflowStore.SignAdmission reserveSignAdmission() {
        requireStoreUsable();
        SigningLedgerStoreEngine.SigningAdmission delegate;
        try {
            delegate = metadataStore.reserveSigningAdmission();
        } catch (SigningDueWorkIndex.CapacityExhaustedException
                | SigningActiveWal.OverloadedException exhausted) {
            throw new SignWorkflowStore.SignAdmissionException(
                    SignWorkflowStore.SignAdmissionFailure.CAPACITY_EXHAUSTED);
        }
        if (closing.get()) {
            delegate.close();
            throw new IllegalStateException("Filesystem store is closing");
        }
        return new StoreSignAdmission(this, delegate);
    }

    @Override
    public SignWorkflowStore.CreateResult createSignIntent(
            SignWorkflowStore.SignAdmission admission, SignWorkflowStore.Record intent) {
        return createSignIntentInternal(admission, intent, Optional.empty());
    }

    @Override
    public SignWorkflowStore.CreateResult createSignIntent(
            SignWorkflowStore.SignAdmission admission, SignWorkflowStore.Record intent,
            DomainContinuationStore.Record continuation) {
        Objects.requireNonNull(continuation, "continuation");
        return createSignIntentInternal(admission, intent, Optional.of(continuation));
    }

    private SignWorkflowStore.CreateResult createSignIntentInternal(
            SignWorkflowStore.SignAdmission admission, SignWorkflowStore.Record intent,
            Optional<DomainContinuationStore.Record> domainContinuation) {
        requireStoreUsable();
        Objects.requireNonNull(intent, "intent");
        Objects.requireNonNull(domainContinuation, "domainContinuation");
        StoreSignAdmission ownedAdmission = claimAdmission(admission, intent.submissionId());
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
            domainContinuation.ifPresent(value -> validateInitialDomainContinuation(intent, value));
            Optional<SignWorkflowStore.Record> existing = readSignRecord(intent.submissionId());
            if (existing.isPresent()) {
                boolean sameSign = constantTimeAsciiEquals(existing.get().fingerprint(), intent.fingerprint());
                boolean sameDomain = domainContinuation.map(value -> getDomainContinuation(intent.submissionId())
                        .filter(current -> current.commandCommitment().equals(value.commandCommitment())
                                && current.signingContent().equals(value.signingContent())
                                && current.correlationId().equals(value.correlationId()))
                        .isPresent()).orElse(true);
                return sameSign && sameDomain ? SignWorkflowStore.CreateResult.ATTACHED
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
                result = createSignMetadata(intent, reference, ownedAdmission, domainContinuation);
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
            ownedAdmission.close();
        }
    }

    private static void validateInitialDomainContinuation(SignWorkflowStore.Record intent,
            DomainContinuationStore.Record continuation) {
        if (!intent.submissionId().equals(continuation.operationId())
                || continuation.version() != DOMAIN_CONTINUATION_VERSION
                || continuation.state() != DomainContinuationStore.State.SIGNING
                || continuation.revision() != 0L
                || !intent.createdAt().equals(continuation.createdAt())
                || !intent.deadline().equals(continuation.deadline())) {
            throw new IllegalArgumentException("Initial domain continuation does not match signing intent");
        }
        byte[] encoded = FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, continuation);
        DomainContinuationValidation.validate(intent.submissionId(), continuation, encoded.length);
    }

    @Override
    public Optional<DomainContinuationStore.Record> getDomainContinuation(PkiId operationId) {
        requireStoreUsable();
        Objects.requireNonNull(operationId, "operationId");
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataSnapshot.Record stored = snapshot.get(domainContinuationKey(operationId)).orElse(null)) {
            if (stored == null) return Optional.empty();
            return Optional.of(decodeDomainContinuation(operationId, stored));
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to read domain continuation", exception);
        }
    }

    @Override
    public Optional<DomainContinuationStore.Record> getDomainContinuation(
            DomainContinuationStore.Kind kind, String correlationId) {
        requireStoreUsable();
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(correlationId, "correlationId");
        PkiId operationId;
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataSnapshot.Record stored = snapshot.get(domainCorrelationKey(kind, correlationId))
                        .orElse(null)) {
            if (stored == null) return Optional.empty();
            byte[] encoded = readMetadataValue(stored);
            String value = new String(encoded, StandardCharsets.UTF_8);
            if (!Arrays.equals(encoded, value.getBytes(StandardCharsets.UTF_8))
                    || !value.startsWith("v1\n")) {
                throw new IllegalStateException("Domain correlation record is invalid");
            }
            operationId = new PkiId(value.substring(3));
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to read domain correlation", exception);
        }
        DomainContinuationStore.Record continuation = getDomainContinuation(operationId)
                .orElseThrow(() -> new IllegalStateException("Domain correlation target is missing"));
        if (continuation.kind() != kind
                || continuation.correlationId().filter(correlationId::equals).isEmpty()) {
            throw new IllegalStateException("Domain correlation authority differs");
        }
        return Optional.of(continuation);
    }

    @Override
    public Optional<DomainContinuationStore.Record> transitionDomainContinuation(PkiId operationId,
            long expectedRevision, DomainContinuationStore.State target,
            Optional<EncodedObject> result, Optional<String> detailCode) {
        requireStoreUsable();
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(detailCode, "detailCode");
        SignLockEntry lock = acquireSignLock(operationId);
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataSnapshot.Record stored = snapshot.get(domainContinuationKey(operationId)).orElse(null)) {
            if (stored == null) return Optional.empty();
            DomainContinuationStore.Record current = decodeDomainContinuation(operationId, stored);
            if (current.revision() != expectedRevision || !validDomainTransition(current.state(), target)) {
                return Optional.empty();
            }
            DomainContinuationStore.Record replacement = new DomainContinuationStore.Record(
                    current.operationId(), current.version(), current.kind(), current.correlationId(), target,
                    current.revision() + 1L, current.createdAt(), current.deadline(), current.command(),
                    current.commandCommitment(), liveDomainSigningContent(current, target), result, detailCode);
            try (MetadataTransaction transaction =
                    metadataStore.beginSigningProgressTransaction()) {
                transaction.replace(domainContinuationKey(operationId), stored.recordRevision(),
                        byteContent(FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, replacement)),
                        CancellationSignal.NONE);
                MetadataCommitResult committed = requireKnownOutcome(transaction.commit());
                return committed.outcome() == MetadataCommitResult.Outcome.COMMITTED
                        ? Optional.of(replacement) : Optional.empty();
            }
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to transition domain continuation", exception);
        } finally {
            releaseSignLock(operationId, lock);
        }
    }

    private static boolean validDomainTransition(DomainContinuationStore.State source,
            DomainContinuationStore.State target) {
        return source == DomainContinuationStore.State.SIGNING
                && (target == DomainContinuationStore.State.PUBLISHING
                        || target == DomainContinuationStore.State.FAILED
                        || target == DomainContinuationStore.State.EXPIRED)
                || source == DomainContinuationStore.State.PUBLISHING
                && (target == DomainContinuationStore.State.COMPLETED
                        || target == DomainContinuationStore.State.FAILED)
                || source == target && (source == DomainContinuationStore.State.COMPLETED
                        || source == DomainContinuationStore.State.FAILED
                        || source == DomainContinuationStore.State.EXPIRED);
    }

    private static Optional<DurableContentReference> liveDomainSigningContent(
            DomainContinuationStore.Record current, DomainContinuationStore.State target) {
        return target == DomainContinuationStore.State.SIGNING
                || target == DomainContinuationStore.State.PUBLISHING
                ? current.signingContent() : Optional.empty();
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
        Optional<SignExpiry> expiry = Optional.empty();
        Optional<SignWorkflowStore.Record> result;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> stored = readStoredSign(submissionId);
            if (stored.isEmpty()) {
                result = Optional.empty();
            } else {
                expiry = expireIfDeadlineReached(stored.orElseThrow());
                result = expiry.map(SignExpiry::record)
                        .or(() -> Optional.of(stored.orElseThrow().record()));
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return result;
    }

    @Override
    public List<SignWorkflowStore.Record> listSignRecords() {
        requireStoreUsable();
        return listStoredSigns().stream().map(StoredSign::record).toList();
    }

    @Override
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public List<SignWorkflowStore.Record> selectDueSignRecords(Instant cutoffInclusive,
            int maximumRecords) {
        requireStoreUsable();
        Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
        if (maximumRecords < 1 || maximumRecords > 4096) {
            throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
        }
        List<SignWorkflowStore.Record> records = new ArrayList<>(maximumRecords);
        try {
            List<String> dueOperations = metadataStore.selectSigningDue(
                    cutoffInclusive, maximumRecords);
            for (String operationId : dueOperations) {
                readSignRecord(new PkiId(operationId)).ifPresent(records::add);
            }
        } catch (IOException failure) {
            throw new IllegalStateException(
                    "Failed to select authoritative signing records", failure);
        }
        return List.copyOf(records);
    }

    @Override
    public SignWorkflowStore.Page pageSignRecords(Optional<String> exclusiveCursor, int maximumRecords,
            CancellationSignal cancellation) {
        return pageSignRecords(exclusiveCursor, Optional.empty(), maximumRecords, cancellation);
    }

    @Override
    public SignWorkflowStore.Page pageSignRecords(Optional<String> exclusiveCursor,
            Optional<String> inclusiveHighWatermark, int maximumRecords, CancellationSignal cancellation) {
        requireStoreUsable();
        Objects.requireNonNull(exclusiveCursor, "exclusiveCursor");
        Objects.requireNonNull(inclusiveHighWatermark, "inclusiveHighWatermark");
        Objects.requireNonNull(cancellation, "cancellation");
        if (maximumRecords < 1 || maximumRecords > 4096) {
            throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
        }
        Optional<String> lower = exclusiveCursor;
        MetadataSnapshot.KeyRange range = new MetadataSnapshot.KeyRange(SIGN_RECORD_NAMESPACE, lower,
                Optional.empty());
        List<SignWorkflowStore.Record> records = new ArrayList<>(maximumRecords);
        List<SignWorkflowStore.PageCandidate> candidates = new ArrayList<>(maximumRecords);
        int examined = 0;
        int failures = 0;
        Optional<String> nextCursor = exclusiveCursor;
        if (cancellation.isCancelled()) {
            return new SignWorkflowStore.Page(records, nextCursor, examined, failures, false, candidates);
        }
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataCursor cursor = snapshot.scan(range, cancellation)) {
            Optional<String> highWatermark = snapshot.greatestKey(SIGN_RECORD_NAMESPACE)
                    .map(MetadataKey::key);
            while (examined < maximumRecords) {
                Optional<MetadataSnapshot.Record> next;
                try {
                    next = cursor.next(cancellation);
                } catch (InterruptedIOException cancelled) {
                    if (cancellation.isCancelled()) {
                        return new SignWorkflowStore.Page(records, nextCursor, examined, failures, false, candidates,
                                highWatermark);
                    }
                    throw cancelled;
                }
                if (next.isEmpty()) {
                    return new SignWorkflowStore.Page(records, nextCursor, examined, failures, true, candidates,
                            highWatermark);
                }
                try (MetadataSnapshot.Record candidate = next.orElseThrow()) {
                    String candidateCursor = candidate.key().key();
                    if (inclusiveHighWatermark.filter(watermark -> candidateCursor.compareTo(watermark) > 0)
                            .isPresent()) {
                        return new SignWorkflowStore.Page(records, nextCursor, examined, failures, true, candidates,
                                highWatermark);
                    }
                    if (exclusiveCursor.filter(candidateCursor::equals).isPresent()) {
                        continue;
                    }
                    if (cancellation.isCancelled()) {
                        return new SignWorkflowStore.Page(records, nextCursor, examined, failures, false, candidates,
                                highWatermark);
                    }
                    examined++;
                    nextCursor = Optional.of(candidateCursor);
                    try {
                        SignWorkflowStore.Record decoded = decodeStoredSign(snapshot, candidate).record();
                        records.add(decoded);
                        candidates.add(new SignWorkflowStore.PageCandidate(candidateCursor, Optional.of(decoded)));
                    } catch (RuntimeException | IOException malformedCandidate) {
                        failures++;
                        candidates.add(new SignWorkflowStore.PageCandidate(candidateCursor, Optional.empty()));
                    }
                }
            }
            boolean endReached;
            try {
                Optional<MetadataSnapshot.Record> afterPage = cursor.next(cancellation);
                if (afterPage.isEmpty()) {
                    endReached = true;
                } else {
                    try (MetadataSnapshot.Record candidate = afterPage.orElseThrow()) {
                        endReached = inclusiveHighWatermark
                                .filter(watermark -> candidate.key().key().compareTo(watermark) > 0).isPresent();
                    }
                }
            } catch (InterruptedIOException cancelled) {
                if (!cancellation.isCancelled()) {
                    throw cancelled;
                }
                endReached = false;
            }
            return new SignWorkflowStore.Page(records, nextCursor, examined, failures, endReached, candidates,
                    highWatermark);
        } catch (InterruptedIOException exception) {
            if (cancellation.isCancelled()) {
                return new SignWorkflowStore.Page(records, nextCursor, examined, failures, false, candidates);
            }
            throw new IllegalStateException("Failed to page authoritative signing records", exception);
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to page authoritative signing records", exception);
        }
    }

    @Override
    public SignWorkflowStore.Page pageDueSignRecords(Instant cutoffInclusive,
            Optional<String> exclusiveCursor, Optional<String> inclusiveHighWatermark,
            int maximumRecords, CancellationSignal cancellation) {
        requireStoreUsable();
        Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
        Objects.requireNonNull(exclusiveCursor, "exclusiveCursor");
        Objects.requireNonNull(inclusiveHighWatermark, "inclusiveHighWatermark");
        Objects.requireNonNull(cancellation, "cancellation");
        if (maximumRecords < 1 || maximumRecords > 4096) {
            throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
        }
        if (cancellation.isCancelled()) {
            return new SignWorkflowStore.Page(List.of(), exclusiveCursor, 0, 0,
                    false, List.of());
        }
        List<SignWorkflowStore.Record> records = new ArrayList<>(maximumRecords);
        List<SignWorkflowStore.PageCandidate> candidates = new ArrayList<>(maximumRecords);
        int failures = 0;
        try (SegmentedTransactionalMetadataStore.SigningDuePage page =
                metadataStore.pageSigningDue(cutoffInclusive, exclusiveCursor,
                        inclusiveHighWatermark, maximumRecords)) {
            MetadataSnapshot snapshot = page.snapshot();
            for (SegmentedTransactionalMetadataStore.SigningDueCandidate candidate
                    : page.candidates()) {
                if (cancellation.isCancelled()) {
                    Optional<String> cursor = candidates.isEmpty() ? exclusiveCursor
                            : Optional.of(candidates.getLast().cursor());
                    return new SignWorkflowStore.Page(records, cursor, candidates.size(),
                            failures, false, candidates, page.highWatermark());
                }
                Optional<SignWorkflowStore.Record> decoded = Optional.empty();
                if (!candidate.malformed()) {
                    try {
                        Optional<MetadataSnapshot.Record> stored = snapshot.get(
                                signingRecordKey(new PkiId(candidate.operationId())));
                        if (stored.isPresent()) {
                            decoded = Optional.of(decodeStoredSign(snapshot,
                                    stored.orElseThrow()).record());
                        }
                    } catch (IOException | RuntimeException malformed) {
                        decoded = Optional.empty();
                    }
                }
                if (decoded.isPresent()) records.add(decoded.orElseThrow());
                else failures++;
                candidates.add(new SignWorkflowStore.PageCandidate(
                        candidate.operationId(), decoded));
            }
            Optional<String> cursor = candidates.isEmpty() ? exclusiveCursor
                    : Optional.of(candidates.getLast().cursor());
            return new SignWorkflowStore.Page(records, cursor, candidates.size(), failures,
                    page.endReached(), candidates, page.highWatermark());
        } catch (IOException failure) {
            throw new IllegalStateException(
                    "Failed to page authoritative signing records", failure);
        }
    }

    @Override
    public Optional<SignWorkflowStore.Record> deferSignReconciliation(PkiId submissionId, long expectedRevision,
            long fence, SignWorkflowStore.ReconciliationFailureClass failureClass) {
        requireStoreUsable();
        Objects.requireNonNull(failureClass, "failureClass");
        Optional<SignExpiry> expiry;
        Optional<SignWorkflowStore.Record> result;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.orElseThrow();
            SignWorkflowStore.Record current = stored.record();
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                result = Optional.empty();
            } else {
                boolean publishingDomain = current.state() == SignWorkflowStore.State.SUCCEEDED
                        && getDomainContinuation(submissionId)
                                .filter(value -> value.state() == DomainContinuationStore.State.PUBLISHING)
                                .isPresent();
                if (current.revision() != expectedRevision || current.fence() != fence
                        || !isActiveSignState(current.state()) && !publishingDomain) {
                    return Optional.empty();
                }
                int failureCount = current.failureCount() == Integer.MAX_VALUE
                        ? Integer.MAX_VALUE : current.failureCount() + 1;
                long delaySeconds = failureCount >= 5 ? 30L : 2L << failureCount - 1;
                Instant now = signingNow();
                Instant proposedEligibility = now.plusSeconds(Math.min(delaySeconds, 30L));
                Instant horizonEnd = current.createdAt().plus(options.signingOperationHorizon());
                Instant nextEligible = publishingDomain || !proposedEligibility.isAfter(horizonEnd)
                        ? proposedEligibility : horizonEnd;
                SignWorkflowStore.Record deferred = copySignRecord(current, current.state(),
                        current.revision() + 1L, current.fence(), current.leaseUntil(), current.detailCode(),
                        current.result(), current.providerUpdatedAt(), failureCount, Optional.of(nextEligible),
                        Optional.of(failureClass));
                result = replaceSignMetadata(stored, deferred, false) ? Optional.of(deferred) : Optional.empty();
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return result;
    }

    @Override
    public Optional<SignWorkflowStore.Record> clearSignReconciliation(PkiId submissionId, long expectedRevision,
            long fence) {
        requireStoreUsable();
        Optional<SignExpiry> expiry;
        Optional<SignWorkflowStore.Record> result;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.orElseThrow();
            SignWorkflowStore.Record current = stored.record();
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                result = Optional.empty();
            } else {
                if (current.revision() != expectedRevision || current.fence() != fence) {
                    return Optional.empty();
                }
                if (current.failureCount() == 0) {
                    return Optional.of(current);
                }
                SignWorkflowStore.Record cleared = copySignRecord(current, current.state(),
                        current.revision() + 1L, current.fence(), current.leaseUntil(), current.detailCode(),
                        current.result(), current.providerUpdatedAt(), 0, Optional.empty(), Optional.empty());
                result = replaceSignMetadata(stored, cleared, false) ? Optional.of(cleared) : Optional.empty();
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return result;
    }

    private List<StoredSign> listStoredSigns() {
        List<StoredSign> storedSigns = new ArrayList<>();
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(SIGN_RECORD_NAMESPACE),
                    CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    StoredSign stored = decodeStoredSign(snapshot, next.orElseThrow());
                    storedSigns.add(stored);
                }
            }
            validateProjectedSigningOwners();
            return List.copyOf(storedSigns);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to list authoritative signing records", ex);
        }
    }

    private void validateProjectedSigningOwners() throws IOException {
        Optional<String> cursor = Optional.empty();
        while (true) {
            try (SegmentedTransactionalMetadataStore.SigningDuePage page =
                    metadataStore.pageSigningOwners(cursor, 4096)) {
                for (SegmentedTransactionalMetadataStore.SigningDueCandidate candidate
                        : page.candidates()) {
                    PkiId submissionId = new PkiId(candidate.operationId());
                    try (MetadataSnapshot.Record record = page.snapshot()
                            .get(signingRecordKey(submissionId))
                            .orElseThrow(() -> new IOException(
                                    "Signing owner exists without its record"))) {
                        decodeStoredSign(page.snapshot(), record);
                    }
                }
                if (page.endReached()) return;
                if (page.candidates().isEmpty()) {
                    throw new IllegalStateException("Projected signing owner page did not advance");
                }
                cursor = Optional.of(page.candidates().getLast().operationId());
            }
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
            byte[] buffer = new byte[METADATA_BUFFER_BYTES];
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
            if (result.outcome() != MetadataCommitResult.Outcome.UNKNOWN) {
                acknowledgeKnownOutcome(result);
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

    /* package */ static void installSignTransitionAdmissionObserver(Runnable observer) {
        SIGN_ADMISSION_OBSERVER.set(Objects.requireNonNull(observer, "observer"));
    }

    /* package */ static void clearSignTransitionAdmissionObserver() {
        SIGN_ADMISSION_OBSERVER.remove();
    }

    private static void notifySignTransitionAdmission() {
        Runnable observer = SIGN_ADMISSION_OBSERVER.get();
        SIGN_ADMISSION_OBSERVER.remove();
        if (observer != null) {
            observer.run();
        }
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
        Optional<SignExpiry> expiry;
        Optional<SignWorkflowStore.Record> result;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.get();
            SignWorkflowStore.Record current = stored.record();
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                result = Optional.empty();
            } else {
                Instant now = signingNow();
                boolean claimable = current.state() == SignWorkflowStore.State.INTENT;
                boolean leaseAvailable = current.leaseUntil().isEmpty() || !current.leaseUntil().get().isAfter(now);
                if (current.revision() != expectedRevision || !claimable || !leaseAvailable) {
                    return Optional.empty();
                }
                SignWorkflowStore.Record claimed = copySignRecord(current, current.state(),
                        current.revision() + 1L, current.fence() + 1L, Optional.of(now.plus(lease)),
                        current.detailCode(), current.result(), current.providerUpdatedAt(), 0, Optional.empty(),
                        Optional.empty());
                result = replaceSignMetadata(stored, claimed, false) ? Optional.of(claimed) : Optional.empty();
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return result;
    }

    @Override
    public Optional<SignWorkflowStore.Record> renewSignClaim(PkiId submissionId, long expectedRevision, long fence,
            Duration lease) {
        requireStoreUsable();
        requirePositive(lease, "lease");
        Optional<SignExpiry> expiry;
        Optional<SignWorkflowStore.Record> result;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.get();
            SignWorkflowStore.Record current = stored.record();
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                result = Optional.empty();
            } else {
                if (current.revision() != expectedRevision || current.fence() != fence
                        || current.leaseUntil().isEmpty()) {
                    return Optional.empty();
                }
                SignWorkflowStore.Record renewed = copySignRecord(current, current.state(),
                        current.revision() + 1L, fence, Optional.of(signingNow().plus(lease)), current.detailCode(),
                        current.result(), current.providerUpdatedAt(), current.failureCount(), current.nextEligibleAt(),
                        current.reconciliationFailureClass());
                result = replaceSignMetadata(stored, renewed, false) ? Optional.of(renewed) : Optional.empty();
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return result;
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
        Optional<SignExpiry> expiry;
        Optional<SignWorkflowStore.Record> transition;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.get();
            SignWorkflowStore.Record current = stored.record();
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                transition = target == SignWorkflowStore.State.EXPIRED
                        ? expiry.map(SignExpiry::record) : Optional.empty();
            } else {
                if (current.revision() != expectedRevision || current.fence() != fence
                        || !validSignTransition(current.state(), target)) {
                    return Optional.empty();
                }
                if (target == SignWorkflowStore.State.EXPIRED) {
                    expiry = expireSign(stored);
                    transition = expiry.map(SignExpiry::record);
                } else {
                    if (target == SignWorkflowStore.State.SUCCEEDED && result.isEmpty()
                            || target != SignWorkflowStore.State.SUCCEEDED && result.isPresent()) {
                        throw new IllegalArgumentException("Signing result does not match target state");
                    }
                    if (target == SignWorkflowStore.State.SUCCEEDED
                            && (providerUpdatedAt.isEmpty()
                                    || !providerUpdatedAt.get().isBefore(current.deadline()))) {
                        throw new IllegalArgumentException(
                                "Successful signing completion timestamp is not trustworthy");
                    }
                    if (target == SignWorkflowStore.State.CANCELLED
                            && (providerUpdatedAt.isEmpty()
                                    || !providerUpdatedAt.get().isBefore(current.deadline()))) {
                        throw new IllegalArgumentException(
                                "Cancelled signing completion timestamp is not trustworthy");
                    }
                    SignWorkflowStore.Record transitioned = copySignRecord(current, target,
                            current.revision() + 1L, fence, Optional.empty(), detailCode, result,
                            providerUpdatedAt, 0, Optional.empty(), Optional.empty());
                    SignTransitionCommit committed = commitSignTransitionAtAdmission(stored, transitioned);
                    transition = committed.record();
                    expiry = committed.expiry();
                }
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return transition;
    }

    @Override
    public Optional<SignWorkflowStore.Record> retireSign(PkiId submissionId, long expectedRevision, long fence) {
        requireStoreUsable();
        Optional<SignExpiry> expiry;
        Optional<SignWorkflowStore.Record> result;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.get();
            SignWorkflowStore.Record current = stored.record();
            if (current.state() == SignWorkflowStore.State.EXPIRED) {
                return Optional.of(current);
            }
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                result = expiry.map(SignExpiry::record);
            } else {
                if (current.revision() != expectedRevision || current.fence() != fence) {
                    return Optional.empty();
                }
                if (!isRetirableSignState(current.state())) {
                    return Optional.empty();
                }
                PkiSigningBus.SignContinuation continuation = PkiSigningBus.SignContinuation.decode(
                        current.request(), stagedContent);
                EncodedObject retiredRequest = continuation.withoutLiveContent().encode();
                SignWorkflowStore.Record retired = new SignWorkflowStore.Record(current.submissionId(),
                        current.namespace(), current.fingerprint(), current.configurationCommitment(), current.owner(),
                        current.createdAt(), current.deadline(), retiredRequest, SignWorkflowStore.State.RETIRED,
                        current.revision() + 1L, fence, Optional.empty(), Optional.of("RETIRED"), current.result(),
                        current.providerUpdatedAt(), 0, Optional.empty(), Optional.empty());
                if (!replaceSignMetadata(stored, retired, true)) {
                    return Optional.empty();
                }
                stored.reference().ifPresent(reference -> {
                    try {
                        if (reference.lifecycle() == DurableContentReference.Lifecycle.OPERATION) {
                            signingRetirementFaults.beforeRetirement(reference);
                            stagedContent.retireSigningContent(reference);
                        }
                    } catch (IOException exception) {
                        LOG.log(Level.WARNING, "Signing content retirement cleanup failed");
                        throw new PkiException(
                                "Signing content cleanup failed: code=SIGNING_CONTENT_CLEANUP_FAILED");
                    }
                });
                result = Optional.of(retired);
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return result;
    }

    @Override
    public int purgeExpiredSignRecords() {
        requireStoreUsable();
        Instant cutoff = signingNow();
        Instant createdAtCutoff = cutoff.minus(options.signingOperationHorizon());
        List<String> candidates = metadataStore.selectSigningRetention(createdAtCutoff,
                SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS / 3);
        if (candidates.isEmpty()) return 0;
        List<SignLockEntry> locks = new ArrayList<>(candidates.size());
        List<PkiId> ids = candidates.stream().map(PkiId::new)
                .sorted(Comparator.comparing(PkiId::value)).toList();
        try {
            for (PkiId id : ids) locks.add(acquireSignLock(id));
            List<SigningTransactionPayloadCodec.Mutation> deletes = new ArrayList<>(ids.size() * 3);
            int purgedRecords = 0;
            for (PkiId id : ids) {
                Optional<StoredSign> current = readStoredSign(id);
                if (current.isEmpty()) continue;
                StoredSign stored = current.orElseThrow();
                if (isContentFreeSignState(stored.record().state())
                        && !stored.record().createdAt().plus(options.signingOperationHorizon()).isAfter(cutoff)) {
                    deletes.add(new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.DELETE,
                            signingRecordKey(id), stored.recordRevision(), null));
                    try (MetadataSnapshot snapshot = metadataStore.snapshot();
                            MetadataSnapshot.Record domain = snapshot.get(domainContinuationKey(id)).orElse(null)) {
                        if (domain != null) {
                            DomainContinuationStore.Record continuation = decodeDomainContinuation(id, domain);
                            deletes.add(new SigningTransactionPayloadCodec.Mutation(
                                    SigningTransactionPayloadCodec.MutationKind.DELETE,
                                    domainContinuationKey(id), domain.recordRevision(), null));
                            if (continuation.correlationId().isPresent()) {
                                MetadataKey correlationKey = domainCorrelationKey(continuation.kind(),
                                        continuation.correlationId().orElseThrow());
                                try (MetadataSnapshot.Record correlation = snapshot.get(correlationKey).orElse(null)) {
                                    if (correlation != null) {
                                        deletes.add(new SigningTransactionPayloadCodec.Mutation(
                                                SigningTransactionPayloadCodec.MutationKind.DELETE,
                                                correlationKey, correlation.recordRevision(), null));
                                    }
                                }
                            }
                        }
                    }
                    purgedRecords++;
                }
            }
            if (deletes.isEmpty()) return 0;
            MetadataCommitResult result = metadataStore.directCommit(deletes);
            return result.outcome() == MetadataCommitResult.Outcome.COMMITTED ? purgedRecords : 0;
        } catch (IOException failure) {
            durabilityUncertain.set(true);
            throw storeDurabilityUnconfirmed("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
        } finally {
            for (int index = locks.size() - 1; index >= 0; index--) {
                releaseSignLock(ids.get(index), locks.get(index));
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (!closing.compareAndSet(false, true)) return;
        IOException failure = null;
        try {
            revocations.close();
        } catch (IOException exception) {
            failure = exception;
        }
        try {
            metadataStore.close();
        } catch (IOException exception) {
            if (failure == null) {
                failure = exception;
            } else {
                failure.addSuppressed(exception);
            }
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

    /* default */ SigningActiveWal.Snapshot localSigningWriterSnapshot() {
        requireStoreUsable();
        return metadataStore.writerSnapshot();
    }

    /* default */ Throwable firstLocalSigningRecoveryFailure() {
        return metadataStore.firstRecoveryFailure();
    }

    /**
     * Returns an immutable observation of the shared local-signing WAL writer,
     * accumulated across every WAL rotation of the open store.
     *
     * <p>This is operational evidence only. It does not expose mutable writer
     * state and does not alter admission or durability behavior. The counters are
     * cumulative for the lifetime of the open store, so a snapshot taken later
     * never reports a smaller total than an earlier one even when the active WAL
     * has been rotated in between.</p>
     *
     * @return cumulative bounded writer counters, monotone across WAL rotation
     */
    public LocalSigningWriterMetrics localSigningWriterMetrics() {
        requireStoreUsable();
        SigningActiveWal.Snapshot snapshot = metadataStore.cumulativeWriterSnapshot();
        return new LocalSigningWriterMetrics(snapshot.groupsCommitted(), snapshot.requestsCommitted(),
                snapshot.forces(), snapshot.bytesAppended(), snapshot.maximumBatchSize(),
                snapshot.batchWaitNanos(), snapshot.maximumBatchWaitNanos(), snapshot.forceNanos(),
                snapshot.maximumForceNanos());
    }

    /**
     * Immutable operational counters for the shared local-signing WAL writer.
     * @param groupsCommitted total durability groups committed
     * @param requestsCommitted total requests committed across groups
     * @param forces total durable force operations
     * @param bytesAppended total WAL bytes appended
     * @param maximumBatchSize largest committed request group
     * @param groupCommitWaitNanos cumulative group-commit wait in nanoseconds
     * @param maximumGroupCommitWaitNanos longest group-commit wait in nanoseconds
     * @param forceNanos cumulative force time in nanoseconds
     * @param maximumForceNanos longest force time in nanoseconds
     */
    public record LocalSigningWriterMetrics(long groupsCommitted, long requestsCommitted, long forces,
            long bytesAppended, long maximumBatchSize, long groupCommitWaitNanos,
            long maximumGroupCommitWaitNanos, long forceNanos, long maximumForceNanos) {
    }

    /**
     * Returns an immutable observation of the local signing indexes' steady and
     * transient resident-memory accounting.
     *
     * <p>The observation is constant-time and does not require the ledger to be
     * quiescent. Values are conservative accounting rather than a JVM heap
     * measurement. Calling this method does not reset the lifetime high-water
     * value.</p>
     *
     * @return current, lifetime-high-water, and configured maximum byte counts
     */
    public LocalSigningIndexCapacityMetrics localSigningIndexCapacityMetrics() {
        requireStoreUsable();
        SigningLedgerStoreEngine.CapacitySnapshot snapshot = metadataStore.capacitySnapshot();
        return new LocalSigningIndexCapacityMetrics(
                snapshot.steady().reservedBytes(), snapshot.steady().highWaterReservedBytes(),
                snapshot.steady().maximumBytes(), snapshot.transientBudget().reservedBytes(),
                snapshot.transientBudget().highWaterReservedBytes(),
                snapshot.transientBudget().maximumBytes(), snapshot.combinedReservedBytes(),
                snapshot.combinedHighWaterBytes(), snapshot.combinedMaximumBytes());
    }

    /**
     * Immutable local signing-index capacity counters.
     *
     * @param steadyCurrentReservedBytes currently reserved live-index bytes
     * @param steadyHighWaterReservedBytes greatest steady reservation since open
     * @param steadyMaximumBytes configured steady reservation ceiling
     * @param transientCurrentReservedBytes currently reserved detached-compaction bytes
     * @param transientHighWaterReservedBytes greatest transient reservation since open
     * @param transientMaximumBytes configured transient reservation ceiling
     * @param combinedCurrentReservedBytes checked sum of current reservations
     * @param combinedHighWaterReservedBytes checked conservative sum of both high-water values
     * @param combinedMaximumBytes checked sum of both configured ceilings
     */
    @SuppressWarnings("PMD.LongVariable")
    public record LocalSigningIndexCapacityMetrics(long steadyCurrentReservedBytes,
            long steadyHighWaterReservedBytes, long steadyMaximumBytes,
            long transientCurrentReservedBytes, long transientHighWaterReservedBytes,
            long transientMaximumBytes, long combinedCurrentReservedBytes,
            long combinedHighWaterReservedBytes, long combinedMaximumBytes) {
    }

    private void requireStoreUsable() {
        if (closing.get()) {
            throw new IllegalStateException("Filesystem store is closing");
        }
        if (durabilityUncertain.get()) {
            throw storeDurabilityUnconfirmed("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
        }
    }

    private StoreSignAdmission claimAdmission(SignWorkflowStore.SignAdmission admission,
            PkiId submissionId) {
        Objects.requireNonNull(admission, "admission");
        if (!(admission instanceof StoreSignAdmission owned)) {
            throw new IllegalArgumentException("Signing admission belongs to another store");
        }
        owned.claim(this, Objects.requireNonNull(submissionId, "submissionId").value());
        return owned;
    }

    private String validateAdmissionIdentifier(PkiId submissionId) {
        requireStoreUsable();
        SigningSubmissionId parsed = SigningSubmissionId.parse(
                Objects.requireNonNull(submissionId, "submissionId"));
        if (!parsed.namespace().startsWith(signingNamespace + ".")) {
            throw new IllegalArgumentException(
                    "Signing admission belongs to a different store namespace");
        }
        parsed.validate(parsed.namespace(), signingNow(), options.signingOperationHorizon(),
                options.signingIdPermittedSkew());
        return parsed.id().value();
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

    private CredentialStateLockEntry acquireCredentialStateLock(PkiId credentialId) {
        CredentialStateLockEntry entry = credentialStateLocks.compute(credentialId, (ignored, current) -> {
            CredentialStateLockEntry selected = current == null ? new CredentialStateLockEntry() : current;
            selected.references.incrementAndGet();
            return selected;
        });
        entry.lock.lock();
        return entry;
    }

    private void releaseCredentialStateLock(PkiId credentialId, CredentialStateLockEntry entry) {
        entry.lock.unlock();
        credentialStateLocks.computeIfPresent(credentialId, (ignored, current) -> {
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

    private static RevocationTransition nextRevocationTransition(
            Optional<RevocationRecord> current, RevocationCommand command, Instant transitionTime) {
        if (current.isPresent() && transitionTime.isBefore(current.orElseThrow().transition().time())) {
            throw new PkiException("Revocation transition conflict: code=REVOCATION_TRANSITION_CONFLICT",
                    PkiFailureReason.REVOCATION_TRANSITION_CONFLICT);
        }
        RevocationState previous = current.map(RevocationRecord::transition)
                .map(RevocationTransition::state).orElse(null);
        RevocationState next = nextRevocationState(previous, command);
        long revision = current.map(RevocationRecord::transition).map(RevocationTransition::revision).map(value -> {
            try {
                return Math.addExact(value, 1L);
            } catch (ArithmeticException ex) {
                throw corruptRevocationState();
            }
        }).orElse(1L);
        Optional<RevocationReason> permanentReason = command instanceof RevocationCommand.RevokePermanently revoke
                ? Optional.of(revoke.reason())
                : Optional.empty();
        return new RevocationTransition(revision, next, transitionTime, permanentReason, command.attributes());
    }

    private static RevocationState nextRevocationState(RevocationState previous, RevocationCommand command) {
        if (previous == RevocationState.PERMANENTLY_REVOKED) {
            throw new PkiException("Revocation is terminal: code=REVOCATION_TERMINAL",
                    PkiFailureReason.REVOCATION_TERMINAL);
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
            case PERMANENTLY_REVOKED -> throw new PkiException("Revocation is terminal: code=REVOCATION_TERMINAL",
                    PkiFailureReason.REVOCATION_TERMINAL);
        };
    }

    private static RevocationState throwIllegalTransition() {
        throw illegalRevocationTransition();
    }

    private static PkiException illegalRevocationTransition() {
        return new PkiException("Revocation transition rejected: code=REVOCATION_TRANSITION_ILLEGAL",
                PkiFailureReason.REVOCATION_TRANSITION_ILLEGAL);
    }

    private static PkiException corruptRevocationState() {
        return new PkiException("Revocation state invalid: code=REVOCATION_STATE_CORRUPT",
                PkiFailureReason.REVOCATION_STATE_CORRUPT);
    }

    private Optional<SignWorkflowStore.Record> readSignRecord(PkiId submissionId) {
        return readStoredSign(submissionId).map(StoredSign::record);
    }

    private Optional<StoredSign> readStoredSign(PkiId submissionId) {
        MetadataKey recordKey = signingRecordKey(submissionId);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> storedRecord = snapshot.get(recordKey);
            if (storedRecord.isEmpty()) {
                if (metadataStore.containsSigningOwner(submissionId.value())) {
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
        if (isContentFreeSignState(record.state())) {
            if (metadataStore.containsSigningOwner(submissionId.value())) {
                throw new IllegalStateException("Content-free signing record retains an owner edge");
            }
            return new StoredSign(record, storedRecord.recordRevision(), OptionalLong.empty(), Optional.empty());
        }
        PkiSigningBus.SignContinuation continuation = PkiSigningBus.SignContinuation.decode(
                record.request(), stagedContent);
        DurableContentReference expectedReference = continuation.content();
        Optional<MetadataSnapshot.Record> storedOwner = snapshot.get(
                SigningOwnerKey.exact(expectedReference, submissionId));
        try (MetadataSnapshot.Record owner = storedOwner.orElseThrow(
                () -> new IllegalStateException("Signing record owner edge is missing"))) {
            DurableContentReference reference = decodeSigningOwner(owner, submissionId);
            if (!reference.equals(expectedReference)) {
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
        requireValidSignRecord(isContentFreeSignState(record.state()) != continuation.hasLiveContent(),
                record, "CONTINUATION_LIFECYCLE_MISMATCH");

        byte[] storedRequest = record.request().bytes();
        byte[] canonicalRequest = null;
        String expectedFingerprint;
        try {
            canonicalRequest = continuation.encode().bytes();
            expectedFingerprint = continuation.semanticFingerprint(record.configurationCommitment(),
                    record.namespace(), record.deadline());
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
        if (record.nextEligibleAt().isPresent()) {
            Instant nextEligible = record.nextEligibleAt().orElseThrow();
            boolean durablePublicationRetry = record.state() == SignWorkflowStore.State.SUCCEEDED
                    && getDomainContinuation(record.submissionId())
                            .filter(domain -> domain.state() == DomainContinuationStore.State.PUBLISHING)
                            .isPresent();
            requireValidSignRecord((durablePublicationRetry || !nextEligible.isAfter(horizonEnd))
                    && !nextEligible.isAfter(signingNow().plusSeconds(30L)), record,
                    "RECONCILIATION_ELIGIBILITY_INVALID");
        }
        if (record.result().isPresent()) {
            requireValidSignRecord(record.result().get().encoding() == Encoding.BINARY
                    && record.result().get().bytes().length > 0
                    && record.result().get().bytes().length <= 1_048_576, record,
                    "RESULT_SIZE_INVALID");
        }

        validateSignRecordState(record);
    }

    private MetadataCommitResult createSignMetadata(SignWorkflowStore.Record record,
            DurableContentReference reference, StoreSignAdmission admission,
            Optional<DomainContinuationStore.Record> domainContinuation) {
        validateSignRecord(record.submissionId(), record);
        try (MetadataTransaction transaction = metadataStore.beginTransaction(admission.transfer())) {
            transaction.create(signingRecordKey(record.submissionId()),
                    byteContent(FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, record)), CancellationSignal.NONE);
            transaction.create(SigningOwnerKey.exact(reference, record.submissionId()),
                    byteContent(encodeSigningOwner(record.submissionId(), reference)), CancellationSignal.NONE);
            if (domainContinuation.isPresent()) {
                DomainContinuationStore.Record exactDomain = domainContinuation.orElseThrow();
                transaction.create(domainContinuationKey(record.submissionId()),
                        byteContent(FsCodec.encode(FsCodec.DOMAIN_CONTINUATION,
                                exactDomain)), CancellationSignal.NONE);
                if (exactDomain.correlationId().isPresent()) {
                    transaction.create(domainCorrelationKey(exactDomain.kind(),
                            exactDomain.correlationId().orElseThrow()),
                            byteContent(encodeDomainCorrelation(record.submissionId())),
                            CancellationSignal.NONE);
                }
            }
            return requireKnownOutcome(transaction.commit());
        } catch (MetadataStoreException failure) {
            throw translateSigningMetadataFailure(failure);
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
    }

    private boolean replaceSignMetadata(StoredSign current, SignWorkflowStore.Record replacement,
            boolean removeOwner) {
        validateSignRecord(replacement.submissionId(), replacement);
        try (MetadataTransaction transaction =
                metadataStore.beginSigningProgressTransaction()) {
            transaction.replace(signingRecordKey(replacement.submissionId()), current.recordRevision(),
                    byteContent(FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, replacement)), CancellationSignal.NONE);
            if (removeOwner) {
                transaction.delete(SigningOwnerKey.exact(current.reference().orElseThrow(),
                                replacement.submissionId()),
                        current.ownerRevision().orElseThrow());
            }
            return requireKnownOutcome(transaction.commit()).outcome()
                    == MetadataCommitResult.Outcome.COMMITTED;
        } catch (MetadataStoreException failure) {
            throw translateSigningMetadataFailure(failure);
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
    }

    private Optional<SignExpiry> expireIfDeadlineReached(StoredSign stored) {
        SignWorkflowStore.Record current = stored.record();
        if (!isActiveSignState(current.state()) || current.deadline().isAfter(signingNow())) {
            return Optional.empty();
        }
        return expireSign(stored);
    }

    private Optional<SignExpiry> expireSign(StoredSign stored) {
        SignWorkflowStore.Record current = stored.record();
        if (!isActiveSignState(current.state())) {
            return Optional.empty();
        }
        SignWorkflowStore.Record expired = expiredSignRecord(current);
        if (!replaceSignMetadata(stored, expired, true)) {
            return Optional.empty();
        }
        signalLocalSignExpiry(current.submissionId());
        return Optional.of(new SignExpiry(expired, stored.reference()));
    }

    private SignTransitionCommit commitSignTransitionAtAdmission(StoredSign stored,
            SignWorkflowStore.Record replacement) {
        SignWorkflowStore.Record expired = expiredSignRecord(stored.record());
        validateSignRecord(replacement.submissionId(), replacement);
        validateSignRecord(expired.submissionId(), expired);
        SigningLedgerStoreEngine.ConditionalCommitResult committed;
        try {
            SigningLedgerStoreEngine.ConditionalDirectCommit alternatives =
                    new SigningLedgerStoreEngine.ConditionalDirectCommit(
                            signReplacementMutations(stored, replacement, false),
                            signReplacementMutations(stored, expired, true),
                            () -> stored.record().deadline().isAfter(signingAdmissionNow()),
                            FilesystemPkiStore::notifySignTransitionAdmission);
            committed = metadataStore.directCommitAtAdmission(alternatives);
            if (committed.result().outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                return new SignTransitionCommit(Optional.empty(), Optional.empty());
            }
        } catch (MetadataStoreException failure) {
            throw translateSigningMetadataFailure(failure);
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
        if (committed.primaryAdmitted()) {
            recordSigningEvidence(replacement);
            return new SignTransitionCommit(Optional.of(replacement), Optional.empty());
        }
        recordSigningEvidence(expired);
        signalLocalSignExpiry(expired.submissionId());
        SignExpiry expiry = new SignExpiry(expired, stored.reference());
        return new SignTransitionCommit(Optional.of(expired), Optional.of(expiry));
    }

    private static boolean isTerminalSignState(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.SUCCEEDED || state == SignWorkflowStore.State.FAILED
                || state == SignWorkflowStore.State.CANCELLED || state == SignWorkflowStore.State.EXPIRED;
    }

    // Records one append-ordered signing (CA key-usage) evidence entry for a committed TERMINAL outcome,
    // only when the operator opted into signing audit (signingEvidenceLog != null). Recorded here rather
    // than co-committed into the signing record so it survives record retirement. Best-effort and derived
    // from the terminal record: the terminal outcome is already durable, so an unconfirmed evidence append
    // must not fail the signing operation; startup reconciliation re-appends any missing entry. This is a
    // SEPARATE metadata commit, so it costs an additional durable fsync per terminal outcome — the
    // documented cost of the opt-in.
    private void recordSigningEvidence(SignWorkflowStore.Record record) {
        if (signingEvidenceLog == null || !isTerminalSignState(record.state())) {
            return;
        }
        zeroecho.pki.application.SigningExecutionEvidence.Outcome outcome = switch (record.state()) {
            case SUCCEEDED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.SIGNED;
            case FAILED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.FAILED;
            case CANCELLED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.CANCELLED;
            default -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.EXPIRED;
        };
        zeroecho.pki.application.SigningExecutionEvidence evidence =
                zeroecho.pki.application.SigningExecutionEvidence.terminal(record.namespace(), record.fingerprint(),
                        record.owner().type(), record.owner().name(), record.detailCode(), outcome);
        byte[] payload = zeroecho.pki.impl.core.async.DomainAttributeEncoding.encode(evidence.attributes())
                .getBytes(StandardCharsets.UTF_8);
        try {
            signingEvidenceLog.append(record.submissionId(), record.providerUpdatedAt().orElse(signingNow()), payload);
        } catch (IOException failure) {
            LOG.log(Level.WARNING, "Signing evidence log append deferred to reconciliation: code=EVIDENCE_APPEND_UNCONFIRMED");
        }
    }

    // Re-appends signing evidence for any signing record that reached a terminal state before its evidence
    // append (the crash window between the terminal commit and the evidence-log append). Terminal records
    // persist until a later retirement step, so they are still enumerable here. No-op unless the operator
    // opted into signing audit; idempotent per submission; non-terminal records are skipped.
    private void reconcileSigningEvidence() {
        if (signingEvidenceLog == null) {
            return;
        }
        for (StoredSign stored : listStoredSigns()) {
            recordSigningEvidence(stored.record());
        }
    }

    // The active WAL invokes this bounded guard at its admission linearization point.
    // It performs no I/O or wait, sharing the lock-free monotonic time source so that
    // admission and ordinary signing observe one non-decreasing signing clock.
    private Instant signingAdmissionNow() {
        return advanceSigningTime();
    }

    private List<SigningTransactionPayloadCodec.Mutation> signReplacementMutations(
            StoredSign current, SignWorkflowStore.Record replacement, boolean removeOwner) {
        SigningTransactionPayloadCodec.Mutation replace = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.REPLACE,
                signingRecordKey(replacement.submissionId()), current.recordRevision(),
                FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, replacement));
        if (!removeOwner) {
            return List.of(replace);
        }
        SigningTransactionPayloadCodec.Mutation deleteOwner = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.DELETE,
                SigningOwnerKey.exact(current.reference().orElseThrow(), replacement.submissionId()),
                current.ownerRevision().orElseThrow(), null);
        return List.of(replace, deleteOwner);
    }

    private SignWorkflowStore.Record expiredSignRecord(SignWorkflowStore.Record current) {
        PkiSigningBus.SignContinuation continuation = PkiSigningBus.SignContinuation.decode(
                current.request(), stagedContent);
        return new SignWorkflowStore.Record(current.submissionId(), current.namespace(), current.fingerprint(),
                current.configurationCommitment(), current.owner(), current.createdAt(), current.deadline(),
                continuation.withoutLiveContent().encode(), SignWorkflowStore.State.EXPIRED,
                current.revision() + 1L, current.fence(), Optional.empty(), Optional.of("EXPIRED"),
                Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty());
    }

    private void signalLocalSignExpiry(PkiId submissionId) {
        AtomicBoolean cancellation = localSignCancellations.remove(submissionId);
        if (cancellation != null) {
            cancellation.set(true);
        }
    }

    private void finishSignExpiry(SignExpiry expiry) {
        expiry.reference().ifPresent(reference -> {
            if (reference.lifecycle() != DurableContentReference.Lifecycle.OPERATION) {
                return;
            }
            try {
                signingRetirementFaults.beforeRetirement(reference);
                stagedContent.retireSigningContent(reference);
            } catch (IOException exception) {
                LOG.log(Level.WARNING, "Expired signing content cleanup failed");
                throw new PkiException("Signing content cleanup failed: code=SIGNING_CONTENT_CLEANUP_FAILED");
            }
        });
    }

    private boolean directReplaceSignMetadata(StoredSign current, SignWorkflowStore.Record replacement) {
        validateSignRecord(replacement.submissionId(), replacement);
        List<SigningTransactionPayloadCodec.Mutation> mutations = List.of(
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.REPLACE,
                        signingRecordKey(replacement.submissionId()), current.recordRevision(),
                        FsCodec.encode(FsCodec.SIGN_WORKFLOW_RECORD, replacement)));
        try {
            MetadataCommitResult result = metadataStore.directSigningProgressCommit(mutations);
            return result.outcome() == MetadataCommitResult.Outcome.COMMITTED;
        } catch (MetadataStoreException failure) {
            throw translateSigningMetadataFailure(failure);
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
    }

    /* package */ PkiException translateSigningMetadataFailure(MetadataStoreException failure) {
        Objects.requireNonNull(failure, "failure");
        if (failure.category() == MetadataCommitResult.FailureCategory.STORAGE_FAILURE) {
            return signingDurabilityFailure(failure);
        }
        String code = switch (failure.category()) {
            case LIMIT_EXCEEDED -> "SIGNING_METADATA_CAPACITY_UNAVAILABLE";
            case CANCELLED -> "SIGNING_METADATA_CANCELLED";
            case CONFLICT, FOREIGN_TRANSACTION, TRANSACTION_NOT_ISSUED,
                    ABANDONED_BY_RECOVERY, UNSUPPORTED_CAPABILITY,
                    INTEGRITY_FAILURE -> "SIGNING_METADATA_REJECTED";
            case STORAGE_FAILURE -> throw new IllegalStateException(
                    "Storage failure must be handled as durability uncertainty");
        };
        return new PkiException("Signing metadata operation rejected: code=" + code, failure);
    }

    // Builds the store-wide durability-uncertain failure. The typed reason travels
    // structurally so callers classify or re-throw it without parsing the message;
    // the retained "code=" suffix stays only for human-readable diagnostics.
    private static PkiException storeDurabilityUnconfirmed(String message) {
        return new PkiException(message, PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);
    }

    private static PkiException storeDurabilityUnconfirmed(String message, Throwable cause) {
        return new PkiException(message, PkiFailureReason.STORE_DURABILITY_UNCONFIRMED, cause);
    }

    private PkiException signingDurabilityFailure(IOException failure) {
        durabilityUncertain.set(true);
        return storeDurabilityUnconfirmed(
                "Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED", failure);
    }

    private MetadataCommitResult requireKnownOutcome(MetadataCommitResult result) {
        if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) {
            durabilityUncertain.set(true);
            throw storeDurabilityUnconfirmed(
                    "Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
        }
        acknowledgeKnownOutcome(result);
        return result;
    }

    private void acknowledgeKnownOutcome(MetadataCommitResult result) {
        try {
            metadataStore.acknowledge(result.transactionId());
        } catch (IOException failure) {
            durabilityUncertain.set(true);
            throw storeDurabilityUnconfirmed(
                    "Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED", failure);
        }
    }

    @SuppressWarnings("PMD.ExcessiveParameterList")
    private static SignWorkflowStore.Record copySignRecord(SignWorkflowStore.Record current,
            SignWorkflowStore.State state, long revision, long fence, Optional<Instant> leaseUntil,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt,
            int failureCount, Optional<Instant> nextEligibleAt,
            Optional<SignWorkflowStore.ReconciliationFailureClass> failureClass) {
        return new SignWorkflowStore.Record(current.submissionId(), current.namespace(), current.fingerprint(),
                current.configurationCommitment(), current.owner(), current.createdAt(), current.deadline(),
                current.request(), state, revision, fence, leaseUntil, detailCode, result, providerUpdatedAt,
                failureCount, nextEligibleAt, failureClass);
    }

    private static MetadataKey signingRecordKey(PkiId submissionId) {
        SigningSubmissionId parsed = SigningSubmissionId.parse(submissionId);
        return new MetadataKey(SIGN_RECORD_NAMESPACE, parsed.id().value());
    }

    private static MetadataKey domainContinuationKey(PkiId operationId) {
        SigningSubmissionId parsed = SigningSubmissionId.parse(operationId);
        return new MetadataKey(DOMAIN_CONT_NAMESPACE, parsed.id().value());
    }

    private static MetadataKey domainCorrelationKey(DomainContinuationStore.Kind kind, String correlationId) {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(correlationId, "correlationId");
        try {
            String value = kind.name() + '\n' + correlationId;
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
            return new MetadataKey(DOMAIN_CORRELATION_NAMESPACE, digest);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static byte[] encodeDomainCorrelation(PkiId operationId) {
        return ("v1\n" + operationId.value()).getBytes(StandardCharsets.UTF_8);
    }

    private static MetadataKey statusRecordKey(PkiId statusObjectId) {
        return new MetadataKey(STATUS_RECORD_NAMESPACE, statusObjectId.value());
    }

    private static MetadataKey statusOwnerKey(PkiId statusObjectId) {
        return new MetadataKey(STATUS_OWNER_NAMESPACE, statusObjectId.value());
    }

    private static MetadataKey publicationRecordKey(PkiId publicationId) {
        return new MetadataKey(PUBLICATION_RECORD_NAMESPACE, publicationId.value());
    }

    private PublicationRecord decodePublicationRecord(MetadataSnapshot.Record stored, MetadataSnapshot snapshot)
            throws IOException {
        PublicationRecord record = PublicationRecordCodec.decode(readMetadataValue(stored), stagedContent);
        if (!publicationRecordKey(record.publicationId()).equals(stored.key())) {
            throw new IOException("Publication metadata key mismatch");
        }
        validatePublicationRecord(record, snapshot);
        return record;
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private void recoverPublicationRecords() {
        try (PublicationCursor cursor = openPublicationRecords()) {
            Optional<PublicationRecord> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                PublicationRecord record = next.orElseThrow();
                if (record.status() == PublicationStatus.DISPATCH_PREPARED) {
                    Instant observed = clock.instant();
                    Instant updatedAt = observed.isAfter(record.updatedAt()) ? observed : record.updatedAt();
                    PublicationRecord unknown = new PublicationRecord(record.publicationId(), record.sourceType(),
                            record.sourceId(), record.content(), record.target(), PublicationStatus.OUTCOME_UNKNOWN,
                            record.attemptNumber(), record.attemptToken(), record.createdAt(), updatedAt,
                            Optional.of(PublicationFailure.EXTERNAL_OUTCOME_UNKNOWN), Optional.empty());
                    if (!replacePublicationRecord(record, unknown)) {
                        throw new IllegalStateException("Publication recovery conflict");
                    }
                } else if (isTerminalPublication(record.status())) {
                    // Reconcile the crash window between a terminal publication commit and its evidence append.
                    recordPublicationEvidence(record);
                }
            }
        } catch (IOException exception) {
            throw new IllegalStateException("Publication recovery failed");
        }
    }

    private void validatePublicationRecord(PublicationRecord record) {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            validatePublicationRecord(record, snapshot);
        } catch (IOException exception) {
            throw new IllegalStateException("Publication source authority is invalid");
        }
    }

    private void validatePublicationRecord(PublicationRecord record, MetadataSnapshot snapshot) throws IOException {
        publicationRecordKey(record.publicationId());
        DurableContentReference reference = record.content();
        if (!stagedContent.contentStoreId().equals(reference.storeId())
                || reference.lifecycle() != DurableContentReference.Lifecycle.PERSISTED) {
            throw new IllegalArgumentException("Publication content is not persistent store authority");
        }
        try {
            stagedContent.restoreReference(reference.storeId(), reference.contentId(), reference.encoding(),
                    reference.length(), reference.sha256(), reference.lifecycle());
        } catch (IOException exception) {
            throw new IllegalStateException("Publication content commitment is invalid");
        }
        DurableContentReference authoritative = record.sourceType() == PublicationSourceType.CREDENTIAL
                ? getCredential(record.sourceId()).map(Credential::content).orElseThrow(
                        () -> new IllegalStateException("Publication credential source is missing"))
                : statusContent(snapshot, record.sourceId());
        if (!sameContentReference(authoritative, reference)) {
            throw new IllegalArgumentException("Publication content does not match its source object");
        }
    }

    private DurableContentReference statusContent(MetadataSnapshot snapshot, PkiId statusId) throws IOException {
        Optional<MetadataSnapshot.Record> stored = snapshot.get(statusRecordKey(statusId));
        if (stored.isPresent()) {
            return decodeStoredStatus(snapshot, stored.orElseThrow()).status().content();
        }
        Optional<MetadataSnapshot.Record> owner = snapshot.get(statusOwnerKey(statusId));
        if (owner.isPresent()) {
            try (MetadataSnapshot.Record ignored = owner.orElseThrow()) {
                throw new IOException("Status owner exists without its record");
            }
        }
        throw new IllegalStateException("Publication status source is missing");
    }

    private static void validatePublicationReplacement(PublicationRecord expected, PublicationRecord replacement) {
        if (!expected.hasSameOperation(replacement)
                || replacement.updatedAt().isBefore(expected.updatedAt())) {
            throw new IllegalArgumentException("Publication immutable fields cannot change");
        }
        PublicationStatus previous = expected.status();
        PublicationStatus next = replacement.status();
        boolean valid = switch (previous) {
            case PENDING -> next == PublicationStatus.DISPATCH_PREPARED
                    && replacement.attemptNumber() == Math.addExact(expected.attemptNumber(), 1L);
            case DISPATCH_PREPARED -> (next == PublicationStatus.SUCCEEDED
                    || next == PublicationStatus.RETRYABLE_FAILURE
                    || next == PublicationStatus.TERMINAL_FAILURE
                    || next == PublicationStatus.OUTCOME_UNKNOWN)
                    && sameAttempt(expected, replacement);
            case RETRYABLE_FAILURE -> next == PublicationStatus.PENDING
                    && replacement.attemptNumber() == expected.attemptNumber();
            case OUTCOME_UNKNOWN -> next == PublicationStatus.DISPATCH_PREPARED
                    && sameAttempt(expected, replacement);
            case SUCCEEDED, TERMINAL_FAILURE -> false;
        };
        if (!valid) {
            throw new IllegalArgumentException("Publication state transition is illegal");
        }
    }

    private static boolean sameAttempt(PublicationRecord first, PublicationRecord second) {
        return first.attemptNumber() == second.attemptNumber()
                && first.attemptToken().equals(second.attemptToken());
    }

    private static boolean publicationRecordsEqual(PublicationRecord first, PublicationRecord second) {
        return first.hasSameOperation(second) && second.hasSameOperation(first)
                && first.status() == second.status() && first.attemptNumber() == second.attemptNumber()
                && first.attemptToken().equals(second.attemptToken())
                && first.updatedAt().equals(second.updatedAt()) && first.failure().equals(second.failure())
                && first.evidence().equals(second.evidence());
    }

    private static boolean sameContentReference(DurableContentReference first, DurableContentReference second) {
        return first.storeId().equals(second.storeId()) && first.contentId().equals(second.contentId())
                && first.encoding() == second.encoding() && first.length() == second.length()
                && first.sha256().equals(second.sha256()) && first.lifecycle() == second.lifecycle();
    }

    private static PkiException publicationPersistenceUnknown() {
        return new PkiException(
                "Publication metadata outcome requires recovery: code=PUBLICATION_PERSISTENCE_UNKNOWN");
    }

    /* package */ static void installPublicationCommitFault(PublicationCommitFaultPoint point) {
        PUBLICATION_COMMIT_FAULT.set(Objects.requireNonNull(point, "point"));
    }

    /* package */ static void clearPublicationCommitFault() {
        PUBLICATION_COMMIT_FAULT.remove();
    }

    private static PublicationCommitFaultPoint takePublicationCommitFault() {
        PublicationCommitFaultPoint point = PUBLICATION_COMMIT_FAULT.get();
        PUBLICATION_COMMIT_FAULT.remove();
        return point;
    }

    /** Test-only publication metadata commit boundary. */
    /* default */
    enum PublicationCommitFaultPoint {
        /** Fails registration before the metadata commit attempt. */
        CREATE_BEFORE_COMMIT,
        /** Fails one state replacement before the metadata commit attempt. */
        REPLACE_BEFORE_COMMIT,
        /** Reports uncertainty after one replacement was durably committed. */
        REPLACE_COMMIT_AS_UNKNOWN
    }

    /** Test seam at the post-RETIRED physical content-deletion boundary. */
    /* default */
    @FunctionalInterface
    interface SigningContentRetirementFaultInjector {
        /** Production no-op. */
        SigningContentRetirementFaultInjector NONE = reference -> {
            // No fault.
        };

        /** Invoked immediately before physical signing-content retirement. */
        void beforeRetirement(DurableContentReference reference) throws IOException;
    }

    /** Test seam after authoritative revocation and before derived confirmation cleanup. */
    /* default */
    @FunctionalInterface
    interface ConfirmationRevocationCleanupFaultInjector {
        /** Production no-op. */
        ConfirmationRevocationCleanupFaultInjector NONE = credentialId -> {
            // No fault.
        };

        /** Invoked after authoritative revocation and before derived metadata cleanup. */
        void beforeCleanup(PkiId credentialId) throws IOException;
    }

    private static RepeatableContent byteContent(byte[] value) {
        return new ByteValueContent(value);
    }

    private static byte[] readMetadataValue(MetadataSnapshot.Record record) throws IOException {
        long length = record.length().orElseThrow();
        if (length < 0L || length > MAX_METADATA_VALUE_BYTES) {
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

    private DomainContinuationStore.Record decodeDomainContinuation(PkiId operationId,
            MetadataSnapshot.Record stored) throws IOException {
        byte[] encoded = readMetadataValue(stored);
        DomainContinuationStore.Record decoded = FsCodec.decode(FsCodec.DOMAIN_CONTINUATION,
                encoded, stagedContent);
        return DomainContinuationValidation.validate(operationId, decoded, encoded.length);
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
                DurableContentOwner.Category.SIGNING_OPERATION,
                reference -> SigningOwnerKey.exact(reference, expectedId), "signing");
    }

    private DurableContentReference decodeStatusOwner(MetadataSnapshot.Record owner, PkiId expectedId)
            throws IOException {
        return decodeTransactionalOwner(owner, expectedId, STATUS_OWNER_VALUE_VERSION,
                DurableContentOwner.Category.STATUS_OBJECT_RECORD,
                reference -> statusOwnerKey(expectedId), "status");
    }

    private DurableContentReference decodeTransactionalOwner(MetadataSnapshot.Record owner, PkiId expectedId,
            int expectedVersion, DurableContentOwner.Category expectedCategory,
            java.util.function.Function<DurableContentReference, MetadataKey> expectedKey,
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
            Encoding encoding = Encoding.valueOf(readOwnerField(input));
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
            if (!expectedKey.apply(restored).equals(owner.key())) {
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

    private record StoredConfirmation(CredentialConfirmationLifecycle lifecycle,
            long recordRevision) {
    }

    private record StoredConfirmationReview(CredentialConfirmationReview review,
            long recordRevision) {
    }

    private record CredentialConfirmationReviewScope(PkiId authorityId,
            Optional<String> profileId) {
        private CredentialConfirmationReviewScope {
            Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(profileId, "profileId");
        }
    }

    private record StoredConfirmationChallenge(CredentialConfirmationChallenge challenge,
            long recordRevision) {
    }

    private enum ConfirmationIndexRepairKind { CREATE, REPLACE, DELETE }

    private record ConfirmationIndexRepair(ConfirmationIndexRepairKind kind, MetadataKey key,
            long expectedRevision, byte[] content) {
        private static ConfirmationIndexRepair create(MetadataKey key, byte[] content) {
            return new ConfirmationIndexRepair(ConfirmationIndexRepairKind.CREATE, key, -1L, content);
        }

        private static ConfirmationIndexRepair replace(MetadataKey key, long expectedRevision,
                byte[] content) {
            return new ConfirmationIndexRepair(ConfirmationIndexRepairKind.REPLACE, key,
                    expectedRevision, content);
        }

        private static ConfirmationIndexRepair delete(MetadataKey key, long expectedRevision) {
            return new ConfirmationIndexRepair(ConfirmationIndexRepairKind.DELETE, key,
                    expectedRevision, new byte[0]);
        }
    }

    private record ConfirmationRepairBatch(List<ConfirmationIndexRepair> repairs,
            Optional<MetadataKey> lastExamined, boolean endReached) {
        private ConfirmationRepairBatch {
            repairs = List.copyOf(repairs);
        }
    }

    private record SignExpiry(SignWorkflowStore.Record record,
            Optional<DurableContentReference> reference) {
    }

    private record SignTransitionCommit(Optional<SignWorkflowStore.Record> record,
            Optional<SignExpiry> expiry) {
    }

    /** Store-bound one-shot façade over the metadata ledger's ephemeral token. */
    private static final class StoreSignAdmission implements SignWorkflowStore.SignAdmission {
        private static final int AVAILABLE = 0;
        private static final int CLAIMED = 1;
        private static final int TRANSFERRED_OR_CLOSED = 2;

        private final FilesystemPkiStore owner;
        private final SigningLedgerStoreEngine.SigningAdmission delegate;
        private final ReentrantLock lock = new ReentrantLock();
        private String submissionId;
        private int state = AVAILABLE;

        private StoreSignAdmission(FilesystemPkiStore owner,
                SigningLedgerStoreEngine.SigningAdmission delegate) {
            this.owner = owner;
            this.delegate = delegate;
        }

        @Override public void bind(PkiId identifier) {
            String normalized = owner.validateAdmissionIdentifier(identifier);
            lock.lock();
            try {
                if (state != AVAILABLE || submissionId != null) {
                    throw new IllegalStateException("Signing admission is already bound or used");
                }
                submissionId = normalized;
            } finally {
                lock.unlock();
            }
        }

        @SuppressWarnings("PMD.CompareObjectsWithEquals") // Store capability ownership requires exact identity.
        private void requireOwner(FilesystemPkiStore expectedOwner) {
            if (owner != expectedOwner) {
                throw new IllegalArgumentException("Signing admission belongs to another store");
            }
        }

        private void claim(FilesystemPkiStore expectedOwner, String expectedSubmissionId) {
            requireOwner(expectedOwner);
            boolean mismatched = false;
            boolean release = false;
            lock.lock();
            try {
                if (submissionId == null) {
                    throw new IllegalStateException("Signing admission is not bound");
                }
                if (submissionId.equals(expectedSubmissionId)) {
                    if (state == AVAILABLE) {
                        state = CLAIMED;
                    } else {
                        throw new IllegalStateException("Signing admission is already used");
                    }
                } else {
                    mismatched = true;
                    if (state == TRANSFERRED_OR_CLOSED) {
                        release = false;
                    } else {
                        state = TRANSFERRED_OR_CLOSED;
                        release = true;
                    }
                }
            } finally {
                lock.unlock();
            }
            if (release) {
                delegate.close();
            }
            if (mismatched) {
                throw new IllegalArgumentException("Signing admission submission identifier is mismatched");
            }
        }

        private SigningLedgerStoreEngine.SigningAdmission transfer() {
            lock.lock();
            try {
                if (state != CLAIMED) {
                    throw new IllegalStateException("Signing admission cannot be transferred");
                }
                state = TRANSFERRED_OR_CLOSED;
                return delegate;
            } finally {
                lock.unlock();
            }
        }

        @Override public void close() {
            boolean release = false;
            lock.lock();
            try {
                if (state != TRANSFERRED_OR_CLOSED) {
                    state = TRANSFERRED_OR_CLOSED;
                    release = true;
                }
            } finally {
                lock.unlock();
            }
            if (release) {
                delegate.close();
            }
        }
    }

    private record StoredStatus(StatusObject status, long recordRevision, long ownerRevision) {
    }

    @FunctionalInterface
    private interface SigningOwnerVisitor {
        void visit(PkiId submissionId, DurableContentReference reference) throws IOException;
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
                || state == SignWorkflowStore.State.CANCELLED;
    }

    private static boolean isContentFreeSignState(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.EXPIRED || state == SignWorkflowStore.State.RETIRED;
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
     * Reference-counted per-credential confirmation and revocation transition lock.
     */
    private static final class CredentialStateLockEntry {
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
                    lock = WriterExclusionLock.tryAcquire(channel);
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

    private void ensureVersionFile() throws IOException {
        Path vf = this.paths.versionFile();
        if (!Files.exists(vf, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            FsOperations.writeAtomic(vf, CURRENT_STORE_VERSION_BYTES);
            return;
        }
        requireCurrentStoreVersion(vf);
    }

    private static void requireCurrentStoreVersion(Path version) throws IOException {
        if (!Files.isRegularFile(version, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(version)) {
            throw unsupportedStoreFormat();
        }
        ByteBuffer encoded = ByteBuffer.allocate(CURRENT_STORE_VERSION_BYTES.length);
        try (FileChannel channel = FileChannel.open(version, StandardOpenOption.READ,
                java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            if (channel.size() != CURRENT_STORE_VERSION_BYTES.length) {
                throw unsupportedStoreFormat();
            }
            SigningFormatSupport.readFully(channel, encoded,
                    "Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
            if (channel.size() != CURRENT_STORE_VERSION_BYTES.length
                    || !MessageDigest.isEqual(encoded.array(), CURRENT_STORE_VERSION_BYTES)) {
                throw unsupportedStoreFormat();
            }
        }
    }

    private static IOException unsupportedStoreFormat() {
        return new IOException("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
    }

    private void rejectNonEmptyUnversionedStore() throws IOException {
        Path lockDirectory = this.paths.lockFile().getParent();
        try (Stream<Path> entries = Files.list(this.paths.root())) {
            if (entries.anyMatch(entry -> !entry.equals(lockDirectory))) {
                throw new IllegalStateException("unversioned store is not empty");
            }
        }
        try (Stream<Path> entries = Files.list(lockDirectory)) {
            if (entries.anyMatch(entry -> !entry.equals(this.paths.lockFile()))) {
                throw new IllegalStateException("unversioned store is not empty");
            }
        }
    }

    private void rejectObsoletePublicationLayout() {
        if (Files.exists(this.paths.root().resolve("publications"))) {
            throw new IllegalStateException("obsolete publication layout is not supported");
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

    private <T> List<T> listCurrentRecords(final Path byIdDir, final FsCodec.Schema<T> schema) {
        if (!Files.isDirectory(byIdDir)) {
            return List.of();
        }
        try {
            List<Path> entityDirs;
            try (Stream<Path> entries = Files.list(byIdDir)) {
                entityDirs = entries.filter(Files::isDirectory)
                        .sorted(Comparator.comparing(p -> p.getFileName().toString())).toList();
            }

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

    private <T> List<T> listBinaryRecords(final Path byIdDir, final FsCodec.Schema<T> schema) {
        if (!Files.isDirectory(byIdDir)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(byIdDir)) {
            List<T> records = new ArrayList<>();
            for (Path file : files.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(path -> path.getFileName().toString())).toList()) {
                records.add(FsCodec.decode(schema, FsOperations.readAll(file), stagedContent));
            }
            return List.copyOf(records);
        } catch (IOException exception) {
            throw new IllegalStateException("list immutable records failed", exception);
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

        try (Stream<Path> entries = Files.list(historyDir)) {
            entries.filter(Files::isRegularFile)
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

    /** Stable metadata cursor that decodes and validates one record at a time. */
    private final class PublicationMetadataCursor implements PublicationCursor {
        private final MetadataSnapshot snapshot;
        private final MetadataCursor cursor;
        private final AtomicBoolean cursorClosed = new AtomicBoolean();

        private PublicationMetadataCursor(MetadataSnapshot snapshot, MetadataCursor cursor) {
            this.snapshot = snapshot;
            this.cursor = cursor;
        }

        @Override
        public Optional<PublicationRecord> next(CancellationSignal cancellation) throws IOException {
            Objects.requireNonNull(cancellation, "cancellation");
            if (cursorClosed.get()) {
                throw new IllegalStateException("Publication cursor is closed");
            }
            Optional<MetadataSnapshot.Record> next = cursor.next(cancellation);
            if (next.isEmpty()) {
                return Optional.empty();
            }
            try (MetadataSnapshot.Record stored = next.orElseThrow()) {
                return Optional.of(decodePublicationRecord(stored, snapshot));
            }
        }

        @Override
        public void close() {
            if (cursorClosed.compareAndSet(false, true)) {
                cursor.close();
                snapshot.close();
            }
        }
    }
}
