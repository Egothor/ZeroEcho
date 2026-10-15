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
import zeroecho.pki.api.schedule.StatusSchedule;
import zeroecho.pki.api.schedule.StatusScheduleState;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.content.DurableContentOwner;
import zeroecho.pki.impl.ProfileLifecycleFailure;
import zeroecho.pki.impl.ProfileLifecycleFailure.Code;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofBindings;
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
 * <p>Version 14 stores CA bases, small current/history heads, append-only ordered
 * generation memberships, generations, paths and credentials in transactional
 * metadata. Credential records and content-owner sets commit together. Opening
 * validates both directions of these ownership edges before content reclamation,
 * then validates permanent
 * X.509 scope ownership and serial reservations against retained credentials and
 * signing commands before repairing derived serial lookups or issuance evidence.
 * Missing permanent authority and contradictory projections fail closed. Consumed
 * reservations survive abandoned publication and signing-record purge; terminal
 * commands do not require retired signing bytes. The added authority checks stream
 * records with metadata point lookups and O(W) transient command bookkeeping, where
 * W is the retained workflow count. Public {@code putCa} ingestion, including
 * lifecycle-only updates, and CA reconstruction perform O(G) metadata visits in
 * generation count, plus validation of the referenced credential bytes;
 * startup checks O(G + H) normalized rows without expanding H historical lists.
 * Snapshot assembly restores bounded batches into an unexposed target and
 * publishes each selected CA head only after its dependencies.</p>
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
 * Public opens hold an external process lock in a sibling restore-control
 * directory until close. The parent must therefore be writable. Cold restore
 * activation requires same-filesystem atomic directory moves and directory
 * synchronization; a live root mounted directly as a volume is unsuitable.
 * Pending restoration is reconciled before normal recovery opens the live root.
 * No legacy binary may start concurrently with activation. Existing root-local
 * owners remain excluded through compatible locks retained across root moves.
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
        "PMD.AvoidInstantiatingObjectsInLoops", "PMD.CloseResource", "PMD.CommentRequired",
        "PMD.LongVariable", "PMD.UnusedPrivateField", "PMD.UnusedFormalParameter",
        "PMD.UnusedLocalVariable", "PMD.UnusedPrivateMethod" })
public final class FilesystemPkiStore implements PkiStore, Closeable {

    private static final Logger LOG = Logger.getLogger(FilesystemPkiStore.class.getName());

    /* package */ static final String CURRENT_STORE_VERSION = "v18";
    private static final byte[] CURRENT_STORE_VERSION_BYTES =
            CURRENT_STORE_VERSION.getBytes(StandardCharsets.US_ASCII);
    private static final String SIGN_ENVELOPE_NAMESPACE = "io.zeroecho.pki.signing-envelope";
    private static final String SIGN_STATE_NAMESPACE = "io.zeroecho.pki.signing-state";
    private static final String SIGN_CANDIDATE_BINDING_NAMESPACE =
            "io.zeroecho.pki.signing-candidate-binding";
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
    private static final int CURRENT_SIGN_ENVELOPE_VERSION = 1;
    private static final int CURRENT_SIGN_STATE_VERSION = 1;
    private static final int CURRENT_SIGN_CANDIDATE_BINDING_VERSION = 1;
    private static final int DOMAIN_CONTINUATION_VERSION = 2;
    private static final int STATUS_OWNER_VALUE_VERSION = 1;
    private static final int METADATA_BUFFER_BYTES = 16 * 1024;
    private static final int MAX_METADATA_VALUE_BYTES = AuthorityMetadataCodec.MAX_VALUE_BYTES;
    private static final ThreadLocal<StatusCommitFaultPoint> STATUS_COMMIT_FAULT = new ThreadLocal<>();
    private static final ThreadLocal<PublicationCommitFaultPoint> PUBLICATION_COMMIT_FAULT = new ThreadLocal<>();
    private static final ThreadLocal<CredentialReservationFault> CREDENTIAL_RESERVATION_FAULT = new ThreadLocal<>();
    private static final ThreadLocal<long[]> ISSUER_GENERATION_READ_COUNTS = new ThreadLocal<>();
    private static final ThreadLocal<InitializationFaultPoint> INITIALIZATION_FAULT = new ThreadLocal<>();
    private static final ThreadLocal<Runnable> SIGN_ADMISSION_OBSERVER = new ThreadLocal<>();
    private static final ThreadLocal<Runnable> SIGN_ACCEPTANCE_VALIDATED_OBSERVER = new ThreadLocal<>();
    private static final ThreadLocal<SignAcceptanceCommitFault> SIGN_ACCEPTANCE_COMMIT_FAULT = new ThreadLocal<>();
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
    private final ConcurrentMap<String, SignLockEntry> signCandidateLocks;
    private final ConcurrentMap<PkiId, CredentialStateLockEntry> credentialStateLocks;
    private final ConcurrentMap<String, ProfileLockEntry> profileLocks;
    private final AtomicBoolean durabilityUncertain;
    private final AtomicBoolean closing;
    private final int maximumSigningWork;
    private final SigningActiveWal.Operations signingWalOperations;
    private final SigningActiveWal.Configuration signingWalConfiguration;
    private final FilesystemStagedContentStore stagedContent;
    private final SegmentedTransactionalMetadataStore metadataStore;
    private final CrlScopeReservationStore crlScopeReservations;
    private final MetadataEvidenceLog issuanceEvidenceLog;
    private final MetadataEvidenceLog statusEvidenceLog;
    private final MetadataEvidenceLog publicationEvidenceLog;
    private final MetadataEvidenceLog signingEvidenceLog;
    private final FilesystemRevocationAuthority revocations;
    private final SigningContentRetirementFaultInjector signingRetirementFaults;
    private final ConfirmationRevocationCleanupFaultInjector confirmationCleanupFaults;

    private final StoreOwnership ownership;
    private final FsRestoreCoordinator restoreCoordinator;
    private final StoreMutationBarrier mutationBarrier = new StoreMutationBarrier();
    private CredentialSearchIndex credentialSearch;
    private final zeroecho.pki.api.backup.BackupLimits backupLimits;

    /** Optional CT journal; {@code null} when CT Mode A is not configured. */
    private volatile zeroecho.pki.spi.ct.CtJournalStore ctJournalStore; // NOPMD AvoidUsingVolatile - Journal attachment is published independently of store operation locks.

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

    /**
     * Opens a store with explicit backup resource limits, preserving the store format.
     * @param root private store root
     * @param options store options
     * @param clock authoritative clock
     * @param backupLimits limits for file-backed backups and legacy adapters
     * @throws NullPointerException if an argument is null
     * @throws IllegalStateException if opening or ownership acquisition fails
     */
    public FilesystemPkiStore(Path root, FsPkiStoreOptions options, Clock clock,
            zeroecho.pki.api.backup.BackupLimits backupLimits) {
        this(root, options, clock, FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE,
                SigningContentRetirementFaultInjector.NONE, ConfirmationRevocationCleanupFaultInjector.NONE,
                false, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, null,
                SigningActiveWal.Configuration.defaults(Objects.requireNonNull(options, "options").signingMaximumGroupSize()),
                backupLimits);
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


    private FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock,
            final FilesystemRevocationAuthority.IndexUpdateFaultInjector indexUpdateFaults,
            final SigningContentRetirementFaultInjector signingRetirementFaults,
            final ConfirmationRevocationCleanupFaultInjector confirmationCleanupFaults,
            final boolean snapshotAssembly, final int maximumSigningWork,
            final SigningActiveWal.Operations signingWalOperations,
            final SigningActiveWal.Configuration signingWalConfiguration) {
        this(root, options, clock, indexUpdateFaults, signingRetirementFaults, confirmationCleanupFaults,
                snapshotAssembly, maximumSigningWork, signingWalOperations, signingWalConfiguration,
                zeroecho.pki.api.backup.BackupLimits.defaults());
    }

    private FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock,
            final FilesystemRevocationAuthority.IndexUpdateFaultInjector indexUpdateFaults,
            final SigningContentRetirementFaultInjector signingRetirementFaults,
            final ConfirmationRevocationCleanupFaultInjector confirmationCleanupFaults,
            final boolean snapshotAssembly, final int maximumSigningWork,
            final SigningActiveWal.Operations signingWalOperations,
            final SigningActiveWal.Configuration signingWalConfiguration,
            final zeroecho.pki.api.backup.BackupLimits backupLimits) {
        this(root, options, clock, indexUpdateFaults, signingRetirementFaults, confirmationCleanupFaults,
                snapshotAssembly, maximumSigningWork, signingWalOperations, signingWalConfiguration, backupLimits, false);
    }

    private FilesystemPkiStore(final Path root, final FsPkiStoreOptions options, final Clock clock,
            final FilesystemRevocationAuthority.IndexUpdateFaultInjector indexUpdateFaults,
            final SigningContentRetirementFaultInjector signingRetirementFaults,
            final ConfirmationRevocationCleanupFaultInjector confirmationCleanupFaults,
            final boolean snapshotAssembly, final int maximumSigningWork,
            final SigningActiveWal.Operations signingWalOperations,
            final SigningActiveWal.Configuration signingWalConfiguration,
            final zeroecho.pki.api.backup.BackupLimits backupLimits, final boolean borrowed) {
        this.backupLimits = Objects.requireNonNull(backupLimits, "backupLimits");
        this.options = Objects.requireNonNull(options, "options");
        Objects.requireNonNull(root, "root");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.signLocks = new ConcurrentHashMap<>();
        this.signCandidateLocks = new ConcurrentHashMap<>();
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
        FsRestoreCoordinator coordinator = null;
        try {
            if (!borrowed) coordinator = FsRestoreCoordinator.open(root, backupLimits, options, clock);
            preflightExistingRoot(root, snapshotAssembly,
                    recoveryConfiguration(signingWalConfiguration));
            FsOperations.ensureDir(root);
            PlatformFs.requireOwnerOnlyCapable(root);
            PlatformFs.ops().restrictToOwner(root);
            FsOperations.ensureDir(this.paths.lockFile().getParent());
            if (coordinator != null) coordinator.lockRoot(root);
            acquiredOwnership = StoreOwnership.borrowed();
        } catch (UnsupportedStoreFormatException e) {
            closeCoordinatorAfterFailedOpen(coordinator);
            throw new IllegalStateException(
                    "Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
        } catch (IOException e) {
            closeCoordinatorAfterFailedOpen(coordinator);
            throw new IllegalStateException("Filesystem store open failed: code=STORE_OPEN_FAILED", e);
        } catch (RuntimeException | Error failure) {
            closeCoordinatorAfterFailedOpen(coordinator);
            throw failure;
        }
        this.restoreCoordinator = coordinator;

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
            rejectObsoletePublicationLayout();
            this.signingNamespace = ensureSigningNamespace();
            if (newStore) {
                tripInitializationFault(InitializationFaultPoint.NAMESPACE_PUBLISHED);
                FsOperations.ensureDir(this.paths.stagedContentRoot());
            }
            this.stagedContent = new FilesystemStagedContentStore(this.paths.stagedContentRoot(),
                    this.signingNamespace, maximumSigningWork, null, false, mutationBarrier);
            if (newStore) {
                SigningFormatSupport.forceDirectory(this.paths.stagedContentRoot());
                SigningFormatSupport.forceDirectory(this.paths.root());
                tripInitializationFault(InitializationFaultPoint.STAGED_CONTENT_PUBLISHED);
            }
            FsOperations.ensureDir(this.paths.transactionalMetadataRoot());
            if (newStore) {
                SigningFormatSupport.forceDirectory(this.paths.root());
            }
            openedMetadata = openMetadataStore(initializeMetadata);
            this.stagedContent.cleanupValidatedTemporaryState();
            if (newStore) {
                tripInitializationFault(InitializationFaultPoint.METADATA_PUBLISHED);
            }
            this.signingTimeWatermark = new AtomicLong(openedMetadata.recoveredWatermark());
            this.metadataStore = openedMetadata;
            this.crlScopeReservations = new CrlScopeReservationStore(openedMetadata, options.initialCrlNumber(),
                    this::requireCrlReservationOutcome);
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
            this.historySeq = new AtomicLong(0L);
            if (!snapshotAssembly) {
                recoverStagedContent();
            }
            recoverPublicationRecords();
            boolean snapshotRestore = requireSnapshotBoundary();
            openedRevocations = FilesystemRevocationAuthority.open(
                    this.paths, new MetadataStoreId(this.signingNamespace), credentialId -> {
                        if (getCredential(credentialId).isEmpty()) {
                            throw new IOException("Revocation credential authority is missing");
                        }
                    }, newStore, indexUpdateFaults);
            this.revocations = openedRevocations;
            if (newStore) {
                SigningFormatSupport.forceDirectory(this.paths.root());
                tripInitializationFault(InitializationFaultPoint.REVOCATIONS_PUBLISHED);
            }
            rebuildCredentialConfirmationReviewIndex();
            removeRevokedCredentialConfirmationChallenges();
            validateCredentialConfirmationChallenges();
            if (snapshotRestore) {
                Files.delete(this.paths.revocationSnapshotBoundary());
                SigningFormatSupport.forceDirectory(this.paths.root());
            }
            if (newStore) {
                validatePreparedStore();
                publishVersionFile();
            }

            if (!snapshotAssembly && options.credentialSearch().isPresent()) {
                credentialSearch = new CredentialSearchIndex(this.paths.root(),
                        options.credentialSearch().orElseThrow(), this::certificateHolder);
                credentialSearch.rebuild(new CredentialMetadataAuthority(metadataStore, stagedContent));
            }

            LOG.log(Level.INFO, "Filesystem PKI store opened");
            this.ownership = acquiredOwnership;
            ownershipTransferred = true;
        } catch (UnsupportedStoreFormatException e) {
            throw new IllegalStateException(
                    "Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
        } catch (IOException e) {
            throw new IllegalStateException("Filesystem store open failed: code=STORE_OPEN_FAILED", e);
        } finally {
            if (!ownershipTransferred) {
                if (credentialSearch != null) {
                    try { credentialSearch.close(); }
                    catch (IOException ignored) { LOG.log(Level.WARNING, "Search-index cleanup failed during initialization"); }
                }
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
                closeCoordinatorAfterFailedOpen(coordinator);
            }
        }
    }

    private static void closeCoordinatorAfterFailedOpen(FsRestoreCoordinator coordinator) {
        if (coordinator != null) {
            try { coordinator.close(); } catch (IOException ignored) {
                LOG.log(Level.WARNING, "Restore coordinator cleanup failed during initialization");
            }
        }
    }

    /* default */ static FilesystemPkiStore openRestoreBorrowed(Path root, FsPkiStoreOptions options,
            Clock clock, zeroecho.pki.api.backup.BackupLimits limits) {
        return new FilesystemPkiStore(root, options, clock,
                FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE,
                SigningContentRetirementFaultInjector.NONE, ConfirmationRevocationCleanupFaultInjector.NONE,
                false, SigningDueWorkIndex.FOUR_GIB_MAXIMUM_WORK, null,
                SigningActiveWal.Configuration.defaults(options.signingMaximumGroupSize()), limits, true);
    }

    private static void preflightExistingRoot(Path root, boolean snapshotAssembly,
            SigningLedgerRecovery.Configuration recoveryConfiguration)
            throws IOException {
        if (!Files.exists(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return;
        if (!Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(root)) {
            throw unsupportedStoreFormat();
        }
        Path version = root.resolve("VERSION");
        if (!Files.exists(version, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            try (Stream<Path> entries = Files.list(root)) {
                if (entries.findAny().isPresent() && !snapshotAssembly) {
                    throw unsupportedStoreFormat();
                }
            }
            return;
        }
        requireCurrentStoreVersion(version);
        rejectLegacyAuthorityLayout(root);
        Path metadata = root.resolve("metadata");
        if (Files.exists(metadata, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            try {
                SigningLedgerRecovery.validateExistingLayout(
                        metadata, recoveryConfiguration);
            } catch (SigningLedgerRecovery.RecoveryException malformed) {
                throw unsupportedStoreFormat();
            }
        } else if (!snapshotAssembly) {
            throw unsupportedStoreFormat();
        }
        if (!snapshotAssembly) {
            Path namespace = root.resolve("SIGNING_NAMESPACE");
            Path staged = root.resolve("staged-content");
            if (!Files.isRegularFile(namespace, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(namespace)
                    || Files.size(namespace) != 32L
                    || !Files.isDirectory(staged, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(staged)) {
                throw unsupportedStoreFormat();
            }
            String encoded = Files.readString(namespace, StandardCharsets.US_ASCII);
            if (!encoded.matches("[a-f0-9]{32}")) {
                throw unsupportedStoreFormat();
            }
            try {
                FilesystemStagedContentStore.validateExistingLayout(staged);
            } catch (FilesystemStagedContentStore.MalformedLayoutException malformed) {
                throw unsupportedStoreFormat();
            }
        }
    }

    /** Read-only cutover guard; empty legacy directories are harmless. */
    private static void rejectLegacyAuthorityLayout(Path root) throws IOException {
        for (String tree : List.of("cas", "issuer-generations", "issuer-chain-paths", "credentials", "credential-handoffs")) {
            Path directory = root.resolve(tree);
            if (!Files.exists(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS)) { continue; }
            try (Stream<Path> entries = Files.walk(directory)) {
                java.util.Iterator<Path> iterator = entries.iterator();
                while (iterator.hasNext()) {
                    Path path = iterator.next();
                    if (Files.isSymbolicLink(path)) { throw unsupportedStoreFormat(); }
                    if (Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) { continue; }
                    String name = path.getFileName().toString();
                    boolean history = false;
                    for (Path component : directory.relativize(path)) { if ("history".equals(component.toString())) { history = true; } }
                    boolean legacy = "cas".equals(tree) ? "current.bin".equals(name) || history
                            : name.endsWith(".bin") || name.endsWith(".intent") || name.endsWith(".credential.pending");
                    if (legacy) { throw unsupportedStoreFormat(); }
                }
            }
        }
    }

    private static SigningLedgerRecovery.Configuration recoveryConfiguration(
            SigningActiveWal.Configuration activeWalConfiguration) {
        SigningLedgerRecovery.Configuration defaults = SigningLedgerRecovery.Configuration.defaults();
        return new SigningLedgerRecovery.Configuration(defaults.maximumRootEntries(),
                defaults.maximumArtifactBytes(), defaults.maximumCheckpointEntries(),
                activeWalConfiguration);
    }

    private void validatePreparedStore() throws IOException {
        Path namespace = paths.signingNamespaceFile();
        Path staged = paths.stagedContentRoot();
        if (!Files.isRegularFile(namespace, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(namespace)
                || Files.size(namespace) != 32L
                || !Files.isDirectory(staged, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(staged)) {
            throw unsupportedStoreFormat();
        }
        String encoded = Files.readString(namespace, StandardCharsets.US_ASCII);
        if (!encoded.matches("[a-f0-9]{32}")) {
            throw unsupportedStoreFormat();
        }
        try {
            FilesystemStagedContentStore.validateExistingLayout(staged);
            SigningLedgerRecovery.validateExistingLayout(paths.transactionalMetadataRoot(),
                    recoveryConfiguration(signingWalConfiguration));
        } catch (SigningLedgerRecovery.RecoveryException
                | FilesystemStagedContentStore.MalformedLayoutException malformed) {
            throw unsupportedStoreFormat();
        }
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
        StagedContentStore recoveryContent = FilesystemStagedContentStore.readOnlyResolver(
                paths.stagedContentRoot(), signingNamespace);
        SegmentedTransactionalMetadataStore opened;
        try {
            opened = initialize
                    ? SegmentedTransactionalMetadataStore.create(root,
                            new MetadataStoreId(signingNamespace), signingWalOperations,
                            maximumSigningWork, signingWalConfiguration,
                            options.signingResidentIndexBudgetBytes(),
                            options.signingCompactionTransientBudgetBytes(), recoveryContent)
                    : SegmentedTransactionalMetadataStore.open(root,
                            new MetadataStoreId(signingNamespace), maximumSigningWork,
                            signingWalConfiguration, options.signingResidentIndexBudgetBytes(),
                            options.signingCompactionTransientBudgetBytes(), recoveryContent);
        } catch (SegmentedTransactionalMetadataStore.OpenIntegrityException failure) {
            throw unsupportedStoreFormat();
        }
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
        owners.addAll(new CredentialMetadataAuthority(metadataStore, stagedContent).owners(reference));
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
        if (!new CredentialMetadataAuthority(metadataStore, stagedContent).owners(reference).isEmpty()) return true;
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            return stagedContent;
        }
    }

    private void recoverStagedContent() throws IOException {
        // Validate both committed credential/owner directions before any reclaim.
        new CredentialMetadataAuthority(metadataStore, stagedContent).validateAll(credential -> { });
        // Handoff recovery establishes durable credential publication before any
        // cross-file authority check or derived projection repair.
        validateRecoveredCrlAuthority();
        // Prove both directions before repair/reclamation, without retaining the population.
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            visitStoredStatuses(snapshot, stored -> { });
            visitStoredStatuses(snapshot, stored -> recordStatusEvidence(stored.status()));
        }
        try (TemporaryUniqueIndex retained = stagedContent.beginUniqueIndex();
                TemporaryUniqueIndex retainedOwners = stagedContent.beginOwnerIndex();
                TemporaryUniqueIndex transactionalOwners = stagedContent.beginUniqueIndex()) {
            try {
                addPersistedCredentialReferences(retained, retainedOwners);
                new CredentialMetadataAuthority(metadataStore, stagedContent).validateAll(
                        credential -> addRetained(transactionalOwners, credential.content()));
                try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
                    visitStoredStatuses(snapshot,
                            stored -> addRetained(transactionalOwners, stored.status().content()));
                }
                addSigningReferences(retained, transactionalOwners);
                stagedContent.recoverContent(retained, retainedOwners, transactionalOwners);
            } catch (IllegalStateException | PkiException malformedDurableState) {
                // Recovery cannot prove abandonment while durable metadata is
                // corrupt. Preserve content so the normal owning subsystem can
                // report the authoritative corruption without destructive loss.
                LOG.log(Level.WARNING, "Staged-content reclamation skipped: code=DURABLE_METADATA_INVALID");
            }
        }
    }

    /* default */ void validateRecoveredCrlAuthority() throws IOException {
        schedules().validate(this::validateScheduleReceipt);
        new CredentialMetadataAuthority(metadataStore, stagedContent).validateAll(this::validateCredentialScopeAuthority);
        validateAuthorityMetadata();
        CrlScopeRecovery.validate(this, crlScopeReservations);
        validateGenerationScopeOwners();
        validateCredentialSerialIndex();
        validateIssuanceEvidence();
        rebuildCredentialSerialIndex();
    }

    private void validateAuthorityMetadata() throws IOException {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            AuthorityMetadataStore.validateAll(snapshot);
            AuthorityMetadataStore.visit(snapshot, AuthorityMetadataCodec.ISSUER_PATH, AuthorityMetadataCodec::path,
                    path -> validateIssuerChainPath(snapshot, path));
        }
    }

    private void validateCredentialSerialIndex() throws IOException {
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(CREDENTIAL_SERIAL_NAMESPACE),
                        CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    byte[] encoded = readMetadataValue(record);
                    if (encoded.length > 16_384) { throw new IOException("Credential serial index exceeds its bound"); }
                    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
                        if (input.readInt() != 1) { throw new IOException("Credential serial index version is obsolete"); }
                        PkiId issuerId = new PkiId(input.readUTF());
                        BigInteger serial = new BigInteger(input.readUTF());
                        if (!record.key().equals(serialIndexKey(issuerId, serial))) {
                            throw new IOException("Credential serial index differs from its key");
                        }
                        decodeSerialIndex(record, issuerId, serial);
                        getCredentialByIssuerAndSerial(issuerId, serial)
                                .orElseThrow(() -> new IOException("Credential serial index target is missing"));
                    }
                }
            }
        }
    }

    private void validateGenerationScopeOwners() throws IOException {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            AuthorityMetadataStore.visit(snapshot, AuthorityMetadataCodec.ISSUER_GENERATION, AuthorityMetadataCodec::generation, generation -> {
                Credential credential = requireCredential(snapshot, generation.credentialId());
                if (BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
                    CrlScopeOwner owner = crlScopeReservations.findOwner(snapshot, certificateScope(certificateHolder(credential)))
                            .orElseThrow(() -> new IOException("Issuer generation scope owner is missing"));
                    if (!owner.authorityId().equals(generation.authorityId())) {
                        throw new IOException("Issuer generation scope authority differs");
                    }
                }
            });
        }
    }

    private void validateCredentialScopeAuthority(Credential credential) throws IOException {
        Optional<SnapshotCredentialAuthority> authority = credentialSnapshotAuthority(credential);
        if (authority.isEmpty()) { return; }
        ScopeSerialReservation reservation = authority.orElseThrow().reservation();
        if (reservation.issuanceOwner() instanceof ScopeSerialReservation.SigningOwner signing) {
            Optional<DomainContinuationStore.Record> domain = getDomainContinuation(signing.operationId());
            if (domain.isPresent()) {
                DomainContinuationStore.Record retained = domain.orElseThrow();
                if (!retained.commandCommitment().equals("domain:v1:" + signing.commandCommitment())) {
                    throw new IOException("Credential signing command commitment differs");
                }
                requirePublicationIssuer(credential, retained);
            }
        }
    }

    private void validateIssuanceEvidence() throws IOException {
        try (MetadataEvidenceLog.Reader reader = issuanceEvidenceLog.openReader(-1);
                MetadataSnapshot snapshot = metadataStore.snapshot()) {
            long expectedSequence = 0;
            while (reader.next(CancellationSignal.NONE)) {
                MetadataEvidenceLog.Entry entry = reader.current();
                Credential credential = getCredential(entry.objectId())
                        .orElseThrow(() -> new IOException("Issuance evidence credential is missing"));
                byte[] expected = DomainAttributeEncoding.encode(credential.attributes()).getBytes(StandardCharsets.UTF_8);
                if (entry.sequence() != expectedSequence++
                        || !(credential.profileBinding() instanceof EndEntityProfileBinding)
                        || entry.recordedAt().toEpochMilli() != credential.validity().notBefore().toEpochMilli()
                        || !MessageDigest.isEqual(expected, entry.payload())) {
                    throw new IOException("Issuance evidence differs from its authoritative credential");
                }
                try (MetadataSnapshot.Record marker = snapshot.get(new MetadataKey(ISSUANCE_EVIDENCE_NAMESPACE,
                        "m:" + entry.objectId().value())).orElse(null)) {
                    if (marker == null || marker.length().orElse(-1) != 0) {
                        throw new IOException("Issuance evidence marker is missing or malformed");
                    }
                }
            }
            if (expectedSequence != reader.highWatermark()) {
                throw new IOException("Issuance evidence sequence is incomplete");
            }
            long markers = 0;
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(ISSUANCE_EVIDENCE_NAMESPACE),
                    CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        String key = record.key().key();
                        if (key.startsWith("m:")) {
                            if (record.length().orElse(-1) != 0 || getCredential(new PkiId(key.substring(2))).isEmpty()) {
                                throw new IOException("Issuance evidence marker is invalid");
                            }
                            markers++;
                        } else if (!"head".equals(key) && !key.startsWith("e:")) {
                            throw new IOException("Issuance evidence metadata key is invalid");
                        }
                    }
                }
            }
            if (markers != expectedSequence) {
                throw new IOException("Issuance evidence marker has no entry");
            }
        }
    }

    private void addPersistedCredentialReferences(TemporaryUniqueIndex retained, TemporaryUniqueIndex retainedOwners)
            throws IOException {
        new CredentialMetadataAuthority(metadataStore, stagedContent).validateAll(credential -> addRetained(retained, credential.content()));
    }

    private static void addTransactionalStatusOwnership(TemporaryUniqueIndex transactionalOwners,
            List<StoredStatus> statuses)
            throws IOException {
        for (StoredStatus stored : statuses) {
            addRetained(transactionalOwners, stored.status().content());
        }
    }

    private void addSigningReferences(TemporaryUniqueIndex retained,
            TemporaryUniqueIndex active) throws IOException {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            visitSnapshotSigningWorkflows(snapshot, workflow -> {
                validateCompletedFullCrl(workflow);
                recordSigningEvidence(workflow);
                for (DurableContentReference reference : workflow.candidates()) {
                    addRetained(retained, reference);
                    if (isLiveContentState(workflow.state())) { addRetained(active, reference); }
                }
            });
        }
    }

    private void validateCompletedFullCrl(SignWorkflowStore.Workflow workflow) throws IOException {
        if (workflow.envelope().outer().isEmpty()) { return; }
        zeroecho.pki.impl.core.continuation.DomainCommandEncoding.Decoded command =
                zeroecho.pki.impl.core.continuation.DomainCommandEncoding.decode(
                        workflow.envelope().outer().orElseThrow().command());
        if (!zeroecho.pki.impl.core.continuation.FullCrlSigningCommand.supports(command.operation())) { return; }
        try {
            DomainContinuationStore.Record domain = getDomainContinuation(workflow.operationId()).orElseThrow();
            if (domain.state() != DomainContinuationStore.State.COMPLETED) { return; }
            PkiId statusId = zeroecho.pki.impl.core.continuation.FullCrlSigningCommand.resultId(domain.result().orElseThrow());
            // The preceding status recovery pass has checked all content and owner edges.
            // Only bounded metadata is read here; snapshot assembly does not run this pass.
            try (MetadataSnapshot snapshot = metadataStore.snapshot();
                    MetadataSnapshot.Record record = snapshot.get(statusRecordKey(statusId))
                            .orElseThrow(() -> new IOException("Completed full CRL publication is missing"))) {
                StatusObject status = FsCodec.decode(FsCodec.STATUS_OBJECT, readMetadataValue(record), stagedContent);
                zeroecho.pki.impl.core.continuation.FullCrlSigningCommand.requireCompleted(status, domain);
            }
        } catch (RuntimeException failure) {
            // Fail before reclamation; this must not enter the best-effort cleanup catch.
            throw new IOException("Completed full CRL publication authority is invalid", failure);
        }
    }

    private void visitSigningOwners(DurableContentReference reference,
            SigningOwnerVisitor visitor) throws IOException {
        visitSigningOwners(reference, visitor, false);
    }

    private void visitSigningOwners(DurableContentReference reference,
            SigningOwnerVisitor visitor, boolean stopAfterFirst) throws IOException {
        Optional<SignWorkflowStore.CandidateBinding> binding = readCandidateBinding(
                reference.contentId());
        if (binding.isEmpty()) {
            return;
        }
        SignWorkflowStore.CandidateBinding exact = binding.orElseThrow();
        Optional<StoredSign> workflow = readStoredSign(exact.operationId());
        if (workflow.isPresent() && isLiveContentState(workflow.orElseThrow().record().state())
                && workflow.orElseThrow().record().candidates().contains(reference)) {
            visitor.visit(exact.operationId(), reference);
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
     * store; it clones a new store layout and reconstructs selected CA heads from
     * one pinned metadata revision. Standalone credential authority is reconstructed by
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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

    /* default */ Set<String> snapshotNonCredentialContentIds(MetadataSnapshot snapshot) throws IOException {
        requireStoreUsable();
        Set<String> contentIds = new HashSet<>();
        for (StoredSign stored : listStoredSigns(snapshot)) {
            for (DurableContentReference reference : stored.record().candidates()) { contentIds.add(reference.contentId()); }
        }
        return Set.copyOf(contentIds);
    }

    /* default */ List<StatusObject> snapshotStatusObjects(MetadataSnapshot snapshot) throws IOException {
        requireStoreUsable();
        return listStoredStatuses(snapshot).stream().map(StoredStatus::status).toList();
    }

    /* default */ void visitSnapshotSigningWorkflows(MetadataSnapshot snapshot,
            AuthorityMetadataStore.Visitor<SignWorkflowStore.Workflow> visitor) throws IOException {
        requireStoreUsable();
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(SIGN_STATE_NAMESPACE), CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    visitor.accept(decodeStoredSign(snapshot, record).record());
                }
            }
        }
    }

    /* default */ void copySnapshotMetadataTo(MetadataSnapshot snapshot, Path targetRoot) throws IOException {
        requireStoreUsable();
        Objects.requireNonNull(targetRoot, "targetRoot");
        Path metadataRoot = new FsPaths(targetRoot).transactionalMetadataRoot();
        FsOperations.ensureDir(metadataRoot);
        metadataStore.exportSnapshotTo(snapshot, metadataRoot, Set.of(STATUS_RECORD_NAMESPACE,
                STATUS_OWNER_NAMESPACE, PUBLICATION_RECORD_NAMESPACE,
                CREDENTIAL_SERIAL_NAMESPACE, AuthorityMetadataCodec.CA_BASE, AuthorityMetadataCodec.CA_CURRENT,
                AuthorityMetadataCodec.CA_HISTORY, AuthorityMetadataCodec.CA_GENERATION_ORDER, AuthorityMetadataCodec.CA_GENERATION_MEMBER,
                AuthorityMetadataCodec.ISSUER_GENERATION, AuthorityMetadataCodec.ISSUER_PATH,
                AuthorityMetadataCodec.CREDENTIAL_RECORD, AuthorityMetadataCodec.CREDENTIAL_OWNER_SET));
    }

    /* default */ void restoreSnapshotCa(CaRecord ca) throws IOException {
        requireStoreUsable();
        validateCaCredentialReferences(ca);
        authorityMetadata().restoreCa(ca, options.caHistoryPolicy());
    }

    /**
     * Stores a complete logical CA value after validating its credential dependencies.
     *
     * @implNote End-to-end ingestion visits all {@code G} supplied memberships,
     * even for a lifecycle-only update. Only the new membership suffix and small
     * heads are staged; constant suffix-helper work is not a constant-time public write.
     * @param record complete CA value to store
     * @throws NullPointerException if {@code record} is null
     * @throws IllegalStateException if authority validation or persistence fails
     */
    @Override
    public void putCa(final CaRecord record) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(record, "record");
            validateCaCredentialReferences(record);
            try { authorityMetadata().putCa(record, options.caHistoryPolicy()); }
            catch (IOException failure) { throw signingDurabilityFailure(failure); }
        }
    }

    /**
     * Conditionally publishes a complete CA value using its observed current value.
     *
     * @implNote Validation and comparison visit O(G) generation memberships plus
     * bounded path and certificate validation. Auxiliary memory is O(G) plus the
     * existing validation workspace; no authority-population scan is introduced.
     * @param expected complete previously observed value
     * @param replacement complete new value for the same CA
     * @return whether publication was confirmed; false denotes absence, inequality,
     *         or a definite commit conflict
     * @throws NullPointerException if either record is null
     * @throws IllegalArgumentException if the CA identities differ
     * @throws IllegalStateException if validation or definite persistence fails
     * @throws PkiException if durability or acknowledgement is uncertain
     */
    @Override
    public boolean replaceCa(CaRecord expected, CaRecord replacement) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(expected, "expected");
            Objects.requireNonNull(replacement, "replacement");
            if (!expected.caId().equals(replacement.caId())) {
                throw new IllegalArgumentException("CA replacement identities differ");
            }
            validateCaCredentialReferences(replacement);
            try { return authorityMetadata().replaceCa(expected, replacement, options.caHistoryPolicy()); }
            catch (IOException failure) { throw signingDurabilityFailure(failure); }
        }
    }

    @Override
    public Optional<CaRecord> getCa(final PkiId caId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(caId, "caId");
            try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
                Optional<CaRecord> record = AuthorityMetadataStore.ca(snapshot, caId);
                if (record.isPresent()) { validateCaCredentialReferences(snapshot, record.orElseThrow()); }
                return record;
            } catch (IOException failure) { throw new IllegalStateException("CA metadata read failed", failure); }
        }
    }

    @Override
    public List<CaRecord> listCas() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
                List<CaRecord> values = new ArrayList<>();
                for (AuthorityMetadataCodec.Head head : AuthorityMetadataStore.list(snapshot, AuthorityMetadataCodec.CA_CURRENT, AuthorityMetadataCodec::head)) {
                    values.add(validateCaCredentialReferences(snapshot, AuthorityMetadataStore.reconstruct(snapshot, head)));
                }
                values.sort(Comparator.comparing(value -> value.caId().value()));
                return List.copyOf(values);
            } catch (IOException failure) { throw new IllegalStateException("CA metadata list failed", failure); }
        }
    }

    @Override
    public List<CaRecord> listCasPage(Optional<PkiId> afterCaId, int limit) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(afterCaId, "afterCaId");
            if (limit <= 0 || limit > 1_000) {
                throw new IllegalArgumentException("limit must be between 1 and 1000");
            }
            String after = afterCaId.map(PkiId::value).orElse("");
            List<AuthorityMetadataCodec.Head> selected = new ArrayList<>(limit);
            try (MetadataSnapshot snapshot = metadataStore.snapshot();
                    MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.CA_CURRENT), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    AuthorityMetadataCodec.Head record;
                    try (MetadataSnapshot.Record stored = next.orElseThrow()) {
                        record = AuthorityMetadataCodec.head(stored.key(), readMetadataValue(stored));
                    }
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
                List<CaRecord> values = new ArrayList<>(selected.size());
                for (AuthorityMetadataCodec.Head head : selected) {
                    values.add(validateCaCredentialReferences(snapshot, AuthorityMetadataStore.reconstruct(snapshot, head)));
                }
                return List.copyOf(values);
            } catch (IOException exception) {
                throw new IllegalStateException("list CA page failed", exception);
            }
        }
    }

    @Override
    public List<CaRecord> selectAuthoritiesPage(Optional<String> after, int limit,
            java.util.function.Predicate<CaRecord> include, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            return selectionMetadataPage(AuthorityMetadataCodec.CA_CURRENT, after, limit,
                    (snapshot, record) -> validateCaCredentialReferences(snapshot,
                            AuthorityMetadataStore.reconstruct(snapshot,
                                    AuthorityMetadataCodec.head(record.key(), readMetadataValue(record)))),
                    include, value -> value.caId().value(), cancellation);
        }
    }

    @Override
    public void visitAuthorityKeyReferences(java.util.function.Consumer<zeroecho.pki.api.KeyRef> visitor,
            CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(visitor, "visitor");
            checkSelectionCancellation(cancellation);
            try (MetadataSnapshot snapshot = metadataStore.snapshot();
                    MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(AuthorityMetadataCodec.CA_CURRENT), cancellation)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(cancellation)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        checkSelectionCancellation(cancellation);
                        CaRecord authority = validateCaCredentialReferences(snapshot, AuthorityMetadataStore.reconstruct(snapshot,
                                AuthorityMetadataCodec.head(record.key(), readMetadataValue(record))));
                        visitor.accept(authority.issuerKeyRef());
                    }
                }
            } catch (IOException failure) {
                checkSelectionCancellation(cancellation);
                throw new IllegalStateException("Known key selection failed", failure);
            }
        }
    }

    @Override
    public List<String> listProfileIdsPage(Optional<String> after, int limit, java.util.function.Predicate<String> include, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            validateSelectionPage(after, limit);
            checkSelectionCancellation(cancellation);
            Path directory = paths.root().resolve("profiles").resolve("by-id");
            if (!Files.isDirectory(directory)) { return List.of(); }
            java.util.Queue<String> selected = new java.util.PriorityQueue<>(limit, Comparator.reverseOrder());
            try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path entry : entries) {
                    checkSelectionCancellation(cancellation);
                    if (!Files.isDirectory(entry)) { continue; }
                    String name = entry.getFileName().toString();
                    if (!name.startsWith("id-")) { throw new IOException("Invalid profile directory identity"); }
                    String id = new String(java.util.Base64.getUrlDecoder().decode(name.substring(3)),
                            StandardCharsets.UTF_8);
                    if (!paths.profileDir(id).equals(entry)) { throw new IOException("Invalid profile directory identity"); }
                    // Empty directories can remain after an interrupted first import.
                    if (!Files.isDirectory(entry.resolve("versions"))) { continue; }
                    try (java.nio.file.DirectoryStream<Path> versions = Files.newDirectoryStream(entry.resolve("versions"), "*.bin")) {
                        if (!versions.iterator().hasNext()) { continue; }
                    }
                    if (after.isPresent() && id.compareTo(after.orElseThrow()) <= 0) { continue; }
                    if (include.test(id)) { selectSmallest(selected, id, limit, Comparator.naturalOrder()); }
                }
                return selected.stream().sorted().toList();
            } catch (IOException failure) { throw new IllegalStateException("Profile selection failed", failure); }
        }
    }

    @Override
    public List<RequestSelection> listRequestsPage(Optional<String> after, int limit, java.util.function.Predicate<RequestSelection> include, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            validateSelectionPage(after, limit);
            checkSelectionCancellation(cancellation);
            Path directory = paths.requestsById();
            if (!Files.isDirectory(directory)) { return List.of(); }
            Comparator<RequestSelection> order = Comparator.comparing(value -> value.requestId().value());
            java.util.Queue<RequestSelection> selected = new java.util.PriorityQueue<>(limit, order.reversed());
            try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path entry : entries) {
                    checkSelectionCancellation(cancellation);
                    if (!Files.isRegularFile(entry)) { continue; }
                    ParsedCertificationRequest request = FsCodec.decode(FsCodec.PARSED_REQUEST,
                            FsOperations.readAll(entry), stagedContent);
                    if (after.isPresent() && request.requestId().value().compareTo(after.orElseThrow()) <= 0) { continue; }
                    RequestSelection row = new RequestSelection(request.requestId(), request.formatId(), request.requestedProfileId());
                    if (include.test(row)) { selectSmallest(selected, row, limit, order); }
                }
                return selected.stream().sorted(order).toList();
            } catch (IOException failure) { throw new IllegalStateException("Request selection failed", failure); }
        }
    }

    @Override
    public List<Credential> listCredentialsPage(PkiId authorityId, Optional<String> after, int limit, java.util.function.Predicate<Credential> include, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            Objects.requireNonNull(authorityId, "authorityId");
            return selectionMetadataPage(AuthorityMetadataCodec.CREDENTIAL_RECORD, after, limit,
                    (snapshot, record) -> {
                        Credential decoded = AuthorityMetadataCodec.credential(record.key(), readMetadataValue(record), stagedContent);
                        return new CredentialMetadataAuthority(metadataStore, stagedContent)
                                .find(snapshot, decoded.credentialId()).orElseThrow();
                    },
                    value -> value.issuerRef().caId().equals(authorityId) && include.test(value),
                    value -> value.credentialId().value(), cancellation);
        }
    }

    @Override
    public boolean credentialSearchAvailable() {
        return !closing.get() && !durabilityUncertain.get() && credentialSearch != null && credentialSearch.available();
    }

    @Override
    public List<Credential> searchCredentials(zeroecho.pki.api.credential.CredentialSearchQuery query,
            Optional<String> after, int limit, java.util.function.Predicate<Credential> include,
            CancellationSignal cancellation) {
        requireStoreUsable();
        if (!credentialSearchAvailable()) throw new IllegalStateException("Credential search is unavailable");
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(
                options.credentialSearch().orElseThrow().queryTimeoutMillis());
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter(deadline, cancellation)) {
            return credentialSearch.search(query, after, limit, this::getCredential, include, cancellation, deadline);
        } catch (InterruptedIOException failure) {
            throw new java.util.concurrent.CancellationException("Credential search cancelled");
        } catch (IOException failure) { throw new IllegalStateException("Credential search failed", failure); }
    }

    @Override
    public List<IssuerGeneration> listIssuerGenerationsPage(PkiId authorityId, Optional<String> after, int limit, java.util.function.Predicate<IssuerGeneration> include, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            Objects.requireNonNull(authorityId, "authorityId");
            return selectionMetadataPage(AuthorityMetadataCodec.ISSUER_GENERATION, after, limit,
                    (snapshot, record) -> validateIssuerGeneration(
                            AuthorityMetadataCodec.generation(record.key(), readMetadataValue(record))),
                    value -> value.authorityId().equals(authorityId) && include.test(value), value -> value.issuerId().value(), cancellation);
        }
    }

    @Override
    public List<StatusObject> listStatusObjectsPage(PkiId authorityId, Optional<String> after, int limit, java.util.function.Predicate<StatusObject> include, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            Objects.requireNonNull(authorityId, "authorityId");
            return selectionMetadataPage(STATUS_RECORD_NAMESPACE, after, limit,
                    (snapshot, record) -> decodeStoredStatus(snapshot, record).status(),
                    value -> value.issuerCaId().equals(authorityId) && include.test(value), value -> value.statusObjectId().value(), cancellation);
        }
    }

    @Override
    public List<PublicationRecord> listPublicationsPage(Optional<String> after, int limit, java.util.function.Predicate<PublicationRecord> include, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            return selectionMetadataPage(PUBLICATION_RECORD_NAMESPACE, after, limit,
                    (snapshot, record) -> decodePublicationRecord(record, snapshot), include, value -> value.publicationId().value(), cancellation);
        }
    }

    private static void checkSelectionCancellation(CancellationSignal cancellation) {
        if (Objects.requireNonNull(cancellation, "cancellation").isCancelled()) {
            throw new java.util.concurrent.CancellationException("Selection cancelled");
        }
    }

    private static <T> void selectSmallest(java.util.Queue<T> selected, T candidate, int limit,
            Comparator<T> order) {
        if (selected.size() < limit) { selected.add(candidate); }
        else if (order.compare(candidate, selected.element()) < 0) { selected.remove(); selected.add(candidate); }
    }

    private static void validateSelectionPage(Optional<String> after, int limit) {
        Objects.requireNonNull(after, "after");
        after.ifPresent(value -> new MetadataKey("selection", value));
        if (limit < 1 || limit > 1001) { throw new IllegalArgumentException("Selection limit must be 1 through 1001"); }
    }

    @FunctionalInterface
    private interface SelectionDecoder<T> {
        T decode(MetadataSnapshot snapshot, MetadataSnapshot.Record record) throws IOException;
    }

    // Authoritative identity namespaces use hashed keys. Select by the decoded wire identifier,
    // with authorization before heap admission: one scan, O(N log L) time and O(L) retained rows.
    private <T> List<T> selectionMetadataPage(String namespace, Optional<String> after, int limit,
            SelectionDecoder<T> decoder, java.util.function.Predicate<T> include,
            java.util.function.Function<T, String> identity, CancellationSignal cancellation) {
        requireStoreUsable();
        validateSelectionPage(after, limit);
        checkSelectionCancellation(cancellation);
        Objects.requireNonNull(include, "include");
        Comparator<T> order = Comparator.comparing(identity);
        java.util.Queue<T> selected = new java.util.PriorityQueue<>(limit, order.reversed());
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace), cancellation)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(cancellation)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    checkSelectionCancellation(cancellation);
                    T candidate = decoder.decode(snapshot, record);
                    if (after.isPresent() && identity.apply(candidate).compareTo(after.orElseThrow()) <= 0) { continue; }
                    if (include.test(candidate)) { selectSmallest(selected, candidate, limit, order); }
                }
            }
            return selected.stream().sorted(order).toList();
        } catch (IOException failure) {
            checkSelectionCancellation(cancellation);
            throw new IllegalStateException("Metadata selection failed", failure);
        }
    }

    @Override
    public void putIssuerGeneration(IssuerGeneration generation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(generation, "generation");
            Credential credential = getCredential(generation.credentialId())
                    .orElseThrow(() -> new IllegalStateException("Issuer credential reference is missing"));
            if (!credential.credentialId().equals(generation.credentialId())) {
                throw new IllegalStateException("Issuer credential identity mismatch");
            }
            if (BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
                try {
                    X509Certificate certificate = certificateHolder(credential);
                    crlScopeReservations.claim(new CrlScopeOwner(certificateScope(certificate), generation.authorityId()));
                } catch (IOException failure) {
                    throw signingDurabilityFailure(failure);
                }
            }
            try { authorityMetadata().create(AuthorityMetadataCodec.generationKey(generation.issuerId()), FsCodec.encode(FsCodec.ISSUER_GENERATION, generation)); }
            catch (IOException failure) { throw signingDurabilityFailure(failure); }
        }
    }

    @Override
    public Optional<IssuerGeneration> getIssuerGeneration(PkiId issuerId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(issuerId, "issuerId");
            long[] counts = ISSUER_GENERATION_READ_COUNTS.get();
            if (counts != null) { counts[0]++; }
            try {
                Optional<IssuerGeneration> value = authorityMetadata().find(AuthorityMetadataCodec.generationKey(issuerId), AuthorityMetadataCodec::generation);
                if (value.isPresent() && !value.orElseThrow().issuerId().equals(issuerId)) { throw new IOException("Issuer metadata identity differs"); }
                return value.map(this::validateIssuerGeneration);
            } catch (IOException failure) { throw new IllegalStateException("Issuer generation metadata read failed", failure); }
        }
    }

    @Override
    public BigInteger reserveCrlNumber(PkiId issuerGenerationId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(issuerGenerationId, "issuerGenerationId");
            try {
                IssuerGeneration generation = getIssuerGeneration(issuerGenerationId)
                        .orElseThrow(() -> new IllegalStateException("CRL issuer generation is missing"));
                if (!generation.issuerId().equals(issuerGenerationId)) {
                    throw new IllegalStateException("CRL issuer generation identity mismatch");
                }
                Credential credential = getCredential(generation.credentialId())
                        .orElseThrow(() -> new IllegalStateException("CRL issuer credential is missing"));
                if (!credential.credentialId().equals(generation.credentialId())
                        || !BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
                    throw new IllegalStateException("CRL issuer credential is not authoritative X.509 content");
                }
                CrlScopeOwner owner = new CrlScopeOwner(certificateScope(certificateHolder(credential)),
                        generation.authorityId());
                BigInteger number = crlScopeReservations.reserve(owner);
                requireStoreUsable();
                return number;
            } catch (MetadataStoreException failure) {
                throw translateSigningMetadataFailure(failure);
            } catch (IOException failure) {
                throw signingDurabilityFailure(failure);
            } catch (IllegalStateException failure) {
                if (failure.getCause() instanceof IOException ioFailure) {
                    throw signingDurabilityFailure(ioFailure);
                }
                throw failure;
            }
        }
    }

    @Override
    public List<IssuerGeneration> listIssuerGenerations(PkiId authorityId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(authorityId, "authorityId");
            long[] counts = ISSUER_GENERATION_READ_COUNTS.get();
            if (counts != null) { counts[1]++; }
            try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
                return AuthorityMetadataStore.generations(snapshot, authorityId).stream()
                        .map(this::validateIssuerGeneration)
                        .sorted(Comparator.comparing(value -> value.issuerId().value())).toList();
            } catch (IOException failure) { throw new IllegalStateException("Issuer metadata list failed", failure); }
        }
    }

    // Test-only, calling-thread counters; setup/startup reads are excluded by
    // installing immediately before the measured ingress and clearing afterward.
    /* default */ static void startIssuerGenerationReadCounting() {
        ISSUER_GENERATION_READ_COUNTS.set(new long[2]);
    }

    /* default */ static long[] issuerGenerationReadCounts() {
        return Objects.requireNonNull(ISSUER_GENERATION_READ_COUNTS.get(), "read counting is not installed").clone();
    }

    /* default */ static void stopIssuerGenerationReadCounting() { ISSUER_GENERATION_READ_COUNTS.remove(); }

    @Override
    public void putIssuerChainPath(IssuerChainPath path) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(path, "path");
            validateIssuerChainPath(path);
            try { authorityMetadata().create(AuthorityMetadataCodec.pathKey(path.pathId()), FsCodec.encode(FsCodec.ISSUER_CHAIN_PATH, path)); }
            catch (IOException failure) { throw signingDurabilityFailure(failure); }
        }
    }

    @Override
    public Optional<IssuerChainPath> getIssuerChainPath(PkiId pathId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(pathId, "pathId");
            try {
                Optional<IssuerChainPath> value = authorityMetadata().find(AuthorityMetadataCodec.pathKey(pathId), AuthorityMetadataCodec::path);
                if (value.isPresent() && !value.orElseThrow().pathId().equals(pathId)) { throw new IOException("Issuer path identity differs"); }
                return value.map(this::validateIssuerChainPath);
            } catch (IOException failure) { throw new IllegalStateException("Issuer path metadata read failed", failure); }
        }
    }

    @Override
    public List<IssuerChainPath> listIssuerChainPaths(PkiId issuerId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(issuerId, "issuerId");
            try {
                return authorityMetadata().list(AuthorityMetadataCodec.ISSUER_PATH, AuthorityMetadataCodec::path).stream()
                        .map(this::validateIssuerChainPath).filter(value -> issuerId.equals(value.issuerId()))
                        .sorted(Comparator.comparing(value -> value.pathId().value())).toList();
            } catch (IOException failure) { throw new IllegalStateException("Issuer path metadata list failed", failure); }
        }
    }

    private AuthorityMetadataStore authorityMetadata() { return new AuthorityMetadataStore(metadataStore, this::requireKnownOutcome); }

    @Override
    public void putCredential(final Credential credential) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(credential, "credential");
            putCredentialReserved(credential, null);
        }
    }

    @Override
    public void putCredentialFromSigning(Credential credential, PkiId operationId, String commandCommitment) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(credential, "credential");
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(commandCommitment, "commandCommitment");
            DomainContinuationStore.Record domain = getDomainContinuation(operationId)
                    .orElseThrow(() -> new IllegalStateException("Credential signing continuation is missing"));
            SignWorkflowStore.Workflow workflow = getSignWorkflow(operationId)
                    .orElseThrow(() -> new IllegalStateException("Credential signing operation is missing"));
            if (domain.state() != DomainContinuationStore.State.PUBLISHING
                    || !domain.commandCommitment().equals(commandCommitment)
                    || domain.kind() == DomainContinuationStore.Kind.STATUS
                    || domain.kind() == DomainContinuationStore.Kind.KEY_PROOF
                    || workflow.state() != SignWorkflowStore.State.SUCCEEDED
                    || !BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
                throw new IllegalStateException("Credential signing publication authority differs");
            }
            try {
                X509Certificate certificate = certificateHolder(credential);
                DurableContentReference tbs = domain.signingContent().orElseThrow();
                if (tbs.length() <= 0 || tbs.length() > 1_048_576) {
                    throw new IllegalStateException("Credential signing content exceeds its bound");
                }
                byte[] input;
                try (RepeatableContent content = stagedContent.openContent(tbs); InputStream stream = content.openStream()) {
                    input = stream.readNBytes(Math.toIntExact(tbs.length()));
                    if (input.length != tbs.length() || stream.read() != -1) {
                        throw new IllegalStateException("Credential signing content length differs");
                    }
                }
                EncodedObject signature = workflow.result().orElseThrow();
                if (signature.encoding() != Encoding.BINARY || !MessageDigest.isEqual(certificate.getEncoded(),
                        Pkix.assembleCertificateOrCrl(input, signature.bytes(), false))) {
                    throw new IllegalStateException("Credential differs from the authoritative signing result");
                }
                requirePublicationIssuer(credential, domain);
            } catch (IOException | java.security.cert.CertificateEncodingException failure) {
                throw new IllegalStateException("Credential signing result validation failed", failure);
            }
            putCredentialReserved(credential, new ScopeSerialReservation.SigningOwner(operationId,
                    commandCommitment.substring("domain:v1:".length())));
        }
    }

    private void putCredentialReserved(Credential credential, ScopeSerialReservation.IssuanceOwner signingOwner) {
        Optional<BigInteger> serial = Optional.empty();
        if (BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
            reserveCredentialScope(credential, signingOwner);
            if (CREDENTIAL_RESERVATION_FAULT.get() == CredentialReservationFault.BEFORE_CREDENTIAL) {
                throw new IllegalStateException("Injected interruption after credential serial reservation");
            }
            serial = x509Serial(credential);
        }
        putCredentialMetadata(credential, BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId()));
        if (CREDENTIAL_RESERVATION_FAULT.get() == CredentialReservationFault.BEFORE_SERIAL_INDEX) {
            throw new IllegalStateException("Injected interruption after confirmed credential publication");
        }
        serial.ifPresent(value -> ensureSerialIndex(credential.issuerRef().issuerId(), value,
                credential.credentialId()));
        recordIssuanceEvidence(credential);
    }

    private void putCredentialMetadata(Credential credential, boolean exactReplay) {
        CredentialStateLockEntry lock = acquireCredentialStateLock(credential.credentialId());
        if (credentialSearch != null) credentialSearch.lockPublication();
        boolean publicationAttempted = false;
        try (FilesystemStagedContentStore.TransactionalReservation reservation = stagedContent.reserveTransactionalPublication(credential.content())) {
            boolean commitAttempted = false;
            try {
                requireStoreUsable();
                CredentialMetadataAuthority authority = new CredentialMetadataAuthority(metadataStore, stagedContent);
                try (MetadataSnapshot snapshot = metadataStore.snapshot(); MetadataTransaction transaction = metadataStore.beginTransaction()) {
                    Optional<Credential> existing = authority.find(snapshot, credential.credentialId());
                    if (existing.isPresent()) {
                        if (!exactReplay) { throw new IllegalStateException("Credential is write-once; already exists"); }
                        requireExactCredentialReplay(existing.orElseThrow(), credential);
                        return;
                    }
                    authority.stageCreate(snapshot, transaction, credential);
                    commitAttempted = true;
                    publicationAttempted = true;
                    MetadataCommitResult result = transaction.commit();
                    commitAttempted = result.outcome() == MetadataCommitResult.Outcome.UNKNOWN;
                    if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN) { reservation.preserveUntilRecovery(); }
                    requireKnownOutcome(result);
                    if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                        throw new IllegalStateException("Credential metadata transaction was not committed");
                    }
                    if (credentialSearch != null) credentialSearch.published(credential);
                    publicationAttempted = false;
                }
            } catch (IOException failure) {
                boolean uncertainStorage = failure instanceof MetadataStoreException metadataFailure
                        && metadataFailure.category() == MetadataCommitResult.FailureCategory.STORAGE_FAILURE;
                if (!commitAttempted && !uncertainStorage) {
                    throw new IllegalStateException("Credential metadata validation failed", failure);
                }
                reservation.preserveUntilRecovery();
                throw signingDurabilityFailure(failure);
            }
        } catch (IOException failure) {
            if (publicationAttempted && credentialSearch != null) credentialSearch.fence();
            throw new IllegalStateException("Credential content reservation failed", failure);
        } catch (RuntimeException failure) {
            if (publicationAttempted && credentialSearch != null) credentialSearch.fence();
            throw failure;
        } finally {
            if (credentialSearch != null) credentialSearch.unlockPublication();
            releaseCredentialStateLock(credential.credentialId(), lock);
        }
    }

    private void reserveCredentialScope(Credential credential, ScopeSerialReservation.IssuanceOwner signingOwner) {
        ScopeSerialReservation reservation = credentialReservation(credential, signingOwner);
        try {
            CrlScopeOwner owner = new CrlScopeOwner(reservation.scope(), credential.issuerRef().caId());
            if (signingOwner instanceof ScopeSerialReservation.SigningOwner) {
                crlScopeReservations.verify(owner, reservation);
            } else {
                crlScopeReservations.claim(owner, reservation);
            }
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
    }

    private void requireCrlReservationOutcome(MetadataCommitResult result) {
        if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED
                && CREDENTIAL_RESERVATION_FAULT.get() == CredentialReservationFault.COMMIT_AS_UNKNOWN) {
            requireKnownOutcome(new MetadataCommitResult(result.transactionId(), MetadataCommitResult.Outcome.UNKNOWN,
                    OptionalLong.empty(), Optional.empty()));
            return;
        }
        requireKnownOutcome(result);
    }

    /* default */ enum CredentialReservationFault {
        BEFORE_CREDENTIAL, COMMIT_AS_UNKNOWN, BEFORE_SERIAL_INDEX,
        SERIAL_INDEX_READ_IO, SERIAL_INDEX_WRITE_IO, ISSUANCE_EVIDENCE_IO
    }

    /* default */ static void installCredentialReservationFault(CredentialReservationFault point) {
        CREDENTIAL_RESERVATION_FAULT.set(Objects.requireNonNull(point, "point"));
    }

    /* default */ static void clearCredentialReservationFault() { CREDENTIAL_RESERVATION_FAULT.remove(); }

    private ScopeSerialReservation credentialReservation(Credential credential,
            ScopeSerialReservation.IssuanceOwner signingOwner) {
        return credentialReservation(credential, signingOwner, null);
    }

    // A supplied snapshot is borrowed and is the sole metadata authority. Null
    // preserves the ordinary write path's existing full dependency validation.
    private ScopeSerialReservation credentialReservation(Credential credential,
            ScopeSerialReservation.IssuanceOwner signingOwner, MetadataSnapshot snapshot) {
        try {
            X509Certificate certificate = certificateHolder(credential);
            if (credential.content().encoding() != Encoding.DER
                    || !certificate.getSerialNumber().toString().equals(credential.serialOrUniqueId())) {
                throw new IllegalStateException("X.509 credential serial or encoding differs from its content");
            }
            PkiId authority = credential.issuerRef().caId();
            Optional<IssuerGeneration> generation = snapshot == null ? getIssuerGeneration(credential.issuerRef().issuerId())
                    : AuthorityMetadataStore.find(snapshot, AuthorityMetadataCodec.generationKey(credential.issuerRef().issuerId()), AuthorityMetadataCodec::generation);
            X509Certificate issuer;
            PkiId rootIssuerId = IssuerGeneration.idFor(authority, credential.credentialId());
            IssuerChainPath rootPath = IssuerChainPath.create(authority, rootIssuerId, List.of(credential.credentialId()));
            boolean selfReference = credential.issuerRef().issuerId().equals(rootIssuerId)
                    && credential.issuerRef().chainPathId().equals(rootPath.pathId());
            if (selfReference && credential.profileBinding() instanceof CaProfileBinding
                    && certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
                // Root replay may observe the committed generation before its
                // path is published. Its exact self-reference is authoritative.
                issuer = certificate;
            } else if (generation.isPresent()) {
                issuer = reservationIssuer(credential, generation.orElseThrow(), authority, snapshot);
            } else {
                throw new IllegalStateException("X.509 credential issuer cannot be resolved");
            }
            if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                    || !signatureValid(certificate, issuer.getPublicKey())) {
                throw new IllegalStateException("X.509 credential issuer signature differs");
            }
            zeroecho.pki.impl.core.CrlScope scope = certificateScope(issuer);
            ScopeSerialReservation.IssuanceOwner owner = signingOwner != null ? signingOwner
                    : new ScopeSerialReservation.ImportedCertificateOwner(HexFormat.of().formatHex(
                            sha256Digest(certificate.getEncoded())));
            return new ScopeSerialReservation(scope, certificate.getSerialNumber(), owner);
        } catch (java.security.cert.CertificateEncodingException failure) {
            throw new IllegalStateException("X.509 credential encoding is invalid", failure);
        } catch (IOException failure) {
            throw new IllegalStateException("X.509 credential content is invalid", failure);
        }
    }

    /* default */ Optional<SnapshotCredentialAuthority> credentialSnapshotAuthority(Credential credential) throws IOException {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) { return credentialSnapshotAuthority(snapshot, credential); }
    }

    /* default */ Optional<SnapshotCredentialAuthority> credentialSnapshotAuthority(MetadataSnapshot snapshot, Credential credential) throws IOException {
        if (!BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) { return Optional.empty(); }
        requireExactCredentialReplay(new CredentialMetadataAuthority(metadataStore, stagedContent).find(snapshot, credential.credentialId())
                .orElseThrow(() -> new SnapshotCredentialAuthorityException()), credential);
        ScopeSerialReservation expected = credentialReservation(credential, null, snapshot);
        CrlScopeOwner owner = crlScopeReservations.findOwner(snapshot, expected.scope())
                .orElseThrow(() -> new SnapshotCredentialAuthorityException());
        if (!owner.authorityId().equals(credential.issuerRef().caId())) {
            throw new SnapshotCredentialAuthorityException();
        }
        ScopeSerialReservation retained = crlScopeReservations.findReservation(snapshot, expected.scope(), expected.serial())
                .orElseThrow(() -> new SnapshotCredentialAuthorityException());
        if (retained.issuanceOwner() instanceof ScopeSerialReservation.ImportedCertificateOwner
                && !retained.equals(expected)) {
            throw new SnapshotCredentialAuthorityException();
        }
        String commitment = ((ScopeSerialReservation.ImportedCertificateOwner) expected.issuanceOwner()).certificateCommitment();
        return Optional.of(new SnapshotCredentialAuthority(owner, retained, commitment));
    }

    // Called only by the snapshot transfer after its exact source credential and
    // permanent reservation have been validated. Target content is reminted, but
    // issuance ownership is read from the copied authoritative metadata revision.
    /* default */ void putSnapshotCredential(Credential credential, Optional<SnapshotCredentialAuthority> sourceAuthority)
            throws IOException {
        requireStoreUsable();
        if (!BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
            if (sourceAuthority.isPresent()) { throw new SnapshotCredentialAuthorityException(); }
            putCredential(credential);
            return;
        }
        SnapshotCredentialAuthority frozen = sourceAuthority
                .orElseThrow(() -> new SnapshotCredentialAuthorityException());
        ScopeSerialReservation derived = credentialReservation(credential, null);
        String commitment = ((ScopeSerialReservation.ImportedCertificateOwner) derived.issuanceOwner()).certificateCommitment();
        if (!commitment.equals(frozen.certificateCommitment())
                || !derived.scope().equals(frozen.reservation().scope())
                || !derived.serial().equals(frozen.reservation().serial())
                || !frozen.scopeOwner().authorityId().equals(credential.issuerRef().caId())
                || !crlScopeReservations.findOwner(derived.scope()).filter(frozen.scopeOwner()::equals).isPresent()
                || !crlScopeReservations.findReservation(derived.scope(), derived.serial())
                        .filter(frozen.reservation()::equals).isPresent()) {
            throw new SnapshotCredentialAuthorityException();
        }
        putCredentialReserved(credential, frozen.reservation().issuanceOwner());
    }

    /* default */ record SnapshotCredentialAuthority(CrlScopeOwner scopeOwner,
            ScopeSerialReservation reservation, String certificateCommitment) {
        SnapshotCredentialAuthority {
            Objects.requireNonNull(scopeOwner, "scopeOwner");
            Objects.requireNonNull(reservation, "reservation");
            CrlScopeMetadataCodec.requireHash(certificateCommitment);
            if (!scopeOwner.scope().equals(reservation.scope())) {
                throw new IllegalArgumentException("Snapshot credential authorities differ");
            }
        }
    }

    /* default */ static final class SnapshotCredentialAuthorityException extends IOException {
        private static final long serialVersionUID = 1L;

        /* default */ SnapshotCredentialAuthorityException() {
            super("Snapshot credential differs from its permanent scope or serial authority");
        }
    }

    private static zeroecho.pki.impl.core.CrlScope certificateScope(X509Certificate certificate) {
        return zeroecho.pki.impl.core.CrlScope.of(certificate.getSubjectX500Principal().getEncoded(),
                Pkix.subjectPublicKeyInfo(certificate));
    }

    private static byte[] sha256Digest(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (java.security.NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 unavailable", unavailable);
        }
    }

    private static void requireExactCredentialReplay(Credential actual, Credential expected) {
        CredentialContentTransaction.requireExactReplay(actual, expected);
    }

    private static void requirePublicationIssuer(Credential credential, DomainContinuationStore.Record domain) {
        zeroecho.pki.impl.core.continuation.DomainCommandEncoding.Decoded command =
                zeroecho.pki.impl.core.continuation.DomainCommandEncoding.decode(domain.command());
        PkiId authority;
        if (domain.kind() == DomainContinuationStore.Kind.ISSUANCE) {
            authority = new PkiId(command.field(0));
            if (!credential.issuerRef().issuerId().value().equals(command.field(1))
                    || !credential.issuerRef().chainPathId().value().equals(command.field(2))) {
                throw new IllegalStateException("Credential publication issuer selection differs");
            }
        } else if ("CREATE_ROOT".equals(command.operation())) {
            authority = new PkiId(command.field(13));
        } else if ("ROLLOVER_ROOT".equals(command.operation())) {
            authority = new PkiId(command.field(13));
        } else {
            authority = new PkiId(command.field(1));
            if (!credential.issuerRef().issuerId().value().equals(command.field(3))
                    || !credential.issuerRef().chainPathId().value().equals(command.field(4))) {
                throw new IllegalStateException("Intermediate publication issuer selection differs");
            }
        }
        if (!authority.equals(credential.issuerRef().caId())) {
            throw new IllegalStateException("Credential publication authority differs");
        }
    }

    // Appends one append-ordered issuance-evidence index entry for a committed end-entity credential, so the
    // audit projector can advance a durable cursor. Idempotent per credential (safe under crash-window retry
    // and startup reconciliation). The credential's co-committed attributes remain the evidence authority.
    // Publication has already committed: an append I/O failure fences further use until startup
    // reconciliation re-appends the missing entry from the retained authoritative credential.
    private void recordIssuanceEvidence(Credential credential) {
        if (!(credential.profileBinding() instanceof EndEntityProfileBinding)) {
            return;
        }
        byte[] payload = DomainAttributeEncoding.encode(credential.attributes())
                .getBytes(StandardCharsets.UTF_8);
        try {
            if (CREDENTIAL_RESERVATION_FAULT.get() == CredentialReservationFault.ISSUANCE_EVIDENCE_IO) {
                throw new IOException("Injected issuance-evidence I/O failure");
            }
            issuanceEvidenceLog.append(credential.credentialId(), credential.validity().notBefore(), payload);
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
        appendCtJournalEntry(credential);
    }

    // Appends a CT journal entry for the committed credential. Best-effort: a
    // CtJournalException does not fail issuance (cert is already durable), but
    // the warning is logged so operators can reconcile. The CT store is null when
    // CT Mode A is not configured.

    private void appendCtJournalEntry(Credential credential) {
        zeroecho.pki.spi.ct.CtJournalStore journal = ctJournalStore;
        if (journal == null) {
            return;
        }
        try {
            byte[] fingerprint = fingerprintFromCredentialId(credential.credentialId().value());
            BigInteger serial = parseSerial(credential.serialOrUniqueId());
            String authorityId = credential.issuerRef().issuerId().value();
            long nextSeq = journal.latestSequenceNumber() + 1L;
            byte[] previousHash = headEntryHash(journal);
            zeroecho.pki.spi.ct.CtJournalEntry entry = zeroecho.pki.spi.ct.CtJournalEntry.create(
                    nextSeq, clock.instant(), fingerprint, serial, authorityId, previousHash);
            journal.append(entry);
        } catch (zeroecho.pki.spi.ct.CtJournalException failure) {
            LOG.warning(() -> "CT journal append deferred; credential already durable: " + failure.getMessage());
        } catch (Exception failure) {
            LOG.log(Level.WARNING, "CT journal append failed unexpectedly", failure);
        }
    }

    // Returns the entryHash of the current head entry, or all-zeros for an empty journal.
    // FsCtJournalStore exposes headEntryHash() directly; other implementations return zeros
    // (append() will validate and reject a bad chain before persisting).
    private static byte[] headEntryHash(zeroecho.pki.spi.ct.CtJournalStore journal)
            throws zeroecho.pki.spi.ct.CtJournalException {
        if (journal.latestSequenceNumber() == 0L) {
            return new byte[zeroecho.pki.spi.ct.CtJournalEntry.HASH_BYTES];
        }
        if (journal instanceof zeroecho.pki.impl.fs.ct.FsCtJournalStore fsJournal) {
            return fsJournal.headEntryHash();
        }
        return new byte[zeroecho.pki.spi.ct.CtJournalEntry.HASH_BYTES];
    }

    // Decodes a credential ID to a 32-byte fingerprint. If the value is 64 hex
    // chars, decode directly. Otherwise compute SHA-256 of the UTF-8 bytes.
    private static byte[] fingerprintFromCredentialId(String credentialId) {
        if (credentialId != null && credentialId.length() == 64) {
            try {
                return HexFormat.of().parseHex(credentialId);
            } catch (IllegalArgumentException ignored) {
                // fall through to hash
            }
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(credentialId == null ? new byte[0]
                    : credentialId.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 unavailable", unavailable);
        }
    }

    // Parses the serial number string to BigInteger. Tries decimal first, then hex.
    private static BigInteger parseSerial(String serialOrUniqueId) {
        if (serialOrUniqueId == null || serialOrUniqueId.isBlank()) {
            return BigInteger.ZERO;
        }
        try {
            return new BigInteger(serialOrUniqueId);
        } catch (NumberFormatException ignored) {
            // fall through
        }
        try {
            return new BigInteger(serialOrUniqueId, 16);
        } catch (NumberFormatException ignored) {
            return BigInteger.ZERO;
        }
    }

    /**
     * Attaches a CT journal store for Mode A (internal Merkle journal).
     *
     * <p>Once set, every issued end-entity credential is appended to the journal
     * after its primary evidence record is committed. The store is not closed when
     * this PKI store is closed — the caller retains lifecycle ownership.</p>
     *
     * @param store the CT journal store to attach; {@code null} detaches any existing store
     */
    /* package */ void setCtJournalStore(final zeroecho.pki.spi.ct.CtJournalStore store) {
        this.ctJournalStore = store;
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
        byte[] payload = DomainAttributeEncoding.encode(evidence.attributes())
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(credentialId, "credentialId");
            try {
                return new CredentialMetadataAuthority(metadataStore, stagedContent).find(credentialId);
            } catch (IOException failure) {
                throw new IllegalStateException("Credential read failed", failure);
            }
        }
    }

    @Override
    public Optional<Credential> getCredentialByIssuerAndSerial(PkiId issuerId, BigInteger serial) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    private void rebuildCredentialSerialIndex() throws IOException {
        new CredentialMetadataAuthority(metadataStore, stagedContent).validateAll(credential -> {
                Optional<BigInteger> serial = indexableSerial(credential);
                if (serial.isPresent()) {
                    requireSerialAvailable(credential.issuerRef().issuerId(), serial.orElseThrow(), credential);
                    ensureSerialIndex(credential.issuerRef().issuerId(), serial.orElseThrow(),
                            credential.credentialId());
                }
                recordIssuanceEvidence(credential);
        });
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
        try {
            if (verifySerialIndex(key, issuerId, serial, credentialId)) { return; }
            try (MetadataTransaction transaction = metadataStore.beginTransaction()) {
                if (CREDENTIAL_RESERVATION_FAULT.get() == CredentialReservationFault.SERIAL_INDEX_WRITE_IO) {
                    throw new IOException("Injected serial-index write I/O failure");
                }
                transaction.create(key, byteContent(encodeSerialIndex(issuerId, serial, credentialId)),
                        CancellationSignal.NONE);
                MetadataCommitResult result = requireKnownOutcome(transaction.commit());
                if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) { return; }
                if (result.failureCategory().orElse(null) == MetadataCommitResult.FailureCategory.STORAGE_FAILURE) {
                    throw new IOException("Credential serial index persistence failed");
                }
            }
            // A concurrent create is successful only when the resulting exact
            // index is present. Its verification uses the same I/O failure path.
            if (!verifySerialIndex(key, issuerId, serial, credentialId)) {
                throw new IOException("Credential serial index persistence was not completed");
            }
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        } catch (IllegalStateException failure) {
            // Credential reads used to validate an existing index preserve the
            // underlying I/O cause; they must fence this post-publication path too.
            if (failure.getCause() instanceof IOException ioFailure) {
                throw signingDurabilityFailure(ioFailure);
            }
            throw failure;
        }
    }

    private boolean verifySerialIndex(MetadataKey key, PkiId issuerId, BigInteger serial, PkiId credentialId)
            throws IOException {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            if (CREDENTIAL_RESERVATION_FAULT.get() == CredentialReservationFault.SERIAL_INDEX_READ_IO) {
                throw new IOException("Injected serial-index read I/O failure");
            }
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
                return true;
            }
            return false;
        }
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(intent, "intent");
            Credential[] match = {null};
            try {
                new CredentialMetadataAuthority(metadataStore, stagedContent).validateAll(credential -> {
                    Optional<AttributeValue> issuance = credential.attributes().get(IssuanceIntent.ID_ATTRIBUTE);
                    if (issuance.orElse(null) instanceof AttributeValue.StringValue value
                            && intent.issuanceId().equals(value.value())) {
                        Optional<AttributeValue> commitment = credential.attributes()
                                .get(IssuanceIntent.COMMITMENT_ATTRIBUTE);
                        if (!(commitment.orElse(null) instanceof AttributeValue.StringValue command)
                                || !intent.commandCommitment().equals(command.value())) {
                            throw new IllegalStateException("Issuance identity was reused with different input");
                        }
                        if (match[0] != null) {
                            throw new IllegalStateException("Duplicate issuance identity");
                        }
                        match[0] = credential;
                    }
                });
                return Optional.ofNullable(match[0]);
            } catch (IOException failure) {
                throw new IllegalStateException("Issuance correlation read failed", failure);
            }
        }
    }

    @Override
    public CredentialConfirmationLifecycle initializeCredentialConfirmation(
            final CredentialConfirmationInitialization initialization) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public Optional<CredentialConfirmationLifecycle> getCredentialConfirmation(final PkiId credentialId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            PkiId exact = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
            return readStoredConfirmation(exact).map(StoredConfirmation::lifecycle);
        }
    }

    @Override
    public Optional<CredentialConfirmationChallenge> getCredentialConfirmationChallenge(
            final PkiId credentialId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public CredentialConfirmationChallenge issueCredentialConfirmationChallenge(
            final CredentialConfirmationChallengeIssuance issuance) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public CredentialConfirmationLifecycle completeCredentialConfirmation(
            final CredentialConfirmationProofCas proofCas) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    @SuppressWarnings("PMD.NPathComplexity")
    public CredentialConfirmationReviewPage pagePendingCredentialConfirmationReviews(
            final PkiId authorityId,
            final Optional<String> profileId,
            final Instant cutoffInclusive,
            final Optional<CredentialConfirmationReviewCursor> afterExclusive,
            final int limit) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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

    private CaRecord validateCaCredentialReferences(CaRecord record) {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) { return validateCaCredentialReferences(snapshot, record); }
        catch (IOException failure) { throw new IllegalStateException("CA credential authority is invalid", failure); }
    }

    private CaRecord validateCaCredentialReferences(MetadataSnapshot snapshot, CaRecord record) throws IOException {
        for (PkiId issuerId : record.issuerIds()) {
            IssuerGeneration generation = requireGeneration(snapshot, issuerId);
            if (!record.caId().equals(generation.authorityId())) {
                throw new IllegalStateException("CA issuer-generation authority mismatch");
            }
        }
        IssuerChainPath issuancePath = AuthorityMetadataStore.find(snapshot, AuthorityMetadataCodec.pathKey(record.issuanceChainPathId()), AuthorityMetadataCodec::path)
                .orElseThrow(() -> new IllegalStateException("CA issuance chain path is missing"));
        validateIssuerChainPath(snapshot, issuancePath);
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

    private Credential requireCredential(MetadataSnapshot snapshot, PkiId id) throws IOException {
        return new CredentialMetadataAuthority(metadataStore, stagedContent).find(snapshot, id)
                .orElseThrow(() -> new IllegalStateException("Issuer credential reference is missing"));
    }

    private IssuerGeneration requireGeneration(MetadataSnapshot snapshot, PkiId id) throws IOException {
        IssuerGeneration generation = AuthorityMetadataStore.find(snapshot, AuthorityMetadataCodec.generationKey(id), AuthorityMetadataCodec::generation)
                .orElseThrow(() -> new IllegalStateException("Issuer generation is missing"));
        if (!generation.issuerId().equals(id)) { throw new IllegalStateException("Issuer generation identity differs"); }
        requireCredential(snapshot, generation.credentialId());
        return generation;
    }

    private IssuerChainPath validateIssuerChainPath(IssuerChainPath path) {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) { return validateIssuerChainPath(snapshot, path); }
        catch (IOException failure) { throw new IllegalStateException("Issuer chain validation failed", failure); }
    }

    private IssuerChainPath validateIssuerChainPath(MetadataSnapshot snapshot, IssuerChainPath path) throws IOException {
        IssuerGeneration generation = requireGeneration(snapshot, path.issuerId());
        if (!path.authorityId().equals(generation.authorityId())
                || !path.orderedCredentialIds().get(0).equals(generation.credentialId())) {
            throw new IllegalStateException("Issuer chain path generation mismatch");
        }
        List<Credential> credentials = new ArrayList<>(path.orderedCredentialIds().size());
        for (PkiId id : path.orderedCredentialIds()) { credentials.add(requireCredential(snapshot, id)); }
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
                IssuerGeneration signingGeneration = requireGeneration(snapshot, credential.issuerRef().issuerId());
                IssuerGeneration parentGeneration = requireGeneration(snapshot, IssuerGeneration.idFor(
                        credential.issuerRef().caId(), parent.credentialId()));
                if (!credential.issuerRef().caId().equals(signingGeneration.authorityId())
                        || !credential.issuerRef().caId().equals(parentGeneration.authorityId())
                        || !parent.credentialId().equals(parentGeneration.credentialId())
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

    /* default */ X509Certificate certificateHolder(Credential credential) throws IOException {
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(request, "request");
            PkiId id = request.requestId();
            writeOnce(this.paths.requestPath(id), FsCodec.encode(FsCodec.PARSED_REQUEST, request), "REQUEST",
                    FsUtil.safeId(id));
        }
    }

    @Override
    public RevocationRecord revokeOverduePendingCredentialConfirmation(
            final RevocationCommand.RevokePermanently command) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(requestId, "requestId");
            return readOptional(this.paths.requestPath(requestId), FsCodec.PARSED_REQUEST);
        }
    }

    @Override
    // Filesystem failures are normalized to the stable store failure code.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public List<ParsedCertificationRequest> searchRequests(
            final zeroecho.pki.api.request.RequestQuery query, final int maxResults) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public Optional<RevocationRecord> getRevocation(final PkiId credentialId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(credentialId, "credentialId");
            try {
                return revocations.current(credentialId);
            } catch (IOException failure) {
                throw corruptRevocationState();
            }
        }
    }

    @Override
    public RevocationHistory openRevocationHistory(final PkiId credentialId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(credentialId, "credentialId");
            try {
                return revocations.history(credentialId);
            } catch (IOException failure) {
                throw corruptRevocationState();
            }
        }
    }

    @Override
    public RevocationTransitionFeed openRevocationTransitionFeed(
            final Optional<RevocationTransitionFeed.Position> afterExclusive) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(afterExclusive, "afterExclusive");
            try {
                return revocations.feed(afterExclusive);
            } catch (IOException failure) {
                throw corruptRevocationState();
            }
        }
    }

    @Override
    public void requireRevocationPrefix(RevocationTransitionFeed.HighWatermark prefix, long boundary,
            CancellationSignal cancellation) throws IOException {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            revocations.requirePrefix(prefix, boundary, cancellation);
        }
    }

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public AuditEvidenceFeed openIssuanceEvidenceFeed(final long afterSequenceExclusive) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try {
                return new EvidenceFeedAdapter(issuanceEvidenceLog.openReader(afterSequenceExclusive));
            } catch (IOException failure) {
                throw new IllegalStateException("Issuance evidence feed cannot be opened");
            }
        }
    }

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public AuditEvidenceFeed openStatusEvidenceFeed(final long afterSequenceExclusive) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try {
                return new EvidenceFeedAdapter(statusEvidenceLog.openReader(afterSequenceExclusive));
            } catch (IOException failure) {
                throw new IllegalStateException("Status evidence feed cannot be opened");
            }
        }
    }

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public AuditEvidenceFeed openPublicationEvidenceFeed(final long afterSequenceExclusive) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try {
                return new EvidenceFeedAdapter(publicationEvidenceLog.openReader(afterSequenceExclusive));
            } catch (IOException failure) {
                throw new IllegalStateException("Publication evidence feed cannot be opened");
            }
        }
    }


    @Override
    public boolean supportsSigningEvidenceFeed() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return signingEvidenceLog != null;
        }
    }

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace") // Feed failures expose only a fixed safe diagnostic.
    public AuditEvidenceFeed openSigningEvidenceFeed(long afterSequenceExclusive) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            if (signingEvidenceLog == null) {
                throw new UnsupportedOperationException("Signing evidence feed is not enabled");
            }
            try {
                return new EvidenceFeedAdapter(signingEvidenceLog.openReader(afterSequenceExclusive));
            } catch (IOException failure) {
                throw new IllegalStateException("Signing evidence feed cannot be opened");
            }
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try {
                return revocations.snapshot();
            } catch (IOException failure) {
                throw corruptRevocationState();
            }
        }
    }

    @Override
    public RevocationView openRevocationView() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try {
                return revocations.view();
            } catch (IOException failure) {
                throw corruptRevocationState();
            }
        }
    }

    @Override
    public void putStatusObject(final StatusObject object) {
        putStatusObject(object, Optional.empty());
    }

    @Override
    public void putStatusObjectFromSigning(StatusObject object, PkiId operationId, String commandCommitment) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            SignLockEntry lock = acquireSignLock(operationId);
            try {
                SignWorkflowStore.Workflow workflow = readSignWorkflow(operationId).orElseThrow();
                DomainContinuationStore.Record domain = getDomainContinuation(operationId).orElseThrow();
                requireMatchingOuter(workflow, domain);
                if (domain.kind() != DomainContinuationStore.Kind.STATUS || domain.state() != DomainContinuationStore.State.PUBLISHING
                        || workflow.state() != SignWorkflowStore.State.SUCCEEDED || !domain.commandCommitment().equals(commandCommitment)) {
                    throw new IllegalStateException("Status signing publication authority differs");
                }
                zeroecho.pki.impl.core.continuation.FullCrlSigningCommand.requireSigningEffect(this, object, domain, workflow.result().orElseThrow());
                Optional<StatusObject> existing = getStatusObject(object.statusObjectId());
                if (existing.isPresent()) {
                    if (!Arrays.equals(validateStatusObject(existing.orElseThrow()), validateStatusObject(object))) throw new IllegalStateException("Status replay differs");
                    try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
                        Optional<StatusScheduleState.Execution> receipt = schedules().receipt(snapshot, operationId);
                        if (receipt.isEmpty() || receipt.orElseThrow().statusObjectId().equals(Optional.of(object.statusObjectId()))) return;
                    }
                }
                putStatusObject(object, Optional.of(operationId));
            } catch (IOException failure) { throw new IllegalStateException("Status signing result validation failed", failure); }
            finally { releaseSignLock(operationId, lock); }
        }
    }

    private void putStatusObject(StatusObject object, Optional<PkiId> signingOperation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(object, "object");
            byte[] encoded = validateStatusObject(object);
            DurableContentReference reference = object.content();
            try (FilesystemStagedContentStore.TransactionalReservation reservation =
                    stagedContent.reserveTransactionalPublication(reference)) {
                validateStatusContent(reference);
                MetadataCommitResult result = createStatusMetadata(object, encoded, signingOperation);
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
    }

    @Override
    public Optional<StatusObject> getStatusObject(final PkiId statusObjectId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public List<StatusObject> listStatusObjects(final PkiId issuerCaId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public PublicationRecord createPublicationRecord(final PublicationRecord record) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public Optional<PublicationRecord> getPublicationRecord(final PkiId publicationId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public boolean replacePublicationRecord(final PublicationRecord expected,
            final PublicationRecord replacement) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
        byte[] payload = DomainAttributeEncoding.encode(evidence.attributes())
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    /* default */ PublicationCursor openPublicationRecords(MetadataSnapshot snapshot) throws IOException {
        requireStoreUsable();
        return new PublicationMetadataCursor(snapshot, snapshot.scan(MetadataSnapshot.KeyRange.all(PUBLICATION_RECORD_NAMESPACE),
                CancellationSignal.NONE), false);
    }

    @Override
    // Persistence causes may contain filesystem data and are intentionally
    // redacted.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public ImportedCertificateProfileVersion importProfileVersion(final ImportedCertificateProfileVersion version) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            requireProfileIdentity(profileId, profileVersion);
            Path path = paths.profileVersion(profileId, profileVersion);
            return Files.exists(path) ? Optional.of(decodeProfileVersion(path, profileId, profileVersion))
                    : Optional.empty();
        }
    }

    @Override
    // Filesystem failures are normalized to the stable store failure code.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public List<ImportedCertificateProfileVersion> listProfileVersions(final String profileId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    // Persistence causes may contain filesystem data and are intentionally
    // redacted.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public CertificateProfileRef activateProfile(final String profileId, final long profileVersion) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public Optional<CertificateProfileRef> getActiveProfileRef(final String profileId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            requireProfileIdentity(profileId, 1L);
            return readValidatedActiveProfile(profileId).map(validated -> validated.version().reference());
        }
    }

    @Override
    public ActiveCertificateProfile requireActiveProfile(final String profileId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            requireProfileIdentity(profileId, 1L);
            ValidatedImportedProfile validated = readValidatedActiveProfile(profileId)
                    .orElseThrow(() -> new ProfileLifecycleFailure(Code.PROFILE_NOT_ACTIVE));
            ImportedCertificateProfileVersion version = validated.version();
            return new ActiveCertificateProfile(version.reference(), version.definition());
        }
    }

    @Override
    public void putPolicyTrace(final PolicyTrace trace) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(trace, "trace");
            PkiId id = trace.decisionId();
            writeOnce(this.paths.policyTracePath(id), FsCodec.encode(FsCodec.POLICY_TRACE, trace), "POLICY_TRACE",
                    FsUtil.safeId(id));
        }
    }

    @Override
    public Optional<PolicyTrace> getPolicyTrace(final PkiId decisionId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(decisionId, "decisionId");
            return readOptional(this.paths.policyTracePath(decisionId), FsCodec.POLICY_TRACE);
        }
    }

    // -------------------------------------------------------------------------
    // Workflow continuation state (orchestration)
    // -------------------------------------------------------------------------

    @Override
    public void putWorkflowState(final WorkflowStateRecord record) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(record, "record");

            PkiId opId = record.opId();
            Path current = this.paths.workflowCurrent(opId);

            // Never log payload; writeWithHistory logs only type + safe identifiers.
            writeWithHistory(this.paths.workflowHistoryDir(opId), current, FsCodec.encode(FsCodec.WORKFLOW_STATE, record),
                    this.options.workflowHistoryPolicy(), "WORKFLOW", FsUtil.safeId(opId));
        }
    }

    @Override
    public Optional<WorkflowStateRecord> getWorkflowState(final PkiId opId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(opId, "opId");
            return readOptional(this.paths.workflowCurrent(opId), FsCodec.WORKFLOW_STATE);
        }
    }

    @Override
    public void deleteWorkflowState(final PkiId opId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(opId, "opId");
            Path current = this.paths.workflowCurrent(opId);

            try {
                Files.deleteIfExists(current);
            } catch (IOException e) {
                throw new IllegalStateException("failed to delete workflow state opId=" + FsUtil.safeId(opId), e);
            }
        }
    }

    @Override
    public List<WorkflowStateRecord> listWorkflowStates() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            // List by operation directory (workflows/by-op/<opId>/current.bin)
            return listCurrentRecords(this.paths.workflowRoot(), FsCodec.WORKFLOW_STATE);
        }
    }

    @Override
    public Optional<StatusSchedule> getStatusSchedule(PkiId caId, StatusObjectType statusType) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try { return schedules().get(caId, statusType).map(StatusScheduleState::configuration); }
            catch (IOException failure) { throw new IllegalStateException("Schedule read failed", failure); }
        }
    }

    @Override
    public List<StatusSchedule> listActiveStatusSchedulesPage(Optional<String> after, int limit,
            CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try { return schedules().page(after, limit, false, cancellation).stream()
                    .map(StatusScheduleState::configuration).toList(); }
            catch (IOException failure) { throw new IllegalStateException("Schedule listing failed", failure); }
        }
    }

    @Override
    public StatusSchedule putStatusSchedule(StatusSchedule schedule) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try { return schedules().put(schedule, Optional.empty(), signingNow()); }
            catch (IOException failure) { throw new IllegalStateException("Schedule update failed", failure); }
        }
    }

    @Override
    public boolean replaceStatusSchedule(StatusSchedule expected, StatusSchedule replacement) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            if (!expected.caId().equals(replacement.caId()) || expected.statusType() != replacement.statusType()) {
                throw new IllegalArgumentException("Schedule identity cannot change");
            }
            try { return schedules().put(replacement, Optional.of(expected), signingNow()) != null; }
            catch (IOException failure) { throw new IllegalStateException("Schedule replacement failed", failure); }
        }
    }

    private FsStatusSchedules schedules() { return new FsStatusSchedules(metadataStore, this::requireKnownOutcome, this::requireFailedSchedule); }

    private void validateScheduleReceipt(StatusScheduleState.Execution execution) {
        SignWorkflowStore.Workflow workflow = readSignWorkflow(execution.signingOperationId().orElseThrow()).orElseThrow();
        FsStatusSchedules.validateBinding(execution, workflow.envelope());
        DomainContinuationStore.Record domain = getDomainContinuation(workflow.operationId()).orElseThrow();
        requireMatchingOuter(workflow, domain);
        if (execution.phase() == StatusScheduleState.Phase.FAILED) requireFailedSchedule(execution);
        if (execution.statusObjectId().isPresent()) {
            StatusObject status = getStatusObject(execution.statusObjectId().orElseThrow()).orElseThrow();
            zeroecho.pki.impl.core.continuation.FullCrlSigningCommand.requirePublicationMetadata(status, domain);
            if (domain.state() == DomainContinuationStore.State.COMPLETED) {
                zeroecho.pki.impl.core.continuation.FullCrlSigningCommand.requireCompleted(status, domain);
            } else if (domain.state() == DomainContinuationStore.State.PUBLISHING) {
                try {
                    zeroecho.pki.impl.core.continuation.FullCrlSigningCommand.requireSigningEffect(this, status, domain, workflow.result().orElseThrow());
                } catch (IOException failure) { throw new IllegalStateException("Scheduled effect validation failed", failure); }
            }
            if (domain.state() != DomainContinuationStore.State.PUBLISHING && domain.state() != DomainContinuationStore.State.COMPLETED) {
                throw new IllegalStateException("Scheduled effect lacks publication authority");
            }
        } else if (domain.state() == DomainContinuationStore.State.COMPLETED) {
            throw new IllegalStateException("Scheduled completion lacks effect marker");
        }
    }

    private void requireFailedSchedule(StatusScheduleState.Execution execution) {
        if (execution.statusObjectId().isPresent()) throw new IllegalStateException("Committed schedule cannot be reset");
        PkiId id = execution.signingOperationId().orElseThrow();
        SignWorkflowStore.Workflow workflow = readSignWorkflow(id).orElseThrow();
        DomainContinuationStore.Record domain = getDomainContinuation(id).orElseThrow();
        FsStatusSchedules.validateBinding(execution, workflow.envelope());
        requireMatchingOuter(workflow, domain);
        if (isActiveSignState(workflow.state()) || domain.kind() != DomainContinuationStore.Kind.STATUS
                || domain.state() != DomainContinuationStore.State.FAILED && domain.state() != DomainContinuationStore.State.EXPIRED) {
            throw new IllegalStateException("Scheduled failure is not terminal without an effect");
        }
    }

    @Override public boolean supportsStatusScheduling() { return true; }

    @Override public Optional<StatusScheduleState> getStatusScheduleState(PkiId caId, StatusObjectType type) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try { return schedules().get(caId, type); }
            catch (IOException failure) { throw new IllegalStateException("Schedule read failed", failure); }
        }
    }

    @Override public List<StatusScheduleState> listStatusScheduleWork(Optional<String> after, int limit,
            CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try { return schedules().page(after, limit, true, cancellation); }
            catch (IOException failure) { throw new IllegalStateException("Schedule listing failed", failure); }
        }
    }

    @Override public Optional<StatusScheduleState.Execution> claimStatusSchedule(StatusScheduleState expected) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try { return schedules().claim(expected, signingNow()); }
            catch (IOException failure) { throw new IllegalStateException("Schedule claim failed", failure); }
        }
    }

    @Override public boolean advanceStatusSchedule(StatusScheduleState.Execution expected) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try { return schedules().advance(expected, getStatusObject(expected.statusObjectId().orElseThrow())
                    .orElseThrow().nextUpdate().orElseThrow()); }
            catch (IOException failure) { throw new IllegalStateException("Schedule advancement failed", failure); }
        }
    }

    @Override public boolean failStatusSchedule(StatusScheduleState.Execution expected, String detailCode) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            try { return schedules().fail(expected, detailCode); }
            catch (IOException failure) { throw new IllegalStateException("Schedule failure recording failed", failure); }
        }
    }

    @Override
    public Instant signingNow() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return advanceSigningTime();
        }
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return signingNamespace;
        }
    }

    @Override
    public Duration signingPermittedSkew() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return options.signingIdPermittedSkew();
        }
    }

    @Override
    public Duration signingHorizon() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return options.signingOperationHorizon();
        }
    }

    private static boolean isActiveSignState(SignWorkflowStore.State state) {
        return state == SignWorkflowStore.State.INTENT || state == SignWorkflowStore.State.DISPATCHED
                || state == SignWorkflowStore.State.CANCELLING;
    }

    @Override
    public SignWorkflowStore.AcceptanceResult acceptSign(
            SignWorkflowStore.AcceptanceCommand command) {
        return acceptSign(command, Optional.empty());
    }

    @Override public SignWorkflowStore.AcceptanceResult acceptScheduledSign(
            SignWorkflowStore.AcceptanceCommand command, StatusScheduleState.Execution claim) {
        return acceptSign(command, Optional.of(Objects.requireNonNull(claim, "claim")));
    }

    private SignWorkflowStore.AcceptanceResult acceptSign(SignWorkflowStore.AcceptanceCommand command,
            Optional<StatusScheduleState.Execution> scheduledClaim) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            SignWorkflowStore.AcceptanceCommand exact = Objects.requireNonNull(command, "command");
            PkiId operationId = exact.operationId();
            List<DurableContentReference> candidates = acceptanceCandidates(exact).stream()
                    .sorted(Comparator.comparing(DurableContentReference::contentId)).toList();
            List<SignLockEntry> locks = new ArrayList<>(candidates.size());
            try {
                for (DurableContentReference candidate : candidates) { locks.add(acquireSignCandidateLock(candidate.contentId())); }
                SignWorkflowStore.AcceptanceResult result = acceptSignWithCandidateCustody(exact, operationId, exact.candidate(), scheduledClaim);
                if (scheduledClaim.isPresent() && result == SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING) {
                    try {
                        if (!schedules().attached(scheduledClaim.orElseThrow(), exact)) return SignWorkflowStore.AcceptanceResult.CONFLICT;
                    } catch (IOException failure) { throw new IllegalStateException("Schedule receipt read failed", failure); }
                }
                return result;
            } finally {
                for (int index = locks.size() - 1; index >= 0; index--) {
                    releaseSignCandidateLock(candidates.get(index).contentId(), locks.get(index));
                }
            }
        }
    }

    private SignWorkflowStore.AcceptanceResult acceptSignWithCandidateCustody(
            SignWorkflowStore.AcceptanceCommand exact, PkiId operationId,
            DurableContentReference candidate, Optional<StatusScheduleState.Execution> scheduledClaim) {
        try {
            validateAcceptanceCommand(exact);
            validateAcceptanceOuter(exact);
            scheduledClaim.ifPresent(claim -> FsStatusSchedules.validateBinding(claim, SignWorkflowStore.AcceptanceEnvelope.from(exact)));
            notifySignAcceptanceValidated();
        } catch (IllegalArgumentException | IllegalStateException failure) {
            reclaimDefinitelyUnboundCandidates(exact);
            throw failure;
        }
        SignLockEntry lock = acquireSignLock(operationId);
        try {
            Optional<StoredSign> existing = readStoredSign(operationId);
            if (existing.isPresent()) {
                SignWorkflowStore.AcceptanceResult result = existing.orElseThrow().record()
                        .envelope().acceptanceCommitment().matches(exact.commitment())
                                ? SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING
                                : SignWorkflowStore.AcceptanceResult.CONFLICT;
                reclaimDefinitelyUnboundCandidates(exact);
                return result;
            }
            if (acceptanceCandidates(exact).stream().anyMatch(value -> readCandidateBinding(value.contentId()).isPresent())) {
                reclaimDefinitelyUnboundCandidates(exact);
                return SignWorkflowStore.AcceptanceResult.CONFLICT;
            }

            SigningLedgerStoreEngine.SigningAdmission admission;
            try {
                admission = metadataStore.reserveAcceptanceCapacity();
            } catch (SigningDueWorkIndex.CapacityExhaustedException
                    | SigningActiveWal.OverloadedException exhausted) {
                reclaimDefinitelyUnboundCandidates(exact);
                return SignWorkflowStore.AcceptanceResult.CAPACITY_REJECTED;
            }
            try (admission;
                    FilesystemStagedContentStore.TransactionalReservation reservation =
                            stagedContent.reserveTransactionalPublication(candidate);
                    FilesystemStagedContentStore.TransactionalReservation proofReservation = reserveProofCandidate(exact);
                    RepeatableContent ignoredContent = stagedContent.openContent(candidate)) {
                stagedContent.restoreReference(candidate.storeId(), candidate.contentId(),
                        candidate.encoding(), candidate.length(), candidate.sha256(),
                        candidate.lifecycle());
                if (exact.outer().filter(outer -> outer.kind() == DomainContinuationStore.Kind.KEY_PROOF).isPresent()) {
                    zeroecho.pki.impl.core.continuation.DomainCommandEncoding.Decoded proof =
                            ManagedKeyProofBindings.requireEnvelope(SignWorkflowStore.AcceptanceEnvelope.from(exact));
                    ManagedKeyProofBindings.readChallenge(stagedContent, exact.operationId(), exact.deadline(), Optional.empty(), proof, candidate);
                }
                if (exact.proofStep().isPresent()) {
                    zeroecho.pki.impl.core.continuation.CaSubjectProofBindings.requireLiveCandidates(stagedContent,
                            SignWorkflowStore.AcceptanceEnvelope.from(exact));
                }
                Optional<SignAcceptanceCrlScope> claims = SignAcceptanceCrlScope.derive(this, exact, ignoredContent);
                MetadataCommitResult committed = createSignAcceptance(exact, admission, claims, scheduledClaim);
                if (committed.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                    return SignWorkflowStore.AcceptanceResult.ACCEPTED;
                }
                if (committed.failureCategory()
                        .filter(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED::equals)
                        .isPresent()) {
                    return resolveAcceptanceCapacityFailure(exact);
                }
                if (committed.failureCategory()
                        .filter(category -> category != MetadataCommitResult.FailureCategory.CONFLICT)
                        .isPresent()) {
                    MetadataCommitResult.FailureCategory category = committed.failureCategory().orElseThrow();
                    throw translateSigningMetadataFailure(new MetadataStoreException(category,
                            "Signing acceptance was not committed"));
                }
            } catch (CrlScopeReservationStore.ConflictException conflict) {
                reclaimDefinitelyUnboundCandidates(exact);
                return SignWorkflowStore.AcceptanceResult.CONFLICT;
            } catch (MetadataStoreException failure) {
                if (failure.category() == MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED) {
                    return resolveAcceptanceCapacityFailure(exact);
                }
                throw translateSigningMetadataFailure(failure);
            } catch (IOException failure) {
                if (durabilityUncertain.get()) {
                    throw signingDurabilityFailure(failure);
                }
                reclaimDefinitelyUnboundCandidates(exact);
                throw new PkiException(
                        "Signing staged content is invalid: code=CONTENT_INTEGRITY_FAILED", failure);
            } catch (PkiException | IllegalArgumentException | IllegalStateException failure) {
                if (!durabilityUncertain.get()) {
                    reclaimDefinitelyUnboundCandidates(exact);
                }
                throw failure;
            }
            SignWorkflowStore.AcceptanceResolution resolution = resolveAcceptance(
                    operationId, exact.commitment());
            reclaimDefinitelyUnboundCandidates(exact);
            return resolution == SignWorkflowStore.AcceptanceResolution.MATCHED
                    ? SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING
                    : SignWorkflowStore.AcceptanceResult.CONFLICT;
        } finally {
            releaseSignLock(operationId, lock);
        }
    }

    @Override
    public SignWorkflowStore.AcceptanceResolution resolveAcceptance(PkiId operationId,
            SignWorkflowStore.AcceptanceCommitment commitment) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            PkiId exactId = Objects.requireNonNull(operationId, "operationId");
            SignWorkflowStore.AcceptanceCommitment exactCommitment = Objects.requireNonNull(
                    commitment, "commitment");
            Optional<StoredSign> existing = readStoredSign(exactId);
            if (existing.isEmpty()) {
                return SignWorkflowStore.AcceptanceResolution.NOT_ACCEPTED;
            }
            return existing.orElseThrow().record().envelope().acceptanceCommitment()
                    .matches(exactCommitment)
                            ? SignWorkflowStore.AcceptanceResolution.MATCHED
                            : SignWorkflowStore.AcceptanceResolution.CONFLICT;
        }
    }

    private static List<DurableContentReference> acceptanceCandidates(SignWorkflowStore.AcceptanceCommand command) {
        return command.proofStep().map(proof -> List.of(command.candidate(), proof.challenge()))
                .orElseGet(() -> List.of(command.candidate()));
    }

    private void reclaimDefinitelyUnboundCandidates(SignWorkflowStore.AcceptanceCommand command) {
        for (DurableContentReference candidate : acceptanceCandidates(command)) { reclaimDefinitelyUnboundCandidate(candidate); }
    }

    private FilesystemStagedContentStore.TransactionalReservation reserveProofCandidate(SignWorkflowStore.AcceptanceCommand command)
            throws IOException {
        return command.proofStep().isPresent() ? stagedContent.reserveTransactionalPublication(command.proofStep().orElseThrow().challenge()) : null;
    }

    private void validateAcceptanceCommand(SignWorkflowStore.AcceptanceCommand command) {
        SigningSubmissionId parsed = SigningSubmissionId.parse(command.operationId());
        if (!command.providerNamespace().startsWith(signingNamespace + ".")) {
            throw new IllegalArgumentException(
                    "Signing acceptance belongs to a different store namespace");
        }
        parsed.validate(command.providerNamespace(), signingNow(),
                options.signingOperationHorizon(), options.signingIdPermittedSkew());
        if (!parsed.createdAt().equals(command.createdAt())
                || !command.deadline().isAfter(command.createdAt())
                || command.deadline().isAfter(command.createdAt().plus(
                        options.signingOperationHorizon()))) {
            throw new IllegalArgumentException(
                    "Signing acceptance timestamps do not match its identifier");
        }
        command.proofStep().ifPresent(proof -> {
            SigningSubmissionId step = SigningSubmissionId.parse(proof.operationId());
            step.validate(command.providerNamespace(), signingNow(), options.signingOperationHorizon(), options.signingIdPermittedSkew());
            if (!command.deadline().isAfter(step.createdAt())) {
                throw new IllegalArgumentException("CA proof deadline does not follow step identity");
            }
        });
        if (command.candidate().lifecycle()
                != DurableContentReference.Lifecycle.OPERATION) {
            throw new IllegalArgumentException(
                    "Signing candidate lifecycle must be OPERATION");
        }
    }

    private void validateAcceptanceOuter(SignWorkflowStore.AcceptanceCommand command) {
        command.outer().ifPresent(outer -> {
            if (outer.kind() == DomainContinuationStore.Kind.KEY_PROOF) {
                ManagedKeyProofBindings.requireEnvelope(SignWorkflowStore.AcceptanceEnvelope.from(command));
            }
            DomainContinuationStore.Record continuation = acceptanceContinuation(command, outer);
            if (zeroecho.pki.impl.core.continuation.IntermediateSigningCommand.supports(
                    zeroecho.pki.impl.core.continuation.DomainCommandEncoding.operation(outer.command()))) {
                zeroecho.pki.impl.core.continuation.IntermediateSigningCommand.requireEnvelope(
                        SignWorkflowStore.AcceptanceEnvelope.from(command));
            }
            byte[] encoded = FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, continuation);
            DomainContinuationValidation.validate(command.operationId(), continuation, encoded.length);
        });
    }

    private SignWorkflowStore.AcceptanceResult resolveAcceptanceCapacityFailure(
            SignWorkflowStore.AcceptanceCommand command) {
        Optional<StoredSign> existing = readStoredSign(command.operationId());
        if (existing.isPresent()) {
            SignWorkflowStore.AcceptanceResult result = existing.orElseThrow().record()
                    .envelope().acceptanceCommitment().matches(command.commitment())
                            ? SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING
                            : SignWorkflowStore.AcceptanceResult.CONFLICT;
            reclaimDefinitelyUnboundCandidates(command);
            return result;
        }
        if (acceptanceCandidates(command).stream().anyMatch(value -> readCandidateBinding(value.contentId()).isPresent())) {
            reclaimDefinitelyUnboundCandidates(command);
            return SignWorkflowStore.AcceptanceResult.CONFLICT;
        }
        reclaimDefinitelyUnboundCandidates(command);
        return SignWorkflowStore.AcceptanceResult.CAPACITY_REJECTED;
    }

    private MetadataCommitResult createSignAcceptance(
            SignWorkflowStore.AcceptanceCommand command,
            SigningLedgerStoreEngine.SigningAdmission admission,
            Optional<SignAcceptanceCrlScope> claims,
            Optional<StatusScheduleState.Execution> scheduledClaim) throws MetadataStoreException {
        SignWorkflowStore.AcceptanceEnvelope envelope =
                SignWorkflowStore.AcceptanceEnvelope.from(command);
        SignWorkflowStore.MutableState state = SignWorkflowStore.MutableState.intent(
                command.operationId(), command.mode(), command.proofStep().isPresent()
                        ? SignWorkflowStore.Stage.CA_PROOF : SignWorkflowStore.Stage.SINGLE);
        try (MetadataTransaction transaction = metadataStore.beginTransaction(admission)) {
            if (scheduledClaim.isPresent()) schedules().stageAcceptance(transaction, scheduledClaim.orElseThrow(), command);
            if (claims.isPresent()) {
                crlScopeReservations.stageAcceptance(transaction, claims.orElseThrow());
            }
            transaction.create(signingEnvelopeKey(command.operationId()),
                    byteContent(FsCodec.encode(FsCodec.SIGN_ACCEPTANCE_ENVELOPE, envelope)),
                    CancellationSignal.NONE);
            transaction.create(signingStateKey(command.operationId()),
                    byteContent(FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE, state)),
                    CancellationSignal.NONE);
            for (DurableContentReference candidate : acceptanceCandidates(command)) {
                SignWorkflowStore.CandidateBinding owned = new SignWorkflowStore.CandidateBinding(candidate.contentId(),
                        command.operationId(), candidate.length(), candidate.sha256());
                transaction.create(signingCandidateBindingKey(candidate.contentId()),
                        byteContent(FsCodec.encode(FsCodec.SIGN_CANDIDATE_BINDING, owned)), CancellationSignal.NONE);
            }
            if (command.outer().isPresent()) {
                SignWorkflowStore.OuterCommand outer = command.outer().orElseThrow();
                DomainContinuationStore.Record continuation = acceptanceContinuation(command, outer);
                transaction.create(domainContinuationKey(command.operationId()),
                        byteContent(FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, continuation)),
                        CancellationSignal.NONE);
                transaction.create(domainCorrelationKey(outer.kind(), outer.correlationId()),
                        byteContent(encodeDomainCorrelation(command.operationId())),
                        CancellationSignal.NONE);
            }
            SignAcceptanceCommitFault fault = SIGN_ACCEPTANCE_COMMIT_FAULT.get();
            if (fault == SignAcceptanceCommitFault.BEFORE_COMMIT_FAILURE) {
                throw new MetadataStoreException(MetadataCommitResult.FailureCategory.STORAGE_FAILURE,
                        "Injected definite signing acceptance failure");
            }
            if (fault == SignAcceptanceCommitFault.BEFORE_COMMIT_AS_UNKNOWN) {
                return requireKnownOutcome(new MetadataCommitResult(transaction.id(), MetadataCommitResult.Outcome.UNKNOWN,
                        OptionalLong.empty(), Optional.empty()));
            }
            MetadataCommitResult committed = transaction.commit();
            if (fault == SignAcceptanceCommitFault.AFTER_COMMIT_AS_UNKNOWN
                    && committed.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                return requireKnownOutcome(new MetadataCommitResult(committed.transactionId(), MetadataCommitResult.Outcome.UNKNOWN,
                        OptionalLong.empty(), Optional.empty()));
            }
            return requireKnownOutcome(committed);
        } catch (MetadataStoreException failure) {
            throw failure;
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
    }

    private static DomainContinuationStore.Record acceptanceContinuation(
            SignWorkflowStore.AcceptanceCommand command, SignWorkflowStore.OuterCommand outer) {
        return new DomainContinuationStore.Record(command.operationId(), DOMAIN_CONTINUATION_VERSION,
                outer.kind(), Optional.of(outer.correlationId()), DomainContinuationStore.State.SIGNING,
                0L, command.createdAt(), command.deadline(), outer.command(),
                outer.commandCommitment(), Optional.of(command.candidate()),
                Optional.empty(), Optional.empty());
    }

    /* default */ enum SignAcceptanceCommitFault {
        BEFORE_COMMIT_FAILURE, BEFORE_COMMIT_AS_UNKNOWN, AFTER_COMMIT_AS_UNKNOWN
    }

    /* default */ static void installSignAcceptanceCommitFault(SignAcceptanceCommitFault fault) {
        SIGN_ACCEPTANCE_COMMIT_FAULT.set(Objects.requireNonNull(fault, "fault"));
    }

    /* default */ static void clearSignAcceptanceCommitFault() { SIGN_ACCEPTANCE_COMMIT_FAULT.remove(); }

    private void reclaimDefinitelyUnboundCandidate(DurableContentReference candidate) {
        try {
            if (readCandidateBinding(candidate.contentId()).isPresent()) {
                return;
            }
            stagedContent.retireUnownedContent(candidate);
        } catch (IOException | RuntimeException cleanupFailure) {
            LOG.log(Level.WARNING,
                    "Unbound signing candidate cleanup deferred: code=SIGNING_CANDIDATE_CLEANUP_DEFERRED");
        }
    }

    @Override
    public Optional<DomainContinuationStore.Record> getDomainContinuation(PkiId operationId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public Optional<DomainContinuationStore.Record> getDomainContinuation(
            DomainContinuationStore.Kind kind, String correlationId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    @Override
    public Optional<DomainContinuationStore.Record> transitionDomainContinuation(PkiId operationId,
            long expectedRevision, DomainContinuationStore.State target,
            Optional<EncodedObject> result, Optional<String> detailCode) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
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
    }

    private static boolean validDomainTransition(DomainContinuationStore.State source,
            DomainContinuationStore.State target) {
        return source == DomainContinuationStore.State.SIGNING
                && (target == DomainContinuationStore.State.PUBLISHING
                        || target == DomainContinuationStore.State.FAILED
                        || target == DomainContinuationStore.State.EXPIRED)
                || source == DomainContinuationStore.State.PUBLISHING
                && (target == DomainContinuationStore.State.COMPLETED
                        || target == DomainContinuationStore.State.FAILED
                        || target == DomainContinuationStore.State.EXPIRED)
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
    public Optional<SignWorkflowStore.Workflow> getSignWorkflow(PkiId submissionId) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(submissionId, "submissionId");
            Optional<SignExpiry> expiry = Optional.empty();
            Optional<SignWorkflowStore.Workflow> result;
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
    }

    @Override
    public List<SignWorkflowStore.Workflow> listSignWorkflows() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return listStoredSigns().stream().map(StoredSign::record).toList();
        }
    }

    @Override
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public List<SignWorkflowStore.Workflow> selectDueSignWorkflows(Instant cutoffInclusive,
            int maximumRecords) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
            if (maximumRecords < 1 || maximumRecords > 4096) {
                throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
            }
            List<SignWorkflowStore.Workflow> records = new ArrayList<>(maximumRecords);
            try {
                List<String> dueOperations = metadataStore.selectSigningDue(
                        cutoffInclusive, maximumRecords);
                for (String operationId : dueOperations) {
                    readSignWorkflow(new PkiId(operationId)).ifPresent(records::add);
                }
            } catch (IOException failure) {
                throw new IllegalStateException(
                        "Failed to select authoritative signing records", failure);
            }
            return List.copyOf(records);
        }
    }

    @Override
    public SignWorkflowStore.Page pageSignWorkflows(Optional<String> exclusiveCursor, int maximumRecords,
            CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            return pageSignWorkflows(exclusiveCursor, Optional.empty(), maximumRecords, cancellation);
        }
    }

    @Override
    public SignWorkflowStore.Page pageSignWorkflows(Optional<String> exclusiveCursor,
            Optional<String> inclusiveHighWatermark, int maximumRecords, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(exclusiveCursor, "exclusiveCursor");
            Objects.requireNonNull(inclusiveHighWatermark, "inclusiveHighWatermark");
            Objects.requireNonNull(cancellation, "cancellation");
            if (maximumRecords < 1 || maximumRecords > 4096) {
                throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
            }
            Optional<String> lower = exclusiveCursor;
            MetadataSnapshot.KeyRange range = new MetadataSnapshot.KeyRange(SIGN_STATE_NAMESPACE, lower,
                    Optional.empty());
            List<SignWorkflowStore.Workflow> records = new ArrayList<>(maximumRecords);
            List<SignWorkflowStore.PageCandidate> candidates = new ArrayList<>(maximumRecords);
            int examined = 0;
            int failures = 0;
            Optional<String> nextCursor = exclusiveCursor;
            if (cancellation.isCancelled()) {
                return new SignWorkflowStore.Page(records, nextCursor, examined, failures, false, candidates);
            }
            try (MetadataSnapshot snapshot = metadataStore.snapshot();
                    MetadataCursor cursor = snapshot.scan(range, cancellation)) {
                Optional<String> highWatermark = snapshot.greatestKey(SIGN_STATE_NAMESPACE)
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
                            SignWorkflowStore.Workflow decoded = decodeStoredSign(snapshot, candidate).record();
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
    }

    @Override
    public SignWorkflowStore.DuePage pageDueSignWorkflows(Instant cutoffInclusive,
            Optional<String> exclusiveCursor, Optional<String> inclusiveHighWatermark,
            int maximumRecords, CancellationSignal cancellation) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
            Objects.requireNonNull(exclusiveCursor, "exclusiveCursor");
            Objects.requireNonNull(inclusiveHighWatermark, "inclusiveHighWatermark");
            Objects.requireNonNull(cancellation, "cancellation");
            if (maximumRecords < 1 || maximumRecords > 4096) {
                throw new IllegalArgumentException("maximumRecords must be between 1 and 4096");
            }
            if (cancellation.isCancelled()) {
                return new SignWorkflowStore.DuePage(List.of(), Optional.empty(), 0,
                        false, inclusiveHighWatermark);
            }
            try {
                SegmentedTransactionalMetadataStore.SigningDuePage page =
                        metadataStore.pageSigningDue(cutoffInclusive, exclusiveCursor,
                                inclusiveHighWatermark, maximumRecords);
                List<SignWorkflowStore.DueCandidate> candidates =
                        new ArrayList<>(page.candidates().size());
                int failures = 0;
                for (SegmentedTransactionalMetadataStore.SigningDueCandidate candidate
                        : page.candidates()) {
                    if (cancellation.isCancelled()) {
                        Optional<String> cursor = candidates.isEmpty() ? Optional.empty()
                                : Optional.of(candidates.getLast().operationId().value());
                        return new SignWorkflowStore.DuePage(candidates, cursor, failures,
                                false, page.highWatermark());
                    }
                    SignWorkflowStore.DueCandidate mapped = new SignWorkflowStore.DueCandidate(
                            new PkiId(candidate.operationId()), candidate.scheduling(),
                            candidate.malformed());
                    candidates.add(mapped);
                    if (mapped.malformed()) {
                        failures++;
                    }
                }
                Optional<String> cursor = candidates.isEmpty() ? Optional.empty()
                        : Optional.of(candidates.getLast().operationId().value());
                return new SignWorkflowStore.DuePage(candidates, cursor, failures,
                        page.endReached(), page.highWatermark());
            } catch (IOException failure) {
                throw new IllegalStateException(
                        "Failed to page authoritative signing records", failure);
            }
        }
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> deferSignReconciliation(PkiId submissionId, long expectedRevision,
            long fence, SignWorkflowStore.ReconciliationFailureClass failureClass) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(failureClass, "failureClass");
            Optional<SignExpiry> expiry;
            Optional<SignWorkflowStore.Workflow> result;
            SignLockEntry lock = acquireSignLock(submissionId);
            try {
                Optional<StoredSign> optional = readStoredSign(submissionId);
                if (optional.isEmpty()) {
                    return Optional.empty();
                }
                StoredSign stored = optional.orElseThrow();
                SignWorkflowStore.Workflow current = stored.record();
                expiry = expireIfDeadlineReached(stored);
                if (expiry.isPresent()) {
                    result = Optional.empty();
                } else {
                    result = deferCurrentSignWorkflow(stored, current, expectedRevision,
                            fence, failureClass);
                }
            } finally {
                releaseSignLock(submissionId, lock);
            }
            expiry.ifPresent(this::finishSignExpiry);
            return result;
        }
    }

    private Optional<SignWorkflowStore.Workflow> deferCurrentSignWorkflow(StoredSign stored,
            SignWorkflowStore.Workflow current, long expectedRevision, long fence,
            SignWorkflowStore.ReconciliationFailureClass failureClass) {
        if (current.revision() != expectedRevision || current.fence() != fence) {
            return Optional.empty();
        }
        boolean outerContinuation = isOuterContinuationRetry(current, failureClass);
        boolean providerReconciliation = isProviderReconciliation(current);
        if (!providerReconciliation && !outerContinuation) {
            return Optional.empty();
        }
        int failureCount = nextReconciliationFailureCount(current.failureCount());
        Instant nextEligible = nextReconciliationEligibility(
                current, failureCount, outerContinuation);
        SignWorkflowStore.Workflow deferred = deferredSignWorkflow(
                current, failureClass, failureCount, nextEligible);
        return persistDeferredSignWorkflow(stored, deferred);
    }

    private boolean isOuterContinuationRetry(SignWorkflowStore.Workflow workflow,
            SignWorkflowStore.ReconciliationFailureClass failureClass) {
        return workflow.state() == SignWorkflowStore.State.SUCCEEDED
                && failureClass == SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE
                && retryableOuterContinuation(workflow);
    }

    private static boolean isProviderReconciliation(SignWorkflowStore.Workflow workflow) {
        return workflow.state() == SignWorkflowStore.State.DISPATCHED
                || workflow.state() == SignWorkflowStore.State.CANCELLING;
    }

    private static int nextReconciliationFailureCount(int current) {
        return current == Integer.MAX_VALUE ? Integer.MAX_VALUE : current + 1;
    }

    private Instant nextReconciliationEligibility(SignWorkflowStore.Workflow workflow,
            int failureCount, boolean outerContinuation) {
        long delaySeconds = failureCount >= 5 ? 30L : 2L << failureCount - 1;
        Instant proposed = signingNow().plusSeconds(Math.min(delaySeconds, 30L));
        Instant horizonEnd = workflow.createdAt().plus(options.signingOperationHorizon());
        return outerContinuation || !proposed.isAfter(horizonEnd) ? proposed : horizonEnd;
    }

    private static SignWorkflowStore.Workflow deferredSignWorkflow(
            SignWorkflowStore.Workflow current,
            SignWorkflowStore.ReconciliationFailureClass failureClass,
            int failureCount, Instant nextEligible) {
        return copySignRecord(current, current.state(), current.revision() + 1L,
                current.fence(), Optional.empty(), current.detailCode(), current.result(),
                current.providerUpdatedAt(), failureCount, Optional.of(nextEligible),
                Optional.of(failureClass), failedInitialAttempt(current));
    }

    private Optional<SignWorkflowStore.Workflow> persistDeferredSignWorkflow(
            StoredSign stored, SignWorkflowStore.Workflow deferred) {
        return replaceSignMetadata(stored, deferred, false)
                ? Optional.of(deferred) : Optional.empty();
    }

    private boolean retryableOuterContinuation(SignWorkflowStore.Workflow workflow) {
        if (workflow.envelope().outer().isEmpty()) {
            return false;
        }
        Optional<DomainContinuationStore.Record> loaded =
                getDomainContinuation(workflow.operationId());
        if (loaded.isEmpty()) {
            throw new IllegalStateException("Signing outer continuation is missing");
        }
        DomainContinuationStore.Record continuation = loaded.orElseThrow();
        requireMatchingOuter(workflow, continuation);
        return continuation.state() == DomainContinuationStore.State.SIGNING
                || continuation.state() == DomainContinuationStore.State.PUBLISHING;
    }

    private List<StoredSign> listStoredSigns() {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            return listStoredSigns(snapshot);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to list authoritative signing records", ex);
        }
    }

    private List<StoredSign> listStoredSigns(MetadataSnapshot snapshot) throws IOException {
        List<StoredSign> storedSigns = new ArrayList<>();
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(SIGN_STATE_NAMESPACE),
                CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                StoredSign stored = decodeStoredSign(snapshot, next.orElseThrow());
                storedSigns.add(stored);
            }
        }
        return List.copyOf(storedSigns);
    }

    private List<StoredStatus> listStoredStatuses() {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) { return listStoredStatuses(snapshot); }
        catch (IOException exception) { throw new IllegalStateException("Failed to list authoritative status objects", exception); }
    }

    private List<StoredStatus> listStoredStatuses(MetadataSnapshot snapshot) throws IOException {
        List<StoredStatus> statuses = new ArrayList<>();
        visitStoredStatuses(snapshot, statuses::add);
        return List.copyOf(statuses);
    }

    private void visitStoredStatuses(MetadataSnapshot snapshot,
            AuthorityMetadataStore.Visitor<StoredStatus> visitor) throws IOException {
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(STATUS_RECORD_NAMESPACE),
                CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record record = next.orElseThrow()) {
                    visitor.accept(decodeStoredStatus(snapshot, record));
                }
            }
        }
        try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(STATUS_OWNER_NAMESPACE),
                CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                try (MetadataSnapshot.Record owner = next.orElseThrow();
                        MetadataSnapshot.Record record = snapshot.get(
                                statusRecordKey(new PkiId(owner.key().key()))).orElse(null)) {
                    if (record == null) throw new IllegalStateException("Status owner exists without its record");
                }
            }
        }
    }

    /* default */ Optional<SignWorkflowStore.Workflow> recoverySigningWorkflow(PkiId id) {
        return readSignWorkflow(id); // Recovery must not expire a workflow while validating its reservation.
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

    private MetadataCommitResult createStatusMetadata(StatusObject status, byte[] encoded, Optional<PkiId> signingOperation) throws IOException {
        PkiId statusId = status.statusObjectId();
        try (MetadataSnapshot snapshot = metadataStore.snapshot(); MetadataTransaction transaction = metadataStore.beginTransaction();
                MetadataSnapshot.Record existing = snapshot.get(statusRecordKey(statusId)).orElse(null)) {
            if (signingOperation.isPresent() && existing != null) {
                if (!Arrays.equals(encoded, readMetadataValue(existing))) throw new IllegalStateException("Status replay differs");
            } else {
                transaction.create(statusRecordKey(statusId), byteContent(encoded), CancellationSignal.NONE);
                transaction.create(statusOwnerKey(statusId),
                        byteContent(encodeStatusOwner(statusId, status.content())), CancellationSignal.NONE);
            }
            if (signingOperation.isPresent()) schedules().stageEffect(transaction, signingOperation.orElseThrow(), status);
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

    /* package */ static void installSignAcceptanceValidatedObserver(Runnable observer) {
        SIGN_ACCEPTANCE_VALIDATED_OBSERVER.set(Objects.requireNonNull(observer, "observer"));
    }

    /* package */ static void clearSignAcceptanceValidatedObserver() {
        SIGN_ACCEPTANCE_VALIDATED_OBSERVER.remove();
    }

    private static void notifySignAcceptanceValidated() {
        Runnable observer = SIGN_ACCEPTANCE_VALIDATED_OBSERVER.get();
        SIGN_ACCEPTANCE_VALIDATED_OBSERVER.remove();
        if (observer != null) {
            observer.run();
        }
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
    public Optional<SignWorkflowStore.Workflow> claimSignStep(PkiId submissionId, long expectedRevision,
            Duration lease) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            requirePositive(lease, "lease");
            Optional<SignExpiry> expiry;
            Optional<SignWorkflowStore.Workflow> result;
            SignLockEntry lock = acquireSignLock(submissionId);
            try {
                Optional<StoredSign> optional = readStoredSign(submissionId);
                if (optional.isEmpty()) {
                    return Optional.empty();
                }
                StoredSign stored = optional.get();
                SignWorkflowStore.Workflow current = stored.record();
                expiry = expireIfDeadlineReached(stored);
                if (expiry.isPresent()) {
                    result = Optional.empty();
                } else {
                    Instant now = signingNow();
                    boolean claimable = current.state() == SignWorkflowStore.State.INTENT
                            || current.state() == SignWorkflowStore.State.DISPATCHED
                            || current.state() == SignWorkflowStore.State.CANCELLING;
                    boolean leaseAvailable = current.leaseUntil().isEmpty() || !current.leaseUntil().get().isAfter(now);
                    boolean retryEligible = current.nextEligibleAt().isEmpty()
                            || !current.nextEligibleAt().orElseThrow().isAfter(now);
                    if (current.revision() != expectedRevision || !claimable || !leaseAvailable || !retryEligible) {
                        return Optional.empty();
                    }
                    SignWorkflowStore.State claimedState = current.state() == SignWorkflowStore.State.INTENT
                            ? SignWorkflowStore.State.DISPATCHED : current.state();
                    Optional<String> detail = claimedState == SignWorkflowStore.State.DISPATCHED
                            ? Optional.of("DISPATCHED") : current.detailCode();
                    Instant leaseUntil = signLeaseUntil(current, now, lease);
                    SignWorkflowStore.Workflow claimed = current.stage() == SignWorkflowStore.Stage.CA_CERTIFICATE_READY
                            ? caStageRecord(current, claimedState, SignWorkflowStore.Stage.CA_CERTIFICATE, current.proofOutcome(),
                                    current.revision() + 1L, current.fence() + 1L, Optional.of(leaseUntil),
                                    Optional.of(current.operationId()), detail, Optional.empty(), Optional.empty())
                            : copySignRecordWithDownstream(current, claimedState,
                                    current.revision() + 1L, current.fence() + 1L, Optional.of(leaseUntil),
                                    Optional.of(current.providerOperationId()), detail, current.result(), current.providerUpdatedAt(),
                                    0, Optional.empty(), Optional.empty(), claimedInitialAttempt(current));
                    result = replaceSignMetadata(stored, claimed, false) ? Optional.of(claimed) : Optional.empty();
                }
            } finally {
                releaseSignLock(submissionId, lock);
            }
            expiry.ifPresent(this::finishSignExpiry);
            return result;
        }
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> checkpointPendingSignDispatch(PkiId submissionId,
            long expectedRevision, long fence) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            return checkpointInitialSignAttempt(submissionId, expectedRevision, fence,
                    SignWorkflowStore.InitialAttemptPhase.DISPATCH_OWED,
                    SignWorkflowStore.InitialAttemptPhase.OBSERVATION_OWED);
        }
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> completeSignObservation(PkiId submissionId,
            long expectedRevision, long fence) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            return checkpointInitialSignAttempt(submissionId, expectedRevision, fence,
                    SignWorkflowStore.InitialAttemptPhase.OBSERVATION_CONSUMED,
                    SignWorkflowStore.InitialAttemptPhase.COMPLETED);
        }
    }

    private Optional<SignWorkflowStore.Workflow> checkpointInitialSignAttempt(PkiId submissionId,
            long expectedRevision, long fence, SignWorkflowStore.InitialAttemptPhase expectedPhase,
            SignWorkflowStore.InitialAttemptPhase targetPhase) {
        requireStoreUsable();
        Optional<SignExpiry> expiry;
        Optional<SignWorkflowStore.Workflow> result;
        SignLockEntry lock = acquireSignLock(submissionId);
        try {
            Optional<StoredSign> optional = readStoredSign(submissionId);
            if (optional.isEmpty()) {
                return Optional.empty();
            }
            StoredSign stored = optional.orElseThrow();
            SignWorkflowStore.Workflow current = stored.record();
            expiry = expireIfDeadlineReached(stored);
            if (expiry.isPresent()) {
                result = Optional.empty();
            } else {
                if (current.mode() != SignWorkflowStore.Mode.BOUNDED_OBSERVATION
                        || current.state() != SignWorkflowStore.State.DISPATCHED
                        || current.initialAttemptPhase() != expectedPhase
                        || current.revision() != expectedRevision || current.fence() != fence
                        || current.leaseUntil().isEmpty()) {
                    return Optional.empty();
                }
                Optional<Instant> leaseUntil = targetPhase == SignWorkflowStore.InitialAttemptPhase.OBSERVATION_OWED
                        ? Optional.empty() : current.leaseUntil();
                SignWorkflowStore.Workflow checkpoint = copySignRecord(current, current.state(),
                        current.revision() + 1L, fence, leaseUntil, current.detailCode(), current.result(),
                        current.providerUpdatedAt(), 0, Optional.empty(), Optional.empty(), targetPhase);
                SignTransitionCommit committed = commitSignTransitionAtAdmission(stored, checkpoint);
                result = committed.record().filter(record -> record.state() == SignWorkflowStore.State.DISPATCHED);
                expiry = committed.expiry();
            }
        } finally {
            releaseSignLock(submissionId, lock);
        }
        expiry.ifPresent(this::finishSignExpiry);
        return result;
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> renewSignStep(PkiId submissionId, long expectedRevision, long fence,
            Duration lease) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            requirePositive(lease, "lease");
            Optional<SignExpiry> expiry;
            Optional<SignWorkflowStore.Workflow> result;
            SignLockEntry lock = acquireSignLock(submissionId);
            try {
                Optional<StoredSign> optional = readStoredSign(submissionId);
                if (optional.isEmpty()) {
                    return Optional.empty();
                }
                StoredSign stored = optional.get();
                SignWorkflowStore.Workflow current = stored.record();
                expiry = expireIfDeadlineReached(stored);
                if (expiry.isPresent()) {
                    result = Optional.empty();
                } else {
                    Instant now = signingNow();
                    if (current.revision() != expectedRevision || current.fence() != fence
                            || current.leaseUntil().isEmpty()
                            || !current.leaseUntil().orElseThrow().isAfter(now)
                            || current.state() != SignWorkflowStore.State.DISPATCHED
                                    && current.state() != SignWorkflowStore.State.CANCELLING) {
                        return Optional.empty();
                    }
                    SignWorkflowStore.Workflow renewed = copySignRecord(current, current.state(),
                            current.revision() + 1L, fence, Optional.of(signLeaseUntil(current, now, lease)),
                            current.detailCode(),
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
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> requestSignCancellation(PkiId submissionId,
            long expectedRevision, long fence) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Optional<SignExpiry> expiry;
            Optional<SignWorkflowStore.Workflow> result;
            SignLockEntry lock = acquireSignLock(submissionId);
            try {
                Optional<StoredSign> optional = readStoredSign(submissionId);
                if (optional.isEmpty()) {
                    return Optional.empty();
                }
                StoredSign stored = optional.orElseThrow();
                SignWorkflowStore.Workflow current = stored.record();
                expiry = expireIfDeadlineReached(stored);
                if (expiry.isPresent()) {
                    result = Optional.empty();
                } else {
                    if (current.revision() != expectedRevision || current.fence() != fence) {
                        return Optional.empty();
                    }
                    if (current.state() == SignWorkflowStore.State.INTENT
                            || current.state() == SignWorkflowStore.State.DISPATCHED
                            && (current.stage() == SignWorkflowStore.Stage.CA_PROOF_VERIFYING
                                || current.stage() == SignWorkflowStore.Stage.CA_CERTIFICATE_READY)) {
                        SignWorkflowStore.Workflow cancelled = copySignRecord(current,
                                SignWorkflowStore.State.CANCELLED, current.revision() + 1L, fence,
                                Optional.empty(), Optional.of("CANCELLED"), Optional.empty(),
                                Optional.of(signingNow()), 0, Optional.empty(), Optional.empty());
                        result = commitSignTransitionAtAdmission(stored, cancelled).record();
                    } else if (current.state() == SignWorkflowStore.State.DISPATCHED) {
                        SignWorkflowStore.Workflow cancelling = copySignRecord(current,
                                SignWorkflowStore.State.CANCELLING, current.revision() + 1L, fence,
                                Optional.empty(), Optional.of("CANCEL_REQUESTED"), Optional.empty(),
                                Optional.empty(), 0, Optional.empty(), Optional.empty());
                        result = commitSignTransitionAtAdmission(stored, cancelling).record();
                    } else if (current.state() == SignWorkflowStore.State.CANCELLING) {
                        result = Optional.of(current);
                    } else {
                        result = Optional.empty();
                    }
                }
            } finally {
                releaseSignLock(submissionId, lock);
            }
            expiry.ifPresent(this::finishSignExpiry);
            if (expiry.isEmpty()) { result.ifPresent(this::recordSigningEvidence); }
            return result;
        }
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> transitionSign(PkiId submissionId, long expectedRevision, long fence,
            SignWorkflowStore.State target, Optional<String> detailCode, Optional<EncodedObject> result,
            Optional<Instant> providerUpdatedAt) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(detailCode, "detailCode");
            Objects.requireNonNull(result, "result");
            Objects.requireNonNull(providerUpdatedAt, "providerUpdatedAt");
            Optional<SignExpiry> expiry;
            Optional<SignWorkflowStore.Workflow> transition;
            SignLockEntry lock = acquireSignLock(submissionId);
            try {
                Optional<StoredSign> optional = readStoredSign(submissionId);
                if (optional.isEmpty()) {
                    return Optional.empty();
                }
                StoredSign stored = optional.get();
                SignWorkflowStore.Workflow current = stored.record();
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
                        if (target == SignWorkflowStore.State.SUCCEEDED
                                && current.stage() != SignWorkflowStore.Stage.SINGLE
                                && current.stage() != SignWorkflowStore.Stage.CA_CERTIFICATE) {
                            throw new IllegalArgumentException("Proof cannot complete parent signing");
                        }
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
                        SignWorkflowStore.Workflow transitioned = copySignRecord(current, target,
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
            if (expiry.isEmpty()) { transition.ifPresent(this::recordSigningEvidence); }
            return transition;
        }
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> checkpointCaProof(PkiId submissionId, long expectedRevision, long fence,
            SignWorkflowStore.CaSubjectProofOutcome outcome, Optional<EncodedObject> signature) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Objects.requireNonNull(outcome, "outcome");
            Objects.requireNonNull(signature, "signature");
            boolean succeeded = outcome.disposition() == zeroecho.pki.spi.crypto.SigningProvider.ObservationState.SUCCEEDED;
            requireProofSignature(succeeded, signature);
            Optional<SignExpiry> expiry;
            Optional<SignWorkflowStore.Workflow> result;
            SignLockEntry lock = acquireSignLock(submissionId);
            try {
                Optional<StoredSign> found = readStoredSign(submissionId);
                if (found.isEmpty()) { return Optional.empty(); }
                StoredSign stored = found.orElseThrow();
                SignWorkflowStore.Workflow current = stored.record();
                if (current.revision() != expectedRevision || current.fence() != fence || current.leaseUntil().isEmpty()
                        || current.stage() != SignWorkflowStore.Stage.CA_PROOF
                        || current.state() != SignWorkflowStore.State.DISPATCHED && current.state() != SignWorkflowStore.State.CANCELLING) {
                    return Optional.empty();
                }
                expiry = expireIfDeadlineReached(stored);
                if (expiry.isEmpty()
                        && (succeeded || outcome.disposition() == zeroecho.pki.spi.crypto.SigningProvider.ObservationState.CANCELLED)
                        && outcome.providerUpdatedAt().filter(time -> !time.isBefore(current.deadline())).isPresent()) {
                    expiry = expireSign(stored);
                }
                if (expiry.isPresent()) {
                    result = expiry.map(SignExpiry::record);
                } else {
                    SignWorkflowStore.Workflow changed = checkpointedProof(current, succeeded, outcome, signature, fence);
                    SignTransitionCommit committed = commitSignTransitionAtAdmission(stored, changed);
                    result = committed.record();
                    expiry = committed.expiry();
                }
            } finally { releaseSignLock(submissionId, lock); }
            expiry.ifPresent(this::finishSignExpiry);
            if (expiry.isEmpty()) { result.ifPresent(this::recordSigningEvidence); }
            return result;
        }
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> completeCaProofVerification(PkiId submissionId, long expectedRevision, long fence) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Optional<SignExpiry> expiry;
            Optional<SignWorkflowStore.Workflow> result;
            SignLockEntry lock = acquireSignLock(submissionId);
            try {
                Optional<StoredSign> found = readStoredSign(submissionId);
                if (found.isEmpty()) { return Optional.empty(); }
                StoredSign stored = found.orElseThrow();
                SignWorkflowStore.Workflow current = stored.record();
                if (current.revision() != expectedRevision || current.fence() != fence || current.leaseUntil().isEmpty()
                        || current.state() != SignWorkflowStore.State.DISPATCHED
                        || current.stage() != SignWorkflowStore.Stage.CA_PROOF_VERIFYING || current.result().isEmpty()
                        || current.proofOutcome().filter(value -> value.disposition()
                                == zeroecho.pki.spi.crypto.SigningProvider.ObservationState.SUCCEEDED).isEmpty()) {
                    return Optional.empty();
                }
                expiry = expireIfDeadlineReached(stored);
                if (expiry.isPresent()) { result = expiry.map(SignExpiry::record); }
                else {
                    SignWorkflowStore.MutableState old = current.mutableState();
                    SignWorkflowStore.MutableState ready = new SignWorkflowStore.MutableState(current.operationId(), current.state(),
                            current.revision() + 1L, fence, Optional.empty(), Optional.empty(), Optional.of("DISPATCHED"),
                            Optional.empty(), Optional.empty(), 0, Optional.empty(), Optional.empty(), old.initialAttemptPhase(),
                            SignWorkflowStore.Stage.CA_CERTIFICATE_READY, current.proofOutcome());
                    SignTransitionCommit committed = commitSignTransitionAtAdmission(stored, new SignWorkflowStore.Workflow(current.envelope(), ready));
                    result = committed.record();
                    expiry = committed.expiry();
                }
            } finally { releaseSignLock(submissionId, lock); }
            expiry.ifPresent(this::finishSignExpiry);
            return result;
        }
    }

    // Explicit collaborators or atomic persisted coordinates remain visible at this boundary.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    private static SignWorkflowStore.Workflow caStageRecord(SignWorkflowStore.Workflow current,
            SignWorkflowStore.State state, SignWorkflowStore.Stage stage, Optional<SignWorkflowStore.CaSubjectProofOutcome> outcome,
            long revision, long fence, Optional<Instant> lease, Optional<PkiId> downstream, Optional<String> detail,
            Optional<EncodedObject> result, Optional<Instant> providerTime) {
        return new SignWorkflowStore.Workflow(current.envelope(), new SignWorkflowStore.MutableState(current.operationId(),
                state, revision, fence, lease, downstream, detail, result, providerTime, 0, Optional.empty(), Optional.empty(),
                current.initialAttemptPhase(), stage, outcome));
    }

    @Override
    public Optional<SignWorkflowStore.Workflow> retireSign(PkiId submissionId, long expectedRevision, long fence) {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Optional<SignExpiry> expiry;
            Optional<SignWorkflowStore.Workflow> result;
            SignLockEntry lock = acquireSignLock(submissionId);
            try {
                Optional<StoredSign> optional = readStoredSign(submissionId);
                if (optional.isEmpty()) {
                    return Optional.empty();
                }
                StoredSign stored = optional.get();
                SignWorkflowStore.Workflow current = stored.record();
                if (current.state() == SignWorkflowStore.State.EXPIRED) {
                    requireOuterTerminal(current);
                    return Optional.of(current);
                }
                expiry = expireIfDeadlineReached(stored);
                if (expiry.isPresent()) {
                    result = expiry.map(SignExpiry::record);
                } else {
                    if (current.revision() != expectedRevision || current.fence() != fence) {
                        return Optional.empty();
                    }
                    if (!outerTerminal(current)) {
                        return Optional.empty();
                    }
                    if (!isRetirableSignState(current.state())) {
                        return Optional.empty();
                    }
                    Optional<String> retirementDetail = switch (current.state()) {
                        case SUCCEEDED -> Optional.of("SIGNED");
                        case FAILED -> Optional.of(current.detailCode()
                                .filter(FilesystemPkiStore::isRetainedFailureDetail)
                                .orElse("FAILED"));
                        case CANCELLED -> Optional.of("CANCELLED");
                        default -> throw new IllegalStateException("Signing state is not retirable");
                    };
                    SignWorkflowStore.Workflow retired = copySignRecord(current,
                            SignWorkflowStore.State.RETIRED, current.revision() + 1L, fence,
                            Optional.empty(), retirementDetail, current.result(),
                            current.providerUpdatedAt(), 0, Optional.empty(), Optional.empty());
                    if (!replaceSignMetadata(stored, retired, true)) {
                        return Optional.empty();
                    }
                    try {
                        for (DurableContentReference reference : current.candidates()) {
                        if (reference.lifecycle() == DurableContentReference.Lifecycle.OPERATION) {
                            signingRetirementFaults.beforeRetirement(reference);
                            stagedContent.retireSigningContent(reference);
                        }
                        }
                    } catch (IOException exception) {
                        LOG.log(Level.WARNING, "Signing content retirement cleanup failed");
                        throw new PkiException(
                                "Signing content cleanup failed: code=SIGNING_CONTENT_CLEANUP_FAILED");
                    }
                    result = Optional.of(retired);
                }
            } finally {
                releaseSignLock(submissionId, lock);
            }
            expiry.ifPresent(this::finishSignExpiry);
            if (expiry.isEmpty()) { result.ifPresent(this::recordSigningEvidence); }
            return result;
        }
    }

    @Override
    public int purgeExpiredSignRecords() {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            Instant cutoff = signingNow();
            List<PkiId> ids = listStoredSigns().stream()
                    .filter(stored -> isContentFreeSignState(stored.record().state()))
                    .filter(stored -> !stored.record().createdAt().plus(options.signingOperationHorizon())
                            .isAfter(cutoff))
                    .filter(stored -> !isPinnedScheduleReceipt(stored.record().operationId()))
                    .limit(SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS / 3)
                    .map(stored -> stored.record().submissionId())
                    .sorted(Comparator.comparing(PkiId::value)).toList();
            if (ids.isEmpty()) return 0;
            List<SignLockEntry> locks = new ArrayList<>(ids.size());
            try {
                for (PkiId id : ids) locks.add(acquireSignLock(id));
                List<SigningTransactionPayloadCodec.Mutation> deletes = new ArrayList<>(ids.size() * 3);
                List<DurableContentReference> retiredCandidates = new ArrayList<>(ids.size());
                int purgedRecords = 0;
                for (PkiId id : ids) {
                    Optional<StoredSign> current = readStoredSign(id);
                    if (current.isEmpty()) continue;
                    StoredSign stored = current.orElseThrow();
                    if (isContentFreeSignState(stored.record().state())
                            && !stored.record().createdAt().plus(options.signingOperationHorizon()).isAfter(cutoff)) {
                        int mutationStart = deletes.size();
                        int candidateStart = retiredCandidates.size();
                        deletes.add(new SigningTransactionPayloadCodec.Mutation(
                                SigningTransactionPayloadCodec.MutationKind.DELETE,
                                signingStateKey(id), stored.recordRevision(), null));
                        deletes.add(new SigningTransactionPayloadCodec.Mutation(
                                SigningTransactionPayloadCodec.MutationKind.DELETE,
                                signingEnvelopeKey(id), stored.envelopeRevision(), null));
                        deletes.add(new SigningTransactionPayloadCodec.Mutation(
                                SigningTransactionPayloadCodec.MutationKind.DELETE,
                                signingCandidateBindingKey(stored.reference().contentId()),
                                stored.bindingRevision(), null));
                        retiredCandidates.add(stored.reference());
                        if (stored.proofCandidate().isPresent()) {
                            BoundSignCandidate proof = stored.proofCandidate().orElseThrow();
                            deletes.add(new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.DELETE,
                                    signingCandidateBindingKey(proof.reference().contentId()), proof.bindingRevision(), null));
                            retiredCandidates.add(proof.reference());
                        }
                        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                                MetadataSnapshot.Record domain = snapshot.get(domainContinuationKey(id)).orElse(null);
                                MetadataSnapshot.Record scheduleReceipt = snapshot.get(FsStatusSchedules.receiptKey(id)).orElse(null)) {
                            if (scheduleReceipt != null) {
                                StatusScheduleState.Execution execution = schedules().receipt(snapshot, id).orElseThrow();
                                if (schedules().pinned(snapshot, execution)) {
                                    deletes.subList(mutationStart, deletes.size()).clear();
                                    retiredCandidates.subList(candidateStart, retiredCandidates.size()).clear();
                                    continue;
                                }
                                deletes.add(new SigningTransactionPayloadCodec.Mutation(SigningTransactionPayloadCodec.MutationKind.DELETE,
                                        scheduleReceipt.key(), scheduleReceipt.recordRevision(), null));
                            }
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
                        if (deletes.size() > SigningTransactionPayloadCodec.MAXIMUM_MUTATIONS) {
                            deletes.subList(mutationStart, deletes.size()).clear();
                            retiredCandidates.subList(candidateStart, retiredCandidates.size()).clear();
                            break;
                        }
                        purgedRecords++;
                    }
                }
                return commitPurgedSigns(deletes, retiredCandidates, purgedRecords);
            } catch (IOException failure) {
                durabilityUncertain.set(true);
                throw storeDurabilityUnconfirmed("Store durability unconfirmed: code=STORE_DURABILITY_UNCONFIRMED");
            } finally {
                for (int index = locks.size() - 1; index >= 0; index--) {
                    releaseSignLock(ids.get(index), locks.get(index));
                }
            }
        }
    }

    private int commitPurgedSigns(List<SigningTransactionPayloadCodec.Mutation> deletes,
            List<DurableContentReference> retiredCandidates, int purgedRecords) throws IOException {
        if (deletes.isEmpty()) return 0;
        MetadataCommitResult result = metadataStore.directCommit(deletes);
        if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) return 0;
        for (DurableContentReference candidate : retiredCandidates) {
            stagedContent.purgeSigningContent(candidate);
        }
        return purgedRecords;
    }


    private boolean isPinnedScheduleReceipt(PkiId operationId) {
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<StatusScheduleState.Execution> receipt = schedules().receipt(snapshot, operationId);
            return receipt.isPresent() && schedules().pinned(snapshot, receipt.orElseThrow());
        } catch (IOException failure) { throw new IllegalStateException("Schedule cleanup authority unavailable", failure); }
    }

    @Override
    public boolean supportsBackup() { return true; }

    /**
     * Creates a versioned logical backup through the bounded legacy adapter.
     * @param request backup request
     * @return complete legacy payload only when it fits the configured adapter limit
     * @throws NullPointerException if request is null
     * @throws IllegalStateException if creation fails or the array limit is exceeded
     */
    @Override
    public zeroecho.pki.api.backup.BackupArtifact createBackup(zeroecho.pki.api.backup.BackupRequest request) {
        try (zeroecho.pki.api.backup.BackupSource source = createBackupSource(request)) {
            if (source.contentLength() > backupLimits.legacyBytes()) {
                throw new IllegalStateException("BACKUP_LEGACY_LIMIT");
            }
            byte[] bytes = new byte[Math.toIntExact(source.contentLength())];
            try (InputStream input = source.openStream()) {
                int offset = 0;
                while (offset < bytes.length) {
                    int count = input.read(bytes, offset, bytes.length - offset);
                    if (count <= 0) throw new IOException("BACKUP_TRUNCATED");
                    offset += count;
                }
                if (input.read() != -1) throw new IOException("BACKUP_LENGTH");
            }
            return new zeroecho.pki.api.backup.BackupArtifact(source.backupId(),
                    new EncodedObject(Encoding.BINARY, bytes));
        } catch (IOException failure) {
            throw new IllegalStateException("BACKUP_CREATE_FAILED", failure);
        }
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.BackupSource createBackupSource(
            zeroecho.pki.api.backup.BackupRequest request) throws IOException {
        Objects.requireNonNull(request, "request");
        Path frozen = null;
        zeroecho.pki.api.backup.BackupSource result = null;
        try {
            Path work;
            Instant captured;
            try (StoreMutationBarrier.Lease freeze = mutationBarrier.freeze()) {
                requireStoreUsable();
                work = backupWorkDirectory();
                frozen = Files.createTempDirectory(work, ".snapshot-");
                captured = clock.instant();
                freezeBackup(frozen);
            }
            PkiId id = new PkiId("backup-" + java.util.UUID.randomUUID().toString().replace("-", ""));
            result = FsBackupArchive.write(frozen, work, id, captured, backupLimits);
            FsBackupFiles.deleteTree(frozen);
            return result;
        } catch (IOException | RuntimeException failure) {
            if (result != null) {
                try { result.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            }
            if (frozen != null) {
                try { FsBackupFiles.deleteTree(frozen); } catch (IOException cleanup) {
                    throw new IOException("BACKUP_CLEANUP_FAILED", cleanup);
                }
            }
            if (failure instanceof IOException io) throw new IOException("BACKUP_CREATE_FAILED", io);
            throw failure;
        }
    }

    private Path backupWorkDirectory() throws IOException {
        Path work = paths.root().resolve(".backup-work");
        Files.createDirectories(work);
        return work;
    }

    private void freezeBackup(Path target) throws IOException {
        freezeBackup(target, true);
    }

    private void freezeBackup(Path target, boolean advanceTime) throws IOException {
        FsBackupFiles.Budget budget = new FsBackupFiles.Budget(backupLimits);
        FsBackupFiles.copy(paths.versionFile(), target.resolve("VERSION"), budget);
        FsBackupFiles.copy(paths.signingNamespaceFile(), target.resolve("SIGNING_NAMESPACE"), budget);
        if (advanceTime) metadataStore.advanceWatermark(signingNow().toEpochMilli());
        Path metadata = target.resolve("metadata");
        Files.createDirectory(metadata);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            metadataStore.exportBackupSnapshotTo(snapshot, metadata, Math.min(backupLimits.entryBytes(),
                    backupLimits.expandedBytes() - 1024));
        }
        try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(metadata)) {
            for (Path entry : entries) budget.add(Files.size(entry));
        }
        long revocationBytes = revocations.head().boundary();
        budget.add(revocationBytes);
        revocations.copyAuthoritativePrefix(target.resolve("revocations/transitions.log"));
        try (TemporaryUniqueIndex selected = stagedContent.beginUniqueIndex();
                TemporaryUniqueIndex requiredPayload = stagedContent.beginUniqueIndex();
                MetadataSnapshot snapshot = metadataStore.snapshot()) {
            new CredentialMetadataAuthority(metadataStore, stagedContent).validateAll(
                    credential -> {
                        addRetained(selected, credential.content());
                        addRetained(requiredPayload, credential.content());
                    });
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(STATUS_RECORD_NAMESPACE),
                    CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        DurableContentReference content = decodeStoredStatus(snapshot, record).status().content();
                        addRetained(selected, content);
                        addRetained(requiredPayload, content);
                    }
                }
            }
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(SIGN_STATE_NAMESPACE),
                    CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        SignWorkflowStore.Workflow workflow = decodeStoredSign(snapshot, record).record();
                        for (DurableContentReference content : workflow.candidates()) {
                            addRetained(selected, content);
                            if (isLiveContentState(workflow.state())) addRetained(requiredPayload, content);
                        }
                    }
                }
            }
            stagedContent.copyBackupContent(target.resolve("staged-content"), budget, selected, requiredPayload);
        }
        for (String tree : List.of("requests", "policy", "profiles", "workflows")) {
            Path liveTree = paths.root().resolve(tree);
            if (!Files.exists(liveTree)) continue;
            try (Stream<Path> pathsToCopy = Files.walk(liveTree, 5)) {
                java.util.Iterator<Path> iterator = pathsToCopy.iterator();
                while (iterator.hasNext()) {
                    Path file = iterator.next();
                    if (Files.isDirectory(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) continue;
                    String relative = paths.root().relativize(file).toString().replace(java.io.File.separatorChar, '/');
                    if (!FsBackupFiles.domain(relative)) continue;
                    FsBackupFiles.validatePath(relative, backupLimits);
                    if (Files.size(file) > backupLimits.recordBytes()) throw new IOException("BACKUP_RECORD_LIMIT");
                    FsBackupFiles.copy(file, target.resolve(relative), budget);
                }
            }
        }
        FsBackupFiles.forceTree(target);
        FsBackupFiles.forceDirectory(paths.root());
        FsBackupFiles.observe(FsBackupFiles.Phase.FROZEN, target);
    }

    /**
     * Verifies a bounded legacy archive using the same verifier as streaming input.
     * @param artifact caller-owned legacy artifact
     * @return integrity and recovery report; never an authenticity claim
     * @throws NullPointerException if artifact is null
     */
    @Override
    public zeroecho.pki.api.backup.BackupVerificationReport verifyBackup(
            zeroecho.pki.api.backup.BackupArtifact artifact) {
        Objects.requireNonNull(artifact, "artifact");
        if (artifact.payload().byteLength() > backupLimits.legacyBytes()) {
            return backupInvalid("BACKUP_LEGACY_LIMIT");
        }
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter();
                zeroecho.pki.api.backup.BackupSink sink = zeroecho.pki.api.backup.BackupSink.create(
                        backupWorkDirectory(), artifact.backupId(), backupLimits)) {
            requireStoreUsable();
            sink.outputStream().write(artifact.payload().bytes());
            try (zeroecho.pki.api.backup.BackupSource source = sink.complete()) {
                return verifyBackupSource(source);
            }
        } catch (IOException failure) {
            return backupInvalid(backupIssue(failure));
        }
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.BackupVerificationReport verifyBackupSource(
            zeroecho.pki.api.backup.BackupSource source) {
        Objects.requireNonNull(source, "source");
        try (zeroecho.pki.api.backup.BackupPreparation prepared = prepareBackup(source)) {
            return new zeroecho.pki.api.backup.BackupVerificationReport(true, List.of());
        } catch (IOException | RuntimeException failure) {
            return backupInvalid(backupIssue(failure));
        }
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.BackupPreparation prepareBackup(
            zeroecho.pki.api.backup.BackupSource source) throws IOException {
        Objects.requireNonNull(source, "source");
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return FsBackupEngine.prepare(backupWorkDirectory(), source, backupLimits, options, clock);
        }
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.RestoreStatus stageRestore(zeroecho.pki.api.backup.BackupSource source)
            throws IOException {
        return stageRestore(source, new PkiId(java.util.UUID.randomUUID().toString()));
    }

    /** {@inheritDoc} */
    @Override
    public zeroecho.pki.api.backup.RestoreStatus stageRestore(zeroecho.pki.api.backup.BackupSource source,
            PkiId restoreId) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(restoreId, "restoreId");
        if (!java.util.UUID.fromString(restoreId.value()).toString().equals(restoreId.value())) {
            throw new IllegalArgumentException("Restore identifier must be a canonical UUID");
        }
        zeroecho.pki.api.backup.BackupPreparation candidate;
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            if (restoreCoordinator == null) throw new UnsupportedOperationException("RESTORE_BORROWED_STORE");
            try { candidate = FsBackupEngine.prepare(restoreCoordinator.work(), source, backupLimits, options, clock); }
            catch (IOException rejection) { throw new zeroecho.pki.api.backup.RestoreRejectedException(rejection); }
        }
        try (zeroecho.pki.api.backup.BackupPreparation prepared = candidate;
                StoreMutationBarrier.Lease freeze = mutationBarrier.freeze()) {
            requireStoreUsable();
            Path work = restoreCoordinator.work();
            Path baseline;
            try { baseline = Files.createTempDirectory(work, ".baseline-"); }
            catch (IOException rejection) { throw new zeroecho.pki.api.backup.RestoreRejectedException(rejection); }
            try {
                try { freezeBackup(baseline, false); }
                catch (IOException rejection) { throw new zeroecho.pki.api.backup.RestoreRejectedException(rejection); }
                return restoreCoordinator.stage(prepared, baseline, restoreId);
            } finally { FsBackupFiles.deleteTree(baseline); }
        }
    }

    /** {@inheritDoc} */
    @Override
    public Optional<zeroecho.pki.api.backup.RestoreStatus> latestRestoreStatus() throws IOException {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return restoreCoordinator == null ? Optional.empty() : restoreCoordinator.status();
        }
    }

    /** {@inheritDoc} */
    @Override
    public void discardUnpublishedRestore(PkiId restoreId, Optional<PkiId> previousRestoreId,
            String manifestSha256) throws IOException {
        try (StoreMutationBarrier.Lease freeze = mutationBarrier.freeze()) {
            requireStoreUsable();
            if (restoreCoordinator == null) throw new UnsupportedOperationException("RESTORE_BORROWED_STORE");
            restoreCoordinator.discardUnpublished(restoreId, previousRestoreId, manifestSha256);
        }
    }

    /** {@inheritDoc} */
    @Override
    public Optional<zeroecho.pki.api.backup.RestoreIdentity> latestRestoreIdentity() throws IOException {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            return restoreCoordinator == null ? Optional.empty() : restoreCoordinator.identity();
        }
    }

    private static String backupIssue(Exception failure) {
        String message = failure.getMessage();
        return message != null && message.matches("BACKUP_[A-Z_]+") ? message : "BACKUP_INVALID";
    }

    private static zeroecho.pki.api.backup.BackupVerificationReport backupInvalid(String code) {
        return new zeroecho.pki.api.backup.BackupVerificationReport(false, List.of(code));
    }

    private void validateBackupDomainFile(String tree, Path file) throws IOException {
        String relative = paths.root().relativize(file).toString().replace(java.io.File.separatorChar, '/');
        if (!FsBackupFiles.domain(relative)) throw new IOException("BACKUP_INVENTORY");
        if (Files.size(file) > backupLimits.recordBytes()) throw new IOException("BACKUP_RECORD_LIMIT");
        byte[] bytes = Files.readAllBytes(file); // bounded legacy codec buffer, never a whole archive
        if ("requests".equals(tree)) {
            ParsedCertificationRequest request = FsCodec.decode(FsCodec.PARSED_REQUEST, bytes, stagedContent);
            if (!file.equals(paths.requestPath(request.requestId()))) throw new IOException("BACKUP_RECORD_ID");
        } else if ("policy".equals(tree)) {
            PolicyTrace trace = FsCodec.decode(FsCodec.POLICY_TRACE, bytes, stagedContent);
            if (!file.equals(paths.policyTracePath(trace.decisionId()))) throw new IOException("BACKUP_RECORD_ID");
        } else if ("workflows".equals(tree)) {
            WorkflowStateRecord state = FsCodec.decode(FsCodec.WORKFLOW_STATE, bytes, stagedContent);
            if (!file.getParent().equals(paths.workflowDir(state.opId()))
                    && !file.getParent().equals(paths.workflowHistoryDir(state.opId()))) {
                throw new IOException("BACKUP_RECORD_ID");
            }
        } else if ("active.bin".equals(file.getFileName().toString())) {
            CertificateProfileRef reference = FsCodec.decode(FsCodec.ACTIVE_PROFILE_REF, bytes, stagedContent);
            if (!file.equals(paths.profileActive(reference.profileId()))) throw new IOException("BACKUP_RECORD_ID");
            requireActiveProfile(reference.profileId());
        } else {
            ImportedCertificateProfileVersion version = FsCodec.decode(FsCodec.PROFILE_VERSION, bytes, stagedContent);
            CertificateProfileRef reference = version.reference();
            if (!file.equals(paths.profileVersion(reference.profileId(), reference.profileVersion()))) {
                throw new IOException("BACKUP_RECORD_ID");
            }
            getProfileVersion(reference.profileId(), reference.profileVersion()).orElseThrow();
        }
    }

    /* default */ void validateBackupDomainFiles() throws IOException {
        for (String tree : List.of("requests", "policy", "profiles", "workflows")) {
            Path directory = paths.root().resolve(tree);
            if (!Files.exists(directory)) continue;
            try (Stream<Path> walker = Files.walk(directory, 5)) {
                java.util.Iterator<Path> iterator = walker.iterator();
                while (iterator.hasNext()) {
                    Path file = iterator.next();
                    if (Files.isDirectory(file)) continue;
                    validateBackupDomainFile(tree, file);
                }
            }
        }
    }

    /**
     * Stages a bounded legacy archive for cold activation on the next store open.
     * A staged report has {@code success=false} and {@code RESTORE_RESTART_REQUIRED}.
     *
     * @param request restore request
     * @return staging or failure report; activation is reported by {@link #latestRestoreStatus()}
     * @throws NullPointerException if {@code request} is {@code null}
     * @throws IllegalStateException if the store is closing
     */
    @Override
    public zeroecho.pki.api.backup.RestoreReport restoreBackup(zeroecho.pki.api.backup.RestoreRequest request) {
        Objects.requireNonNull(request, "request");
        requireStoreUsable();
        PkiId failureId = new PkiId(java.util.UUID.randomUUID().toString());
        if (request.artifact().payload().byteLength() > backupLimits.legacyBytes()) {
            return new zeroecho.pki.api.backup.RestoreReport(failureId, false, List.of(), List.of("BACKUP_LEGACY_LIMIT"));
        }
        try (zeroecho.pki.api.backup.BackupSink sink = zeroecho.pki.api.backup.BackupSink.create(
                backupWorkDirectory(), request.artifact().backupId(), backupLimits)) {
            sink.outputStream().write(request.artifact().payload().bytes());
            try (zeroecho.pki.api.backup.BackupSource source = sink.complete()) {
                zeroecho.pki.api.backup.RestoreStatus status = stageRestore(source);
                return new zeroecho.pki.api.backup.RestoreReport(status.restoreId(), false, status.issues(), List.of());
            }
        } catch (IOException failure) {
            if ("RESTORE_OUTCOME_UNCERTAIN".equals(failure.getMessage()) && restoreCoordinator != null) {
                zeroecho.pki.api.backup.RestoreStatus status = restoreCoordinator.status().orElseThrow();
                return new zeroecho.pki.api.backup.RestoreReport(status.restoreId(), false, status.issues(), List.of());
            }
            return new zeroecho.pki.api.backup.RestoreReport(failureId, false, List.of(), List.of("RESTORE_STAGING_REJECTED"));
        }
    }

    @Override
    public void close() throws IOException {
        try (StoreMutationBarrier.Lease admission = mutationBarrier.stop()) {
            if (!closing.compareAndSet(false, true)) return;
            IOException failure = null;
            if (credentialSearch != null) {
                try { credentialSearch.close(); }
                catch (IOException exception) { failure = exception; }
            }
            try {
                revocations.close();
            } catch (IOException exception) {
                if (failure == null) failure = exception;
                else failure.addSuppressed(exception);
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
                if (restoreCoordinator != null) restoreCoordinator.close();
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            SigningActiveWal.Snapshot snapshot = metadataStore.cumulativeWriterSnapshot();
            return new LocalSigningWriterMetrics(snapshot.groupsCommitted(), snapshot.requestsCommitted(),
                    snapshot.forces(), snapshot.bytesAppended(), snapshot.maximumBatchSize(),
                    snapshot.batchWaitNanos(), snapshot.maximumBatchWaitNanos(), snapshot.forceNanos(),
                    snapshot.maximumForceNanos());
        }
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
        try (StoreMutationBarrier.Lease admission = mutationBarrier.enter()) {
            requireStoreUsable();
            SigningLedgerStoreEngine.CapacitySnapshot snapshot = metadataStore.capacitySnapshot();
            return new LocalSigningIndexCapacityMetrics(
                    snapshot.steady().reservedBytes(), snapshot.steady().highWaterReservedBytes(),
                    snapshot.steady().maximumBytes(), snapshot.transientBudget().reservedBytes(),
                    snapshot.transientBudget().highWaterReservedBytes(),
                    snapshot.transientBudget().maximumBytes(), snapshot.combinedReservedBytes(),
                    snapshot.combinedHighWaterBytes(), snapshot.combinedMaximumBytes());
        }
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

    private SignLockEntry acquireSignCandidateLock(String contentId) {
        SignLockEntry entry = signCandidateLocks.compute(contentId, (ignored, current) -> {
            SignLockEntry selected = current == null ? new SignLockEntry() : current;
            selected.references.incrementAndGet();
            return selected;
        });
        entry.lock.lock();
        return entry;
    }

    private void releaseSignCandidateLock(String contentId, SignLockEntry entry) {
        entry.lock.unlock();
        signCandidateLocks.computeIfPresent(contentId, (ignored, current) -> {
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

    private Optional<SignWorkflowStore.Workflow> readSignWorkflow(PkiId submissionId) {
        return readStoredSign(submissionId).map(StoredSign::record);
    }

    private Optional<StoredSign> readStoredSign(PkiId submissionId) {
        MetadataKey stateKey = signingStateKey(submissionId);
        try (MetadataSnapshot snapshot = metadataStore.snapshot()) {
            Optional<MetadataSnapshot.Record> storedState = snapshot.get(stateKey);
            if (storedState.isEmpty()) {
                if (snapshot.get(signingEnvelopeKey(submissionId)).isPresent()) {
                    throw new IllegalStateException(
                            "Signing envelope exists without mutable state");
                }
                return Optional.empty();
            }
            return Optional.of(decodeStoredSign(snapshot, storedState.orElseThrow()));
        } catch (java.nio.channels.ClosedByInterruptException ex) {
            // ClosedByInterruptException already sets the interrupt flag; preserve it for the
            // caller's interruption-detection path (MetadataStoreException CANCELLED traversal).
            throw new IllegalStateException("Failed to read authoritative signing record",
                    new MetadataStoreException(MetadataCommitResult.FailureCategory.CANCELLED,
                            "Signing record read interrupted by thread interrupt", ex));
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to read authoritative signing record", ex);
        }
    }

    private StoredSign decodeStoredSign(MetadataSnapshot snapshot, MetadataSnapshot.Record storedState)
            throws IOException {
        SignWorkflowStore.MutableState state = FsCodec.decode(FsCodec.SIGN_MUTABLE_STATE,
                readMetadataValue(storedState), stagedContent);
        PkiId submissionId = state.operationId();
        if (!signingStateKey(submissionId).equals(storedState.key())) {
            throw new IllegalStateException("Signing state metadata key mismatch");
        }
        MetadataSnapshot.Record storedEnvelope = snapshot.get(signingEnvelopeKey(submissionId))
                .orElseThrow(() -> new IllegalStateException(
                        "Signing mutable state has no immutable envelope"));
        SignWorkflowStore.AcceptanceEnvelope envelope = FsCodec.decode(
                FsCodec.SIGN_ACCEPTANCE_ENVELOPE, readMetadataValue(storedEnvelope),
                stagedContent);
        SignWorkflowStore.Workflow record = new SignWorkflowStore.Workflow(envelope, state);
        validateSignRecord(submissionId, record);
        DurableContentReference reference = envelope.candidate();
        MetadataSnapshot.Record storedBinding = snapshot.get(
                signingCandidateBindingKey(reference.contentId())).orElseThrow(
                        () -> new IllegalStateException("Signing candidate binding is missing"));
        SignWorkflowStore.CandidateBinding binding = FsCodec.decode(
                FsCodec.SIGN_CANDIDATE_BINDING, readMetadataValue(storedBinding));
        if (!binding.operationId().equals(submissionId)
                || binding.length() != reference.length()
                || !constantTimeAsciiEquals(binding.sha256(), reference.sha256())) {
            throw new IllegalStateException("Signing candidate binding is inconsistent");
        }
        Optional<BoundSignCandidate> proofCandidate = Optional.empty();
        if (envelope.proofStep().isPresent()) {
            DurableContentReference proof = envelope.proofStep().orElseThrow().challenge();
            MetadataSnapshot.Record proofRecord = snapshot.get(signingCandidateBindingKey(proof.contentId()))
                    .orElseThrow(() -> new IllegalStateException("CA proof candidate binding is missing"));
            SignWorkflowStore.CandidateBinding proofBinding = FsCodec.decode(FsCodec.SIGN_CANDIDATE_BINDING, readMetadataValue(proofRecord));
            if (!proof.contentId().equals(proofBinding.candidateId()) || !submissionId.equals(proofBinding.operationId())
                    || proof.length() != proofBinding.length() || !proof.sha256().equals(proofBinding.sha256())) {
                throw new IllegalStateException("CA proof candidate binding differs");
            }
            proofCandidate = Optional.of(new BoundSignCandidate(proof, proofRecord.recordRevision()));
        }
        return new StoredSign(record, storedState.recordRevision(),
                storedEnvelope.recordRevision(), storedBinding.recordRevision(), reference, proofCandidate);
    }

    private Optional<SignWorkflowStore.CandidateBinding> readCandidateBinding(String candidateId) {
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataSnapshot.Record stored = snapshot.get(
                        signingCandidateBindingKey(candidateId)).orElse(null)) {
            if (stored == null) {
                return Optional.empty();
            }
            return Optional.of(FsCodec.decode(FsCodec.SIGN_CANDIDATE_BINDING,
                    readMetadataValue(stored)));
        } catch (IOException failure) {
            throw new IllegalStateException("Failed to read signing candidate binding", failure);
        }
    }

    // Parsing and canonicalization failures can carry persisted request material;
    // validation deliberately replaces every such cause with a safe corruption
    // code.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private void validateSignRecord(PkiId requestedId, SignWorkflowStore.Workflow record) {
        Objects.requireNonNull(requestedId, "requestedId");
        Objects.requireNonNull(record, "record");

        SigningSubmissionId parsed;
        Instant horizonEnd;
        Instant futureLimit;
        try {
            parsed = SigningSubmissionId.parse(record.submissionId());
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
        requireValidSignRecord(record.envelope().candidate().lifecycle()
                == DurableContentReference.Lifecycle.OPERATION, record,
                "CANDIDATE_LIFECYCLE_INVALID");
        requireValidSignRecord(record.envelope().acceptanceCommitment().matches(
                new SignWorkflowStore.AcceptanceCommand(record.operationId(), record.namespace(),
                        record.configurationCommitment(), record.envelope().accessContext(),
                        record.envelope().keyRef(), record.envelope().fairnessAuthorityId(),
                        record.envelope().algorithmId(), record.envelope().signatureEncoding(),
                        record.createdAt(), record.deadline(), record.envelope().candidate(),
                        record.envelope().outer(), record.mode(), record.envelope().proofStep()).commitment()), record,
                "ACCEPTANCE_COMMITMENT_MISMATCH");

        requireValidSignRecord(record.revision() >= record.fence(), record, "REVISION_FENCE_ORDER_INVALID");
        requireValidSignRecord(record.detailCode().isEmpty() || !record.detailCode().get().isBlank(), record,
                "DETAIL_CODE_INVALID");
        if (record.leaseUntil().isPresent()) {
            Instant leaseUntil = record.leaseUntil().get();
            requireValidSignRecord(leaseUntil.isAfter(record.createdAt()) && !leaseUntil.isAfter(horizonEnd), record,
                    "LEASE_TIME_INVALID");
        }
        boolean durablePublicationRetry = record.state() == SignWorkflowStore.State.SUCCEEDED
                && record.failureCount() > 0;
        if (durablePublicationRetry) {
            requireValidSignRecord(record.envelope().outer().isPresent()
                    && record.reconciliationFailureClass()
                            .filter(SignWorkflowStore.ReconciliationFailureClass.LOCAL_FAILURE::equals)
                            .isPresent(), record, "OUTER_PUBLICATION_RETRY_INVALID");
        }
        if (record.nextEligibleAt().isPresent()) {
            Instant nextEligible = record.nextEligibleAt().orElseThrow();
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

    private boolean replaceSignMetadata(StoredSign current, SignWorkflowStore.Workflow replacement,
            boolean removeOwner) {
        validateSignRecord(replacement.submissionId(), replacement);
        try (MetadataTransaction transaction =
                metadataStore.beginSigningProgressTransaction()) {
            transaction.replace(signingStateKey(replacement.submissionId()), current.recordRevision(),
                    byteContent(FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE,
                            replacement.mutableState())), CancellationSignal.NONE);
            return requireKnownOutcome(transaction.commit()).outcome()
                    == MetadataCommitResult.Outcome.COMMITTED;
        } catch (MetadataStoreException failure) {
            throw translateSigningMetadataFailure(failure);
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
    }

    private Optional<SignExpiry> expireIfDeadlineReached(StoredSign stored) {
        SignWorkflowStore.Workflow current = stored.record();
        if (!isActiveSignState(current.state()) || current.deadline().isAfter(signingNow())) {
            return Optional.empty();
        }
        return expireSign(stored);
    }

    private Optional<SignExpiry> expireSign(StoredSign stored) {
        SignWorkflowStore.Workflow current = stored.record();
        if (!isActiveSignState(current.state())) {
            return Optional.empty();
        }
        SignWorkflowStore.Workflow expired = expiredSignRecord(current);
        if (!replaceExpiredSignMetadata(stored, expired)) {
            return Optional.empty();
        }
        return Optional.of(new SignExpiry(expired, stored.record().candidates()));
    }

    private SignTransitionCommit commitSignTransitionAtAdmission(StoredSign stored,
            SignWorkflowStore.Workflow replacement) {
        SignWorkflowStore.Workflow expired = expiredSignRecord(stored.record());
        validateSignRecord(replacement.submissionId(), replacement);
        validateSignRecord(expired.submissionId(), expired);
        SigningLedgerStoreEngine.ConditionalCommitResult committed;
        try {
            SigningLedgerStoreEngine.ConditionalDirectCommit alternatives =
                    new SigningLedgerStoreEngine.ConditionalDirectCommit(
                            signReplacementMutations(stored, replacement, false),
                            signExpiryMutations(stored, expired),
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
            return new SignTransitionCommit(Optional.of(replacement), Optional.empty());
        }
        SignExpiry expiry = new SignExpiry(expired, stored.record().candidates());
        return new SignTransitionCommit(Optional.of(expired), Optional.of(expiry));
    }

    // Derived delivery follows confirmed primary transitions, outside signing locks and cleanup.
    // Recovery calls the same helper from the existing signing-reference enumeration. Neither a
    // missing append nor invalid optional evidence can revise a committed primary disposition.
    private void recordSigningEvidence(SignWorkflowStore.Workflow workflow) {
        if (signingEvidenceLog == null) { return; }
        zeroecho.pki.application.SigningExecutionEvidence.Outcome outcome = switch (workflow.state()) {
            case SUCCEEDED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.SIGNED;
            case FAILED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.FAILED;
            case CANCELLED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.CANCELLED;
            case EXPIRED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.EXPIRED;
            case RETIRED -> workflow.result().isPresent() && workflow.detailCode().filter("SIGNED"::equals).isPresent()
                    ? zeroecho.pki.application.SigningExecutionEvidence.Outcome.SIGNED
                    : workflow.detailCode().filter("CANCELLED"::equals).isPresent()
                            ? zeroecho.pki.application.SigningExecutionEvidence.Outcome.CANCELLED
                            : zeroecho.pki.application.SigningExecutionEvidence.Outcome.FAILED;
            default -> null;
        };
        if (outcome != null && !appendSigningEvidence(workflow, workflow.operationId(), workflow.detailCode(), outcome,
                workflow.providerUpdatedAt())) { return; }
        workflow.proofOutcome().ifPresent(proof -> {
            zeroecho.pki.application.SigningExecutionEvidence.Outcome proofDisposition = switch (proof.disposition()) {
                case SUCCEEDED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.SIGNED;
                case CANCELLED -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.CANCELLED;
                case FAILED, UNRECOVERABLE -> zeroecho.pki.application.SigningExecutionEvidence.Outcome.FAILED;
                case PENDING, RETRYABLE_UNKNOWN -> throw new IllegalStateException("Retained proof outcome is not terminal");
            };
            appendSigningEvidence(workflow, workflow.envelope().proofStep().orElseThrow().operationId(),
                    Optional.of(proof.detailCode().name()), proofDisposition, proof.providerUpdatedAt());
        });
    }

    // The apparently unused result deliberately validates overflow or representability before any side effect.
    @SuppressWarnings({ "PMD.UselessPureMethodCall" })
    private boolean appendSigningEvidence(SignWorkflowStore.Workflow workflow, PkiId marker,
            Optional<String> detail, zeroecho.pki.application.SigningExecutionEvidence.Outcome outcome,
            Optional<Instant> providerTime) {
        try {
            zeroecho.pki.application.SigningExecutionEvidence evidence =
                    zeroecho.pki.application.SigningExecutionEvidence.terminal(workflow.namespace(), workflow.fingerprint(),
                            workflow.owner().type(), workflow.owner().name(), detail, outcome);
            byte[] payload = DomainAttributeEncoding.encode(evidence.attributes()).getBytes(StandardCharsets.UTF_8);
            // Use the existing monotonic clock fallback without a second usability check after
            // an independent evidence append may have fenced the underlying metadata engine.
            Instant recordedAt = providerTime.orElseGet(this::advanceSigningTime);
            try {
                // The evidence log uses epoch milliseconds; admission/provider timestamps do not.
                recordedAt.toEpochMilli();
            } catch (ArithmeticException unrepresentableAuditTime) {
                return deferredSigningEvidence();
            }
            signingEvidenceLog.append(marker, recordedAt, payload);
            return true;
        } catch (IOException | IllegalArgumentException deferred) {
            return deferredSigningEvidence();
        } catch (IllegalStateException unavailable) {
            // The engine records this cause before it rejects subsequent access for recovery.
            // Do not swallow an unrelated lifecycle/programming failure in an otherwise usable engine.
            if (metadataStore.firstRecoveryFailure() == null) { throw unavailable; }
            return deferredSigningEvidence();
        }
    }

    private static boolean deferredSigningEvidence() {
        LOG.log(Level.WARNING, "Signing evidence log append deferred: code=EVIDENCE_APPEND_UNCONFIRMED");
        return false;
    }

    // The active WAL invokes this bounded guard at its admission linearization point.
    // It performs no I/O or wait, sharing the lock-free monotonic time source so that
    // admission and ordinary signing observe one non-decreasing signing clock.
    private Instant signingAdmissionNow() {
        return advanceSigningTime();
    }

    private List<SigningTransactionPayloadCodec.Mutation> signReplacementMutations(
            StoredSign current, SignWorkflowStore.Workflow replacement, boolean removeOwner) {
        SigningTransactionPayloadCodec.Mutation replace = new SigningTransactionPayloadCodec.Mutation(
                SigningTransactionPayloadCodec.MutationKind.REPLACE,
                signingStateKey(replacement.submissionId()), current.recordRevision(),
                FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE, replacement.mutableState()));
        return List.of(replace);
    }

    private boolean replaceExpiredSignMetadata(StoredSign current,
            SignWorkflowStore.Workflow expired) {
        validateSignRecord(expired.submissionId(), expired);
        try {
            MetadataCommitResult result = metadataStore.directSigningProgressCommit(
                    signExpiryMutations(current, expired));
            return result.outcome() == MetadataCommitResult.Outcome.COMMITTED;
        } catch (MetadataStoreException failure) {
            throw translateSigningMetadataFailure(failure);
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
    }

    private List<SigningTransactionPayloadCodec.Mutation> signExpiryMutations(
            StoredSign current, SignWorkflowStore.Workflow expired) {
        List<SigningTransactionPayloadCodec.Mutation> mutations = new ArrayList<>(2);
        mutations.addAll(signReplacementMutations(current, expired, true));
        if (current.record().envelope().outer().isEmpty()) {
            return List.copyOf(mutations);
        }
        try (MetadataSnapshot snapshot = metadataStore.snapshot();
                MetadataSnapshot.Record stored = snapshot.get(
                        domainContinuationKey(current.record().operationId())).orElse(null)) {
            if (stored == null) {
                throw new IllegalStateException("Signing outer continuation is missing");
            }
            DomainContinuationStore.Record outer = decodeDomainContinuation(
                    current.record().operationId(), stored);
            requireMatchingOuter(current.record(), outer);
            if (!isTerminalOuterState(outer.state())) {
                DomainContinuationStore.Record outerExpired = new DomainContinuationStore.Record(
                        outer.operationId(), outer.version(), outer.kind(), outer.correlationId(),
                        DomainContinuationStore.State.EXPIRED, outer.revision() + 1L,
                        outer.createdAt(), outer.deadline(), outer.command(), outer.commandCommitment(),
                        Optional.empty(), Optional.empty(), Optional.of("EXPIRED"));
                mutations.add(new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.REPLACE,
                        domainContinuationKey(outer.operationId()), stored.recordRevision(),
                        FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, outerExpired)));
            }
            return List.copyOf(mutations);
        } catch (IOException failure) {
            throw signingDurabilityFailure(failure);
        }
    }

    private boolean outerTerminal(SignWorkflowStore.Workflow workflow) {
        if (workflow.envelope().outer().isEmpty()) {
            return true;
        }
        DomainContinuationStore.Record outer = getDomainContinuation(workflow.operationId())
                .orElseThrow(() -> new IllegalStateException("Signing outer continuation is missing"));
        requireMatchingOuter(workflow, outer);
        return isTerminalOuterState(outer.state());
    }

    private void requireOuterTerminal(SignWorkflowStore.Workflow workflow) {
        if (!outerTerminal(workflow)) {
            throw new IllegalStateException("Expired signing outer continuation is not terminal");
        }
    }

    private static void requireMatchingOuter(SignWorkflowStore.Workflow workflow,
            DomainContinuationStore.Record continuation) {
        SignWorkflowStore.OuterCommand expected = workflow.envelope().outer().orElseThrow();
        boolean sameCommand = expected.command().encoding() == continuation.command().encoding()
                && MessageDigest.isEqual(expected.command().bytes(), continuation.command().bytes());
        if (continuation.kind() != expected.kind()
                || continuation.correlationId().filter(expected.correlationId()::equals).isEmpty()
                || !constantTimeAsciiEquals(expected.commandCommitment(), continuation.commandCommitment())
                || !sameCommand) {
            throw new IllegalStateException("Signing outer continuation differs from acceptance");
        }
    }

    private static boolean isTerminalOuterState(DomainContinuationStore.State state) {
        return state == DomainContinuationStore.State.COMPLETED
                || state == DomainContinuationStore.State.FAILED
                || state == DomainContinuationStore.State.EXPIRED;
    }

    private SignWorkflowStore.Workflow expiredSignRecord(SignWorkflowStore.Workflow current) {
        return copySignRecord(current, SignWorkflowStore.State.EXPIRED,
                current.revision() + 1L, current.fence(), Optional.empty(),
                Optional.of("EXPIRED"), Optional.empty(), Optional.empty(), 0,
                Optional.empty(), Optional.empty());
    }

    private void finishSignExpiry(SignExpiry expiry) {
        expiry.references().forEach(reference -> {
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
        recordSigningEvidence(expiry.record());
    }

    private boolean directReplaceSignMetadata(StoredSign current, SignWorkflowStore.Workflow replacement) {
        validateSignRecord(replacement.submissionId(), replacement);
        List<SigningTransactionPayloadCodec.Mutation> mutations = List.of(
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.REPLACE,
                        signingStateKey(replacement.submissionId()), current.recordRevision(),
                        FsCodec.encode(FsCodec.SIGN_MUTABLE_STATE,
                                replacement.mutableState())));
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
    private static SignWorkflowStore.Workflow copySignRecord(SignWorkflowStore.Workflow current,
            SignWorkflowStore.State state, long revision, long fence, Optional<Instant> leaseUntil,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt,
            int failureCount, Optional<Instant> nextEligibleAt,
            Optional<SignWorkflowStore.ReconciliationFailureClass> failureClass) {
        return copySignRecord(current, state, revision, fence, leaseUntil, detailCode, result,
                providerUpdatedAt, failureCount, nextEligibleAt, failureClass,
                transitionedInitialAttempt(current, state));
    }

    @SuppressWarnings("PMD.ExcessiveParameterList")
    private static SignWorkflowStore.Workflow copySignRecord(SignWorkflowStore.Workflow current,
            SignWorkflowStore.State state, long revision, long fence, Optional<Instant> leaseUntil,
            Optional<String> detailCode, Optional<EncodedObject> result, Optional<Instant> providerUpdatedAt,
            int failureCount, Optional<Instant> nextEligibleAt,
            Optional<SignWorkflowStore.ReconciliationFailureClass> failureClass,
            SignWorkflowStore.InitialAttemptPhase phase) {
        return copySignRecordWithDownstream(current, state, revision, fence, leaseUntil,
                current.downstreamOperationId(), detailCode, result, providerUpdatedAt,
                failureCount, nextEligibleAt, failureClass, phase);
    }

    @SuppressWarnings("PMD.ExcessiveParameterList")
    private static SignWorkflowStore.Workflow copySignRecordWithDownstream(SignWorkflowStore.Workflow current,
            SignWorkflowStore.State state, long revision, long fence, Optional<Instant> leaseUntil,
            Optional<PkiId> downstreamOperationId, Optional<String> detailCode, Optional<EncodedObject> result,
            Optional<Instant> providerUpdatedAt, int failureCount, Optional<Instant> nextEligibleAt,
            Optional<SignWorkflowStore.ReconciliationFailureClass> failureClass,
            SignWorkflowStore.InitialAttemptPhase phase) {
        SignWorkflowStore.MutableState mutable = new SignWorkflowStore.MutableState(current.operationId(), state,
                revision, fence, leaseUntil, downstreamOperationId, detailCode, result, providerUpdatedAt,
                failureCount, nextEligibleAt, failureClass, phase, current.stage(), current.proofOutcome());
        return new SignWorkflowStore.Workflow(current.envelope(), mutable);
    }

    private static SignWorkflowStore.InitialAttemptPhase transitionedInitialAttempt(
            SignWorkflowStore.Workflow current, SignWorkflowStore.State target) {
        if (current.mode() == SignWorkflowStore.Mode.NORMAL || current.initialAttemptPhase().finished()
                || target == SignWorkflowStore.State.INTENT || target == SignWorkflowStore.State.DISPATCHED
                || target == SignWorkflowStore.State.CANCELLING) {
            return current.initialAttemptPhase();
        }
        return SignWorkflowStore.InitialAttemptPhase.COMPLETED;
    }

    private static SignWorkflowStore.InitialAttemptPhase failedInitialAttempt(SignWorkflowStore.Workflow current) {
        return current.mode() == SignWorkflowStore.Mode.NORMAL || current.initialAttemptPhase().finished()
                ? current.initialAttemptPhase() : SignWorkflowStore.InitialAttemptPhase.FAILED;
    }

    private static SignWorkflowStore.InitialAttemptPhase claimedInitialAttempt(SignWorkflowStore.Workflow current) {
        if (current.mode() == SignWorkflowStore.Mode.NORMAL || current.state() == SignWorkflowStore.State.INTENT
                || current.state() == SignWorkflowStore.State.CANCELLING) {
            return current.initialAttemptPhase();
        }
        return switch (current.initialAttemptPhase()) {
            case DISPATCH_OWED, OBSERVATION_OWED -> SignWorkflowStore.InitialAttemptPhase.OBSERVATION_CONSUMED;
            case OBSERVATION_CONSUMED -> SignWorkflowStore.InitialAttemptPhase.FAILED;
            case COMPLETED, FAILED -> current.initialAttemptPhase();
            case NOT_APPLICABLE -> throw new IllegalStateException("Bounded signing phase is missing");
        };
    }

    private static Instant signLeaseUntil(SignWorkflowStore.Workflow workflow, Instant now, Duration lease) {
        Duration untilDeadline = Duration.between(now, workflow.deadline());
        return lease.compareTo(untilDeadline) >= 0 ? workflow.deadline() : now.plus(lease);
    }

    private static MetadataKey signingEnvelopeKey(PkiId submissionId) {
        SigningSubmissionId parsed = SigningSubmissionId.parse(submissionId);
        return new MetadataKey(SIGN_ENVELOPE_NAMESPACE, parsed.id().value());
    }

    private static MetadataKey signingStateKey(PkiId submissionId) {
        SigningSubmissionId parsed = SigningSubmissionId.parse(submissionId);
        return new MetadataKey(SIGN_STATE_NAMESPACE, parsed.id().value());
    }

    private static MetadataKey signingCandidateBindingKey(String candidateId) {
        Objects.requireNonNull(candidateId, "candidateId");
        return new MetadataKey(SIGN_CANDIDATE_BINDING_NAMESPACE, candidateId);
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
                ? new CredentialMetadataAuthority(metadataStore, stagedContent).find(snapshot, record.sourceId()).map(Credential::content).orElseThrow(
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

    private record StoredSign(SignWorkflowStore.Workflow record, long recordRevision,
            long envelopeRevision, long bindingRevision,
            DurableContentReference reference, Optional<BoundSignCandidate> proofCandidate) {
    }

    private record BoundSignCandidate(DurableContentReference reference, long bindingRevision) { }

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

    private record SignExpiry(SignWorkflowStore.Workflow record,
            List<DurableContentReference> references) {
    }

    private record SignTransitionCommit(Optional<SignWorkflowStore.Workflow> record,
            Optional<SignExpiry> expiry) {
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
            return target == SignWorkflowStore.State.EXPIRED;
        }
        if (source == SignWorkflowStore.State.DISPATCHED) {
            return target == SignWorkflowStore.State.SUCCEEDED || target == SignWorkflowStore.State.FAILED
                    || target == SignWorkflowStore.State.EXPIRED;
        }
        if (source == SignWorkflowStore.State.CANCELLING) {
            return target == SignWorkflowStore.State.SUCCEEDED
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

    private static boolean isLiveContentState(SignWorkflowStore.State state) {
        return !isContentFreeSignState(state);
    }

    private static void validateSignRecordState(SignWorkflowStore.Workflow record) {
        switch (record.state()) {
            case INTENT -> {
                requireValidSignRecord(record.result().isEmpty() && record.providerUpdatedAt().isEmpty(), record,
                        "INTENT_TERMINAL_DATA_PRESENT");
                requireDetailCode(record, "INTENT");
                requireValidSignRecord(record.revision() == 0L && record.fence() == INITIAL_FENCE
                        && record.leaseUntil().isEmpty() && record.downstreamOperationId().isEmpty(), record,
                        "INTENT_INITIAL_STATE_INVALID");
            }
            case DISPATCHED -> {
                requireValidSignRecord(record.fence() > 0L && record.revision() >= record.fence(), record,
                        "DISPATCH_REVISION_INVALID");
                boolean verifying = record.stage() == SignWorkflowStore.Stage.CA_PROOF_VERIFYING;
                boolean ready = record.stage() == SignWorkflowStore.Stage.CA_CERTIFICATE_READY;
                requireValidSignRecord(validActiveClaimOrRetry(record, verifying || ready
                        || record.mode() == SignWorkflowStore.Mode.BOUNDED_OBSERVATION
                        && record.initialAttemptPhase() == SignWorkflowStore.InitialAttemptPhase.OBSERVATION_OWED)
                        && (verifying ? record.result().isPresent() : record.result().isEmpty())
                        && record.providerUpdatedAt().isEmpty(), record, "DISPATCH_TERMINAL_DATA_PRESENT");
                requireValidSignRecord(ready ? record.downstreamOperationId().isEmpty()
                        : record.downstreamOperationId().equals(Optional.of(record.providerOperationId())),
                        record, "DISPATCH_DOWNSTREAM_ID_INVALID");
                requireDetailCode(record, "DISPATCHED");
            }
            case CANCELLING -> {
                requireValidSignRecord(record.revision() >= record.fence(), record, "CANCELLING_REVISION_INVALID");
                requireValidSignRecord(validActiveClaimOrRetry(record, true) && record.result().isEmpty()
                        && record.providerUpdatedAt().isEmpty(), record, "CANCELLING_TERMINAL_DATA_PRESENT");
                requireValidSignRecord(record.downstreamOperationId().equals(Optional.of(record.providerOperationId())),
                        record, "CANCELLING_DOWNSTREAM_ID_INVALID");
                requireValidSignRecord(record.detailCode()
                        .filter(code -> "CANCEL_REQUESTED".equals(code) || "CANCEL_SUBMITTED".equals(code)).isPresent(),
                        record, "DETAIL_CODE_INVALID");
            }
            case SUCCEEDED -> {
                requireValidSignRecord(record.fence() > 0L && record.revision() > record.fence(), record,
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
                requireValidSignRecord(record.revision() > record.fence(), record, "CANCELLED_REVISION_INVALID");
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
                if (record.result().isPresent()) {
                    requireValidSignRecord(
                            record.fence() > 0L && record.revision() - record.fence() >= 2L
                                    && record.providerUpdatedAt().isPresent()
                                    && record.providerUpdatedAt().get().isBefore(record.deadline())
                                    && record.detailCode().equals(Optional.of("SIGNED")),
                            record, "RETIRED_SUCCESS_EVIDENCE_INVALID");
                } else {
                    requireValidSignRecord(record.revision() - record.fence() >= 2L
                            && record.detailCode().filter(code -> "CANCELLED".equals(code)
                                    || isRetainedFailureDetail(code)).isPresent(), record,
                            "RETIRED_TERMINAL_EVIDENCE_INVALID");
                }
            }
        }
    }

    private static boolean validActiveClaimOrRetry(SignWorkflowStore.Workflow record,
            boolean permitsUnclaimedReady) {
        boolean retryEmpty = record.failureCount() == 0 && record.nextEligibleAt().isEmpty()
                && record.reconciliationFailureClass().isEmpty();
        if (record.leaseUntil().isPresent()) {
            return retryEmpty;
        }
        boolean retryComplete = record.failureCount() > 0 && record.nextEligibleAt().isPresent()
                && record.reconciliationFailureClass().isPresent();
        return retryComplete || permitsUnclaimedReady && retryEmpty;
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

    private static boolean isRetainedFailureDetail(String detailCode) {
        return switch (detailCode) {
            case "FAILED", "DENIED", "LOCAL_RESTART_UNRECOVERABLE",
                    "PROVIDER_RESULT_INVALID", "INVALID_KEY_REFERENCE",
                    "INVALID_ALGORITHM", "ALGORITHM_MISMATCH", "KEY_NOT_FOUND",
                    "CONTENT_INTEGRITY_FAILURE", "UNSUPPORTED_SIGNATURE_ENCODING",
                    "KEYRING_IO_FAILURE", "CRYPTO_FAILURE", "DEADLINE_EXPIRED",
                    "PROVIDER_ID_MISMATCH", "PROVIDER_SUBMISSION_FAILED",
                    "PROVIDER_RESULT_MISSING", "LATE_PROVIDER_SUCCESS" -> true;
            default -> false;
        };
    }

    private static void requireDetailCode(SignWorkflowStore.Workflow record, String required) {
        requireValidSignRecord(record.detailCode().filter(required::equals).isPresent(), record,
                "STATE_DETAIL_CODE_INVALID");
    }

    private static void requireValidSignRecord(boolean condition, SignWorkflowStore.Workflow record, String code) {
        if (!condition) {
            throw invalidSignRecord(record, code);
        }
    }

    private static IllegalStateException invalidSignRecord(SignWorkflowStore.Workflow record, String code) {
        return new IllegalStateException("Signing record corruption: type=sign-workflow version="
                + CURRENT_SIGN_ENVELOPE_VERSION + '/' + CURRENT_SIGN_STATE_VERSION
                + " state=" + record.state() + " code=" + code);
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
    /* default */ static final class StoreOwnership implements AutoCloseable {
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
        /* default */ static StoreOwnership acquire(Path lockFile) throws IOException {
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

        /* default */ static StoreOwnership borrowed() { return new StoreOwnership(null, null); }

        /* default */ void closeSilently() {
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
                if (closed || channel == null) {
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
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        DurableMetadataFiles.create(file, encoded.length, output -> output.write(encoded));
        return value;
    }

    private void publishVersionFile() throws IOException {
        Path vf = this.paths.versionFile();
        if (Files.exists(vf, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw unsupportedStoreFormat();
        }
        Path temporary = paths.root().resolve(".version-" + java.util.UUID.randomUUID() + ".tmp");
        boolean moved = false;
        try {
            tripInitializationFault(InitializationFaultPoint.VERSION_TEMP_CREATE);
            if (Files.getFileStore(paths.root()).supportsFileAttributeView("posix")) {
                Files.createFile(temporary, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.util.EnumSet.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE)));
            } else {
                Files.createFile(temporary);
                PlatformFs.ops().restrictToOwner(temporary);
            }
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                tripInitializationFault(InitializationFaultPoint.VERSION_WRITE);
                SigningFormatSupport.writeFully(channel,
                        ByteBuffer.wrap(CURRENT_STORE_VERSION_BYTES));
                tripInitializationFault(InitializationFaultPoint.VERSION_FILE_FORCE);
                channel.force(true);
            }
            tripInitializationFault(InitializationFaultPoint.VERSION_ATOMIC_MOVE);
            Files.move(temporary, vf, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            moved = true;
            tripInitializationFault(InitializationFaultPoint.VERSION_DIRECTORY_FORCE);
            SigningFormatSupport.forceDirectory(paths.root());
        } catch (IOException failure) {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            }
            if (moved) {
                try {
                    Files.deleteIfExists(vf);
                    SigningFormatSupport.forceDirectory(paths.root());
                } catch (IOException cleanupFailure) {
                    failure.addSuppressed(cleanupFailure);
                }
            }
            throw failure;
        }
    }

    /* default */ static void installInitializationFault(InitializationFaultPoint point) {
        INITIALIZATION_FAULT.set(Objects.requireNonNull(point, "point"));
    }

    /* default */ static void clearInitializationFault() {
        INITIALIZATION_FAULT.remove();
    }

    private static void tripInitializationFault(InitializationFaultPoint point) throws IOException {
        if (INITIALIZATION_FAULT.get() == point) {
            throw new IOException("Injected filesystem-store initialization failure");
        }
    }

    /** Durable boundaries exercised while publishing a new v14 store root. */
    /* default */ enum InitializationFaultPoint {
        NAMESPACE_PUBLISHED,
        STAGED_CONTENT_PUBLISHED,
        METADATA_PUBLISHED,
        REVOCATIONS_PUBLISHED,
        VERSION_TEMP_CREATE,
        VERSION_WRITE,
        VERSION_FILE_FORCE,
        VERSION_ATOMIC_MOVE,
        VERSION_DIRECTORY_FORCE
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

    private static UnsupportedStoreFormatException unsupportedStoreFormat() {
        return new UnsupportedStoreFormatException();
    }

    /** Redacted marker used to preserve format rejection across constructor wrapping. */
    private static final class UnsupportedStoreFormatException extends IOException {
        private static final long serialVersionUID = 1L;

        private UnsupportedStoreFormatException() {
            super("Filesystem store format unsupported: code=STORE_FORMAT_UNSUPPORTED");
        }
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
        private final boolean ownsSnapshot;
        private final AtomicBoolean cursorClosed = new AtomicBoolean();

        private PublicationMetadataCursor(MetadataSnapshot snapshot, MetadataCursor cursor) {
            this(snapshot, cursor, true);
        }

        private PublicationMetadataCursor(MetadataSnapshot snapshot, MetadataCursor cursor, boolean ownsSnapshot) {
            this.snapshot = snapshot;
            this.cursor = cursor;
            this.ownsSnapshot = ownsSnapshot;
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
                if (ownsSnapshot) { snapshot.close(); }
            }
        }
    }

    private X509Certificate reservationIssuer(Credential credential, IssuerGeneration exact, PkiId authority,
            MetadataSnapshot snapshot) throws IOException {
        if (!exact.authorityId().equals(authority)) {
            throw new IllegalStateException("X.509 credential issuer authority differs");
        }
        X509Certificate issuer = certificateHolder((snapshot == null ? getCredential(exact.credentialId())
                : new CredentialMetadataAuthority(metadataStore, stagedContent).find(snapshot, exact.credentialId())).orElseThrow());
        IssuerChainPath path = (snapshot == null ? getIssuerChainPath(credential.issuerRef().chainPathId())
                : AuthorityMetadataStore.find(snapshot, AuthorityMetadataCodec.pathKey(credential.issuerRef().chainPathId()), AuthorityMetadataCodec::path))
                .orElseThrow(() -> new IllegalStateException("X.509 credential issuer path is missing"));
        if (!path.issuerId().equals(exact.issuerId()) || !path.authorityId().equals(authority)) {
            throw new IllegalStateException("X.509 credential issuer path differs");
        }
        return issuer;
    }

    private static void requireProofSignature(boolean succeeded, Optional<EncodedObject> signature) {
        if (succeeded != signature.isPresent() || signature.filter(value -> value.encoding() != Encoding.BINARY
                || value.byteLength() == 0 || value.byteLength() > 1_048_576).isPresent()) {
            throw new IllegalArgumentException("CA proof signature shape differs from outcome");
        }
    }

    private static SignWorkflowStore.Workflow checkpointedProof(SignWorkflowStore.Workflow current, boolean succeeded,
            SignWorkflowStore.CaSubjectProofOutcome outcome, Optional<EncodedObject> signature, long fence) {
        boolean verifying = succeeded && current.state() == SignWorkflowStore.State.DISPATCHED;
        SignWorkflowStore.State target = verifying ? SignWorkflowStore.State.DISPATCHED
                : succeeded || outcome.disposition() == zeroecho.pki.spi.crypto.SigningProvider.ObservationState.CANCELLED
                        ? SignWorkflowStore.State.CANCELLED : SignWorkflowStore.State.FAILED;
        Optional<String> detail = Optional.of(verifying ? "DISPATCHED"
                : target == SignWorkflowStore.State.CANCELLED ? "CANCELLED" : outcome.detailCode().name());
        return caStageRecord(current, target,
                verifying ? SignWorkflowStore.Stage.CA_PROOF_VERIFYING : current.stage(), Optional.of(outcome),
                current.revision() + 1L, fence, Optional.empty(), current.downstreamOperationId(), detail,
                verifying ? signature : Optional.empty(), verifying ? Optional.empty() : outcome.providerUpdatedAt());
    }
}
